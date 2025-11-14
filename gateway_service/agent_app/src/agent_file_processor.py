
import sys
import json
from pathlib import Path
import queue

# --- Add project root to sys.path for KMS import ---
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
# ---------------------------------------------------

from agent_crypto import AgentCryptoManager
from gateway_app.src.gateway.kms import KMS
from cryptography.exceptions import InvalidTag

class AgentFileProcessor:
    """Handles the processing of encrypted jobs for the agent."""

    def __init__(self):
        self.crypto_manager = AgentCryptoManager()
        self.kms = KMS()

    def _send_log(self, gui_queue: queue.Queue, job_path: str, message: str):
        if gui_queue:
            gui_queue.put({"event": "LOG_EVENT", "job_path": job_path, "log_message": message})

    def _send_status(self, gui_queue: queue.Queue, job_path: str, status: str):
        if gui_queue:
            gui_queue.put({"event": "STATUS_UPDATE", "job_path": job_path, "status": status})

    def process_encrypted_job(self, job_path: Path, output_path: Path, gui_queue: queue.Queue, job_path_str: str):
        """
        Processes an encrypted job directory, decrypting files to the output path.
        """
        manifest_path = job_path / "manifest.json"
        data_path = job_path / "data"

        if not all([manifest_path.exists(), data_path.exists()]):
            self._send_log(gui_queue, job_path_str, "Error: Job directory is incomplete (missing manifest.json or data folder).")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return

        # 1. Load and Verify Manifest
        self._send_status(gui_queue, job_path_str, "VERIFYING_SIGNATURE")
        self._send_log(gui_queue, job_path_str, "Loading manifest...")
        try:
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
        except Exception as e:
            self._send_log(gui_queue, job_path_str, f"Error: Could not read manifest.json: {e}")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return
        
        if not self.crypto_manager.verify_manifest_signature(manifest.copy()):
            self._send_log(gui_queue, job_path_str, "Error: Manifest signature is invalid. Aborting.")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return
        self._send_log(gui_queue, job_path_str, "Manifest signature verified.")

        # 2. Unwrap CEK using the KMS
        self._send_log(gui_queue, job_path_str, "Unwrapping key via KMS...")
        try:
            wrapped_cek = manifest["encryption_params"]["cek_wrapped"]
            cek = self.kms.unwrap_key(wrapped_cek)
            self._send_log(gui_queue, job_path_str, "Key unwrapped successfully.")
        except (InvalidTag, ValueError, KeyError) as e:
            self._send_log(gui_queue, job_path_str, f"FATAL: Failed to unwrap key. It may be corrupt, tampered with, or missing. {e}")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return
        except Exception as e:
            self._send_log(gui_queue, job_path_str, f"FATAL: An unexpected error occurred during key unwrapping: {e}")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return

        # 3. Decrypt Files
        self._send_status(gui_queue, job_path_str, "DECRYPTING")
        output_path.mkdir(parents=True, exist_ok=True)
        self._send_log(gui_queue, job_path_str, f"Decrypting files to: {output_path.absolute()}")
        for original_path, file_info in manifest["files"].items():
            # Skip system files
            if (original_path.lower().endswith("desktop.ini") or
                original_path.lower().endswith("thumbs.db") or
                original_path.startswith("$") or
                original_path.lower() in [".ds_store", ".spotlight-v100", ".trashes", ".fseventsd"]):
                self._send_log(gui_queue, job_path_str, f"Skipping {original_path} (system file)...")
                continue
                
            encrypted_blob_name = file_info["encrypted_blob_name"]
            encrypted_file_path = data_path / encrypted_blob_name
            nonce = bytes.fromhex(file_info["nonce"])
            tag = bytes.fromhex(file_info["tag"])

            self._send_log(gui_queue, job_path_str, f"Decrypting {original_path}...")
            plaintext = self.crypto_manager.decrypt_file(encrypted_file_path, cek, nonce, tag)

            if plaintext:
                try:
                    # Recreate the original directory structure
                    original_path_obj = Path(original_path)
                    if original_path_obj.is_absolute():
                        relative_path = original_path_obj.relative_to(original_path_obj.anchor)
                    else:
                        relative_path = original_path_obj
                    
                    decrypted_file_path = output_path / relative_path
                    decrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(decrypted_file_path, 'wb') as f:
                        f.write(plaintext)
                    self._send_log(gui_queue, job_path_str, f"  -> Decrypted successfully to {decrypted_file_path}")
                except Exception as e:
                    self._send_log(gui_queue, job_path_str, f"  -> ERROR writing file {original_path}: {e}")
                    self._send_status(gui_queue, job_path_str, "FAILED")
                    return
            else:
                self._send_log(gui_queue, job_path_str, f"Failed to decrypt {original_path}")
                self._send_status(gui_queue, job_path_str, "FAILED")
                return

        self._send_status(gui_queue, job_path_str, "COMPLETE")
