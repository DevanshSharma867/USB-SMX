
import json
from pathlib import Path
import queue
from agent_crypto import AgentCryptoManager

class AgentFileProcessor:
    """Handles the processing of encrypted jobs for the agent."""

    def __init__(self):
        self.crypto_manager = AgentCryptoManager()

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
        cek_path = job_path / "cek.key"
        data_path = job_path / "data"

        if not all([manifest_path.exists(), cek_path.exists(), data_path.exists()]):
            self._send_log(gui_queue, job_path_str, "Error: Job directory is incomplete.")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return

        # 1. Load and Verify Manifest
        self._send_status(gui_queue, job_path_str, "VERIFYING_SIGNATURE")
        self._send_log(gui_queue, job_path_str, "Loading manifest...")
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        if not self.crypto_manager.verify_manifest_signature(manifest.copy()):
            self._send_log(gui_queue, job_path_str, "Error: Manifest signature is invalid. Aborting.")
            self._send_status(gui_queue, job_path_str, "FAILED")
            return
        self._send_log(gui_queue, job_path_str, "Manifest signature verified.")

        # 2. Load CEK (insecurely for MVP)
        cek = self.crypto_manager.load_cek_from_disk(cek_path)

        # 3. Decrypt Files
        self._send_status(gui_queue, job_path_str, "DECRYPTING")
        output_path.mkdir(parents=True, exist_ok=True)
        self._send_log(gui_queue, job_path_str, f"Decrypting files to: {output_path.absolute()}")
        for original_path, file_info in manifest["files"].items():
            # Skip system files and cek.key file
            if (original_path.endswith("cek.key") or 
                original_path.lower().endswith("desktop.ini") or
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
                    # Recreate the original directory structure (similar to decrypt_job.py)
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
