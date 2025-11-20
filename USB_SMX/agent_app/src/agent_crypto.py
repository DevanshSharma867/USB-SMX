import json
import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class AgentCryptoManager:
    """Handles decryption and signature verification for the agent."""

    def __init__(self):
        self._agent_id = None
        self._private_key = self._load_private_key()
        self._public_key = self._load_public_key() # For signature verification

    def _load_private_key(self) -> rsa.RSAPrivateKey | None:
        """Loads the agent's unique RSA private key from the path specified in the config."""
        try:
            config_path = Path(__file__).parent / "agent_config.json"
            if not config_path.exists():
                print("FATAL: agent_config.json not found.")
                return None
            
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self._agent_id = config.get("agent_id")
            private_key_path_str = config.get("private_key_path")

            if not self._agent_id or not private_key_path_str:
                print("FATAL: agent_id or private_key_path missing from config.")
                return None

            project_root = Path(__file__).parent.parent.parent
            private_key_path = project_root / private_key_path_str

            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            print(f"Successfully loaded private key for agent: {self._agent_id}")
            return private_key

        except Exception as e:
            print(f"FATAL: Failed to load agent private key: {e}")
            return None

    def _load_public_key(self) -> ed25519.Ed25519PublicKey | None:
        """Loads the gateway's public key to verify manifest signatures."""
        public_key_path = Path(__file__).parent.parent.parent / "gateway_app" / "src" / "gateway" / "keys" / "gateway_public_key.pem"
        if not public_key_path.exists():
            print("FATAL: Gateway public key not found.")
            return None
        try:
            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            return public_key
        except Exception as e:
            print(f"FATAL: Failed to load public key: {e}")
            return None

    def unwrap_cek(self, manifest: dict) -> bytes | None:
        """
        Finds the appropriate wrapped CEK in the manifest and unwraps it
        using the agent's private key.
        """
        if not self._private_key or not self._agent_id:
            print("Cannot unwrap CEK: Agent private key or ID not loaded.")
            return None

        try:
            wrapped_ceks = manifest["encryption_params"]["multi_recipient_wrapped_ceks"]
            wrapped_cek_b64 = wrapped_ceks.get(self._agent_id)

            if not wrapped_cek_b64:
                print(f"Error: No wrapped CEK found for agent_id '{self._agent_id}' in manifest.")
                return None

            wrapped_cek = base64.b64decode(wrapped_cek_b64)

            plaintext_cek = self._private_key.decrypt(
                wrapped_cek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("CEK unwrapped successfully.")
            return plaintext_cek

        except KeyError:
            print("Error: Manifest does not contain 'multi_recipient_wrapped_ceks'.")
            return None
        except Exception as e:
            print(f"Failed to unwrap CEK: {e}")
            return None

    def verify_manifest_signature(self, signed_manifest: dict) -> bool:
        """
        Verifies the signature of the manifest.
        """
        if not self._public_key:
            print("Cannot verify manifest: Public key not loaded.")
            return False

        # Work on a copy to avoid modifying the original dictionary
        manifest_to_verify = signed_manifest.copy()
        signature_block = manifest_to_verify.pop("signature", None)
        if not signature_block:
            print("Manifest is not signed.")
            return False

        try:
            signature = bytes.fromhex(signature_block["value"])
            canonical_manifest = json.dumps(manifest_to_verify, sort_keys=True, separators=(',', ':')).encode('utf-8')
            
            self._public_key.verify(signature, canonical_manifest)
            print("Manifest signature is valid.")
            return True
        except Exception as e:
            print(f"Manifest signature verification failed: {e}")
            return False

    def get_sha256_hash_for_data(self, data: bytes) -> str:
        """Calculates the SHA-256 hash of a byte string."""
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.hexdigest()

    def get_sha256_hash_for_file(self, file_path: Path) -> str | None:
        """Calculates the SHA-256 hash of a file on disk."""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            print(f"Cannot hash file: {file_path} not found.")
            return None
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return None

    def decrypt_file(self, encrypted_path: Path, cek: bytes, nonce: bytes, tag: bytes) -> bytes | None:
        """
        Decrypts a file using AES-256-GCM.
        """
        try:
            aesgcm = AESGCM(cek)
            with open(encrypted_path, 'rb') as f:
                ciphertext = f.read()
            
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
            return plaintext
        except Exception as e:
            print(f"Failed to decrypt {encrypted_path}: {type(e).__name__} - {e}")
            return None
