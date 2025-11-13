
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import json

class AgentCryptoManager:
    """Handles decryption and signature verification for the agent."""

    def __init__(self):
        self._public_key = self._load_public_key()

    def _load_public_key(self) -> ed25519.Ed25519PublicKey | None:
        """Loads the gateway's public key to verify manifest signatures."""
        public_key_path = Path(__file__).parent.parent / "src" / "gateway" / "keys" / "gateway_public_key.pem"
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

    def verify_manifest_signature(self, signed_manifest: dict) -> bool:
        """
        Verifies the signature of the manifest.
        """
        if not self._public_key:
            print("Cannot verify manifest: Public key not loaded.")
            return False

        signature_block = signed_manifest.pop("signature", None)
        if not signature_block:
            print("Manifest is not signed.")
            return False

        try:
            signature = bytes.fromhex(signature_block["value"])
            canonical_manifest = json.dumps(signed_manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
            
            self._public_key.verify(signature, canonical_manifest)
            print("Manifest signature is valid.")
            return True
        except Exception as e:
            print(f"Manifest signature verification failed: {e}")
            return False

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
            print(f"Failed to decrypt {encrypted_path}: {e}")
            return None

    def load_cek_from_disk(self, path: Path) -> bytes:
        """Loads the plaintext CEK from disk. INSECURE MVP METHOD."""
        print(f"INSECURE: Loading plaintext CEK from {path}")
        with open(path, 'rb') as f:
            return f.read()
