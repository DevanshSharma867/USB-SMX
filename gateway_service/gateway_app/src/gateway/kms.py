
import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class KMS:
    """
    A simulated Key Management Service (KMS) to securely wrap and unwrap
    Content Encryption Keys (CEKs).

    In a real system, this would be a network service like HashiCorp Vault.
    For this MVP, it's a local library that both Gateway and Agent can use.
    """
    _MASTER_KEY_FILENAME = "kms_master.key"

    def __init__(self):
        self.master_key_path = Path(__file__).parent / self._MASTER_KEY_FILENAME
        self._master_key = self._load_master_key()

    def _load_master_key(self) -> bytes:
        """Loads the master key from disk. Raises error if not found."""
        if not self.master_key_path.exists():
            raise FileNotFoundError(
                f"KMS master key '{self._MASTER_KEY_FILENAME}' not found. "
                f"Please run 'python {Path(__file__).name}' to generate it."
            )
        return self.master_key_path.read_bytes()

    def wrap_key(self, plaintext_key: bytes) -> str:
        """
        Encrypts (wraps) a key with the master key using AES-256-GCM.

        Args:
            plaintext_key: The key to wrap (e.g., a 32-byte CEK).

        Returns:
            A base64-encoded string containing the nonce, ciphertext, and tag.
        """
        aesgcm = AESGCM(self._master_key)
        nonce = os.urandom(12)  # GCM standard nonce size
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_key, None)

        # Combine nonce and ciphertext+tag for storage
        wrapped_payload = nonce + ciphertext_with_tag
        
        return base64.b64encode(wrapped_payload).decode('utf-8')

    def unwrap_key(self, wrapped_key: str) -> bytes:
        """
        Decrypts (unwraps) a key that was wrapped with the master key.

        Args:
            wrapped_key: A base64-encoded string from the wrap_key method.

        Returns:
            The original plaintext key.
        
        Raises:
            InvalidTag: If the key is invalid or has been tampered with.
            ValueError: If the wrapped key format is incorrect.
        """
        try:
            wrapped_payload = base64.b64decode(wrapped_key)
            
            nonce = wrapped_payload[:12]
            ciphertext_with_tag = wrapped_payload[12:]

            if len(nonce) != 12:
                raise ValueError("Invalid wrapped key format: incorrect nonce length.")

            aesgcm = AESGCM(self._master_key)
            plaintext_key = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            
            return plaintext_key
        except InvalidTag as e:
            print("KMS UNWRAP FAILED: Key is invalid or has been tampered with.")
            raise e
        except Exception as e:
            print(f"KMS UNWRAP FAILED: An unexpected error occurred: {e}")
            raise e

def generate_master_key_file():
    """Generates and saves a new master key."""
    key_path = Path(__file__).parent / KMS._MASTER_KEY_FILENAME
    if key_path.exists():
        print(f"Master key '{key_path.name}' already exists. Skipping generation.")
        return

    print(f"Generating new master key at '{key_path}'...")
    master_key = AESGCM.generate_key(bit_length=256)
    key_path.write_bytes(master_key)
    print("Master key generated successfully.")

if __name__ == "__main__":
    # This allows the file to be run directly to set up the KMS master key.
    print("--- KMS Setup Utility ---")
    generate_master_key_file()
    print("-----------------------")
