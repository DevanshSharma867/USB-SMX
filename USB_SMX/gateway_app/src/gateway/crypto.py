# Manages cryptographic operations like encryption and signing.
import os
import hashlib
import json
import datetime
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class CryptoManager:
    """Handles encryption, hashing, and digital signing."""

    def __init__(self):
        self._private_key = self._load_private_key()
        self._agent_public_keys = self._load_agent_public_keys()

    def _load_private_key(self) -> ed25519.Ed25519PrivateKey | None:
        """Loads the Ed25519 private key from the filesystem."""
        private_key_path = Path(__file__).parent / "keys" / "gateway_private_key.pem"
        if not private_key_path.exists():
            print("FATAL: Gateway private key not found. Please run generate_gateway_key.py")
            return None
        try:
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            return private_key
        except Exception as e:
            print(f"FATAL: Failed to load private key: {e}")
            return None

    def _load_agent_public_keys(self) -> dict[str, rsa.RSAPublicKey]:
        """Loads agent public keys from the JSON registry."""
        keys = {}
        registry_path = Path(__file__).parent / "keys" / "agent_key_registry.json"
        
        if not registry_path.exists():
            print("Warning: agent_key_registry.json not found. No agent keys loaded.")
            return keys

        try:
            with open(registry_path, 'r') as f:
                registry = json.load(f)
            
            for agent_info in registry.get("agents", []):
                agent_id = agent_info.get("id")
                public_key_pem = agent_info.get("public_key_pem")
                
                if not agent_id or not public_key_pem:
                    continue

                public_key = serialization.load_pem_public_key(
                    public_key_pem.encode('utf-8')
                )
                
                if isinstance(public_key, rsa.RSAPublicKey):
                    keys[agent_id] = public_key
                    print(f"Successfully loaded public key for agent: {agent_id}")

        except Exception as e:
            print(f"Error loading agent public keys: {e}")
        
        return keys

    def generate_cek(self, key_size_bytes: int = 32) -> bytes:
        """Generates a cryptographically secure Content Encryption Key (CEK)."""
        if key_size_bytes not in [16, 24, 32]:
            raise ValueError("Invalid key size for AES. Must be 16, 24, or 32 bytes.")
        return os.urandom(key_size_bytes)

    def get_available_agents(self) -> dict[str, rsa.RSAPublicKey]:
        """Returns the dictionary of loaded agent IDs and their public keys."""
        return self._agent_public_keys

    def wrap_cek_for_selected_agents(self, cek: bytes, selected_agents: list[str]) -> dict[str, str]:
        """Encrypts the CEK for each selected agent using their public RSA key."""
        wrapped_ceks = {}
        for agent_id in selected_agents:
            public_key = self._agent_public_keys.get(agent_id)
            if not public_key:
                print(f"Warning: Public key for selected agent '{agent_id}' not found. Skipping.")
                continue

            try:
                wrapped_key = public_key.encrypt(
                    cek,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                wrapped_ceks[agent_id] = base64.b64encode(wrapped_key).decode('utf-8')
            except Exception as e:
                print(f"Error wrapping CEK for agent '{agent_id}': {e}")
        
        print(f"CEK wrapped for {len(wrapped_ceks)} selected agent(s).")
        return wrapped_ceks

    def encrypt_file(self, file_path: Path, cek: bytes) -> tuple[bytes, bytes, bytes] | None:
        """
        Encrypts a file using AES-256-GCM.

        Args:
            file_path: The path to the file to encrypt.
            cek: The Content Encryption Key (32 bytes for AES-256).

        Returns:
            A tuple containing (ciphertext, nonce, tag), or None on failure.
        """
        try:
            aesgcm = AESGCM(cek)
            nonce = os.urandom(12)  # GCM standard nonce size
            
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            ciphertext = aesgcm.encrypt(nonce, plaintext, None) # No associated data
            
            # The tag is appended to the ciphertext by the library, let's extract it.
            tag_length = 16 # GCM standard tag size
            actual_ciphertext = ciphertext[:-tag_length]
            tag = ciphertext[-tag_length:]

            return actual_ciphertext, nonce, tag, len(plaintext)

        except Exception as e:
            print(f"Failed to encrypt {file_path}: {e}")
            return None

    def get_sha256_hash(self, data: bytes) -> str:
        """Calculates the SHA-256 hash of a byte string."""
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.hexdigest()

    def create_manifest(self, job, file_metadata: dict, multi_wrapped_ceks: dict, gateway_info: dict, file_count: int = None, pendrive_output_path: str = None) -> dict:
        """
        Creates the job manifest.
        
        Args:
            job: The job object.
            file_metadata: A dictionary mapping file paths to their metadata (hash, etc.).
            multi_wrapped_ceks: A dictionary of CEKs wrapped for each agent.
            gateway_info: A dictionary with details about the gateway machine.
            file_count: Total number of a files processed.
            pendrive_output_path: Path where encrypted files are stored on the pendrive.
        
        Returns:
            A dictionary representing the manifest.
        """
        print(f"Creating manifest for job {job.job_id}")
        manifest = {
            "job_id": job.job_id,
            "file_count": file_count or len(file_metadata),
            "encryption_algorithm": "AES-256-GCM",
            "pendrive_output_path": pendrive_output_path or "N/A",
            "gateway_info": gateway_info,
            "files": file_metadata,
            "encryption_params": {
                "algorithm": "AES-256-GCM",
                "multi_recipient_wrapped_ceks": multi_wrapped_ceks
            }
        }
        return manifest

    def sign_manifest(self, manifest: dict) -> dict:
        """
        Signs the manifest using the gateway's Ed25519 private key.
        """
        if not self._private_key:
            print("Cannot sign manifest: Private key not loaded.")
            return manifest

        print("Signing manifest with gateway key...")
        
        # Create a canonical (sorted, no whitespace) JSON string for signing
        # This ensures the signature is consistent regardless of key order
        canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        signature = self._private_key.sign(canonical_manifest)
        
        signed_manifest = manifest.copy()
        signed_manifest["signature"] = {
            "signer": "gateway",
            "value": signature.hex(),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
        print("Manifest signed.")
        return signed_manifest
