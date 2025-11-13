#!/usr/bin/env python
"""
Standalone script to decrypt the output of a Gateway Service job.
"""
import sys
import json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: The 'cryptography' library is required. Please install it using 'pip install cryptography'")
    sys.exit(1)

# --- Configuration ---
JOBS_DIR = Path(__file__).parent / "jobs"
PUBLIC_KEY_PATH = Path(__file__).parent.parent / "gateway_app/src/gateway/keys/gateway_public_key.pem"

def verify_manifest_signature(manifest: dict, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verifies the signature of the manifest."""
    if "signature" not in manifest:
        print("Error: Manifest is not signed.")
        return False

    signature_data = manifest.pop("signature")
    signature = bytes.fromhex(signature_data["value"])
    
    canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    try:
        public_key.verify(signature, canonical_manifest)
        print("Manifest signature verified successfully.")
        return True
    except InvalidTag:
        print("ERROR: Manifest signature is invalid! The manifest may have been tampered with.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during signature verification: {e}")
        return False

def main():
    """Main function to run the decryption process."""
    # 1. Get Job ID from command line argument
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <job_id>")
        print(f"Example: python {sys.argv[0]} b906af11-2616-4065-948a-0905159cba9a")
        sys.exit(1)
    
    job_id = sys.argv[1]
    job_dir = JOBS_DIR / job_id
    output_dir = job_dir / "decrypted_output"

    print(f"--- Decrypting Job: {job_id} ---")

    # 2. Find the manifest on the pendrive
    pendrive_root = Path(sys.argv[1])
    manifest_path = pendrive_root / ".gateway_output" / "manifest.json"

    if not manifest_path.is_file():
        print(f"Error: manifest.json not found on pendrive at {manifest_path}")
        sys.exit(1)

    # 3. Load public key
    if not PUBLIC_KEY_PATH.exists():
        print(f"FATAL: Gateway public key not found at {PUBLIC_KEY_PATH}")
        sys.exit(1)
    try:
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except Exception as e:
        print(f"FATAL: Failed to load public key: {e}")
        sys.exit(1)

    # 4. Load manifest and verify signature
    print("Loading and verifying manifest...")
    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    except Exception as e:
        print(f"Error reading manifest.json: {e}")
        sys.exit(1)

    if not verify_manifest_signature(manifest, public_key):
        sys.exit(1)

    pendrive_output_path_str = manifest.get("pendrive_output_path")
    if not pendrive_output_path_str:
        print("Error: manifest.json does not contain 'pendrive_output_path'. This job was likely created with an older version.")
        sys.exit(1)
    
    pendrive_root = Path(pendrive_output_path_str)
    key_path = pendrive_root / "cek.key"
    data_dir = pendrive_root / "data"

    # 5. Validate pendrive paths
    if not all([key_path.is_file(), data_dir.is_dir()]):
        print(f"Error: Encrypted data or key not found on pendrive at {pendrive_root}. Ensure the pendrive is inserted.")
        sys.exit(1)

    # 6. Load key
    print("Loading decryption key from pendrive...")
    try:
        cek = key_path.read_bytes()
    except Exception as e:
        print(f"Error reading CEK from pendrive: {e}")
        sys.exit(1)

    # 7. Create output directory
    output_dir.mkdir(exist_ok=True)
    print(f"Output will be saved to: {output_dir}")

    # 8. Decryption Loop
    files_to_decrypt = manifest.get('files', {})
    if not files_to_decrypt:
        print("Warning: Manifest contains no files to decrypt.")
        sys.exit(0)

    success_count = 0
    fail_count = 0

    for original_path_str, file_data in files_to_decrypt.items():
        original_path = Path(original_path_str)
        print(f"\nProcessing: {original_path.name}")

        try:
            # Reconstruct the full path for the output file
            if original_path.is_absolute():
                relative_path = original_path.relative_to(original_path.anchor)
            else:
                relative_path = original_path

            output_file_path = output_dir / relative_path
            output_file_path.parent.mkdir(parents=True, exist_ok=True)

            # Get crypto material from manifest
            encrypted_blob_name = file_data['encrypted_blob_name']
            nonce = bytes.fromhex(file_data['nonce'])
            tag = bytes.fromhex(file_data['tag'])

            # Read the encrypted data blob
            encrypted_blob_path = data_dir / encrypted_blob_name
            ciphertext = encrypted_blob_path.read_bytes()

            # Decrypt using AES-GCM
            aesgcm = AESGCM(cek)
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)

            # Write the decrypted plaintext to the output file
            output_file_path.write_bytes(plaintext)
            print(f"  -> Decrypted successfully to {output_file_path}")
            success_count += 1

        except InvalidTag:
            print("  -> ERROR: Decryption failed! The file is corrupt or the key is incorrect (Invalid Tag).")
            fail_count += 1
        except Exception as e:
            print(f"  -> ERROR: An unexpected error occurred: {e}")
            fail_count += 1

    print(f"\n--- Decryption Complete ---")
    print(f"Successfully decrypted: {success_count} file(s)")
    print(f"Failed to decrypt:    {fail_count} file(s)")

if __name__ == "__main__":
    main()
