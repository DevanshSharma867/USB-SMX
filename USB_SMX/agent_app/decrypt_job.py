#!/usr/bin/env python
"""
Standalone script to decrypt the output of a Gateway Service job.
"""
import sys
import json
from pathlib import Path

# --- Add project root to sys.path for imports ---
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
# ---------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    # We will use the AgentCryptoManager to handle all crypto operations
    from agent_app.src.agent_crypto import AgentCryptoManager
except ImportError as e:
    print(f"Error: A required library is missing or could not be imported: {e}")
    print("Please ensure 'cryptography' is installed ('pip install cryptography') and paths are correct.")
    sys.exit(1)

def main():
    """Main function to run the decryption process."""
    # 1. Get Job ID from command line argument
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <job_id_or_drive_letter>")
        print(f"Example (Job ID): python {sys.argv[0]} b906af11-2616-4065-948a-0905159cba9a")
        print(f"Example (Drive Letter): python {sys.argv[0]} E:")
        sys.exit(1)
    
    arg = sys.argv[1]
    
    # Determine if the argument is a drive letter or a job ID
    if ":" in arg:
        drive_letter = arg.strip().upper()
        pendrive_root = Path(f"{drive_letter}/")
        manifest_path = pendrive_root / ".gateway_output" / "manifest.json"
        print(f"--- Decrypting Job from Drive: {drive_letter} ---")
    else:
        # This path is for local testing and may not reflect the pendrive structure
        job_id = arg
        job_dir = Path(__file__).parent.parent / "gateway_app" / "jobs" / job_id
        manifest_path = job_dir / "manifest.json"
        print(f"--- Decrypting Job from local files: {job_id} ---")

    output_dir = Path.cwd() / "decrypted_output"

    # 2. Find the manifest
    if not manifest_path.is_file():
        print(f"Error: manifest.json not found at {manifest_path}")
        sys.exit(1)

    # 3. Initialize Crypto Manager
    # This will load the agent's config and keys automatically
    print("Initializing crypto manager...")
    crypto_manager = AgentCryptoManager()
    if not crypto_manager._private_key: # Check if keys were loaded
        print("FATAL: Could not initialize AgentCryptoManager. Check agent_config.json and key paths.")
        sys.exit(1)

    # 4. Load manifest and verify signature
    print("Loading and verifying manifest...")
    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    except Exception as e:
        print(f"Error reading manifest.json: {e}")
        sys.exit(1)

    if not crypto_manager.verify_manifest_signature(manifest.copy()):
        print("FATAL: Manifest signature verification failed. Aborting.")
        sys.exit(1)

    # 5. Unwrap the Content Encryption Key (CEK)
    print("Unwrapping content key...")
    cek = crypto_manager.unwrap_cek(manifest)
    if not cek:
        print("FATAL: Failed to unwrap content key. This agent may not be authorized or the manifest is corrupt.")
        sys.exit(1)

    # 6. Get data paths from manifest
    pendrive_output_path_str = manifest.get("pendrive_output_path")
    if not pendrive_output_path_str:
        print("Error: manifest.json does not contain 'pendrive_output_path'.")
        sys.exit(1)
    
    # The data path is relative to the manifest's location
    data_dir = manifest_path.parent / "data"
    if not data_dir.is_dir():
        print(f"Error: Encrypted data directory not found at {data_dir}.")
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
                # Make path relative to its anchor (e.g., C:\ -> Users\...)
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
