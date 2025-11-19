
import json
import requests
from pathlib import Path
from src.agent_crypto import AgentCryptoManager

# --- Configuration ---
# Path to the manifest file on the "USB drive"
MANIFEST_PATH = Path("C:/Users/sdeva/Desktop/TestUSB/.gateway_output/manifest.json")
# URL of the running KMS server
KMS_URL = "http://127.0.0.1:8000"
# Where to save the decrypted files
DECRYPT_OUTPUT_DIR = Path(__file__).parent / "DECRYPTED_FILES"
# --- End Configuration ---

def run_decryption():
    """
    Simulates the final agent step: verifying, unwrapping key, and decrypting.
    """
    print("--- Starting Agent Decryption Simulation ---")
    DECRYPT_OUTPUT_DIR.mkdir(exist_ok=True)
    
    # 1. Initialize the Agent's crypto manager
    agent_crypto = AgentCryptoManager()
    
    # 2. Read the manifest from the USB drive
    print(f"Reading manifest from: {MANIFEST_PATH}")
    with open(MANIFEST_PATH, 'r') as f:
        manifest = json.load(f)

    # 3. Verify the manifest signature to ensure it's not tampered with
    print("Verifying manifest signature...")
    if not agent_crypto.verify_manifest_signature(manifest):
        print("FATAL: Manifest signature is INVALID. Halting.")
        return
    print("Signature is valid.")

    # 4. Get the wrapped CEK from the manifest
    wrapped_cek = manifest["encryption_params"]["cek_wrapped"]
    print(f"Found Wrapped CEK: {wrapped_cek[:30]}...")

    # 5. SIMULATE AGENT->GATEWAY->KMS communication to unwrap the key
    print("Sending wrapped key to KMS for unwrapping...")
    try:
        response = requests.post(f"{KMS_URL}/unwrap-key", json={"wrapped_cek": wrapped_cek})
        response.raise_for_status()
        unwrapped_cek_b64 = response.json()["cek"]
        
        import base64
        # The CEK is what's needed for decryption
        cek = base64.b64decode(unwrapped_cek_b64)
        print("Successfully unwrapped CEK from KMS.")

    except requests.exceptions.RequestException as e:
        print(f"FATAL: Failed to unwrap key from KMS: {e}")
        return

    # 6. Decrypt each file listed in the manifest
    print("\n--- Decrypting Files ---")
    encrypted_data_path = MANIFEST_PATH.parent / "data"
    
    for original_path, file_info in manifest["files"].items():
        original_filename = Path(original_path).name
        encrypted_blob_name = file_info["encrypted_blob_name"]
        expected_hash = file_info["sha256_encrypted"]
        nonce = bytes.fromhex(file_info["nonce"])
        tag = bytes.fromhex(file_info["tag"])
        
        encrypted_file = encrypted_data_path / encrypted_blob_name
        
        # --- BEGIN INTEGRITY CHECK ---
        print(f"Verifying integrity of blob '{encrypted_blob_name}'...")
        actual_hash = agent_crypto.get_sha256_hash_for_file(encrypted_file)

        if actual_hash != expected_hash:
            print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print(f"FATAL: TAMPERING DETECTED on blob {encrypted_blob_name}")
            print(f"Expected hash: {expected_hash}")
            print(f"Actual hash:   {actual_hash}")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("Halting decryption process.")
            break # Stop immediately
        print("Integrity check passed.")
        # --- END INTEGRITY CHECK ---

        print(f"Decrypting '{original_filename}' from blob '{encrypted_blob_name}'...")

        plaintext = agent_crypto.decrypt_file(encrypted_file, cek, nonce, tag)

        if plaintext:
            output_path = DECRYPT_OUTPUT_DIR / original_filename
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            print(f"  -> Success! Saved to {output_path}")
        else:
            print(f"  -> FAILED to decrypt {original_filename}")

if __name__ == "__main__":
    run_decryption()
