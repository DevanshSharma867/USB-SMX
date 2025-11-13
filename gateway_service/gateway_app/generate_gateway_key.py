#!/usr/bin/env python
"""
Script to generate Ed25519 private and public keys for the Gateway Service.

WARNING: Storing private keys directly in files is INSECURE for production environments.
In a real system, these keys should be managed by an HSM or a secure key management system (e.g., HashiCorp Vault).
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Define paths for key storage
KEY_DIR = Path(__file__).parent / "src" / "gateway" / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "gateway_private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "gateway_public_key.pem"

def generate_keys():
    """Generates Ed25519 private and public keys and saves them to files."""
    print("Generating Ed25519 private and public keys...")
    
    # Generate private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Get public key
    public_key = private_key.public_key()

    # Ensure key directory exists
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Save private key
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Private key saved to: {PRIVATE_KEY_PATH}")

    # Save public key
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Public key saved to: {PUBLIC_KEY_PATH}")

    print("Key generation complete.")

if __name__ == "__main__":
    generate_keys()
