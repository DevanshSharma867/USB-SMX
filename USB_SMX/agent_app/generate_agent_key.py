import sys
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_agent_key_pair(output_dir: Path):
    """
    Generates a new RSA key pair for an agent and saves it to the specified directory.
    """
    print(f"Generating new agent key pair in: {output_dir}")

    # Create the output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = output_dir / "agent_private_key.pem"
    public_key_path = output_dir / "agent_public_key.pem"

    if private_key_path.exists() or public_key_path.exists():
        print("Error: Key files already exist in the specified directory. Please choose a different directory or remove existing keys.")
        return

    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize and save the private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"  -> Saved private key to {private_key_path}")

    # Get the public key
    public_key = private_key.public_key()

    # Serialize and save the public key
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"  -> Saved public key to {public_key_path}")
    print("\nKey generation complete.")

def main():
    parser = argparse.ArgumentParser(description="Generate a new RSA key pair for an SMX Agent.")
    parser.add_argument(
        "output_dir",
        type=str,
        help="The directory where the generated key pair will be stored."
    )
    args = parser.parse_args()

    try:
        output_path = Path(args.output_dir)
        generate_agent_key_pair(output_path)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
