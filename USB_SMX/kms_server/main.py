from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = FastAPI()

# In a real-world scenario, this would be loaded securely from a KMS or environment variable
# For MVP, we'll use a placeholder master key derived from a password
MASTER_KEY_PASSWORD = os.environ.get("KMS_MASTER_PASSWORD", "supersecretpassword")
SALT = b"some_salt_for_kdf" # Should be unique per application/deployment

def derive_key(password: str, salt: bytes, key_size: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

# Derive a master AES key for CEK encryption/decryption
MASTER_AES_KEY = derive_key(MASTER_KEY_PASSWORD, SALT)

# Placeholder for RSA keys for digital signing (will be loaded from files later)
# For now, generate a new pair for demonstration
try:
    with open("kms_private_key.pem", "rb") as key_file:
        KMS_PRIVATE_KEY = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Assuming no password for MVP
            backend=default_backend()
        )
    with open("kms_public_key.pem", "rb") as key_file:
        KMS_PUBLIC_KEY = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
except FileNotFoundError:
    print("KMS RSA keys not found, generating new ones for MVP...")
    KMS_PRIVATE_KEY = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    KMS_PUBLIC_KEY = KMS_PRIVATE_KEY.public_key()
    with open("kms_private_key.pem", "wb") as f:
        f.write(KMS_PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("kms_public_key.pem", "wb") as f:
        f.write(KMS_PUBLIC_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("KMS RSA keys generated and saved.")


class WrapKeyRequest(BaseModel):
    cek: str # Base64 encoded CEK

class UnwrapKeyRequest(BaseModel):
    wrapped_cek: str # Base64 encoded wrapped CEK

class SignRequest(BaseModel):
    data: str # Base64 encoded data to sign

@app.post("/wrap-key")
async def wrap_key(request: WrapKeyRequest):
    try:
        cek_bytes = base64.b64decode(request.cek)
        
        # Generate a random IV for AES-GCM
        iv = os.urandom(12) # GCM recommended IV size is 12 bytes

        cipher = Cipher(algorithms.AES(MASTER_AES_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the CEK
        wrapped_cek_bytes = encryptor.update(cek_bytes) + encryptor.finalize()
        tag = encryptor.tag

        # Combine IV, wrapped CEK, and tag for storage/transmission
        full_wrapped_cek = iv + wrapped_cek_bytes + tag
        
        return {"wrapped_cek": base64.b64encode(full_wrapped_cek).decode('utf-8')}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to wrap key: {str(e)}")

@app.post("/unwrap-key")
async def unwrap_key(request: UnwrapKeyRequest):
    try:
        full_wrapped_cek = base64.b64decode(request.wrapped_cek)
        
        # Extract IV, wrapped CEK, and tag
        iv = full_wrapped_cek[:12]
        wrapped_cek_bytes = full_wrapped_cek[12:-16] # GCM tag is 16 bytes
        tag = full_wrapped_cek[-16:]

        cipher = Cipher(algorithms.AES(MASTER_AES_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the CEK
        cek_bytes = decryptor.update(wrapped_cek_bytes) + decryptor.finalize()
        
        return {"cek": base64.b64encode(cek_bytes).decode('utf-8')}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to unwrap key: {str(e)}")

@app.post("/sign-data")
async def sign_data(request: SignRequest):
    try:
        data_bytes = base64.b64decode(request.data)
        signature = KMS_PRIVATE_KEY.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"signature": base64.b64encode(signature).decode('utf-8')}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to sign data: {str(e)}")

@app.post("/verify-signature")
async def verify_signature(request: SignRequest, signature: str):
    try:
        data_bytes = base64.b64decode(request.data)
        signature_bytes = base64.b64decode(signature)
        KMS_PUBLIC_KEY.verify(
            signature_bytes,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"status": "signature_valid"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signature verification failed: {str(e)}")

@app.get("/public-key")
async def get_public_key():
    try:
        public_pem = KMS_PUBLIC_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return {"public_key": public_pem}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve public key: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
