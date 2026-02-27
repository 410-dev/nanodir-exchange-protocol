import os
import hashlib
import pyotp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


def generate_rsa_keypair(sk_path="server_private_key.pem", pk_path="server_public_key.pem") -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    print("Generating RSA keypair...")

    # 1. Generate the private key
    # 2048 bits is the standard minimum for security; 65537 is the standard public exponent.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. Serialize and save the private key (PKCS8 PEM format)
    # Note: We use NoEncryption() here to match the server code's startup sequence.
    # For higher security environments, use serialization.BestAvailableEncryption(b"your_password")
    if sk_path:
        with open(sk_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    # 3. Extract the public key from the private key
    public_key = private_key.public_key()

    # 4. Serialize and save the public key (SubjectPublicKeyInfo PEM format)
    if pk_path:
        with open(pk_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    # print("Keypair generated successfully.")
    # print(f"Private Key saved to: {os.path.abspath(private_key_path)}")
    # print(f"Public Key saved to:  {os.path.abspath(public_key_path)}")

    return private_key, public_key

def stringify_rsa_key(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    elif isinstance(key, rsa.RSAPublicKey):
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    else:
        raise ValueError("Unsupported key type for stringification")

def destringify_rsa_key(is_public_key: bool, key: str, password: bytes = None) -> rsa.RSAPrivateKey | rsa.RSAPublicKey:
    if is_public_key:
        return serialization.load_pem_public_key(key.encode('utf-8'))
    else:
        return serialization.load_pem_private_key(key.encode('utf-8'), password=password)


def rsa_encrypt(pk_str: str = None, public_key: rsa.RSAPublicKey = None, plaintext: str = "") -> tuple[bool, bytes]:
    if pk_str:
        try:
            public_key = serialization.load_pem_public_key(pk_str.encode('utf-8'))
        except Exception as e:
            return False, f"Failed to load RSA public key: {e}"
    
    if not public_key:
        return False, b"Public key is required for encryption"
    
    encrypted_content = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return True, encrypted_content


def rsa_decrypt(sk_str: str = None, private_key: rsa.RSAPrivateKey = None, ciphertext: bytes = b"") -> tuple[bool, str]:
    if sk_str:
        try:
            private_key = serialization.load_pem_private_key(sk_str.encode('utf-8'), password=None)
        except Exception as e:
            return False, f"Failed to load RSA private key: {e}"
    
    if not private_key:
        return False, "Private key is required for decryption"
    
    try:
        decrypted_content = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return True, decrypted_content.decode('utf-8')
    except Exception as e:
        return False, f"Decryption failed: {e}"


def generate_totp_seed(length=32) -> str:
    # Generate a random base32-encoded TOTP seed
    return pyotp.random_base32(length)

def hash_password(password: str, totp: str) -> str:
    # Hash the password using SHA-256
    return hashlib.sha256(f"{password}:{totp}".encode()).hexdigest()


def generate_totp_result(totp_seed: str, digits: int = 6, interval: int = 30) -> str:
    # Generate a TOTP code using the provided seed
    totp = pyotp.TOTP(totp_seed, digits=digits, interval=interval)
    return totp.now()

if __name__ == "__main__":
    generate_rsa_keypair()
