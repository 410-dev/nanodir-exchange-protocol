import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keypair(private_key_path="server_private_key.pem", public_key_path="server_public_key.pem"):
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
    with open(private_key_path, "wb") as f:
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
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("Keypair generated successfully.")
    print(f"Private Key saved to: {os.path.abspath(private_key_path)}")
    print(f"Public Key saved to:  {os.path.abspath(public_key_path)}")


if __name__ == "__main__":
    generate_rsa_keypair()
