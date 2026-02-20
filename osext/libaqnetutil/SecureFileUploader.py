import os
import logging
import requests
import base64
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# Configure robust logging for production observability
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SecureFileUploader:
    def __init__(self, relay_server: str, chunk_size: int = 50 * 1024 * 1024): # Set chunk size default to 50MB
        self.relay_server = relay_server
        self.chunk_size = chunk_size

    def _get_retry_session(self) -> requests.Session:
        """Creates an HTTP session with exponential backoff for network resilience."""
        session = requests.Session()
        # Retries 5 times on connection errors and specific server errors (500, 502, 503, 504)
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session

    def mk_file_request(self, session_id: str, dest: str, header: dict, pk: str, jwt_str: str, file_path: str, start_from: int) -> tuple[bool, str, int]:

        url = f"{self.relay_server}/{dest}"

        if jwt_str:
            header["Authorization"] = f"Bearer {jwt_str}"

        # 체크섬
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_checksum = sha256_hash.hexdigest()

        # Destination string hash to SHA256
        dest_hash = sha256_hash.hexdigest()

        header["X-Original-Filename"] = os.path.basename(file_path)
        header["X-File-SHA256"] = file_checksum
        header["X-Session-ID"] = session_id
        header["X-Destination"] = dest
        header["X-Destination-H"] = dest_hash

        # 1. Load the RSA public key once
        try:
            public_key = serialization.load_pem_public_key(pk.encode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to load RSA public key: {e}")
            return False, f"Failed to load RSA public key: {e}", 0

        file_size = os.path.getsize(file_path)
        total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size

        # Calculate which chunk to start from based on the byte offset
        start_chunk = start_from // self.chunk_size
        session = self._get_retry_session()

        with open(file_path, 'rb') as f:
            # Seek directly to the correct chunk boundary
            f.seek(start_chunk * self.chunk_size)
            chunk_index = start_chunk

            while True:
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break  # EOF reached

                # 2. Authenticated Encryption: Generate unique AES-GCM key and IV per chunk
                aes_key = AESGCM.generate_key(bit_length=256)
                iv = os.urandom(12)  # Standard 96-bit IV for GCM
                aesgcm = AESGCM(aes_key)

                # Encrypt the chunk (GCM appends a 16-byte authentication tag automatically)
                encrypted_chunk = aesgcm.encrypt(iv, chunk_data, associated_data=None)

                # 3. Encrypt the chunk's specific AES key with the RSA public key
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 4. Construct the payload for this specific chunk
                # Layout: [4 bytes RSA key length] + [Encrypted AES Key] + [12 bytes IV] + [Encrypted Data + Auth Tag]
                payload = len(encrypted_aes_key).to_bytes(4, 'big') + encrypted_aes_key + iv + encrypted_chunk

                # 5. Add multipart metadata to headers so the server can reassemble
                chunk_headers = header.copy()
                chunk_headers['X-Chunk-Index'] = str(chunk_index)
                chunk_headers['X-Total-Chunks'] = str(total_chunks)

                logger.info(f"Uploading chunk {chunk_index + 1}/{total_chunks}...")

                try:
                    # Timeout: 10 seconds to connect, 120 seconds to upload the 50MB chunk
                    response = session.post(url, headers=chunk_headers, data=payload, timeout=(10, 120))
                    response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    # If all 5 exponential backoff retries fail, log the exact chunk that died
                    logger.error(
                        f"Failed to upload chunk {chunk_index}. Resume transfer at byte offset {chunk_index * self.chunk_size}. Error: {e}")
                    return False, f"Failed to upload chunk {chunk_index}. Resume transfer at byte offset {chunk_index * self.chunk_size}. Error: {e}", chunk_index * self.chunk_size

                chunk_index += 1

        logger.info("File transfer completed securely and successfully.")
        return True, "File uploaded successfully", total_chunks
