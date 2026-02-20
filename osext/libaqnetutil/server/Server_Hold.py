import os
import logging
import shutil
import hashlib
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.concurrency import run_in_threadpool
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Configure robust logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# TODO Adaptive Configuration
UPLOAD_DIR = Path("/tmp/secure_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

PRIVATE_KEY_PATH = os.environ.get("RSA_PRIVATE_KEY_PATH", "server_private_key.pem")

app = FastAPI(title="Secure File Relay")


# --- Security & Cryptography Initialization ---

def load_private_key():
    """Loads the RSA private key required for decrypting the AES symmetric keys."""
    try:
        with open(PRIVATE_KEY_PATH, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
    except Exception as e:
        logger.error(f"Failed to load RSA private key: {e}")
        raise RuntimeError("Server misconfiguration: Cannot load private key.")


# Load the key into memory once at startup
try:
    SERVER_PRIVATE_KEY = load_private_key()
except RuntimeError:
    SERVER_PRIVATE_KEY = None
    logger.warning("Starting without a valid private key. Decryption will fail.")


def verify_jwt(authorization: str = Header(None)):
    # """Validates the JWT token."""
    # if not authorization or not authorization.startswith("Bearer "):
    #     raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    #
    # token = authorization.split(" ")[1]
    # if token == "invalid-token":
    #     raise HTTPException(status_code=403, detail="Invalid token")

    # TODO Implement actual JWT validation
    # Probably should ask to Authentication server

    return ""


def sanitize_filename(filename: str) -> str:
    """Prevents path traversal attacks."""
    return os.path.basename(filename)


# --- Threadpool Worker Functions ---

def decrypt_and_write_chunk(payload: bytes, chunk_file_path: Path):
    """
    CPU-bound task to safely decrypt and save the chunk.
    This runs in a separate worker thread to avoid blocking the server.
    """
    if SERVER_PRIVATE_KEY is None:
        raise RuntimeError("Server private key is not loaded.")

    # 1. Parse the payload structure defined by the client
    rsa_key_length = int.from_bytes(payload[:4], 'big')

    if len(payload) < 4 + rsa_key_length + 12:
        raise ValueError("Malformed payload structure")

    encrypted_aes_key = payload[4: 4 + rsa_key_length]
    iv = payload[4 + rsa_key_length: 4 + rsa_key_length + 12]
    encrypted_chunk = payload[4 + rsa_key_length + 12:]

    # 2. Decrypt the AES key using the server's RSA private key
    aes_key = SERVER_PRIVATE_KEY.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Decrypt the actual chunk data using AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext_chunk = aesgcm.decrypt(iv, encrypted_chunk, associated_data=None)

    # 4. Save the decrypted chunk
    with open(chunk_file_path, "wb") as f:
        f.write(plaintext_chunk)


def _assemble_file(staging_dir: Path, target_file_path: Path, total_chunks: int, checksum: str):
    """Concatenates all the individual chunks in order to create the final file."""
    try:
        with open(target_file_path, "wb") as final_file:
            for i in range(total_chunks):
                chunk_path = staging_dir / f"chunk_{i}"
                if not chunk_path.exists():
                    raise FileNotFoundError(f"Missing expected chunk: {chunk_path}")

                with open(chunk_path, "rb") as chunk_file:
                    shutil.copyfileobj(chunk_file, final_file)

        # Cleanup staging directory after successful assembly
        shutil.rmtree(staging_dir)
        logger.info(f"File successfully assembled at {target_file_path}")

        # Verify the final file's integrity using the provided checksum
        sha256_hash = hashlib.sha256()
        with open(target_file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        calculated_checksum = sha256_hash.hexdigest()
        if calculated_checksum != checksum:
            logger.error(f"Checksum mismatch for {target_file_path}: expected {checksum}, got {calculated_checksum}")
            target_file_path.unlink()  # Remove the corrupted file
            raise ValueError("Checksum verification failed after assembly")
        else:
            logger.info(f"Checksum verification passed for {target_file_path}")

    except Exception as e:
        logger.error(f"Failed to assemble file {target_file_path}: {e}")
        raise RuntimeError("Failed to assemble the final file")


# --- Core Upload Endpoint ---

@app.post("/{dest:path}")
async def upload_secure_chunk(
        dest: str,
        request: Request,
        x_chunk_index: int = Header(...),
        x_total_chunks: int = Header(...),
        x_original_filename: str = Header(None),
        x_file_sha256: str = Header(None),
        x_session_id: str = Header(None),
        x_destination_h: str = Header(None),
        token: str = Depends(verify_jwt)
):
    """
    Async endpoint to read the network stream, offloading the heavy crypto to a thread.
    """
    safe_dest = sanitize_filename(f"{x_session_id}@{x_destination_h}")
    target_file_path = UPLOAD_DIR / safe_dest
    staging_dir = UPLOAD_DIR / f".staging_{safe_dest}"
    staging_dir.mkdir(parents=True, exist_ok=True)

    chunk_file_path = staging_dir / f"chunk_{x_chunk_index}"

    print(f"Received chunk {x_chunk_index} of {x_total_chunks} for {safe_dest} (Original filename: {x_original_filename}, SHA256: {x_file_sha256})")

    try:
        # 1. Read the network payload natively via standard async await
        payload = await request.body()
        if not payload:
            raise HTTPException(status_code=400, detail="Empty payload")
        if len(payload) < 16:
            raise HTTPException(status_code=400, detail="Payload too small to process")

        # 2. Offload the heavy decryption and disk I/O to a threadpool worker
        try:
            await run_in_threadpool(decrypt_and_write_chunk, payload, chunk_file_path)
        except ValueError as e:
            logger.error(f"Decryption or parsing failed: {e}")
            raise HTTPException(status_code=400, detail="Key decryption or parsing failed")
        except InvalidTag:
            logger.error(f"AES-GCM authentication failed for chunk {x_chunk_index}.")
            raise HTTPException(status_code=400, detail="Data corruption or tampering detected")
        except RuntimeError as e:
            logger.error(str(e))
            raise HTTPException(status_code=500, detail="Internal server configuration error")

        logger.info(f"Successfully processed chunk {x_chunk_index + 1}/{x_total_chunks} for {safe_dest}")

        # 3. Check if all chunks have arrived
        saved_chunks = len(list(staging_dir.glob("chunk_*")))
        if saved_chunks == x_total_chunks:
            logger.info(f"All chunks received for {safe_dest}. Assembling file...")
            # Disk I/O for assembly can also be heavy, so we threadpool it
            try:
                await run_in_threadpool(_assemble_file, staging_dir, target_file_path, x_total_chunks, x_file_sha256)
            except RuntimeError:
                raise HTTPException(status_code=500, detail="Failed to assemble the final file")

            return JSONResponse(status_code=200, content={"message": "Upload complete and verified"})

        return JSONResponse(status_code=202, content={"message": f"Chunk {x_chunk_index} processed"})

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing chunk {x_chunk_index}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during upload")


if __name__ == "__main__":
    import uvicorn

    # Run the server on port 8000.
    # The string "server:app" requires this file to be named server.py
    uvicorn.run("Server_Hold:app", host="0.0.0.0", port=8000, workers=4)
