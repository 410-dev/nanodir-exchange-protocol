import os
import logging
import shutil
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Configure robust logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration (In production, load these from environment variables or a secure vault)
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
                password=None,  # Provide a password bytes object here if the PEM is encrypted
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
    """Validates the JWT token. (Mocked for implementation details)"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ")[1]
    # Implement your actual JWT verification logic here (e.g., using python-jose)
    if token == "invalid-token":
        raise HTTPException(status_code=403, detail="Invalid token")
    return token


def sanitize_filename(filename: str) -> str:
    """Prevents path traversal attacks."""
    return os.path.basename(filename)


# --- Core Upload Endpoint ---

@app.post("/{dest:path}")
def upload_secure_chunk(
        dest: str,
        request: Request,
        x_chunk_index: int = Header(...),
        x_total_chunks: int = Header(...),
        token: str = Depends(verify_jwt)
):
    """
    Receives an encrypted chunk, decrypts it, and writes it to a temporary staging area.
    Once all chunks are received, reassembles them into the final file.
    Note: We use a synchronous `def` (not `async def`) because we are performing heavy
    CPU-bound cryptographic operations and blocking file I/O. FastAPI will automatically
    run this in a separate worker thread to avoid blocking the async event loop.
    """
    safe_dest = sanitize_filename(dest)
    target_file_path = UPLOAD_DIR / safe_dest
    staging_dir = UPLOAD_DIR / f".staging_{safe_dest}"
    staging_dir.mkdir(parents=True, exist_ok=True)

    chunk_file_path = staging_dir / f"chunk_{x_chunk_index}"

    try:
        # Read the raw binary payload.
        # For a 50MB chunk, this easily fits in RAM.
        payload = request._api_route.app.state.loop.run_until_complete(request.body())
        if not payload:
            raise HTTPException(status_code=400, detail="Empty payload")

        # 1. Parse the payload structure defined by the client
        if len(payload) < 4:
            raise HTTPException(status_code=400, detail="Payload too small to contain key length")

        rsa_key_length = int.from_bytes(payload[:4], 'big')

        if len(payload) < 4 + rsa_key_length + 12:
            raise HTTPException(status_code=400, detail="Malformed payload structure")

        encrypted_aes_key = payload[4: 4 + rsa_key_length]
        iv = payload[4 + rsa_key_length: 4 + rsa_key_length + 12]
        encrypted_chunk = payload[4 + rsa_key_length + 12:]

        # 2. Decrypt the AES key using the server's RSA private key
        try:
            aes_key = SERVER_PRIVATE_KEY.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError:
            logger.error("RSA decryption failed. Possible key mismatch.")
            raise HTTPException(status_code=400, detail="Key decryption failed")

        # 3. Decrypt the actual chunk data using AES-GCM
        try:
            aesgcm = AESGCM(aes_key)
            plaintext_chunk = aesgcm.decrypt(iv, encrypted_chunk, associated_data=None)
        except InvalidTag:
            logger.error(f"AES-GCM authentication failed for chunk {x_chunk_index}.")
            raise HTTPException(status_code=400, detail="Data corruption or tampering detected")

        # 4. Save the decrypted chunk to the staging directory
        with open(chunk_file_path, "wb") as f:
            f.write(plaintext_chunk)

        logger.info(f"Successfully processed chunk {x_chunk_index + 1}/{x_total_chunks} for {safe_dest}")

        # 5. Check if all chunks have arrived
        # This simple logic assumes chunks aren't skipped. For highly concurrent retries,
        # checking the count of files in the staging directory is safer.
        saved_chunks = len(list(staging_dir.glob("chunk_*")))
        if saved_chunks == x_total_chunks:
            logger.info(f"All chunks received for {safe_dest}. Assembling file...")
            _assemble_file(staging_dir, target_file_path, x_total_chunks)
            return JSONResponse(status_code=200, content={"message": "Upload complete and verified"})

        return JSONResponse(status_code=202, content={"message": f"Chunk {x_chunk_index} processed"})

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing chunk {x_chunk_index}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during upload")


def _assemble_file(staging_dir: Path, target_file_path: Path, total_chunks: int):
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

    except Exception as e:
        logger.error(f"Failed to assemble file {target_file_path}: {e}")
        # Leave staging directory intact for debugging or manual recovery
        raise HTTPException(status_code=500, detail="Failed to assemble the final file")


if __name__ == "__main__":
    import uvicorn

    # Run the server on port 8000
    uvicorn.run("server:app", host="0.0.0.0", port=8000, workers=4)