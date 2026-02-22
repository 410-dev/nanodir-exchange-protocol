import asyncio
import logging
import uuid
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from pydantic import BaseModel
import uvicorn

# Configure production-level logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()

class ConnectionManager:
    """
    Manages active WebSocket connections. In a multi-worker production environment,
    you would typically back this with Redis Pub/Sub so workers can communicate,
    but for a single high-concurrency node, an in-memory dictionary suffices.
    """
    def __init__(self):
        # Maps session_id to the active WebSocket object
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[session_id] = websocket
        logger.info(f"Client connected. Session: {session_id} | Total active: {len(self.active_connections)}")

    def disconnect(self, session_id: str):
        if session_id in self.active_connections:
            del self.active_connections[session_id]
            logger.info(f"Client disconnected. Session: {session_id} | Total active: {len(self.active_connections)}")

    async def send_signal_to_client(self, session_id: str, payload: str):
        """
        Sends the specific ND_EXC_WSSIG string to a single client.
        """
        if websocket := self.active_connections.get(session_id):
            try:
                message = f"ND_EXC_WSSIG:{payload}"
                await websocket.send_text(message)
            except Exception as e:
                logger.error(f"Failed to send message to {session_id}: {e}")

manager = ConnectionManager()

class HandshakePayload(BaseModel):
    machine_data: str

@app.post("/handshake")
async def handshake(payload: HandshakePayload):
    """
    Handles the initial HTTP request, generates a unique session ID,
    and returns the format expected by the client.
    """
    session_id = str(uuid.uuid4())
    logger.info(f"Handshake requested by machine: {payload.machine_data}. Issued session: {session_id}")

    return {
        "state": "OK",
        "session": session_id
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, session: str = None):
    """
    Handles the persistent WebSocket connection, listens for heartbeats,
    and manages disconnection cleanup.
    """
    if not session:
        await websocket.close(code=1008, reason="Session ID missing")
        return

    await manager.connect(session, websocket)

    try:
        while True:
            # Wait for incoming messages (like the 10-second background heartbeat)
            data = await websocket.receive_text()

            # In production, you might want to parse this JSON to update a "last seen" timestamp
            # in a database or cache to track client health.
            logger.debug(f"Received data from {session}: {data}")

    except WebSocketDisconnect:
        manager.disconnect(session)
    except Exception as e:
        logger.error(f"Unexpected error on connection {session}: {e}")
        manager.disconnect(session)

# Example endpoint to trigger a message to a specific client from the server side
@app.post("/trigger-signal/{session_id}")
async def trigger_signal(session_id: str, payload: str):
    await manager.send_signal_to_client(session_id, payload)
    return {"status": "signal sent"}

if __name__ == "__main__":
    # For local testing only. In production, run via command line using Gunicorn/Uvicorn.
    uvicorn.run("Server_Relay:app", host="0.0.0.0", port=8000, log_level="info")