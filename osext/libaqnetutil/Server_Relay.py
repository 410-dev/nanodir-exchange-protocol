import asyncio
import logging
import uuid
import uvicorn
import datetime
import os
import requests

from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from pydantic import BaseModel
from localutil import assert_if

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
        self.online_state_visible: Dict[str, str] = {}  # Online report state for each machine connected over WS (Which is visible to other users)
        self.online_state_real: Dict[str, int] = {}  # Online track state for each machine connected over WS (Which is not visible to other users, but used for internal logic)
        self.session_prepared: Dict[str, int] = {} # Session preparation state for each session, where the int is the last time request. After 30 seconds, the session is considered expired and will be removed from the session table.
        self.identity_session_map: Dict[str, str] = {} # Maps Identity information to session_id for quick lookup. This is used to check if a new handshake request with the same Identity is coming in while the previous session is still active.

    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[session_id] = websocket
        logger.info(f"Client connected. Session: {session_id} | Total active: {len(self.active_connections)}")


    def disconnect(self, session_id: str):
        if session_id in self.active_connections:
            del self.active_connections[session_id]
            del self.online_state_visible[session_id]
            del self.online_state_real[session_id]
            del self.session_prepared[session_id]
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

    def mark_online_status(self, session_id: str, visible_status: str, last_heartbeat: int):
        """
        Updates the online status of a client. This can be used to track both the real connection status
        and the status that is reported to other users.
        """
        self.online_state_visible[session_id] = visible_status
        self.online_state_real[session_id] = last_heartbeat
        logger.info(f"Updated online status for {session_id}: Visible={visible_status}, Real={last_heartbeat}")

manager = ConnectionManager()

@app.post("/handshake")
async def handshake(payload, request: Request):
    """
    Handles the initial HTTP request, generates a unique session ID,
    and returns the format expected by the client.
    """

    # 요청 헤더 가져오기
    headers = dict(request.headers)

    # Authentication 서버로 전달할 정보 불러오기
    machine_full_name: str = headers.get("Machine-Full-Name", "")
    identity_fullpath: str = headers.get("Identity", "")
    client_side_generated_totp: str = headers.get("Authorization", "")

    # 체크
    try:
        assert_if(machine_full_name, None, lambda x, y: x != "")
        assert_if(identity_fullpath, None, lambda x, y: x != "")
        assert_if(client_side_generated_totp, None, lambda x, y: x != "")
    except ValueError as e:
        logger.warning(f"Handshake request missing required headers. Details: {e}")
        return {
            "state": "ERROR",
            "message": str(e)
        }

    # 새 헤더 생성
    new_header = {
        "Machine-Full-Name": machine_full_name,
        "Identity": identity_fullpath,
        "Authorization": client_side_generated_totp
    }

    # v1/is_enrolled 엔드포인트로 인증 서버에 요청하여 사전 등록 여부 확인
    auth_server_url = f"{app.state.server_map['authentication']['url']}:{app.state.server_map['authentication']['port']}/v1/is_enrolled"
    try:
        response = requests.post(auth_server_url, headers=new_header, timeout=5)
        response.raise_for_status()
        auth_response = response.json()

        # enrolled 값이 있고 True인지 확인
        if not auth_response.get("enrolled", False):
            logger.warning(f"Handshake request from {machine_full_name} failed enrollment check.")
            return {
                "state": "ERROR",
                "message": "Machine not enrolled in the network"
            }

    except requests.RequestException as e:
        logger.error(f"Error communicating with authentication server during handshake: {e}")
        return {
            "state": "ERROR",
            "message": "Failed to verify enrollment status"
        }

    # Identity 정보를 스테이트 테이블과 대조 후, 존재한다면 기존 장치의 online 여부 체크 후 새 세션 이슈
    # 같은 Identity 정보로 이미 온라인 상태인 세션이 있다면, 해당 장치를 블랙리스트 처리
    existing_session_id = manager.identity_session_map.get(identity_fullpath)
    if existing_session_id:
        # 온라인 테이블 데이터 홀드
        last_heartbeat_time = manager.online_state_real.get(existing_session_id, 0)

        # Online 상태 확인 요청
        await trigger_signal(existing_session_id, "ND_EXC_WSSIG:IMMEDIATE_REPORT_ONLINE")

        # 잠시 대기 후 상태 확인
        await asyncio.sleep(5)

        # 테이블에 업데이트된 상태 확인
        updated_heartbeat_time = manager.online_state_real.get(existing_session_id, 0)

        # 업데이트된 값이 더 크다면, 즉 최근에 heartbeat이 왔다면 기존 세션이 여전히 온라인 상태로 간주되어 블랙리스트 처리
        if updated_heartbeat_time > last_heartbeat_time:
            logger.warning(f"Duplicate session attempt detected for Identity: {identity_fullpath}. Existing session {existing_session_id} is still active. Blacklisting this Identity.")

            # 세션 무효화
            if existing_session_id in manager.active_connections:
                await manager.active_connections[existing_session_id].close(code=1008, reason="Duplicate session detected. This Identity has been blacklisted.")
                manager.disconnect(existing_session_id)

            # TODO Authentication 서버에 블랙리스트 처리 요청
            

            # TODO 블랙리스트 처리 로직 (예: 데이터베이스에 블랙리스트 기록)
            return {
                "state": "ERROR",
                "message": "Duplicate session detected. This Identity has been blacklisted."
            }

        else: # 업데이트된 heartbeat 시간이 더 크지 않다면, 즉 기존 세션이 오프라인 상태로 간주되어 새 세션 발급
            logger.info(f"Existing session {existing_session_id} for Identity: {identity_fullpath} is considered offline. Issuing new session.")

            # 기존 세션 데이터 정리
            if existing_session_id in manager.active_connections:
                await manager.active_connections[existing_session_id].close(code=1008, reason="Existing session considered offline. Issuing new session.")
                manager.disconnect(existing_session_id)

            # 기존 세션과 Identity 매핑 제거
            del manager.identity_session_map[identity_fullpath]


    session_id = str(uuid.uuid4())
    logger.info(f"Handshake requested by machine: {payload.machine_data}. Issued session: {session_id}")

    # Register to session table
    manager.session_prepared[session_id] = int(datetime.datetime.now().timestamp())

    return {
        "state": "OK",
        "session": session_id
    }

@app.websocket("/online")
async def websocket_endpoint(websocket: WebSocket, session: str = None):
    """
    Handles the persistent WebSocket connection, listens for heartbeats,
    and manages disconnection cleanup.
    """
    if not session:
        await websocket.close(code=1008, reason="Session ID missing")
        return


    # Check if the session is prepared and not expired (30 seconds)
    current_time = int(datetime.datetime.now().timestamp())
    if session not in manager.session_prepared or (current_time - manager.session_prepared[session]) > 30:
        await websocket.close(code=1008, reason="Invalid or expired session")
        logger.warning(f"WebSocket connection attempt with invalid or expired session: {session}")
        return

    await manager.connect(session, websocket)

    try:
        while True:
            # Wait for incoming messages (like the 10-second background heartbeat)
            data = await websocket.receive_text()

            # Data is a line of status report:
            #  BEGIN:<Total Length>:<Format Version>:<Online Status>:END
            components = data.strip().split(":")
            if components[0] != "BEGIN" or components[-1] != "END" or (len(components) > 3 and str(len(components)) != components[1]):
                logger.warning(f"Received malformed heartbeat from {session}: {data}")
                continue

            if components[2] != "1":  # Format version check

                # Update online status
                online_status = components[3] if len(components) > 3 else "unknown"
                datetime_now = datetime.datetime.now().timestamp()
                manager.mark_online_status(session, visible_status=online_status, last_heartbeat=int(datetime_now))


            else:
                # Unsupported
                logger.warning(f"Received unsupported format version from {session}: {data}")
                continue

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


def setup(
        namespace: str,
        port: int,
        domain: str,
        allow_ip_access: bool,
        allow_external_access: bool,
        policy_file: str,
        server_map: dict,
        db_model: dict
):
    logger.info(f"Authentication server setup with namespace={namespace}, port={port}, domain={domain}, allow_ip_access={allow_ip_access}, allow_external_access={allow_external_access}, policy_file={policy_file}, server_map={server_map}, db_model={db_model}")

    # 1. Store your configuration in the app state so endpoints can access them
    app.state.namespace = namespace
    app.state.domain = domain
    app.state.policy_file = policy_file
    app.state.server_map = server_map
    app.state.db_model = db_model

    assert_if("version", db_model, lambda x, y: x in y)
    assert_if(1, db_model.get("version"), lambda x, y: x == y) # 현재 버전은 1로 고정. 향후 버전업 시 이 부분을 수정하여 호환성 검증 로직을 추가할 수 있습니다.
    assert_if(os.path.abspath(policy_file), None, lambda x, y: os.path.isfile(x))
    assert_if("authentication", server_map, lambda x, y: x in y)
    assert_if("url", server_map.get("authentication"), lambda x, y: x in y)
    assert_if("port", server_map.get("authentication"), lambda x, y: x in y)
    assert_if("hold", server_map, lambda x, y: x in y)
    assert_if("url", server_map.get("hold"), lambda x, y: x in y)
    assert_if("port", server_map.get("hold"), lambda x, y: x in y)
    assert_if("relay", server_map, lambda x, y: x in y)
    assert_if("url", server_map.get("relay"), lambda x, y: x in y)
    assert_if("port", server_map.get("relay"), lambda x, y: x in y)
    assert_if([server_map.get("hold").get("port"), server_map.get("relay").get("port")], port, lambda x, y: y not in x) # 인증 서버가 홀드/릴레이 서버와 포트 충돌이 나지 않도록 검증

    app.state.credentials_table = {} # 토큰과 관련된 정보를 저장하는 테이블.

    # 3. Start the server programmatically
    # Note: Calling this will block the thread it runs on.
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    # For local testing only. In production, run via command line using Gunicorn/Uvicorn.
    uvicorn.run("Server_Relay:app", host="0.0.0.0", port=8000, log_level="info")
