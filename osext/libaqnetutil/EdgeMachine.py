import os
import jwt
import requests
import threading
import logging
import websocket
import json
import time

from SecureFileUploader import SecureFileUploader
from localutil import os_specific, read_file


class EdgeMachine:

    def __init__(self, totp_secret: str, network: str, group: str, machine_owner: str, machine_name: str, pk: str):
        self.totp_secret: str = totp_secret        # 32글자 이상의 TOTP 시크릿 키. 장치가 네트워크에 등록될 때 생성되어야 하며, 장치의 고유한 식별자로 사용됩니다.
        self.network:  str = network                # 장치가 등록된 네트워크 이름 (Ex. MegaCorp)
        self.group: str = group                    # 장치가 등록된 네트워크 그룹 이름
        self.machine_owner: str = machine_owner    # 장치의 소유자 이름 (Ex. john@mynetwork.com)
        self.machine_name: str = machine_name      # 장치의 이름 (Ex. Johns-Laptop)
                                                   # 장치의 이름은 네트워크 내에서 고유해야 하며, 사용자 친화적이어야 합니다.
                                                   # 장치의 이름에는 -, _, 공백, 알파벳, 숫자만 사용할 수 있습니다. (특수문자 사용 불가)
        self.pk: str = pk                          # 장치의 공개키. 네트워크에 등록된 장치들은 서로의 공개키를 사용하여 안전하게 통신할 수 있습니다.
        self.jwt_token: str = self.generate_jwt()  # 장치가 네트워크에 등록된 후 발급받는 JWT 토큰. 이 토큰은 장치가 네트워크에 인증된 상태임을 나타내며, 네트워크와의 통신에 사용됩니다.
                                                   #   매 10분마다 갱신됩니다.


    # 현재 장치의 EdgeMachine 인스턴스를 반환하는 클래스 메서드
    @classmethod
    def get_current_machine(cls, namespace: str) -> 'EdgeMachine':

        path_head = os_specific(
            nt = f"C:\\ProgramData\\AquaAbstractionLayer\\aquanetutil\\{namespace}\\",
            linux = f"/etc/aqua/{namespace}/",
            mac = f"/etc/aqua/{namespace}/",
            aqua = f"/etc/aqua/{namespace}/"
        )

        network = cls.get_network_instance(namespace)

        return cls(
            totp_secret = read_file(f"{path_head}totp_secret"),
            network = network.name,
            group = network.group,
            machine_owner = read_file(f"{path_head}machine_owner"),
            machine_name = read_file(f"{path_head}machine_name"),
            pk = read_file(f"{path_head}machine_pk")
        )

    # 현재 장치가 등록된 네트워크 인스턴스를 반환하는 인스턴스 메서드
    @classmethod
    def get_network_instance(cls, namespace: str) -> Network:

        path_head = os_specific(
            nt = f"C:\\ProgramData\\AquaAbstractionLayer\\aquanetutil\\{namespace}\\",
            linux = f"/etc/aqua/{namespace}/",
            mac = f"/etc/aqua/{namespace}/",
            aqua = f"/etc/aqua/{namespace}/"
        )

        return Network(
            name = read_file(f"{path_head}network_name"),
            group = read_file(f"{path_head}network_group"),
            auth_server = read_file(f"{path_head}auth_server"),
            relay_server = read_file(f"{path_head}relay_server"),
            auth_server_pk = read_file(f"{path_head}auth_server_pk"),
            relay_server_pk = read_file(f"{path_head}relay_server_pk"),
            auth_server_port = int(read_file(f"{path_head}auth_server_port", default="38000")),
            relay_server_port = int(read_file(f"{path_head}relay_server_port", default="38001"))
        )

    def generate_jwt(self) -> str:
        # 만약 TOTP 시크릿 키가 32글자 미만이거나 비어있다면 다른 장치의 주소를 포인팅 하는 목적이므로 빈 문자열 반환
        if not self.totp_secret or len(self.totp_secret) < 32:
            return ""

        # TOTP 시크릿 키로 JWT 토큰 생성
        payload = {
            "machine_owner": self.machine_owner,
            "machine_name": self.machine_name
        }
        token = jwt.encode(payload, self.totp_secret, algorithm="HS256")
        return token

    def get_machine_name(self) -> str:
        return f"{self.machine_owner}/{self.machine_name}"

    def get_machine_fullname(self) -> str:
        return f"{self.network}/{self.group}/{self.machine_owner}/{self.machine_name}"

    @classmethod
    def get_current_machine_path(cls, namespace: str) -> str:
        mach: 'EdgeMachine' = cls.get_current_machine(namespace)
        netw: Network = mach.get_network_instance(namespace)
        return f"{netw.name}/{netw.group}/{mach.machine_owner}/{mach.machine_name}"





class Network:

    def __init__(self, name: str, group: str, auth_server: str, relay_server: str, auth_server_pk: str, relay_server_pk: str, auth_server_port: int = 38000, relay_server_port: int = 38001):
        self.name: str = name                            # 네트워크 이름. 장치가 네트워크에 등록될 때 이 이름으로 등록됩니다. (예: "MegaCorp")
        self.group: str = group                          # 네트워크 그룹 이름. 장치가 네트워크에 등록될 때 이 그룹 이름으로 등록됩니다. (예: "Engineering/RnD")
        self.auth_server: str = auth_server              # 네트워크의 인증 서버 URL. 장치가 네트워크에 등록될 때 이 URL로 TOTP 시크릿 키와 장치 정보를 전송하여 JWT 토큰을 발급받습니다.
        self.auth_server_pk: str = auth_server_pk        # 네트워크의 인증 서버 공개키.
        self.auth_server_port: int = auth_server_port    # 네트워크의 인증 서버 포트 번호. 인증 서버와 통신할 때 이 포트 번호를 사용합니다.
        self.relay_server: str = relay_server            # 네트워크의 릴레이 서버 URL. 장치가 다른 장치와 통신할 때 이 URL을 통해 메시지를 중계합니다.
        self.relay_server_pk: str = relay_server_pk      # 네트워크의 릴레이 서버 공개키.
        self.relay_server_port: int = relay_server_port  # 네트워크의 릴레이 서버 포트 번호. 릴레이 서버와 통신할 때 이 포트 번호를 사용합니다.


    @staticmethod
    def _mk_request(url: str, header: dict, pk: str, jwt_str: str) -> dict:

        if jwt_str:
            header["Authorization"] = f"Bearer {jwt_str}"

        response = requests.post(url, headers=header, timeout=5)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Request to {url} failed with status code: {response.status_code}")
            return {}


    # 장치가 네트워크에 등록되어 있는지 확인하는 인스턴스 메서드
    def is_machine_enrolled(self, current_machine: EdgeMachine) -> bool:

        # Authentication 서버의 표준 API 엔드포인트에 장치의 정보를 전송하여 등록되었는지 체크
        machine_name: str = f"{self.name}/{self.group}/{current_machine.machine_owner}/{current_machine.machine_name}"
        endpoint: str = f"v1/is_enrolled"
        header = {
            "Machine-Name": machine_name,
            "Identity": current_machine.get_machine_fullname(),
        }

        # 5초 타임아웃으로 GET 요청을 보내 등록 여부 확인
        try:
            data = self._mk_request(f"{self.auth_server}/{endpoint}", header, self.auth_server_pk, current_machine.generate_jwt())
            return data.get("enrolled", False)

        except Exception as e:
            print(f"Error checking enrollment: {e}")
            return False

    # 네트워크에 등록된 장치들의 목록을 반환하는 인스턴스 메서드
    #    group: 네트워크 그룹 이름 (예: "Engineering/RnD")
    #    user_id: 사용자 ID (예: "john@megacorp.com")
    def get_machines_of(self, identity: EdgeMachine, group: str, user_id: str) -> list[EdgeMachine]:
        # Authentication 서버의 표준 API 엔드포인트에 그룹 이름과 사용자 ID를 전송하여 해당 그룹에 속한 장치들의 목록을 가져옵니다.
        group_path: str = f"{self.name}/{group}/{user_id}"
        endpoint: str = f"v1/get_machines_of"
        header = {
            "Group-Path": group_path,
            "Target-User": user_id,
            "Identity": identity.get_machine_fullname()
        }

        try:
            data = self._mk_request(f"{self.auth_server}/{endpoint}", header, self.auth_server_pk, identity.generate_jwt())
            machines_data = data.get("machines", [])
            machines = []

            # 반환되는 인스턴스 데이터 샘플
            # {
            #     "network": "MegaCorp",
            #     "group": "Engineering/RnD",
            #     "machine_owner": "john@megacorp.com", # 주어진 사용자 ID. 서버단에서 그룹 이메일 조회의 경우 다 다르게 나오기에 이렇게 설정
            #     "machine_name": "Johns-Laptop",
            #     "pk": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
            # }

            for machine_data in machines_data:
                machine = EdgeMachine(
                    totp_secret="",  # TOTP 시크릿 키는 네트워크에서 가져올 수 없으므로 빈 문자열로 설정
                    network=machine_data.get("network", ""),
                    group=machine_data.get("group", ""),
                    machine_owner=machine_data.get("machine_owner", ""),
                    machine_name=machine_data.get("machine_name", ""),
                    pk=machine_data.get("pk", "")
                )
                machines.append(machine)
            return machines
        except Exception as e:
            print(f"Error getting machines of group {group} and user {user_id}: {e}")
            return []


    # 그룹 정보를 가져오는 인스턴스 메서드
    def enumerate_group(self, identity: EdgeMachine, group_to_enumerate: str, depth: int = 1) -> list[str]:
        # Authentication 서버의 표준 API 엔드포인트에서 그룹 정보를 가져옵니다. 그룹 정보에는 해당 그룹에 속한 사용자 ID들과 하위 그룹 이름들이 포함됩니다.
        endpoint: str = f"v1/enumerate_group"
        header = {
            "Directory": f"{self.name}/{group_to_enumerate}",
            "Depth": str(depth),
            "Identity": identity.get_machine_fullname()
        }

        try:
            data = self._mk_request(f"{self.auth_server}/{endpoint}", header, self.auth_server_pk, identity.generate_jwt())
            groups = data.get("groups", [])
            return groups
        except Exception as e:
            print(f"Error getting groups of user {identity.machine_owner}: {e}")
            return []


    # 여러 장치에 동시에 파일을 보내는 인스턴스 메서드
    def relay_send_to_machines(self, network: Network, identity: EdgeMachine, multiple_target_machines: list[EdgeMachine], port: int, file_path: str) -> dict[str, bool]:
        success_dict = {}
        for machine in multiple_target_machines:
            success_dict[machine.get_machine_fullname()] = self.relay_send_to_machine(network, identity, machine, port, file_path)
        return success_dict


    # 단일 장치에 파일을 보내는 인스턴스 메서드
    def relay_send_to_machine(self, network: Network, identity: EdgeMachine, target: EdgeMachine, port: int, file_path: str, ttl: int = 600) -> bool:
        # 파일 크기 계산
        if not os.path.exists(file_path):
            print(f"File does not exist: {file_path}")
            return False

        f_size = os.path.getsize(file_path)
        if f_size == 0:
            print(f"File is empty: {file_path}")
            return False

        # 헤더 구성
        header: dict = {
            "Target-Machine": target.get_machine_fullname(),
            "Identity": identity.get_machine_fullname(),
            "Mode": "relay",
            "Forward-Port": str(port),
            "File-Size": str(f_size),
            "File-TTL": ttl # 파일의 TTL(Time To Live)을 분 단위로 지정. 이 시간이 지나면 릴레이 서버에서 파일이 자동으로 삭제됩니다. 기본값은 10시간 (600분)입니다. 0일 경우, 파일을 보관하지 않습니다.
        }
        endpoint: str = f"v1/send"

        # 릴레이 서버 정책 체크
        data: dict = self._mk_request(f"{self.relay_server}/{endpoint}", header, self.auth_server_pk, target.generate_jwt())
        if not data.get("status", "OK") == "OK":
            print(f"Relay server rejected the request to send file to machine {target.get_machine_fullname()}. Response: {data}")
            return False

        # 관련 정보 수신
        session_id = data.get("session_id", "")
        hold_server = data.get("hold_server", "")
        hold_server_port = data.get("hold_server_port", 0)

        # 정보 체크
        if not session_id or not hold_server or not hold_server_port:
            print(f"Invalid response from relay server for machine {target.get_machine_fullname()}. Missing session_id, hold_server, or hold_server_port. Response: {data}")
            return False

        # 헤더 확장
        header["Session-ID"] = session_id
        header["Hold-Server"] = hold_server
        header["Hold-Server-Port"] = str(hold_server_port)
        header["File-Start-From"] = "0" # 파일을 처음부터 보낼 때는 0으로 설정. 이후 재전송 시에는 바이트 단위로 오프셋을 지정하여 이어서 보낼 수 있습니다.

        # 파일을 바이너리 데이터로 읽어서 요청 본문에 포함
        try:
            f_uploader: SecureFileUploader = SecureFileUploader(f"{network.relay_server}:{network.relay_server_port}")
            state, message, start_from = f_uploader.mk_file_request(session_id, endpoint, header, target.pk, identity.generate_jwt(), file_path, start_from=0)
            return state
        except Exception as e:
            print(f"Error sending file to machine {target.get_machine_fullname()}: {e}")
            return False


    # 여러 장치에 동시에 파일을 직접 보내는 인스턴스 메서드 (릴레이 서버를 거치지 않고 직접 통신)
    def direct_send_to_machines(self, multiple_target_machines: list[EdgeMachine], port: int, file_path: str) -> dict[str, bool]:
        success_dict = {}
        for machine in multiple_target_machines:
            success_dict[machine.get_machine_fullname()] = self.direct_send_to_machine(machine, port, file_path)
        return success_dict


    # 단일 장치에 파일을 직접 보내는 인스턴스 메서드 (릴레이 서버를 거치지 않고 직접 통신)
    def direct_send_to_machine(self, machine: EdgeMachine, port: int, file_path: str) -> bool:
        # TODO - 직접 통신 방식으로 파일을 보내는 로직 추가 (예: P2P 소켓 통신, QUIC, WebRTC 등)
        return False


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Listener:

    @classmethod
    def open_ws_connection_to_relay(cls, relay_server_url: str, handshake_http_port: int, ws_port: int, handshake_path: str, ws_path: str, current_machine: EdgeMachine, file_mapping: dict[str, str], handshake_retry_attempts: int = 5):
        """
        Maintains an indefinite WebSocket connection, automatically reconnecting if dropped.
        """

        # Relay server URL 프로토콜 체크 및 제거
        protocol_pref: str = "https://" if relay_server_url.startswith("https://") else "http://" if relay_server_url.startswith("http://") else ""
        relay_server_url = relay_server_url[len(protocol_pref):] if protocol_pref else relay_server_url

        if not relay_server_url:
            logger.error("Invalid relay server URL provided.")
            return
        if not handshake_http_port or not ws_port:
            logger.error("Invalid port numbers provided for handshake or WebSocket.")
            return
        if not protocol_pref:
            protocol_pref = "http://"

        handshake_fails: int = 0

        while True:

            # 1. Execute the initial handshake
            session_id = cls._perform_handshake(f"{protocol_pref}{relay_server_url}:{handshake_http_port}/{handshake_path}", current_machine)

            if not session_id:
                handshake_fails += 1
                if handshake_fails >= handshake_retry_attempts:
                    logger.error(f"Handshake failed {handshake_fails}/{handshake_retry_attempts} times. Please check the relay server and network connection.")
                    return
                logger.error(f"Handshake failed. Retrying in 5 seconds... ({handshake_fails}/{handshake_retry_attempts})")
                time.sleep(5)
                continue

            logger.info(f"Handshake successful. Session ID: {session_id}")
            ws_url = f"ws://{relay_server_url}:{ws_port}/{ws_path}?session={session_id}"

            # 2. Define WebSocket event handlers
            def on_message(ws, message):
                # Check for the specific prefix and offload to a thread so we don't block the socket receiver
                if isinstance(message, str) and message.startswith("ND_EXC_WSSIG:"):
                    threading.Thread(
                        target=cls._process_incoming_data,
                        args=(message, file_mapping),
                        daemon=True
                    ).start()

            def on_error(ws, error):
                logger.error(f"WebSocket encountered an error: {error}")

            def on_close(ws, close_status_code, close_msg):
                logger.warning("WebSocket connection closed. Will attempt to reconnect.")

            def on_open(ws):
                logger.info("WebSocket connection established.")
                # Start the background heartbeat thread once connected
                threading.Thread(
                    target=cls._send_heartbeat,
                    args=(ws,),
                    daemon=True
                ).start()

            # 3. Initialize and run the WebSocket application
            ws_app = websocket.WebSocketApp(
                ws_url,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close
            )

            # This blocks until the connection is closed or drops
            ws_app.run_forever()

            # Prevent rapid tight-looping if the server is rejecting connections
            time.sleep(5)

    @classmethod
    def _perform_handshake(cls, handshake_url: str, current_machine: EdgeMachine) -> str:
        """
        Executes the HTTP handshake and parses the JSON response for the session ID.
        """

        # TODO - 핸드셰이크 추가

        try:
            # Send basic string representation of the machine
            payload = {"machine_data": str(current_machine)}
            response = requests.post(handshake_url, json=payload, timeout=10)
            response.raise_for_status()

            data = response.json()
            if data.get("state") == "OK" and "session" in data:
                return data["session"]

        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request failed during handshake: {e}")
        except ValueError:
            logger.error("Failed to parse JSON response during handshake.")

        return ""

    @classmethod
    def _process_incoming_data(cls, message: str, file_mapping: dict[str, str]):
        """
        Handles the specific "ND_EXC_WSSIG:" messages in an isolated thread.
        """

        # TODO - 수신된 메시지 처리 로직 추가 (file_mapping을 활용하여 적절한 파일로 매핑 및 저장)

        logger.info(f"Processing signal starting with: {message[:25]}...")
        # Put your file_mapping logic and specific data processing here
        pass

    @classmethod
    def _send_heartbeat(cls, ws: websocket.WebSocketApp):
        """
        Periodically reports online state to the server every 10 seconds.
        """

        # TODO - 서버가 기대하는 형태로 상태 보고 페이로드 구성 (예: {"status": "online"})

        while ws.keep_running:
            try:
                # Send the state report as expected by the server
                heartbeat_payload = json.dumps({"status": "online"})
                ws.send(heartbeat_payload)
                time.sleep(10)
            except Exception as e:
                logger.error(f"Failed to send background heartbeat: {e}")
                break

    ## Polling 모드
    @classmethod
    def start_polling_listener(cls, relay_url: str, port: int, current_machine: EdgeMachine, file_mapping: dict[str, str], interval: int = 30):
        pass

