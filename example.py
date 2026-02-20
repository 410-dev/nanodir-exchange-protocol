
# 서버 관련 라이브러리 가져오기
from osext.libaqnetutil import Authentication, Relay

# EdgeMachine 관련 라이브러리 가져오기
from osext.libaqnetutil.EdgeMachine import EdgeMachine, Network, Listener



### 서버 예시 ###
# 인증 서버 예시
Authentication.setup(
    port = 8000,                     # 인증 서버가 사용할 포트 번호
    domain = "example.com",          # 인증 서버의 도메인 이름. 이 때 Authentication 서버는 xxx.example.com 형태로 서브도메인으로 운영되어야 합니다.
    subdomain = "authentication",    # 인증 서버의 서브도메인 이름
    allow_ip_access = False,         # 인증 서버에 IP 주소로 접근을 허용할지 여부 (True: IP 주소 허용, False: IP 주소로 접근 불허)
    allow_external_access = True,    # 인증 서버에 외부 네트워크에서 접근을 허용할지 여부 (True: 외부 네트워크 허용, False: 내부 네트워크로만 접근 허용)
    policy_file = "auth_policy.json",# 인증 서버가 사용할 정책 파일 경로 (예: "auth_policy.json")
    db_model = {
        "protocol": "json",          # 인증 서버가 사용할 데이터베이스 모델 (예: "json", "sqlite", "mariadb" 중 택 1)
        "version": 1,                # 데이터베이스 모델의 버전 (예: 1)
        "file_path": "auth_db.json", # 데이터베이스 모델이 파일 기반인 경우 사용할 파일 경로
        "connection_info": {         # 데이터베이스 모델이 네트워크 기반인 경우 사용할 연결 정보 (예: 호스트, 포트, 사용자명, 비밀번호 등)
            "host": "localhost",
            "port": 3306,
            "user": "auth_user",
            "password": "auth_password",
            "database": "auth_db"
        }
    }
)
Authentication.init()  # 인증 서버 초기화 (필수)
Authentication.start() # 인증 서버 시작 (필수)


# 홀드 서버 예시
Hold.setup(
    port = 8001,                     # 홀드 서버가 사용할 포트 번호
    domain = "example.com",          # 홀드 서버의 도메인 이름. 이 때 Hold 서버는 xxx.example.com 형태로 서브도메인으로 운영되어야 합니다.
    subdomain = "hold",              # 홀드 서버의 서브도메인 이름
    allow_ip_access = False,         # 홀드 서버에 IP 주소로 접근을 허용할지 여부 (True: IP 주소 허용, False: IP 주소로 접근 불허)
    allow_external_access = True,    # 홀드 서버에 외부 네트워크에서 접근을 허용할지 여부 (True: 외부 네트워크 허용, False: 내부 네트워크로만 접근 허용)
    policy_file = "hold_policy.json",# 홀드 서버가 사용할 정책 파일 경로 (예: "hold_policy.json")
    db_model = {
        "protocol": "json",          # 홀드 서버가 사용할 데이터베이스 모델 (예: "json", "sqlite", "mariadb" 중 택 1)
        "version": 1,                # 데이터베이스 모델의 버전 (예: 1)
        "file_path": "hold_db.json", # 데이터베이스 모델이 파일 기반인 경우 사용할 파일 경로
        "connection_info": {         # 데이터베이스 모델이 네트워크 기반인 경우 사용할 연결 정보 (예: 호스트, 포트, 사용자명, 비밀번호 등)
            "host": "localhost",
            "port": 3306,
            "user": "hold_user",
            "password": "hold_password",
            "database": "hold_db"
        }
    }
)

Hold.init()  # 홀드 서버 초기화 (필수)
Hold.start() # 홀드 서버 시작 (필수)

# 릴레이 서버 예시
Relay.setup(
    port = 8002,                     # 릴레이 서버가 사용할 포트 번호
    domain = "example.com",          # 릴레이 서버의 도메인 이름. 이 때 Relay 서버는 xxx.example.com 형태로 서브도메인으로 운영되어야 합니다.
    subdomain = "relay",            # 릴레이 서버의 서브도메인 이름
    allow_ip_access = False,         # 릴레이 서버에 IP 주소로 접근을 허용할지 여부 (True: IP 주소 허용, False: IP 주소로 접근 불허)
    allow_external_access = True,    # 릴레이 서버에 외부 네트워크에서 접근을 허용할지 여부 (True: 외부 네트워크 허용, False: 내부 네트워크로만 접근 허용)
    policy_file = "relay_policy.json",# 릴레이 서버가 사용할 정책 파일 경로 (예: "relay_policy.json")
    db_model = {
        "protocol": "json",          # 릴레이 서버가 사용할 데이터베이스 모델 (예: "json", "sqlite", "mariadb" 중 택 1)
        "version": 1,                # 데이터베이스 모델의 버전 (예: 1)
        "file_path": "relay_db.json", # 데이터베이스 모델이 파일 기반인 경우 사용할 파일 경로
        "connection_info": {         # 데이터베이스 모델이 네트워크 기반인 경우 사용할 연결 정보 (예: 호스트, 포트, 사용자명, 비밀번호 등)
            "host": "localhost",
            "port": 3306,
            "user": "relay_user",
            "password": "relay_password",
            "database": "relay_db"
        }
    }
)

Relay.init()  # 릴레이 서버 초기화 (필수)
Relay.start() # 릴레이 서버 시작 (필수)


### EdgeMachine 송신 예시 ###

# 현재 장치 인스턴스 가져오기
current_machine: EdgeMachine = EdgeMachine.get_current_machine("master")  # 현재 장치 인스턴스 가져오기
current_network: Network = current_machine.get_network_instance("master") # 현재 장치에 등록된 네트워크 인스턴스 가져오기 (네트워크 실존 여부 체크 안함)

# Check if network is not enrolled.
# If so, the code should not work.

if not current_network.is_machine_enrolled(current_machine): raise Exception("Not enrolled to network!")

# Get machine ID of machine name for john@mycompany.com
multiple_target_machines: list[EdgeMachine] = current_network.get_machines_of(current_machine, "Engineering/Developers", "john@mycompany.com")

# Send to all machines
is_successful: dict[str, bool] = current_network.send_to_machines(current_network, multiple_target_machines, 8080, "/home/user/Desktop/my-file.txt")


### EdgeMachine 수신 예시 ###

# WS 모드로 릴레이 서버와 연결하여 명령 수신 대기
Listener.open_ws_connection_to_relay(
    relay_url = "relay.example.com", # 연결할 릴레이 서버의 URL (예: "relay.example.com")
    port = 8080,                     # 연결할 릴레이 서버의 포트 번호 (예: 8002)
    current_machine = current_machine # 현재 장치 인스턴스 (예: current_machine)
)

# Probe 모드로 릴레이 서버와 연결하여 명령 수신 대기
Listener.start_polling_listener(
    relay_url = "relay.example.com", # 연결할 릴레이 서버의 URL (
    port = 8080,                     # 연결할 릴레이 서버의 포트 번호 (예: 8002)
    current_machine = current_machine # 현재 장치 인스턴스 (예: current_machine
)
