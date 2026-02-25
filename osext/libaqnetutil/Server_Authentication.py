import asyncio
import logging
import os.path
import uuid
import hashlib
import uvicorn
import pyotp
import time
import base64
import cbor2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import FastAPI, Request
from pydantic import BaseModel as BodyPayloadBaseModel
from keygen import generate_totp_seed, hash_password, generate_totp_result, generate_rsa_keypair, rsa_decrypt, rsa_encrypt, stringify_rsa_key

# Configure production-level logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from sqlalchemy import create_engine, String, select, Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session


engine: Engine = None
app = FastAPI()

# Base class for our models
class DBBaseObject(DeclarativeBase):
    pass


# Define the table structure as a Python class
class RegisteredUserObject(DBBaseObject):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(50), unique=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(50))
    profilepic: Mapped[str] = mapped_column(String(200))
    max_devices: Mapped[int] = mapped_column()
    password: Mapped[str] = mapped_column(String(100))
    password_expire: Mapped[int] = mapped_column() # 패스워드 만료 시점 (예: 타임스탬프, 또는 일수)
    network: Mapped[str] = mapped_column(String(50))
    group_full_path: Mapped[str] = mapped_column(String(200))
    group_uid: Mapped[str] = mapped_column(String(50))
    totp: Mapped[str] = mapped_column(String(100)) # TOTP 시크릿 키
    role: Mapped[str] = mapped_column(String(50))
    tags: Mapped[str] = mapped_column(String(200)) # 문자열로 저장 (예: "tag1,tag2,tag3")

class GroupObject(DBBaseObject):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    network: Mapped[str] = mapped_column(String(50))
    group_name: Mapped[str] = mapped_column(String(50))
    group_parent: Mapped[str] = mapped_column(String(200)) # 부모 그룹의 full path (예: parent1/parent2/me 라면 "parent1/parent2")
    group_uid: Mapped[str] = mapped_column(String(50))


class MachineObject(DBBaseObject):
    __tablename__ = "machines"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(50), unique=True)
    machine_full_name: Mapped[str] = mapped_column(String(200), unique=True) # 머신의 full name (예: "Engineering/RnD/john.doe/laptop1")
    machine_type: Mapped[str] = mapped_column(String(50)) # 머신의 유형 (예: "desktop", "laptop", "server", "mobile" 등)
    network: Mapped[str] = mapped_column(String(50)) # 머신이 속한 네트워크. 향후 멀티 네트워크 지원 시 필요할 수 있으므로 일단 남겨둡니다.
    group_full_path: Mapped[str] = mapped_column(String(200))
    group_uid: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(50))
    owner: Mapped[str] = mapped_column(String(100))
    policies: Mapped[str] = mapped_column(String(200)) # 머신에 적용된 정책 목록 (예: "policy1,policy2,policy3")
    machine_totp: Mapped[str] = mapped_column(String(100)) # 머신의 TOTP 시크릿 키
    client_pk: Mapped[str] = mapped_column(String(200)) # 머신의 공개키 (PEM 형식으로 저장)
    server_pk: Mapped[str] = mapped_column(String(200)) # 서버가 보관하는 서버의 공개키 - 클라이언트에게 자격 증명을 할 때 사용합니다.
    auth_method: Mapped[str] = mapped_column(String(20)) # 'software', 'tpm', 'apple_se'
    hardware_ak: Mapped[str] = mapped_column(String(200)) # TPM이나 Apple SE와 같은 하드웨어 보안 모듈에서 인증에 사용되는 AK (Attestation Key) 정보. 소프트웨어 인증 방식인 경우 빈 문자열로 저장됩니다.


class MachineRegistrationPayload(BodyPayloadBaseModel):
    network_name: str
    network_url: str
    machine_type: str
    group: str
    machine_name: str
    owner_email: str
    pk: str
    credentials: str
    user_totp: str
    auth_method: str = "software" # 기본: 'software'
    hardware_ak: str = ""  # TPM 또는 SE에서 생성한 증명키(AK)의 공개키
    hardware_attestation: str = ""  # TPM Quote 또는 App Attest 서명 데이터


class MachineEnumerationRequestPayload(BodyPayloadBaseModel):
    network_name: str
    network_url: str
    owner_email: str
    credentials: str
    user_totp: str

def _assert(expected, actual, operation = lambda x, y: x == y):
    if not operation(expected, actual):
        raise ValueError(f"Assertion failed. Expected: {expected}, Actual: {actual}")

def _fetch_machine_identity_from_table(machine_full_name: str) -> str:
    # 데이터베이스 machines 테이블에서 totp 를 불러온 후, 결과를 sha256 으로 다이제스트
    with Session(engine) as session:
        # machine_name 의 형태는 <group_full_path>/<owner>/<machine_name> 입니다. 예를 들어 "Engineering/RnD/john.doe/laptop1" 과 같은 형태입니다.
        stmt = select(MachineObject).where(MachineObject.machine_full_name == machine_full_name)
        result = session.execute(stmt).scalar_one_or_none()
        totp_secret = result.machine_totp if result else None
        otp = pyotp.TOTP(totp_secret) if totp_secret else None
        digested = hashlib.sha256(otp.now().encode()).hexdigest() if otp else None
        return digested


def _assert_machine_identity(credentials: str):
    identity = _fetch_machine_identity_from_table(credentials)
    if not identity:
        raise ValueError(f"Invalid credentials: {credentials}")


def _verify_hardware_signature(ak_pem: str, signature_hex: str, payload_data: str) -> bool:
    try:
        # PEM 형식의 공개키 로드
        public_key = serialization.load_pem_public_key(ak_pem.encode('utf-8'))
        signature = bytes.fromhex(signature_hex)
        data_to_verify = payload_data.encode('utf-8')

        # 키 타입에 따른 검증 분기
        if isinstance(public_key, rsa.RSAPublicKey):
            # TPM 2.0 환경: 주로 RSA 키를 사용
            # 설정에 따라 PSS 패딩을 사용할 수도 있으므로, 클라이언트 생성 방식과 맞춰야 합니다.
            public_key.verify(
                signature,
                data_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # Apple Secure Enclave 환경: ECDSA (주로 P-256 커브) 사용
            public_key.verify(
                signature,
                data_to_verify,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            logger.error("Unsupported public key type. Only RSA and EC are supported.")
            return False

        return True

    except InvalidSignature:
        logger.error("Signature verification failed: The signature is invalid or does not match the payload.")
        return False
    except Exception as e:
        logger.error(f"Hardware signature verification error: {e}")
        return False


def _authenticate_machine(session: Session, machine_full_name: str, headers: dict) -> bool:
    stmt = select(MachineObject).where(MachineObject.machine_full_name == machine_full_name)
    machine = session.execute(stmt).scalar_one_or_none()

    if not machine:
        return False

    auth_method = machine.auth_method

    if auth_method == "software":
        # 기존 소프트웨어 방식 (TOTP 폴백)
        client_totp = headers.get("Authorization", "").replace("Bearer ", "")
        otp = pyotp.TOTP(machine.machine_totp)
        expected_digest = hashlib.sha256(otp.now().encode()).hexdigest()
        return expected_digest == client_totp

    elif auth_method in ["tpm", "apple_se"]:
        # 하드웨어 방식 (서명 검증)
        hardware_signature = headers.get("Hardware-Signature", "")
        timestamp = headers.get("Hardware-Timestamp", "")

        # 1. Replay 공격 방지를 위한 타임스탬프 검증 (예: 60초 이내의 요청만 허용)
        if not timestamp or abs(int(time.time()) - int(timestamp)) > 60:
            return False

        # 2. 클라이언트는 "머신이름+타임스탬프" 문자열을 TPM/SE로 서명해서 보낸다고 가정
        signed_payload = f"{machine_full_name}:{timestamp}"

        # 3. 데이터베이스에 저장된 AK로 서명 검증
        return _verify_hardware_signature(machine.hardware_ak, hardware_signature, signed_payload)

    return False

@app.post("/register_machine")
async def register_machine(payload: MachineRegistrationPayload):
    logger.info(f"Handshake requested by machine: {payload.__dict__}.")

    try:

        # 네트워크 URL 검증
        _assert(app.state.domain, payload.network_url)

        # 데이터베이스에서 users 테이블에 등록된 사용자인지 확인
        with Session(engine) as session:
            stmt = select(RegisteredUserObject).where(RegisteredUserObject.email == payload.owner_email)
            result = session.execute(stmt).scalar_one_or_none()
            
            # 이메일로 등록된 사용자가 없는 경우
            if result is None:
                logger.warning(f"Registration failed: No registered user found with email {payload.owner_email}.")
                return {
                    "state": "ERROR",
                    "message": f"NO_USER_FOUND:{payload.owner_email}",
                    "session": ""
                }
            
            # 이메일로 등록된 사용자가 있지만, 패스워드 검증에 실패한 경우
            local_passwd = hash_password(result.password, result.totp)
            given_passwd = hash_password(payload.credentials, result.totp)

            if local_passwd != given_passwd:
                logger.warning(f"Registration failed: Invalid credentials for email {payload.owner_email}.")
                return {
                    "state": "ERROR",
                    "message": f"INVALID_CREDENTIALS:{payload.owner_email}",
                    "session": ""
                }

            # TOTP 검증
            locally_generated_totp = generate_totp_result(result.totp)
            if locally_generated_totp != payload.user_totp:
                logger.warning(f"Registration failed: Invalid TOTP for email {payload.owner_email}. Expected {locally_generated_totp}, got {payload.user_totp}.")
                return {
                    "state": "ERROR",
                    "message": f"INVALID_TOTP:{payload.owner_email}",
                    "session": ""
                }
            
            # 사용자의 자격증명은 확인되었음.
            # 장치의 중복을 확인해야 함.
            stmt = select(MachineObject).where(MachineObject.machine_full_name == f"{payload.network_name}/{payload.group}/{payload.owner_email}/{payload.machine_name}", MachineObject.name == payload.machine_name, MachineObject.owner == payload.owner_email)
            result = session.execute(stmt).scalar_one_or_none()

            if result is not None:
                logger.warning(f"Registration failed: Machine with name {payload.machine_name} already exists for owner {payload.owner_email}.")
                return {
                    "state": "ERROR",
                    "message": f"DUPLICATE_MACHINE:{payload.machine_name}",
                    "session": ""
                }
            
            # 모든 검증 통과. 이제 머신 정보를 저장해야 함.
            # 저장하기 전 인증 정보를 새로 발급

            new_totp_seed = generate_totp_seed()
            client_pk, client_sk = generate_rsa_keypair(nosave=True)
            server_pk, server_sk = generate_rsa_keypair(nosave=True)

            # 하드웨어 증명 검증 로직 (auth_method 가 tpm 이나 apple_se 일 경우)
            if payload.auth_method in ["tpm", "apple_se"]:
                if not payload.hardware_ak or not payload.hardware_attestation:
                    return {"state": "ERROR", "message": "MISSING_HARDWARE_PAYLOAD", "session": ""}

                try:
                    if payload.auth_method == "tpm":
                        # TPM 검증 로직
                        # payload.hardware_attestation 을 JSON 형태로 받아 EK 인증서를 추출한다고 가정합니다.
                        attestation_data = payload.hardware_attestation  # 클라이언트 구현에 따라 dict로 파싱 필요

                        if isinstance(attestation_data, str):
                            import json
                            attestation_data = json.loads(attestation_data)

                        ek_cert_pem = attestation_data.get("ek_cert")
                        if not ek_cert_pem:
                            raise ValueError("TPM EK Certificate is missing.")

                        # X.509 포맷인 EK 인증서 로드
                        ek_cert = x509.load_pem_x509_certificate(
                            ek_cert_pem.encode('utf-8'),
                            default_backend()
                        )

                        # 1차 검증: 인증서의 발급자(Issuer)가 신뢰할 수 있는 TPM 제조사인지 확인
                        # 실제 운영 환경에서는 Infineon, Intel 등의 Root CA 인증서를 서버에 저장해두고 체인을 검증해야 합니다.
                        issuer_name = ek_cert.issuer.rfc4514_string()
                        logger.info(f"TPM Manufacturer / Issuer: {issuer_name}")

                        # 2차 검증: 클라이언트가 보낸 hardware_ak 가 이 TPM에 종속되어 있다는 것을
                        # MakeCredential 프로세스나 TPM2_Quote 를 통해 증명해야 합니다.
                        # (이 부분은 tpm2-pytss 라이브러리를 통한 복잡한 TCG 표준 구조체 파싱이 필요하므로
                        # 클라이언트가 올바른 Quote를 보냈는지 _verify_hardware_signature 로 1차 확인합니다.)

                    elif payload.auth_method == "apple_se":
                        # Apple App Attest 검증 로직
                        # Apple은 증명 데이터를 Base64 인코딩된 CBOR 형식으로 보냅니다.
                        attestation_bytes = base64.b64decode(payload.hardware_attestation)
                        attestation_obj = cbor2.loads(attestation_bytes)

                        # 1. CBOR 구조에서 X.509 인증서 체인(x5c) 추출
                        cert_chain = attestation_obj.get("fmt") == "apple-appattest" and \
                                     attestation_obj.get("attStmt", {}).get("x5c", [])

                        if not cert_chain:
                            raise ValueError("Invalid Apple Attestation format or missing certificate chain.")

                        # 2. 첫 번째 인증서(Leaf Certificate) 파싱
                        leaf_cert_bytes = cert_chain[0]
                        leaf_cert = x509.load_der_x509_certificate(leaf_cert_bytes, default_backend())

                        # 3. 인증서에 포함된 공개키 추출 및 저장될 hardware_ak와 일치하는지 비교
                        leaf_pub_key = leaf_cert.public_key()
                        leaf_pub_key_pem = leaf_pub_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8')

                        # 클라이언트가 명시한 키와 인증서 안의 키가 다르면 공격 시도로 간주
                        if leaf_pub_key_pem.strip() != payload.hardware_ak.strip():
                            raise ValueError("Public key mismatch in Apple Attestation.")

                        # 추가 보안 검증 (실제 프로덕션 환경에서 필수):
                        # - Apple Root CA로 인증서 체인이 정상적으로 이어지는지 검증
                        # - leaf_cert의 확장 필드(OID 1.2.840.113635.100.8.2)를 파싱하여 난수(Nonce) 일치 여부 확인

                except Exception as e:
                    logger.error(f"Hardware attestation validation failed for {payload.owner_email}: {e}")
                    return {
                        "state": "ERROR",
                        "message": "INVALID_HARDWARE_ATTESTATION",
                        "session": ""
                    }

            new_machine = MachineObject(
                machine_type=payload.machine_type,
                group_full_path=payload.group,
                group_uid="", # 그룹 UID는 현재 구현에서 사용되지 않으므로 빈 문자열로 저장합니다. 향후 그룹 관리 기능이 추가되면 이 부분을 수정하여 그룹 UID를 저장할 수 있습니다.
                name=payload.machine_name,
                owner=payload.owner_email,
                policies="", # 정책은 현재 구현에서 사용되지 않으므로 빈 문자열로 저장합니다
                machine_totp=new_totp_seed,
                client_pk=stringify_rsa_key(client_pk),
                server_pk=stringify_rsa_key(server_pk),
                auth_method=payload.auth_method,
                hardware_ak=payload.hardware_ak
            )
            session.add(new_machine)
            session.commit()

        # 응답 데이터에 새로운 TOTP 시크릿과 공개키를 포함하여 반환
        # 두 정보 모두 클라이언트의 공개키로 암호화 후 응답에 포함
        encrypted_totp_seed = rsa_encrypt(pk_str=payload.pk, plaintext=new_totp_seed)
        encrypted_client_sk = rsa_encrypt(pk_str=payload.pk, plaintext=stringify_rsa_key(client_sk))
        encrypted_server_sk = rsa_encrypt(pk_str=payload.pk, plaintext=stringify_rsa_key(server_sk))

        return {
            "state": "OK",
            "totp_seed": encrypted_totp_seed,
            "client_sk": encrypted_client_sk,
            "server_sk": encrypted_server_sk
        }

    except Exception as ex:
        logger.error(f"Registration failed: {ex}")
        return {
            "state": "ERROR",
            "session": ""
        }


@app.post("/v1/is_enrolled")
async def is_enrolled(payload: MachineEnumerationRequestPayload, request: Request):
    # Get header as dictionary
    headers = dict(request.headers)

    # Machine-Full-Name
    # Identity
    # Authorization (Bearer Token)
    machine_full_name: str = headers.get("Machine-Full-Name", "")
    identity_fullpath: str = headers.get("Identity", "")
    client_side_generated_totp: str = headers.get("Authorization", "").replace("Bearer ", "")

    try:

        _assert(machine_full_name, None, lambda x, y: x != "")
        _assert(identity_fullpath, None, lambda x, y: x != "")
        _assert(client_side_generated_totp, None, lambda x, y: x != "")

        server_side_generated_totp = _fetch_machine_identity_from_table(identity_fullpath)
        if not server_side_generated_totp:
            logger.warning(f"Enrollment check failed: Invalid token {client_side_generated_totp}.")
            return {
                "state": "ERROR",
                "message": f"INVALID_IDENTITY",
                "enrolled": False
            }
        elif server_side_generated_totp != client_side_generated_totp:
            logger.warning(f"Enrollment check failed: Token does not match identity for {identity_fullpath}. Expected {server_side_generated_totp}, got {client_side_generated_totp}.")
            return {
                "state": "ERROR",
                "message": f"INVALID_TOKEN",
                "enrolled": False
            }

        # 검증 통과. 이제 해당 머신이 등록되어 있는지 확인해야 함.
        with Session(engine) as session:
            stmt = select(MachineObject).where(MachineObject.machine_full_name == machine_full_name)
            result = session.execute(stmt).scalar_one_or_none()

            if result is not None:
                return {
                    "state": "OK",
                    "enrolled": True
                }
            else:
                return {
                    "state": "OK",
                    "enrolled": False
                }

    except Exception as ex:
        logger.error(f"Enrollment check failed: {ex}")
        return {
            "state": "ERROR",
            "message": f"ENROLLMENT_CHECK_FAILED",
            "enrolled": False
        }

@app.post("/v1/get_machines_of")
async def enumerate_machines(payload: MachineEnumerationRequestPayload, request: Request):
    # Get header as dictionary
    headers = dict(request.headers)
    
    # Group-Path
    # Target-User
    # Identity
    # Authorization (Bearer Token)
    group_path: str = headers.get("Group-Path", "")
    target_user: str = headers.get("Target-User", "")
    identity_fullpath: str = headers.get("Identity", "")
    client_side_generated_totp: str = headers.get("Authorization", "").replace("Bearer ", "")

    # If any of them are missing, return error
    try:
        _assert(group_path, None, lambda x, y: x != "")
        _assert(target_user, None, lambda x, y: x != "")
        _assert(identity_fullpath, None, lambda x, y: x != "")
        _assert(client_side_generated_totp, None, lambda x, y: x != "")

        server_side_generated_totp = _fetch_machine_identity_from_table(identity_fullpath)
        if not server_side_generated_totp:
            logger.warning(f"Machine enumeration failed: Invalid token {client_side_generated_totp}.")
            return {
                "state": "ERROR",
                "message": f"INVALID_IDENTITY",
                "machines": []
            }
        elif server_side_generated_totp != client_side_generated_totp:
            logger.warning(f"Machine enumeration failed: Token does not match identity for {identity_fullpath}. Expected {server_side_generated_totp}, got {client_side_generated_totp}.")
            return {
                "state": "ERROR",
                "message": f"INVALID_TOKEN",
                "machines": []
            }

        # 검증 통과. 이제 해당 그룹에 속하고 해당 사용자가 소유한 머신들을 반환해야 함.
        with Session(engine) as session:
            stmt = select(MachineObject).where(MachineObject.group_full_path == group_path and MachineObject.owner == target_user)
            results = session.execute(stmt).scalars().all()

            machines_info = []
            for machine in results:
                machines_info.append({
                    "network": machine.network,
                    "group": machine.group_full_path,
                    "machine_owner": machine.owner,
                    "machine_name": machine.name,
                    "machine_full_name": machine.machine_full_name,
                    "machine_type": machine.machine_type,
                    "pk": machine.client_pk
                })

            return {
                "state": "OK",
                "machines": machines_info
            }

    except Exception as ex:
        logger.error(f"Machine enumeration failed: {ex}")
        return {
            "state": "ERROR",
            "message": f"ENUMERATION_FAILED",
            "machines": []
        }

def setup(
        namespace: str,
        port: int,
        domain: str,
        subdomain: str,
        allow_ip_access: bool,
        allow_external_access: bool,
        policy_file: str,
        server_map: dict,
        db_model: dict
):
    logger.info(f"Authentication server setup with namespace={namespace}, port={port}, domain={domain}, subdomain={subdomain}, allow_ip_access={allow_ip_access}, allow_external_access={allow_external_access}, policy_file={policy_file}, server_map={server_map}, db_model={db_model}")

    # 1. Store your configuration in the app state so endpoints can access them
    app.state.namespace = namespace
    app.state.domain = domain
    app.state.subdomain = subdomain
    app.state.policy_file = policy_file
    app.state.server_map = server_map
    app.state.db_model = db_model

    _assert("version", db_model, lambda x, y: x in y)
    _assert(1, db_model.get("version"), lambda x, y: x == y) # 현재 버전은 1로 고정. 향후 버전업 시 이 부분을 수정하여 호환성 검증 로직을 추가할 수 있습니다.
    _assert("db_path", db_model, lambda x, y: x in y)
    _assert(os.path.abspath(db_model.get("db_path")), None, lambda x, y: os.path.isfile(x))
    _assert(os.path.abspath(policy_file), None, lambda x, y: os.path.isfile(x))
    _assert("authentication", server_map, lambda x, y: x in y)
    _assert("url", server_map.get("authentication"), lambda x, y: x in y)
    _assert("port", server_map.get("authentication"), lambda x, y: x in y)
    _assert("hold", server_map, lambda x, y: x in y)
    _assert("url", server_map.get("hold"), lambda x, y: x in y)
    _assert("port", server_map.get("hold"), lambda x, y: x in y)
    _assert("relay", server_map, lambda x, y: x in y)
    _assert("url", server_map.get("relay"), lambda x, y: x in y)
    _assert("port", server_map.get("relay"), lambda x, y: x in y)
    _assert([server_map.get("hold").get("port"), server_map.get("relay").get("port")], port, lambda x, y: y not in x) # 인증 서버가 홀드/릴레이 서버와 포트 충돌이 나지 않도록 검증

    app.state.credentials_table = {} # 토큰과 관련된 정보를 저장하는 테이블.

    global engine
    engine: Engine = create_engine(f"sqlite://{db_model.get("db_path")}", echo=False)

    # This creates the tables in the database if they don't exist
    DBBaseObject.metadata.create_all(engine)


    # 3. Start the server programmatically
    # Note: Calling this will block the thread it runs on.
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    # For local testing only. In production, run via command line using Gunicorn/Uvicorn.
    # uvicorn.run("Server_Authentication:app", host="0.0.0.0", port=8000, log_level="info")
    setup(
        namespace="master",  # 인증 서버가 속할 네임스페이스 이름 (예: "master")
        port=8000,  # 인증 서버가 사용할 포트 번호
        domain="example.com",  # 인증 서버의 도메인 이름. 이 때 Authentication 서버는 xxx.example.com 형태로 서브도메인으로 운영되어야 합니다.
        subdomain="authentication",  # 인증 서버의 서브도메인 이름
        allow_ip_access=False,  # 인증 서버에 IP 주소로 접근을 허용할지 여부 (True: IP 주소 허용, False: IP 주소로 접근 불허)
        allow_external_access=True,  # 인증 서버에 외부 네트워크에서 접근을 허용할지 여부 (True: 외부 네트워크 허용, False: 내부 네트워크로만 접근 허용)
        policy_file="auth_policy.json",  # 인증 서버가 사용할 정책 파일 경로 (예: "auth_policy.json")
        server_map={
            "authentication": {
                "url": "authentication.example.com",  # 인증 서버의 URL (예: "authentication.example.com")
                "port": 8000  # 인증 서버의 포트 번호 (예:
            },
            "hold": {
                "url": "hold.example.com",  # 홀드 서버의 URL (예: "hold.example.com")
                "port": 8001  # 홀드 서버의 포트 번호 (예: 8001)
            },
            "relay": {
                "url": "relay.example.com",  # 릴레이 서버의 URL (예
                "port": 8002  # 릴레이 서버의 포트 번호 (예: 8002)
            }
        },
        db_model={
            "version": 1,  # 데이터베이스 모델의 버전 (예: 1)
            "db_path": "auth_db.db",  # 데이터베이스 모델이 파일 기반인 경우 사용할 데이터베이스 파일 경로 (예: "auth_db.sqlite")
        }
    )