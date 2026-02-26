#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import pwd

timestamp = int(time.time())
dump_dir = "/AquaSys/dump"
os.makedirs(dump_dir, exist_ok=True)
dump_file = os.path.join(dump_dir, f"{timestamp}.txt")

def log(message):
    # print(message)
    try:
        with open(dump_file, "a") as f:
            f.write(f"{message}\n")
    except Exception as e:
        # print(f"Failed to write to dump file: {e}")
        pass

def main():
    # 1. 루트 권한 및 OS 확인
    if os.geteuid() != 0:
        log("This script must be run as root.")
        sys.exit(1)

    if sys.platform != "linux":
        log("This script is only supported on Linux.")
        sys.exit(1)

    # 3. PAM으로부터 사용자 정보 및 비밀번호 읽기
    pam_user = os.environ.get("PAM_USER")
    # expose_authtok 옵션을 통해 전달된 비밀번호를 stdin에서 읽습니다.
    password = sys.stdin.readline().strip()

    # 4. 환경 변수 및 인자 덤프 작성
    log(f"Timestamp: {timestamp}")
    log(f"Process ID: {os.getpid()}")
    log(f"Target User: {pam_user}")
    log("Environment Variables:")
    log(f"Authtok: {password}")  # expose_authtok으로 전달된 비밀번호도 덤프에 기록
    for key, value in os.environ.items():
        log(f"{key}={value}")

    log("------------log------------")
    if not pam_user:
        log(f"User {pam_user} is not. Exiting.")
        sys.exit(1)  # 사용자 이름이 없으면 인증 실패 처리
    log(f"User {pam_user} is OK.")

    # 5. 사용자 존재 여부 확인 및 생성 로직 (Do stuff here)
    user_locally_exists = False
    log(f"Checking if user {pam_user} exists...")
    try:
        pwd.getpwnam(pam_user)
        log(f"pwd.getpwnam({pam_user}) succeeded. User exists.")
        user_locally_exists = True
    except KeyError:
        user_locally_exists = False

    if user_locally_exists:
        log(f"User {pam_user} already exists. Skipping user creation.")
        sys.exit(0)

    try:
        log(f"Creating user {pam_user}...")
        # 홈 디렉터리(-m)와 기본 쉘(-s)을 지정하여 사용자 생성
        result = subprocess.run(["/usr/sbin/useradd", "-m", "-s", "/bin/bash", pam_user], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"Successfully created user {pam_user}")
        log(f"Return code: {result.returncode}")

        # 생성한 사용자의 비밀번호 설정
        if password:
            chpasswd_input = f"{pam_user}:{password}\n"
            log(f"Setting password for user {pam_user} to {password}")
            result = subprocess.run(["/usr/sbin/chpasswd"], input=chpasswd_input, text=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log(f"Successfully set password for user {pam_user}")
            log(f"Exit code: {result.returncode}")
            log(f"Printed: {result.stdout}")

        # --- 바탕화면 환영 파일 생성 시작 ---
        # 방금 생성된 사용자의 UID, GID 및 홈 디렉터리 정보 가져오기
        log(f"Retrieving user info for {pam_user}...")
        user_info = pwd.getpwnam(pam_user)
        uid = user_info.pw_uid
        gid = user_info.pw_gid
        home_dir = user_info.pw_dir
        log(f"User {pam_user}'s UID: {uid}, GID: {gid}, Home Directory: {home_dir}")

        # Desktop 폴더 경로 지정 및 생성
        # (한글 OS 환경에서 첫 로그인 전이므로 강제로 Desktop을 만들어줍니다)
        log(f"Creating Desktop directory for user {pam_user} at {home_dir}...")
        desktop_dir = os.path.join(home_dir, "Desktop")
        os.makedirs(desktop_dir, exist_ok=True)
        log(f"Desktop directory created at {desktop_dir}")
        os.chown(desktop_dir, uid, gid)  # 폴더 소유권 변경
        log(f"Changed ownership of {desktop_dir} to {pam_user}")

        # 텍스트 파일 생성 및 내용 작성
        welcome_file_name = f"Welcome {pam_user}.txt"
        welcome_file_path = os.path.join(desktop_dir, welcome_file_name)
        log("Creating welcome file on Desktop...")

        with open(welcome_file_path, "w") as x:
            x.write(f"Hello, {pam_user}")

        log(f"Welcome to {pam_user}")

        os.chown(welcome_file_path, uid, gid)  # 파일 소유권 변경
        log(f"Changed ownership of {welcome_file_path} to {pam_user}")
        # --- 바탕화면 환영 파일 생성 끝 ---

    except Exception as e:
        # Write to dump
        log(f"Failed to create user Error: {e}")
        sys.exit(1)

    # 6. 인증 성공 처리 (Do stuff here)
    sys.exit(0)


if __name__ == "__main__":
    main()
