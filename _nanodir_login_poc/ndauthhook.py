#!/usr/bin/env python3
import os
import shutil
import sys
import time
import subprocess
import pwd
import hashlib
import requests

timestamp = int(time.time())
dump_dir = "/AquaSys/dump"
os.makedirs(dump_dir, exist_ok=True)
dump_file = os.path.join(dump_dir, f"{timestamp}.txt")

DUMMY_INFO: dict = {
    "MachineName": "Acadia/SoftwareTeam/hoyounsong@example.com/TestMachine"
}

SERVER_URL = "http://ndauth.example.com/ndauth"

def log(message):
    # print(message)
    try:
        with open(dump_file, "a") as f:
            f.write(f"{message}\n")
    except Exception as e:
        # print(f"Failed to write to dump file: {e}")
        pass
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
    for key, value in os.environ.items():
        log(f"{key}={value}")

    log("------------log------------")
    if not pam_user:
        log(f"User {pam_user} is not. Exiting.")
        sys.exit(1)  # 사용자 이름이 없으면 인증 실패 처리
    log(f"User {pam_user} is OK.")

    # 5. 사용자 존재 여부 확인 및 생성 로직
    log(f"Checking if user '{pam_user}' exists...")

    # 로컬 계정일 경우 (@와 .이 없는 걸로 판단), 시스템의 사용자 계정에서 존재 여부 확인
    if "@" not in pam_user and "." not in pam_user:
        log(f"User '{pam_user}' is considered a local account. Checking local user database...")
        try:
            pwd.getpwnam(pam_user)
            log(f"pwd.getpwnam({pam_user}) succeeded. User exists as a local account. Skipping user creation and proceeding with authentication.")
            sys.exit(0) # 더이상 사용자 생성 로직이 필요 없으므로 인증 성공 처리 (unix_pam 모듈이 로그인을 직접 체크하도록)

        except KeyError:
            log(f"{pam_user} is not a user. Checking if remote server has correct credentials.")


    payload: dict = {}
    try:
        # 서버에 연결하여 사용자 존재 여부 확인
        log(f"Checking user existence on server for {pam_user}...")
        url = f"{SERVER_URL}?machine_name={DUMMY_INFO['MachineName']}&username={pam_user}&otp=dummy_otp&cred={hashlib.md5(password.encode()).hexdigest()}"
        response = requests.get(url, timeout=5)

        # 서버 응답 처리
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "OK" and data.get("authenticated") is True:
                log(f"Server authentication successful for user {pam_user}. Proceeding with user creation.")

            elif data.get("status") == "REVOKED":
                log(f"User {pam_user} is revoked according to server response. Remove account in the background.")

                # 시스템에 해당 사용자가 존재하는 경우, 사용자 계정을 삭제합니다.
                try:
                    pwd.getpwnam(pam_user)  # 사용자 존재 여부 확인
                    log(f"User {pam_user} exists. Deleting user account...")
                    subprocess.run(["/usr/sbin/userdel", "-r", pam_user], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    log(f"User {pam_user} deleted successfully.")
                except KeyError:
                    log(f"User {pam_user} does not exist. No need to delete.")

                sys.exit(1)
            else:
                log(f"Server authentication failed for user {pam_user}. Response: {data}")
                sys.exit(1)
            payload = data.get("payload", {})
        else:
            log(f"Failed to connect to authentication server. Status code: {response.status_code}")
            sys.exit(1)

    except Exception as e:
        log(f"Error checking user existence: {e}")
        sys.exit(1)

    # 만약 profile-pic이 payload의 user_info에 profile-pic 키로 존재하는 경우, 해당 URL에서 이미지를 다운로드하여 사용자 홈 디렉터리에 저장
    user_info: dict = payload.get("user_info", {})
    profile_pic_url = user_info.get("profile-pic")
    profile_pic_path = None
    if profile_pic_url:
        try:
            log(f"Downloading profile picture for user {pam_user} from {profile_pic_url}...")
            response = requests.get(profile_pic_url, timeout=5)
            if response.status_code == 200:
                profile_pic_path = f"/tmp/{pam_user}_profile.png"
                with open(profile_pic_path, "wb") as f:
                    f.write(response.content)
                log(f"Profile picture downloaded successfully for user {pam_user} and saved to {profile_pic_path}")
            else:
                log(f"Failed to download profile picture for user {pam_user}. Status code: {response.status_code}")
                sys.exit(1)
        except Exception as e:
            log(f"Error downloading profile picture for user {pam_user}: {e}")
            sys.exit(1)

    try:
        log(f"Creating user {pam_user}...")

        user_exists = False
        try:
            # 시스템의 사용자 계정에서 존재 여부 확인
            pwd.getpwnam(pam_user)
            log(f"pwd.getpwnam({pam_user}) succeeded. User exists as a local account. Skipping user creation and proceeding with authentication.")
            user_exists = True
        except KeyError:
            log(f"{pam_user} is not a user. Checking if remote server has correct credentials.")

        if not user_exists:
            # full name 정보가 payload의 user_info에 full_name 키로 존재하는 경우, -c 옵션으로 전달하여 사용자 생성
            user_info: dict = payload.get("user_info", {})
            full_name = user_info.get("full_name")

            useradd_command = ["/usr/sbin/useradd", "-m", "-s", "/bin/bash"]
            if full_name:
                useradd_command.extend(["-c", full_name])
            useradd_command.append(pam_user)

            log(f"Full name for user {pam_user} is {full_name}. Creating user with full name.")
            result = subprocess.run(useradd_command, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log(f"Successfully created user {pam_user} with full name {full_name}")
            log(f"Return code: {result.returncode}")

        # 사용자 프로파일 사진이 다운로드된 경우, 해당 사진을 사용자의 홈 디렉터리에 .face 로 복사
        if profile_pic_url and os.path.exists(profile_pic_path):
            user_home_dir = f"/home/{pam_user}"
            target_profile_pic_path = os.path.join(user_home_dir, ".face")
            log(f"Copying profile picture for user {pam_user} to {target_profile_pic_path}...")
            subprocess.run(["cp", profile_pic_path, target_profile_pic_path], check=True)
            subprocess.run(["chown", f"{pam_user}:{pam_user}", target_profile_pic_path], check=True)
            log(f"Profile picture copied and ownership changed for user {pam_user}")

            try:
                # dbus-send --system --dest=org.freedesktop.Accounts --print-reply /org/freedesktop/Accounts/User"$USER_ID" org.freedesktop.Accounts.User.SetIconFile string:"$IMAGE_PATH"
                user_info = pwd.getpwnam(pam_user)
                user_id = user_info.pw_uid

                icons_dir = "/var/lib/AccountsService/icons"
                os.makedirs(icons_dir, exist_ok=True)
                shutil.copy(profile_pic_path, icons_dir)

                file_name = os.path.basename(profile_pic_path)
                stage_image = os.path.join(icons_dir, file_name)

                os.chmod(stage_image, 0o644)

                log(f"Waking up AccountsService for {pam_user}...")

                wake_cmd = [
                    "dbus-send",
                    "--system",
                    "--dest=org.freedesktop.Accounts",
                    "--print-reply",
                    "/org/freedesktop/Accounts",
                    "org.freedesktop.Accounts.FindUserByName",
                    f"string:{pam_user}"
                ]
                result = subprocess.run(wake_cmd, capture_output=True, text=True)
                log(f"AccountsService wake-up command executed for {pam_user}. Return code: {result.returncode}")
                log(f"Stdout: {result.stdout}")
                log(f"Stderr: {result.stderr}")

                log(f"Setting user icon for {pam_user} using dbus-send...")
                result = subprocess.run([
                    "dbus-send",
                    "--system",
                    "--dest=org.freedesktop.Accounts",
                    "--print-reply",
                    f"/org/freedesktop/Accounts/User{user_id}",
                    "org.freedesktop.Accounts.User.SetIconFile",
                    f"string:{stage_image}"
                ], check=True, capture_output=True, text=True)
                log(f"User icon set successfully for {pam_user}")
                log(f"Stdout: {result.stdout}")
                log(f"Stderr: {result.stderr}")
            except Exception as e:
                log(f"Failed to set user icon for {pam_user} using dbus-send: {e}")



        # permission 에 sudo 또는 admin이 있는 경우, 사용자에게 sudo 권한 부여
        permissions: list = payload.get("permission", [])
        if "sudo" in permissions or "admin" in permissions:
            log(f"Granting sudo permissions to user {pam_user}...")
            with open("/etc/sudoers", "a") as sudoers_file:
                sudoers_file.write(f"{pam_user} ALL=(ALL) NOPASSWD:ALL\n")
            log(f"Sudo permissions granted to user {pam_user}")

        # permission 이 user 인데 suder 파일에 이미 sudo 권한이 있는 경우, 해당 권한 제거
        elif "user" in permissions:
            log(f"Ensuring user {pam_user} does not have sudo permissions...")

            with open("/etc/sudoers", "r") as sudoers_file:
                lines = sudoers_file.readlines()
                if any(line.strip() == f"{pam_user} ALL=(ALL) NOPASSWD:ALL" for line in lines):
                    log(f"User {pam_user} currently has sudo permissions. Removing them...")

                    with open("/etc/sudoers", "w") as sudoers_file_w:
                        for line in lines:
                            if line.strip() == f"{pam_user} ALL=(ALL) NOPASSWD:ALL":
                                log(f"Removing sudo permissions for user {pam_user} from /etc/sudoers")
                                continue  # 이 줄을 건너뛰어 해당 사용자의 sudo 권한 제거
                            sudoers_file_w.write(line)
                            log(f"Sudo permissions removed for user {pam_user} if they existed")

        # 생성한 사용자의 비밀번호 설정
        if password:
            chpasswd_input = f"{pam_user}:{password}\n"
            log(f"Setting password for user {pam_user}...")
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

        # Payload 의 files 항목에서 파일 경로와 내용을 읽어와서 바탕화면에 파일로 생성
        files: dict = payload.get("files", {})
        for file_path, content in files.items():
            # 파일 경로가 $HOME/으로 시작하는 경우에만 생성
            # 폴더 생성
            log(f"Processing file {file_path} for user {pam_user}...")
            if file_path.startswith("$HOME/"):
                relative_path = file_path[len("$HOME/"):]
                target_path = os.path.join(home_dir, relative_path)
                target_dir = os.path.dirname(target_path)
                os.makedirs(target_dir, exist_ok=True)
                os.chown(target_dir, uid, gid)  # 폴더 소유권 변경
                with open(target_path, "w") as f:
                    f.write(content)
                os.chown(target_path, uid, gid)  # 파일 소유권 변경
                log(f"Created file {target_path} with content from payload and changed ownership to {pam_user}")

        log(f"Welcome to {pam_user}")
        # --- 바탕화면 환영 파일 생성 끝 ---

    except Exception as e:
        # Write to dump
        log(f"Failed to create user Error: {e}")
        sys.exit(1)

    # 6. 인증 성공 처리 (Do stuff here)
    sys.exit(0)


if __name__ == "__main__":
    main()
