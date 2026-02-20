import platform
import os

def os_specific(nt ="", linux ="", mac ="", aqua ="") -> str:
    os_type = platform.system()
    if os_type == "Windows":
        return nt

    elif os_type == "Linux":
        # AquariusOS 인지 체크한 후, 해당 OS인 경우 aqua 반환
        if os.path.exists("/etc/aqua.txt"):
            return aqua

        # 그렇지 않은 일반적인 리눅스인 경우 linux 반환
        return linux

    elif os_type == "Darwin":
        return mac

    else:
        raise Exception("Unknown OS") # 예상치 못한 OS인 경우 예외 처리

def read_file(file_path: str, default = "") -> str:
    try:
        if not os.path.exists(file_path):
            return default
        with open(file_path, "r") as f:
            return f.read().strip()
    except Exception as e:
        print(f"Failed to read file: {file_path}. Error: {e}")
        return default

def write_file(file_path: str, content: str) -> bool:
    try:
        with open(file_path, "w") as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Failed to write file: {file_path}. Error: {e}")
        return False

def write_file_if_not_exists(file_path: str, content: str) -> bool:
    if os.path.exists(file_path):
        return False
    return write_file(file_path, content)