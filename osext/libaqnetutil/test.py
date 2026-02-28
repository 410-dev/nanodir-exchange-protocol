from SecureFileUploader import SecureFileUploader

def main():
    f_uploader: SecureFileUploader = SecureFileUploader(f"http://localhost:8002/upload")
    with open("server_public_key.pem", "r") as f:
        pk = f.read()
    state, message, start_from = f_uploader.mk_file_request("JUST-ANOTHER-RANDOM-UUID", "dasdf", {}, pk, "-",
                                                            "file2.dmg", start_from=0)
    print(state, message, start_from)

if __name__ == "__main__":
    main()
