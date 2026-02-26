import sys
import json

from osext.libaqnetutil.keygen import generate_rsa_keypair, stringify_rsa_key

auto_input_version: int = 1
auto_input_enabled: bool = False
auto_inputs: list[str] = []

def actions():
    return """1. Generate Configuration file
    2. Generate RSA Keypair for inter-server communication
    3. Exit
    """

def auto_in(prompt: str, default = None):
    if auto_inputs:
        response = auto_inputs.pop(0)
        print(f"{prompt} {response}")
        return response
    else:
        global auto_input_enabled
        if auto_input_enabled:
            print(f"[No more automated inputs available! Switched to manual input mode.]")
            auto_input_enabled = False

        user_input = input(prompt)
        if not user_input and default is not None:
            print(f"{default}\n")
            return default
        return user_input


def generate_config():
    print("Generating configuration file...")
    print("================================")
    print()
    print("[ Active server selections (Multiple choice, comma-separated) ]")
    print("1. Authentication Server")
    print("2. Hold Server")
    print("3. Relay Server")
    active_choices = auto_in("Enter your choices (e.g., 1,2): ").strip()
    active_servers = {}
    for c in active_choices.split(","):
        c = c.strip()
        if c == "1":
            active_servers["Authentication"] = {}
        elif c == "2":
            active_servers["Hold"] = {}
        elif c == "3":
            active_servers["Relay"] = {}
    print("Active Servers:", active_servers)
    print()
    print("[ Namespace Configuration] ")
    namespace = auto_in("Enter the namespace for the active servers (e.g., master): ", "master").strip()
    if not namespace:
        namespace = "master"

    print("[ Server Map Configuration ]")
    master_domain = auto_in("Enter your master domain (e.g., example.com): ", "example.com").strip()
    print()
    iterated = 0
    for server_name in active_servers.keys():
        print(f"Configuring {server_name.lower()} server:")
        subdomain = auto_in(f"Enter the subdomain for {server_name} Server (e.g., {server_name.lower()}): ", server_name.lower()).strip()
        port = int(auto_in(f"Enter the port number for {server_name} Server (e.g., 8000): ", str(8000 + iterated)).strip())
        iterated += 1
        active_servers[server_name]["url"] = f"{subdomain}.{master_domain}"
        active_servers[server_name]["port"] = port
        if auto_in(f"Generate RSA keypair for {server_name} Server? (y/n): ", "y").strip().lower() == "y":
            pk_save_path: str = f"{namespace}_{server_name.lower()}@{subdomain}.{master_domain}_public.pem"
            private_key, public_key = generate_rsa_keypair(sk_path=None, pk_path=pk_save_path)
            active_servers[server_name]["pgp"] = stringify_rsa_key(private_key)
            print(
                f"Generated RSA keypair for {server_name} Server. (PK saved to {pk_save_path}. Make sure to keep PK in its server!)")
        else:
            active_servers[server_name]["pgp"] = ""
        print()

    default_template = {"ActiveServers": list(active_servers.keys()), "ServerMap": active_servers}
    for server in active_servers:
        default_template[server] = {
            "namespace": namespace,
            "allow_ip_access": False, # TODO
            "allow_external_access": True, # TODO
            "policy_file": f"{server.lower()}_policy.json", # TODO
            "db_model": {
                "version": 1,
                "db_path": f"{server.lower()}_db.db"
            }
        }

    print("Generated Configuration:")
    print(json.dumps(default_template, indent=4))

    save_path = auto_in("Enter the file path to save the configuration (e.g., config.json): ", "server-config.json").strip()
    if not save_path:
        save_path = "server-config.json"
    with open(save_path, "w") as fx:
        json.dump(default_template, fx, indent=4)
    print(f"Configuration saved to {save_path}")
    print()


def main():
    while True:
        actions()
        choice = auto_in("Select an action (1-3): ").strip()
        if choice == "1":
            generate_config()

        elif choice == "2":
            print("Unimplemented.")

        elif choice == "3":
            print("Exiting...")
            break

if __name__ == "__main__":
    print("================ NanoDirectory File Exchange Infrastructure Server Configurator ================")
    print()
    print(" V E R S I O N :   1.0.0")
    print()
    print("================================================================================================")
    # Check if argument --auto-input=<input.txt>
    if len(sys.argv) > 1 and sys.argv[1].startswith("--auto-input="):
        input_file = sys.argv[1].split("=", 1)[1]
        print(f"Automated input mode enabled. Reading inputs from {input_file}...")
        with open(input_file, "r") as f:
            auto_inputs = [line.strip() for line in f if line.strip()]
        # Read first line, and check if it has "#AUTO_INPUT_VERSION:<version>"
        if auto_inputs and auto_inputs[0].startswith("#AUTO_INPUT_VERSION:"):
            version_line = auto_inputs[0]
            try:
                version_str = version_line.split(":", 1)[1].strip()
                version = int(version_str)
                if version != auto_input_version:
                    print(f"Warning: Auto input version mismatch. Expected {auto_input_version}, but got {version}.")
                else:
                    print(f"Auto input version {version} confirmed.")
            except Exception as e:
                print(f"Error parsing auto input version: {e}")
        auto_input_enabled = True
        print(f"Loaded {len(auto_inputs)} automated inputs.")
        print("WARNING: RUNNING AUTOCONFIG MODE!")
    main()