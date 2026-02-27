import sys
import json
import copy

from osext.libaqnetutil.keygen import generate_rsa_keypair, stringify_rsa_key

# GTK4 모듈 임포트 시도
try:
    import gi

    gi.require_version('Gtk', '4.0')
    from gi.repository import Gtk, GLib, Gio

    GTK_AVAILABLE = True
except ImportError:
    GTK_AVAILABLE = False

auto_input_version: int = 1
auto_input_enabled: bool = False
auto_inputs: list[str] = []


# ==========================================
# 기존 CLI 로직 영역
# ==========================================

def actions():
    return """1. Generate Configuration file
    2. Generate RSA Keypair for inter-server communication
    3. Exit
    """


def auto_in(prompt: str, default=None):
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
        subdomain = auto_in(f"Enter the subdomain for {server_name} Server (e.g., {server_name.lower()}): ",
                            server_name.lower()).strip()
        port = int(
            auto_in(f"Enter the port number for {server_name} Server (e.g., 8000): ", str(8000 + iterated)).strip())
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
            "allow_ip_access": False,
            "allow_external_access": True,
            "policy_file": f"{server.lower()}_policy.json",
            "db_model": {
                "version": 1,
                "db_path": f"{server.lower()}_db.db"
            }
        }

    print("Generated Configuration:")
    print(json.dumps(default_template, indent=4))

    save_path = auto_in("Enter the file path to save the configuration (e.g., config.json): ",
                        "server-config.json").strip()
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


# ==========================================
# GTK GUI 로직 영역
# ==========================================

if GTK_AVAILABLE:
    class ConfiguratorWindow(Gtk.ApplicationWindow):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.set_title("NanoDirectory Server Configurator")
            self.set_default_size(600, 700)

            # 메인 스크롤 뷰 및 컨테이너 설정
            scrolled = Gtk.ScrolledWindow()
            self.set_child(scrolled)

            main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
            main_box.set_margin_top(15)
            main_box.set_margin_bottom(15)
            main_box.set_margin_start(15)
            main_box.set_margin_end(15)
            scrolled.set_child(main_box)

            # 네임스페이스 및 도메인 설정
            global_frame = Gtk.Frame(label="Global Configuration")
            main_box.append(global_frame)
            global_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            global_box.set_margin_top(10)
            global_box.set_margin_bottom(10)
            global_box.set_margin_start(10)
            global_box.set_margin_end(10)
            global_frame.set_child(global_box)

            self.entry_namespace = Gtk.Entry(text="master", placeholder_text="Namespace (e.g., master)")
            global_box.append(self.entry_namespace)

            self.entry_domain = Gtk.Entry(text="example.com", placeholder_text="Master Domain (e.g., example.com)")
            global_box.append(self.entry_domain)

            # 서버별 설정 UI 생성
            self.server_uis = {}
            servers = ["Authentication", "Hold", "Relay"]

            servers_frame = Gtk.Frame(label="Server Map Configuration")
            main_box.append(servers_frame)
            servers_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
            servers_box.set_margin_top(10)
            servers_box.set_margin_bottom(10)
            servers_box.set_margin_start(10)
            servers_box.set_margin_end(10)
            servers_frame.set_child(servers_box)

            for idx, srv in enumerate(servers):
                row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)

                chk_active = Gtk.CheckButton(label=f"Enable {srv} Server")
                row.append(chk_active)

                settings_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

                entry_sub = Gtk.Entry(text=srv.lower(), placeholder_text="Subdomain")
                settings_box.append(entry_sub)

                entry_port = Gtk.Entry(text=str(8000 + idx), placeholder_text="Port")
                settings_box.append(entry_port)

                chk_rsa = Gtk.CheckButton(label="Generate RSA")
                chk_rsa.set_active(True)
                settings_box.append(chk_rsa)

                row.append(settings_box)
                servers_box.append(row)

                # 체크박스 상태에 따라 하위 설정 활성/비활성 연동
                chk_active.connect("toggled", self.on_server_toggled, settings_box)
                settings_box.set_sensitive(False)  # 기본 비활성화

                self.server_uis[srv] = {
                    "active": chk_active,
                    "subdomain": entry_sub,
                    "port": entry_port,
                    "rsa": chk_rsa
                }

            # 실행 버튼
            btn_generate = Gtk.Button(label="Generate Configuration")
            btn_generate.connect("clicked", self.on_generate_clicked)
            main_box.append(btn_generate)

            # 결과 출력 영역
            self.text_buffer = Gtk.TextBuffer()
            text_view = Gtk.TextView(buffer=self.text_buffer)
            text_view.set_editable(False)
            text_view.set_monospace(True)
            text_view.set_size_request(-1, 200)

            scroll_text = Gtk.ScrolledWindow()
            scroll_text.set_child(text_view)
            main_box.append(scroll_text)

            # 저장 영역
            save_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            self.entry_save_path = Gtk.Entry(text="server-config.json")
            self.entry_save_path.set_hexpand(True)
            save_box.append(self.entry_save_path)

            btn_save = Gtk.Button(label="Save to File")
            btn_save.connect("clicked", self.on_save_clicked)
            save_box.append(btn_save)

            main_box.append(save_box)

        def on_server_toggled(self, checkbutton, settings_box):
            settings_box.set_sensitive(checkbutton.get_active())

        def on_generate_clicked(self, button):
            namespace = self.entry_namespace.get_text().strip() or "master"
            master_domain = self.entry_domain.get_text().strip() or "example.com"

            active_servers = {}
            for srv_name, ui in self.server_uis.items():
                if ui["active"].get_active():
                    subdomain = ui["subdomain"].get_text().strip()
                    port_str = ui["port"].get_text().strip()
                    port = int(port_str) if port_str.isdigit() else 8000

                    active_servers[srv_name] = {
                        "url": f"{subdomain}.{master_domain}",
                        "port": port
                    }

                    if ui["rsa"].get_active():
                        pk_save_path = f"{namespace}_{srv_name.lower()}@{subdomain}.{master_domain}_public.pem"
                        try:
                            private_key, public_key = generate_rsa_keypair(sk_path=None, pk_path=pk_save_path)
                            active_servers[srv_name]["pgp"] = stringify_rsa_key(private_key)
                        except Exception as e:
                            active_servers[srv_name]["pgp"] = f"Error generating key: {e}"
                    else:
                        active_servers[srv_name]["pgp"] = ""

            default_template = {"ActiveServers": list(active_servers.keys()), "ServerMap": active_servers}
            for server in active_servers:
                default_template[server] = {
                    "namespace": namespace,
                    "allow_ip_access": False,
                    "allow_external_access": True,
                    "policy_file": f"{server.lower()}_policy.json",
                    "db_model": {
                        "version": 1,
                        "db_path": f"{server.lower()}_db.db"
                    }
                }

            json_output = json.dumps(default_template, indent=4)
            self.text_buffer.set_text(json_output)

        def on_save_clicked(self, button):
            save_path = self.entry_save_path.get_text().strip() or "server-config.json"
            start, end = self.text_buffer.get_bounds()
            content = self.text_buffer.get_text(start, end, True)

            if content:
                try:
                    with open(save_path, "w") as fx:
                        fx.write(content)
                    print(f"Configuration saved to {save_path} via GUI.")
                except Exception as e:
                    print(f"Error saving file: {e}")


    class ConfigApp(Gtk.Application):
        def __init__(self, **kwargs):
            super().__init__(application_id="com.example.ServerConfigurator", **kwargs)

        def do_activate(self):
            win = ConfiguratorWindow(application=self)
            win.present()

# ==========================================
# 실행 엔트리 포인트
# ==========================================

if __name__ == "__main__":
    # 파라미터에서 --gui 확인
    use_gui = False
    if "--gui" in sys.argv:
        use_gui = True
        sys.argv.remove("--gui")  # GTK Application이 알 수 없는 인자로 인식하는 것을 방지

    if use_gui:
        if GTK_AVAILABLE:
            print("Launching GTK Application...")
            app = ConfigApp()
            app.run(sys.argv)
        else:
            print("Error: PyGObject (GTK4) is not installed or available. Falling back to CLI mode.")
            use_gui = False

    if not use_gui:
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

            if auto_inputs and auto_inputs[0].startswith("#AUTO_INPUT_VERSION:"):
                version_line = auto_inputs[0]
                try:
                    version_str = version_line.split(":", 1)[1].strip()
                    version = int(version_str)
                    if version != auto_input_version:
                        print(
                            f"Warning: Auto input version mismatch. Expected {auto_input_version}, but got {version}.")
                    else:
                        print(f"Auto input version {version} confirmed.")
                except Exception as e:
                    print(f"Error parsing auto input version: {e}")
            auto_input_enabled = True
            print(f"Loaded {len(auto_inputs)} automated inputs.")
            print("WARNING: RUNNING AUTOCONFIG MODE!")

        main()