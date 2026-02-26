import json
import os.path
import threading
import sys
import importlib

def _assert_has(d, key):
    if key not in d:
        raise KeyError(f"Missing required key: {key}")

def _assert_type(d, key, expected_type):
    _assert_has(d, key)
    if not isinstance(d[key], expected_type):
        raise TypeError(f"Key '{key}' must be of type {expected_type.__name__}, but got {type(d[key]).__name__}")

def _chk_cfg_integrity(config: dict):
    # Check required keys
    _assert_has(config, "ServerMap")
    _assert_has(config, "ActiveServers")

    # Get Server Map
    server_map = config.get("ServerMap", {})

    # Check server map has authentication, hold, relay
    servers = ["Authentication", "Hold", "Relay"]
    for server in servers:
        _assert_has(server_map, server)

    # For each map element, check if has 'url' and 'port' and is a string and int
    for server in servers:
        _assert_type(server_map[server], "url", str)
        _assert_type(server_map[server], "port", int)

    # Check if configuration exists for active server
    active_servers = config.get("ActiveServers", [])
    active_server_cfgs: dict[str, dict] = {}
    for active in active_servers:
        _assert_type(config, active, dict)
        active_server_cfgs[active] = config[active]

    # For each element, check the required fields
    for active, cfg in active_server_cfgs.items():
        _assert_type(cfg, "namespace", str)
        _assert_type(cfg, "allow_ip_access", bool)
        _assert_type(cfg, "allow_external_access", bool)
        _assert_type(cfg, "policy_file", str)
        _assert_type(cfg, "db_model", dict)
        db_model = cfg["db_model"]
        _assert_type(db_model, "version", int)
        _assert_type(db_model, "db_path", str)

def _ld_cfg(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

def _init_svr(target, name: str, server_cfg: dict, server_map: dict):
    # Call 'setup' function of the target module with the server configuration and server map
    # Paramters:
    #   - namespace
    #   - port
    #   - domain
    #   - allow_ip_access
    #   - allow_external_access
    #   - policy_file
    #   - server_map
    #   - db_model
    target.setup(
        namespace=server_cfg["namespace"],
        port=server_map[name]["port"],
        domain=server_map[name]["url"],
        allow_ip_access=server_cfg["allow_ip_access"],
        allow_external_access=server_cfg["allow_external_access"],
        policy_file=server_cfg["policy_file"],
        server_map=server_map,
        db_model=server_cfg["db_model"]
    )

def main():

    # Load and validate configuration
    config = _ld_cfg("server-config.json")

    # Check configuration integrity
    _chk_cfg_integrity(config)

    # Add osext.libaqnetutil to import path for server modules
    sys.path.append(os.path.join(os.path.dirname(__file__), "osext", "libaqnetutil"))

    # Launch servers in separate threads
    active_servers = config.get("ActiveServers", [])
    server_map = config.get("ServerMap", {})
    threads = []
    for active_id in active_servers:

        # Import osext.libaqnetutil.Server_{active_id}
        module_name = f"Server_{active_id}"
        try:
            module = importlib.import_module(module_name)
            t = threading.Thread(target=_init_svr, args=(module, active_id, config.get(active_id), server_map))
            t.start()
            threads.append(t)
        except ModuleNotFoundError:
            print(f"Warning: No module found for active server '{active_id}' (expected module name: '{module_name}')")


if __name__ == "__main__":
    main()
