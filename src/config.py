import json, os

DEFAULTS = {
    "DEFAULT_IFACE": "Ethernet 8",
    "LOG_DIR": "logs",
    "LOG_FORMAT": "jsonl",
    "TIME_WINDOW": 60,
    "THRESHOLDS": {
        "PORTSCAN_UNIQUE_PORTS": 50,
        "ICMP_FLOOD_COUNT": 100,
        "DNS_QUERY_COUNT": 50,
        "FLOOD_WINDOW_SEC": 5,
        "FLOOD_MIN_PACKETS": 40
    },
    "WHITELIST_IPS": ["127.0.0.1", "0.0.0.0", "255.255.255.255"],
    "WHITELIST_DOMAIN_SUBSTR": ["windowsupdate.com", "microsoft.com", "office.com", "bing.com"]
}

def load_config(project_root):
    path = os.path.join(project_root, "config.json")
    cfg = DEFAULTS.copy()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user = json.load(f)
            # shallow merge for top-level keys; merge nested dicts
            for k, v in user.items():
                if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except Exception:
            pass
    # make log dir absolute
    cfg["LOG_DIR"] = os.path.abspath(os.path.join(project_root, cfg.get("LOG_DIR", "logs")))
    return cfg
