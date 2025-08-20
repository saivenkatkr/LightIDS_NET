# Design notes - LightIDS Pro (User-Ready)

- Capture: scapy.sniff(...)
- Analyzer: rule-based detectors (portscan, flood, TCP flags, ICMP, DNS heuristic)
- Logger: JSONL (default) or CSV daily files with ISO UTC timestamps
- CLI: list-ifaces, show-config, iface, count, exit-after, stats-every, log-format
- Summary saved to logs/summary.json
