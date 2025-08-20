import argparse, os, json, time
from tabulate import tabulate
from .config import load_config
from .logger import AlertLogger
from .state import IDSState
from .utils import list_interfaces
from .detection_rules import build_detector
from .packet_sniffer import run_sniffer

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def print_config(cfg):
    print('\nEffective Config:')
    print(json.dumps(cfg, indent=2))
    print()

def print_ifaces():
    ifs = list_interfaces()
    if not ifs:
        print('No interfaces found (try running as Administrator/root).')
        return
    print('Available interfaces:')
    print(tabulate([[i] for i in ifs], headers=['Name'], tablefmt='github'))

def main():
    parser = argparse.ArgumentParser(description='LightIDS Pro — user-ready IDS')
    parser.add_argument('--iface', type=str, help='Interface to sniff (e.g., "Ethernet 8", "Wi-Fi")')
    parser.add_argument('--count', type=int, default=0, help='Number of packets to capture (0=∞)')
    parser.add_argument('--exit-after', type=int, default=0, help='Exit after N seconds (0=∞)')
    parser.add_argument('--log-format', choices=['jsonl','csv'], help='Override log format')
    parser.add_argument('--list-ifaces', action='store_true', help='List network interfaces and exit')
    parser.add_argument('--show-config', action='store_true', help='Show effective config and exit')
    parser.add_argument('--stats-every', type=int, default=0, help='Print running stats every N seconds (0=off)')
    args = parser.parse_args()

    cfg = load_config(PROJECT_ROOT)
    if args.log_format:
        cfg['LOG_FORMAT'] = args.log_format

    if args.show_config:
        print_config(cfg)
        return
    if args.list_ifaces:
        print_ifaces()
        return

    iface = args.iface or cfg.get('DEFAULT_IFACE')
    log_dir = cfg.get('LOG_DIR')
    log_format = cfg.get('LOG_FORMAT', 'jsonl')

    print('============================')
    print(' LightIDS Pro Starting')
    print(f' Interface: {iface}')
    print(f' Packet limit: {args.count if args.count>0 else "∞"}')
    print(f' Time limit: {args.exit_after if args.exit_after>0 else "∞"} sec')
    print(f' Log format: {log_format}')
    print(' Press Ctrl+C to stop')
    print('============================')

    logger = AlertLogger(log_dir, log_format)
    state = IDSState()
    analyzer = build_detector(cfg, state, logger)

    last_stats = time.time()
    def process(pkt):
        nonlocal last_stats
        analyzer(pkt)
        if args.stats_every and (time.time() - last_stats) >= args.stats_every:
            s = state.summary()
            print(f"[*] Stats — packets: {s['total_packets']} | alerts: {sum(s['alert_counts'].values())}")
            last_stats = time.time()

    start = time.time()
    run_sniffer(iface=iface, process_packet=process, count=args.count, exit_after=args.exit_after)

    # summary
    runtime = time.time() - start
    summary = state.summary()
    summary_obj = {'runtime_sec': round(runtime,2), **summary}
    # save
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(summary_obj, f, indent=2)

    print('\n============================')
    print(' LightIDS Pro stopped.')
    print(f" Runtime: {summary_obj['runtime_sec']} sec")
    print(f" Packets seen: {summary_obj['total_packets']}")
    if summary_obj['alert_counts']:
        print(' Alerts by rule:')
        for rule, c in summary_obj['alert_counts'].items():
            print(f'  - {rule}: {c}')
    else:
        print(' Alerts by rule: none')
    if summary_obj['top_talkers']:
        print(' Top talkers (src_ip,count):', summary_obj['top_talkers'])
    print(f" Summary saved to {os.path.join(log_dir, 'summary.json')}")
    print('============================\n')

if __name__ == '__main__':
    main()
