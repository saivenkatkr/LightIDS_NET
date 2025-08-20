import time, signal
from scapy.all import sniff

STOP = False
def _signal_handler(sig, frame):
    global STOP
    STOP = True

def run_sniffer(iface, process_packet, count=0, exit_after=0):
    global STOP
    STOP = False
    start = time.time()
    try:
        signal.signal(signal.SIGINT, _signal_handler)
    except Exception:
        pass

    def stop_filter(_pkt):
        if exit_after and (time.time() - start) >= exit_after:
            return True
        if STOP:
            return True
        return False

    iface_arg = iface if iface and iface != 'AUTO' else None
    print(f"[*] Sniffing on: {iface_arg or 'AUTO'} | limit: {'∞' if count<=0 else count} pkts | time: {'∞' if exit_after<=0 else exit_after}s")
    try:
        sniff(iface=iface_arg, prn=process_packet, store=False, count=(count if count>0 else 0), stop_filter=stop_filter)
    except OSError as e:
        print(f"[ERROR] Could not open interface '{iface_arg}': {e}")
        print("Tip: run 'python -m src.main --list-ifaces' and use an exact adapter name.")
    except KeyboardInterrupt:
        pass
