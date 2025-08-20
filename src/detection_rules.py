import time
from collections import defaultdict, deque
from .utils import get_ips, get_ports, get_dns_query, is_icmp_echo

def _prune_deque(dq, now, window):
    while dq and (now - dq[0]) > window:
        dq.popleft()

def build_detector(cfg, state, logger):
    TW = cfg.get('TIME_WINDOW', 60)
    TH = cfg.get('THRESHOLDS', {})
    WL_IPS = set(cfg.get('WHITELIST_IPS', []))
    WL_DOMS = tuple(cfg.get('WHITELIST_DOMAIN_SUBSTR', []))

    portscan = defaultdict(lambda: deque())
    flood = defaultdict(lambda: deque())
    icmp = defaultdict(lambda: deque())
    dns = defaultdict(lambda: deque())

    def is_whitelisted_ip(ip):
        if not ip:
            return True
        return ip in WL_IPS or ip.startswith('169.254.')

    def is_whitelisted_domain(q):
        if not q:
            return False
        qq = q.lower()
        return any(s in qq for s in WL_DOMS)

    def analyze(pkt):
        now = time.time()
        state.inc_packets()

        src, dst = get_ips(pkt)
        if not src and not dst:
            return

        # PORTSCAN: unique destination ports per src within TW
        sp, dp = get_ports(pkt)
        if dp and not (is_whitelisted_ip(src) or is_whitelisted_ip(dst)):
            dq = portscan[src]
            dq.append((now, dp))
            # prune by time window
            while dq and (now - dq[0][0]) > TW:
                dq.popleft()
            unique_ports = {p for _, p in dq}
            if len(unique_ports) >= TH.get('PORTSCAN_UNIQUE_PORTS', 50):
                logger.log('PortScan', src_ip=src, dst_ip=dst, unique_ports=len(unique_ports))
                state.count_alert('PortScan', src)
                dq.clear()

        # FLOOD/BRUTE: many packets to same dst/port
        key = (src, dst, dp)
        fq = flood[key]
        fq.append(now)
        _prune_deque(fq, now, TH.get('FLOOD_WINDOW_SEC', 5))
        if len(fq) >= TH.get('FLOOD_MIN_PACKETS', 40) and not (is_whitelisted_ip(src) or is_whitelisted_ip(dst)):
            logger.log('Flood/Brute', src_ip=src, dst_ip=dst, dst_port=dp, count=len(fq))
            state.count_alert('Flood/Brute', src)
            fq.clear()

        # TCP flags (NULL, FIN, XMAS)
        try:
            from scapy.layers.inet import TCP
            if pkt.haslayer(TCP):
                flags = getattr(pkt[TCP], 'flags', 0)
                if flags == 0:
                    logger.log('SuspiciousTCPFlags-NULL', src_ip=src, dst_ip=dst)
                    state.count_alert('SuspiciousTCPFlags-NULL', src)
                if flags == 0x01:
                    logger.log('SuspiciousTCPFlags-FIN', src_ip=src, dst_ip=dst)
                    state.count_alert('SuspiciousTCPFlags-FIN', src)
                if flags & 0x29 == 0x29:
                    logger.log('SuspiciousTCPFlags-XMAS', src_ip=src, dst_ip=dst)
                    state.count_alert('SuspiciousTCPFlags-XMAS', src)
        except Exception:
            pass

        # ICMP flood (echo request bursts)
        if is_icmp_echo(pkt) and not (is_whitelisted_ip(src) or is_whitelisted_ip(dst)):
            iq = icmp[src]
            iq.append(now)
            _prune_deque(iq, now, TW)
            if len(iq) >= TH.get('ICMP_FLOOD_COUNT', 100):
                logger.log('ICMPFlood', src_ip=src, dst_ip=dst, count=len(iq))
                state.count_alert('ICMPFlood', src)
                iq.clear()

        # DNS heuristic
        q = get_dns_query(pkt)
        if q and not is_whitelisted_domain(q) and not (is_whitelisted_ip(src) or is_whitelisted_ip(dst)):
            dq = dns[src]
            dq.append(now)
            _prune_deque(dq, now, TW)
            # consider long labels as suspicious
            long_label = any(len(part) >= 20 for part in q.split('.'))
            if len(dq) >= TH.get('DNS_QUERY_COUNT', 50) and long_label:
                logger.log('DNSTunnelingHeuristic', src_ip=src, dst_ip=dst, count=len(dq), sample=q[:80])
                state.count_alert('DNSTunnelingHeuristic', src)
                dq.clear()

    return analyze
