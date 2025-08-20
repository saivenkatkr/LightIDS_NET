from scapy.all import get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR

def list_interfaces():
    try:
        return get_if_list()
    except Exception:
        return []

def get_ips(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    return None, None

def get_ports(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    return None, None

def get_dns_query(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            return pkt[DNSQR].qname.decode(errors='ignore').strip('.')
        except Exception:
            return None
    return None

def is_icmp_echo(pkt):
    return pkt.haslayer(ICMP) and getattr(pkt[ICMP], 'type', None) == 8
