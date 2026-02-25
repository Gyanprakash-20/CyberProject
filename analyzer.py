from scapy.all import rdpcap, DNS, IP, ICMP, TCP, ARP
from collections import Counter, defaultdict
from getmac import get_mac_address  # type: ignore

# Thresholds
DDoS_THRESHOLD = 100
MAX_MTU = 1500
SYN_FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 5
ICMP_THRESHOLD = 10


def calculate_mdp(rule_violations):
    """Calculate Malicious Device Probability as a percentage."""
    return round((sum(rule_violations) * 100) / 8, 2)


def analyze(pcap_path: str) -> list[dict]:
    """
    Analyze a PCAP file and return per-IP MDP scores.

    Returns a list of dicts:
    [
        {
            "ip": str,
            "mac": str,
            "rules": [int, int, int, int, int, int, int, int],  # 0 or 1 for rules 1-8
            "mdp": float  # 0.0 - 100.0
        },
        ...
    ]
    """
    packets = rdpcap(pcap_path)

    ip_count = Counter()
    syn_count = defaultdict(int)
    connection_attempts = defaultdict(set)
    unsolicited_arp = []
    large_dns_responses = []
    icmp_requests = Counter()
    non_standard_port_ips = set()
    packet_sizes = defaultdict(int)
    ip_rules = defaultdict(lambda: [0] * 8)

    # Rule 1: Non-standard TCP ports
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            if tcp_layer.dport not in [80, 443, 22]:
                non_standard_port_ips.add(ip_layer.src)

    # Rule 2: High traffic volume (DDoS detection)
    for packet in packets:
        if packet.haslayer(IP):
            ip_count[packet[IP].src] += 1

    # Rule 3: Large packets (exceeds MTU)
    for packet in packets:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            size = len(packet)
            if size > packet_sizes[ip_layer.src]:
                packet_sizes[ip_layer.src] = size

    # Rule 4: Unsolicited ARP replies
    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            if packet[ARP].psrc != '0.0.0.0':
                unsolicited_arp.append(packet[ARP])

    # Rule 5: Unusually large DNS responses
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns_layer = packet[DNS]
            ip_layer = packet[IP]
            if dns_layer.ancount > 0:
                for i in range(dns_layer.ancount):
                    dns_answer = dns_layer.an[i]
                    if len(dns_answer) > 512:
                        large_dns_responses.append((ip_layer.src, len(dns_answer)))

    # Rule 6: Excessive ICMP Echo requests
    for packet in packets:
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            icmp_requests[packet[IP].src] += 1

    # Rule 7: TCP SYN Flood
    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:
            if packet.haslayer(IP):
                syn_count[packet[IP].src] += 1

    # Rule 8: Port Scanning
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            connection_attempts[packet[IP].src].add(packet[TCP].dport)

    # Collect all known IPs
    all_ips = set(ip_count.keys()) | set(non_standard_port_ips) | set(syn_count.keys()) | set(connection_attempts.keys())

    # Assign rule violations
    for ip in all_ips:
        ip_rules[ip][0] = 1 if ip in non_standard_port_ips else 0
        ip_rules[ip][1] = 1 if ip_count.get(ip, 0) > DDoS_THRESHOLD else 0
        ip_rules[ip][2] = 1 if packet_sizes.get(ip, 0) > MAX_MTU else 0
        ip_rules[ip][5] = 1 if icmp_requests.get(ip, 0) > ICMP_THRESHOLD else 0
        ip_rules[ip][6] = 1 if syn_count.get(ip, 0) > SYN_FLOOD_THRESHOLD else 0
        ip_rules[ip][7] = 1 if len(connection_attempts.get(ip, set())) > PORT_SCAN_THRESHOLD else 0

    for arp_packet in unsolicited_arp:
        ip_rules[arp_packet.psrc][3] = 1

    for ip, _ in large_dns_responses:
        ip_rules[ip][4] = 1

    # Build results
    results = []
    for ip, rules in ip_rules.items():
        try:
            mac = get_mac_address(ip=ip) or 'Unknown'
        except Exception:
            mac = 'Unknown'

        results.append({
            "ip": ip,
            "mac": mac,
            "rules": rules[:8],
            "mdp": calculate_mdp(rules)
        })

    # Sort by MDP descending (highest risk first)
    results.sort(key=lambda x: x["mdp"], reverse=True)
    return results
