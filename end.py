from scapy.all import rdpcap, DNS, IP, ICMP, TCP, ARP
from collections import Counter
from collections import defaultdict
import time

# Load the PCAP file
packets = rdpcap('project. pcap')

# Inspect packets
for packet in packets:
    print(packet.summary())

non_standard_ports = set()

###############################################################
# Rule 1: Detecting Traffic on Non-Standard Ports
###############################################################
for packet in packets:
    if packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        if tcp_layer.dport not in [80, 443, 22]:  # Add standard destination ports
            non_standard_ports.add(tcp_layer.dport)

print("Non-standard ports detected:", non_standard_ports)

###############################################################
# Rule 2: High Traffic Volume (DDoS Detection)
###############################################################
ip_count = Counter()

# Count the IP packets
for packet in packets:
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        ip_count[ip_layer.src] += 1

###############################################################
# Rule 3: Detect IPs exceeding a threshold
###############################################################
threshold = 100  # Set your threshold
MAX_MTU = 1500  # Maximum Transmission Unit

ddos_candidates = [ip for ip, count in ip_count.items() if count > threshold]
print("Potential DDoS IPs:", ddos_candidates)

# Packet Size Analysis
for packet in packets:
    size = len(packet)
    if size > MAX_MTU:  # MTU size exceeds standard Ethernet
        print(f"Large packet detected: {size} bytes")

################################################################
# Rule 7: Detect TCP SYN Flood (High number of SYN packets)
################################################################
SYN_FLOOD_THRESHOLD = 100  # Number of SYN packets in a short period
syn_count = defaultdict(int)

for packet in packets:
    if packet.haslayer(TCP) and packet['TCP'].flags == 0x02:  # SYN flag set
        src_ip = packet[IP].src
        syn_count[src_ip] += 1

for ip, count in syn_count.items():
    if count > SYN_FLOOD_THRESHOLD:
        print(f"Potential TCP SYN Flood from {ip}, {count} SYN packets")

################################################################
# Rule 8: Port Scanning Detection
################################################################
PORT_SCAN_THRESHOLD = 5  # Connection attempts on multiple ports from the same IP
connection_attempts = defaultdict(set)  # Source IP -> Set of destination ports

for packet in packets:
    if packet.haslayer(TCP):
        tcp_layer = packet['TCP']
        if packet.haslayer(IP):
            connection_attempts[packet[IP].src].add(tcp_layer.dport)

for ip, ports in connection_attempts.items():
    if len(ports) > PORT_SCAN_THRESHOLD:
        print(f"Potential Port Scan detected from {ip} targeting {len(ports)} ports")
        print("NOting version2")
