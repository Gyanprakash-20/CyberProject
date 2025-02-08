from scapy.all import rdpcap, DNS, IP, ICMP, TCP, ARP
from collections import Counter
from collections import defaultdict
import csv
from getmac import get_mac_address # type: ignore
import time

# Load the PCAP file
packets = rdpcap('project.pcap')

# Inspect packets
for packet in packets:
    print(packet.summary())

# Define constants for thresholds
DDoS_THRESHOLD = 100  # Threshold for DDoS traffic
MAX_MTU = 1500        # Maximum Transmission Unit (MTU)
SYN_FLOOD_THRESHOLD = 100  # Number of SYN packets for flood detection
PORT_SCAN_THRESHOLD = 5    # Number of ports for port scan detection

# Initialize counters and data structures
ip_count = Counter()          # Counts IP traffic for Rule 2 (DDoS)
syn_count = defaultdict(int)  # Counts SYN packets for Rule 7 (SYN flood)
connection_attempts = defaultdict(set)  # Tracks source IPs and destination ports for Rule 8 (Port scan)
unsolicited_arp = []         # List to track unsolicited ARP replies for Rule 4
large_dns_responses = []     # List to track unusually large DNS responses for Rule 5
icmp_requests = Counter()    # Counts ICMP Echo Requests for Rule 6
non_standard_ports = set()   # Set for non-standard TCP/UDP ports (Rule 1)
packet_sizes = defaultdict(int)  # Tracks packet sizes for Rule 3 (Excessive traffic)
src_mac_addresses = {}       # Tracks MAC addresses for mapping to IPs
ip_rules = defaultdict(lambda: [0] * 8)  # Stores the violation status for each rule (0/1)

# Helper function to calculate MDP
def calculate_mdp(rule_violations):
    return (sum(rule_violations) * 100) / 8

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
# Rule 4: Unsolicited ARP replies.
################################################################        
for packet in packets:
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply (op=2)
        if packet[ARP].psrc != '0.0.0.0':  # Ignore broadcast ARP responses
            unsolicited_arp.append(packet[ARP])
            
            
################################################################
# Rule 5: Unusually large DNS responses.
################################################################  
for packet in packets:
    if packet.haslayer(DNS) and packet.haslayer(IP):
        dns_layer = packet[DNS]
        ip_layer = packet[IP]
        if dns_layer.ancount > 0:  # Check if there are answers in the DNS response
            for i in range(dns_layer.ancount):
                dns_answer = dns_layer.an[i]
                if len(dns_answer) > 512:  # DNS response size > 512 bytes is considered unusually large
                    large_dns_responses.append((ip_layer.src, len(dns_answer)))
         
################################################################
# Rule 6: Excessive ICMP Echo requests.
################################################################
for packet in packets:
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
        icmp_requests[packet[IP].src] += 1
                    
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
        

################################################################
## Assign Rule Violations (0 or 1) to IPs
################################################################        
for ip, count in ip_count.items():
    # Rule 2: DDoS - Excessive number of packets from the same IP
    ip_rules[ip][1] = 1 if count > DDoS_THRESHOLD else 0

for ip, size in packet_sizes.items():
    # Rule 3: Large packets
    ip_rules[ip][2] = 1 if size > MAX_MTU else 0

for arp_packet in unsolicited_arp:
    # Rule 4: Unsolicited ARP replies
    ip_rules[arp_packet.psrc][3] = 1

for ip, large_dns in large_dns_responses:
    # Rule 5: Unusually large DNS responses
    ip_rules[ip][4] = 1

for ip, count in icmp_requests.items():
    # Rule 6: Excessive ICMP Echo requests
    ip_rules[ip][5] = 1 if count > 10 else 0  # Threshold for excessive ICMP requests

for ip, count in syn_count.items():
    # Rule 7: TCP SYN flood
    ip_rules[ip][6] = 1 if count > SYN_FLOOD_THRESHOLD else 0

for ip, ports in connection_attempts.items():
    # Rule 8: Port scan
    ip_rules[ip][7] = 1 if len(ports) > PORT_SCAN_THRESHOLD else 0

# Create the CSV Report
with open('report.csv', 'w', newline='') as csvfile:
    fieldnames = ['IP Address', 'MAC Address', 'Rule 1', 'Rule 2', 'Rule 3', 'Rule 4', 'Rule 5', 'Rule 6', 'Rule 7', 'Rule 8', 'MDP(%)']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()

    # Write data for each IP
    for ip, rules in ip_rules.items():
        # Get the real MAC address for the IP
        mac_address = get_mac_address(ip=ip)  # Fetch MAC address using getmac
        if not mac_address:  # If MAC address could not be fetched, assign 'Unknown'
            mac_address = 'Unknown'

        # Calculate MDP
        mdp = calculate_mdp(rules)
        
        writer.writerow({
            'IP Address': ip,
            'MAC Address': mac_address,
            'Rule 1': 1 if ip in non_standard_ports else 0,
            'Rule 2': rules[1],
            'Rule 3': rules[2],
            'Rule 4': rules[3],
            'Rule 5': rules[4],
            'Rule 6': rules[5],
            'Rule 7': rules[6],
            'Rule 8': rules[7],
            'MDP(%)': mdp
        })

print("Report generated: report.csv")        
