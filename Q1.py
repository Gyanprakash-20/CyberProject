import subprocess
import re
import csv
def scan_ip_mac_and_ports_status(network_range, ports=[22, 80, 81, 135, 139, 445, 1433]):
    try:
        # Convert ports list to a comma-separated string
        ports_str = ",".join(map(str, ports))
        # Run the nmap command to scan IP, MAC, port statuses, and service names
        result = subprocess.run(
            ["sudo", "nmap", "-p", ports_str, "-sV", network_range],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            print("Error running nmap:", result.stderr)
            return []
        # Regex patterns
        ip_regex = r"Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
        mac_regex = r"MAC Address: ([0-9A-Fa-f:]+)"
        port_status_service_regex = r"(\d+)/tcp\s+(\w+)\s+([a-zA-Z0-9\-]+)"
        devices = []
        ip_address = None
        mac_address = None
        port_status = {str(port): {"status": "", "service": "Unknown"} for port in
                       ports}  # Initialize with "not found" and service unknown
        # Parse the nmap output
        for line in result.stdout.splitlines():
            ip_match = re.search(ip_regex, line)
            mac_match = re.search(mac_regex, line)
            port_status_service_match = re.search(port_status_service_regex, line)
            if ip_match:
                # Save current device directly as each IP is unique
                ip_address = ip_match.group(1)
            if mac_match:
                mac_address = mac_match.group(1)
            if port_status_service_match:
                port = port_status_service_match.group(1)
                status = port_status_service_match.group(2)
                service = port_status_service_match.group(3)
                if port in port_status:  # Only consider specified ports
                    port_status[port] = {"status": status, "service": service}
            # Store the device when both IP and MAC address are found
            if ip_address and mac_address:
                devices.append({
                    "IP": ip_address,
                    "MAC": mac_address if mac_address else "Unknown",
                    **port_status,
                })
                # Reset for the next device
                ip_address = None
                mac_address = None
                port_status = {str(port): {"status": "not found", "service": "Unknown"} for port in ports}
        return devices
    except Exception as e:
        print("An error occurred:", str(e))
        return []
def save_to_csv(devices, filename='scan_results.csv'):
    if devices:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)
        print(f"Scan results saved to {filename}")
    else:
        print("No devices to save.")
# Example usage
network = "172.17.156.59/24"  # Replace with your network range
ports = [22, 80, 81, 135, 139, 445, 1433]  # List of ports to scan
devices = scan_ip_mac_and_ports_status(network, ports)
if devices:
    print("Discovered devices with port status and services:")
    for device in devices:
        print(device)
    # Save the results to a CSV file
    save_to_csv(devices, 'scan_results.csv')
else:
    print("No devices found.")
    print("Testing git change Vesion 3")