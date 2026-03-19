from modules.service_fingerprint import fingerprint_services

# Our Metasploitable2 target
TARGET_IP = "192.168.221.129"

# The open ports we found in Phase 3
open_ports = [21, 22, 23, 25, 53, 80, 139, 445, 3306, 5900]

results = fingerprint_services(TARGET_IP, open_ports)

print("Service fingerprinting results:")
for port, info in results.items():
    print(f"  Port {port} | {info['service']} | {info['banner'][:60]}")