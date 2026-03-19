from modules.port_scanner import scan_ports

# Metasploitable2 - our intentionally vulnerable target
TARGET_IP = "192.168.221.129"

result = scan_ports(TARGET_IP)

print("Open ports found:")
for port in result:
    print(f"  {port}")