import socket

def scan_ports(ip, ports=None):
    """
    Tries to connect to each port on the target IP.
    Records which ports are open.

    ip: a string like "192.168.221.1"
    ports: a list of port numbers to scan
    returns: a list of open port numbers
    """

    print(f"[*] Starting port scan on {ip}...")

    if ports is None:
        ports = [
            21,    # FTP - File Transfer Protocol
            22,    # SSH - Secure Shell (remote access)
            23,    # Telnet - old remote access, unencrypted
            25,    # SMTP - email sending
            53,    # DNS - domain name resolution
            80,    # HTTP - web server
            110,   # POP3 - email receiving
            135,   # RPC - Windows remote procedure call
            139,   # NetBIOS - Windows file sharing
            143,   # IMAP - email access
            443,   # HTTPS - secure web server
            445,   # SMB - Windows file sharing (EternalBlue lives here)
            993,   # IMAPS - secure email
            995,   # POP3S - secure email
            1723,  # PPTP - VPN protocol
            3306,  # MySQL - database
            3389,  # RDP - Windows remote desktop
            5900,  # VNC - remote desktop
            8080,  # HTTP-Alt - alternative web server
            8443,  # HTTPS-Alt - alternative secure web
        ]

    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))

        if result == 0:
            print(f"  [+] Port {port} is OPEN")
            open_ports.append(port)

        sock.close()

    print(f"\n[*] Port scan complete on {ip}")
    print(f"[*] Found {len(open_ports)} open port(s)\n")

    return open_ports