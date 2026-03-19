import socket

PORT_SERVICE_MAP = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

def grab_banner(ip, port):
    """
    Connects to an open port and reads the first message
    the service sends back — called a banner.

    ip: target IP address string
    port: port number to grab banner from
    returns: the banner string or None if it fails
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        if port in [80, 8080, 443, 8443]:
            sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")

        banner = sock.recv(1024)
        sock.close()

        return banner.decode("utf-8", errors="ignore").strip()

    except:
        return None

def fingerprint_services(ip, open_ports):
    """
    Loops through every open port and tries to identify
    what service and version is running behind it.

    ip: target IP address string
    open_ports: list of open port numbers from the port scanner
    returns: a dictionary of port numbers and their service details
    """

    print(f"[*] Fingerprinting services on {ip}...")

    results = {}

    for port in open_ports:

        service_name = PORT_SERVICE_MAP.get(port, "Unknown")
        banner = grab_banner(ip, port)

        results[port] = {
            "service": service_name,
            "banner": banner if banner else "No banner retrieved"
        }

        if banner:
            print(f"  [+] Port {port} ({service_name}): {banner[:60]}")
        else:
            print(f"  [+] Port {port} ({service_name}): No banner retrieved")

    print(f"\n[*] Service fingerprinting complete on {ip}")
    print(f"[*] Fingerprinted {len(results)} service(s)\n")

    return results