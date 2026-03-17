from scapy.all import ARP, Ether, srp

def discover_hosts(subnet):
    """
    Sends ARP requests to every IP in the subnet.
    Collects every IP address that sends a reply back.

    subnet: a string like "192.168.1.0/24"
    returns: a list of live IP address strings
    """

    print(f"[*] Starting host discovery on subnet: {subnet}")
    print(f"[*] Sending ARP requests to all hosts...\n")

    arp_request = ARP(pdst=subnet)

    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ethernet_frame / arp_request

    answered, unanswered = srp(packet, timeout=2, verbose=False)

    live_hosts = []

    for sent_packet, received_packet in answered:
        ip_address = received_packet.psrc
        live_hosts.append(ip_address)
        print(f"  [+] Host is alive: {ip_address}")

    print(f"\n[*] Host discovery complete.")
    print(f"[*] Found {len(live_hosts)} live host(s) on {subnet}\n")

    return live_hosts