import argparse
from modules.host_discovery import discover_hosts
from modules.port_scanner import scan_ports
from modules.service_fingerprint import fingerprint_services
from modules.cve_lookup import lookup_cve
from modules.report import save_report, print_summary

def main():
    parser = argparse.ArgumentParser(
        description="ReconSuite - Network Reconnaissance & Vulnerability Scanner"
    )

    parser.add_argument(
        "--subnet",
        help="Subnet to scan e.g. 192.168.221.0/24"
    )

    parser.add_argument(
        "--target",
        help="Single IP address to scan e.g. 192.168.221.129"
    )

    args = parser.parse_args()

    scan_results = {
        "hosts": {}
    }

    if not args.subnet and not args.target:
        print("\n[!] Error: You must provide a target to scan")
        print("[!] Examples:")
        print("      sudo python3 main.py --subnet 192.168.221.0/24")
        print("      sudo python3 main.py --target 192.168.221.129\n")
        return

    if args.subnet:
        print(f"\n[*] Mode: Subnet scan")
        print(f"[*] Target subnet: {args.subnet}\n")
        live_hosts = discover_hosts(args.subnet)

    elif args.target:
        print(f"\n[*] Mode: Single target scan")
        print(f"[*] Target: {args.target}\n")
        live_hosts = [args.target]

    if not live_hosts:
        print("[!] No live hosts found. Exiting.\n")
        return

    for ip in live_hosts:

        print(f"\n{'='*60}")
        print(f"  Scanning target: {ip}")
        print(f"{'='*60}\n")

        open_ports = scan_ports(ip)

        if not open_ports:
            print(f"  [!] No open ports found on {ip}\n")
            continue

        services = fingerprint_services(ip, open_ports)

        print(f"[*] Looking up CVEs for services on {ip}...")
        for port, info in services.items():

            cves = lookup_cve(info["banner"])
            services[port]["cves"] = cves

            if cves:
                for cve in cves:
                    if cve["score"] != "N/A" and float(cve["score"]) >= 7.0:
                        print(f"  [!!!] CRITICAL FINDING on port {port}: {cve['id']} Score: {cve['score']}")

        scan_results["hosts"][ip] = {
            "services": services
        }

    print_summary(scan_results)
    save_report(scan_results)

if __name__ == "__main__":
    main()