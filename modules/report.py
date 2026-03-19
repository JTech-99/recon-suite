import json
import os
from datetime import datetime

def save_report(scan_results, output_dir="reports"):
    """
    Takes all scan results and saves them as a structured JSON report.
    Creates a timestamped file in the reports/ folder.

    scan_results: dictionary containing all findings from every module
    output_dir: folder to save reports in (default is "reports")
    returns: the filename of the saved report
    """

    # Create the reports/ folder if it doesn't already exist
    # exist_ok=True means don't crash if the folder already exists
    os.makedirs(output_dir, exist_ok=True)

    # Generate a timestamp for the filename
    # strftime formats the current date and time as a readable string
    # Example output: "2026-03-19_15-30-00"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Build the full filename with the timestamp
    # Example: "reports/scan_2026-03-19_15-30-00.json"
    filename = f"{output_dir}/scan_{timestamp}.json"

    # Add the timestamp into the report data itself
    # So when you open the file you can see exactly when the scan ran
    scan_results["scan_time"] = timestamp

    # open() with "w" opens the file for writing
    # If the file doesn't exist it creates it automatically
    # If it does exist it overwrites it — but timestamps prevent that
    with open(filename, "w") as f:

        # json.dump() converts the Python dictionary into formatted JSON
        # indent=4 makes the JSON human readable with proper indentation
        json.dump(scan_results, f, indent=4)

    print(f"\n[*] Report saved successfully")
    print(f"[*] Location: {filename}\n")

    return filename


def print_summary(scan_results):
    """
    Prints a clean summary of all findings to the terminal.
    Shows hosts, open ports, services and CVE counts at a glance.
    """

    print("\n" + "="*60)
    print("  RECON SUITE — SCAN SUMMARY")
    print("="*60)

    # Loop through every host that was scanned
    hosts = scan_results.get("hosts", {})

    if not hosts:
        print("  No hosts found in scan results.")
        return

    for ip, host_data in hosts.items():
        print(f"\n  Target: {ip}")
        print(f"  {'-'*40}")

        services = host_data.get("services", {})

        if not services:
            print("  No open ports found.")
            continue

        # Loop through every open port found on this host
        for port, info in services.items():
            service_name = info.get("service", "Unknown")
            banner = info.get("banner", "No banner")
            cves = info.get("cves", [])

            # Print port and service info
            print(f"  Port {port} | {service_name}")
            print(f"  Banner : {banner[:50]}")

            # Print CVE summary if any were found
            if cves:
                cve_summary = ", ".join(
                    f"{cve['id']} (Score: {cve['score']})" for cve in cves
                )
                print(f"  CVEs   : {len(cves)} found — {cve_summary}")