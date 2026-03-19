from modules.report import save_report, print_summary

# Simulate what a real scan would produce
# This mirrors exactly what main.py will generate
scan_results = {
    "hosts": {
        "192.168.221.129": {
            "services": {
                "21": {
                    "service": "FTP",
                    "banner": "220 (vsFTPd 2.3.4)",
                    "cves": [
                        {
                            "id": "CVE-2011-2523",
                            "score": 9.8,
                            "description": "vsftpd 2.3.4 contains a backdoor which opens a shell on port 6200"
                        }
                    ]
                },
                "22": {
                    "service": "SSH",
                    "banner": "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1",
                    "cves": [
                        {
                            "id": "CVE-2007-4752",
                            "score": 7.5,
                            "description": "OpenSSH before 4.7 allows privilege escalation"
                        }
                    ]
                },
                "3306": {
                    "service": "MySQL",
                    "banner": "5.0.51a-3ubuntu",
                    "cves": [
                        {
                            "id": "CVE-2007-6303",
                            "score": 3.5,
                            "description": "MySQL 5.0.51a allows privilege escalation through altered views"
                        }
                    ]
                }
            }
        }
    }
}

# Print the summary to terminal
print_summary(scan_results)

# Save the report to the reports/ folder
filename = save_report(scan_results)

print(f"Open your report at: {filename}")