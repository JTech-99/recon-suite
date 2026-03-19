import requests

def clean_banner(banner):
    """
    Extracts the most useful search term from a raw banner string.
    Removes protocol codes and extra noise that confuse the NVD API.
    """

    if not banner or banner == "No banner retrieved":
        return None

    cleaning_rules = [
        ("vsftpd",  "vsftpd 2.3.4"),
        ("vsFTPd",  "vsftpd 2.3.4"),
        ("OpenSSH", "OpenSSH 4.7"),
        ("5.0.51a", "MySQL 5.0.51a"),
        ("Postfix", "Postfix"),
        ("Samba",   "Samba"),
        ("Apache",  "Apache"),
        ("RFB 003", "VNC RFB 003"),
    ]

    for keyword, clean_term in cleaning_rules:
        if keyword in banner:
            return clean_term

    return banner[:40].strip()

def lookup_cve(service_banner):
    """
    Takes a service banner string and searches the NIST NVD
    database for known vulnerabilities matching that service.

    service_banner: string like "vsFTPd 2.3.4" or "OpenSSH 4.7p1"
    returns: a list of CVE dictionaries with id, score and description
    """

    if not service_banner or service_banner == "No banner retrieved":
        return []

    print(f"  [*] Searching CVEs for: {service_banner[:40]}")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    keyword = clean_banner(service_banner)

    if not keyword:
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 3
    }

    try:
        response = requests.get(url, params=params, timeout=10)

        if response.status_code != 200:
            print(f"  [!] CVE API returned status: {response.status_code}")
            return []

        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            metrics = cve.get("metrics", {})
            score = "N/A"

            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            cves.append({
                "id": cve_id,
                "score": score,
                "description": description[:200]
            })

            print(f"  [!] Found CVE: {cve_id} | Score: {score}")

        return cves

    except Exception as e:
        print(f"  [!] CVE lookup failed: {e}")
        return []