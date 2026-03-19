from modules.cve_lookup import lookup_cve

# Test with the banners we grabbed from Metasploitable in Phase 4
banners = [
    "220 (vsFTPd 2.3.4)",
    "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1",
    "5.0.51a-3ubuntu"
]

for banner in banners:
    print(f"\n{'='*50}")
    print(f"Searching CVEs for: {banner}")
    print(f"{'='*50}")
    
    results = lookup_cve(banner)
    
    if results:
        for cve in results:
            print(f"\n  CVE ID: {cve['id']}")
            print(f"  Score:  {cve['score']}")
            print(f"  Info:   {cve['description']}")
    else:
        print("  No CVEs found")