from modules.host_discovery import discover_hosts

results = discover_hosts("192.168.221.128/24")  # replace with your actual subnet

print("Live hosts found:")
for host in results:
    print(f"  {host}")