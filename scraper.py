"""
Advanced Phishing Threat Intelligence Pipeline
Author: SOC Analyst Portfolio
Sources: URLhaus (abuse.ch) + OpenPhish
"""

import requests
import re
import json
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

# --- CONFIG ---
SOURCES = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text/",
    "openphish": "https://openphish.com/feed.txt",
}

OUTPUT_TXT_DOMAIN = "blocklist.txt"
OUTPUT_TXT_IP = "ip-blocklist.txt"
OUTPUT_JSON = "intel-feed.json"

WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "microsoft.com",
    "apple.com", "github.com", "abuse.ch", "openphish.com",
    "amazon.com", "cloudflare.com"
}
WHITELIST_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "127.0.0.1"}

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except:
        return False

def clean_host(host: str):
    if not host: return None
    host = host.lower().strip().strip('.')
    if len(host) < 4 or len(host) > 253: return None
    if host in WHITELIST_DOMAINS: return None
    if '.' not in host: return None
    # block single label and invalid chars
    if not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', host):
        return None
    return host

def fetch_feeds():
    domains, ips = set(), set()
    for name, url in SOURCES.items():
        try:
            print(f"[+] Fetching {name} from {url}")
            r = requests.get(url, timeout=30, headers={"User-Agent": "SOC-Intel-Pipeline/2.0"})
            r.raise_for_status()
            count = 0
            for line in r.text.splitlines():
                if not line or line.startswith('#'):
                    continue
                try:
                    parsed = urlparse(line if '://' in line else f'http://{line}')
                    host = parsed.hostname
                    if not host:
                        continue
                    if is_ip(host):
                        if host not in WHITELIST_IPS:
                            ips.add(host)
                            count += 1
                    else:
                        ch = clean_host(host)
                        if ch:
                            domains.add(ch)
                            count += 1
                except:
                    continue
            print(f"[{name}] Parsed {count} IOCs")
        except Exception as e:
            print(f"[{name}] FAILED: {e}")
    return sorted(domains), sorted(ips)

def main():
    domains, ips = fetch_feeds()
    # Limit for efficiency
    domains = domains[:1000]
    ips = ips[:500]
    now = datetime.now(timezone.utc).isoformat()

    # 1. Domain blocklist (SIEM/DNS)
    with open(OUTPUT_TXT_DOMAIN, 'w') as f:
        f.write(f"# Advanced Threat Intel Feed\n")
        f.write(f"# Generated: {now} UTC\n")
        f.write(f"# Sources: {', '.join(SOURCES.keys())}\n")
        f.write(f"# Stats: Domains={len(domains)} | IPs={len(ips)}\n")
        f.write(f"# Whitelist Applied: Yes\n")
        f.write(f"#----------------------------------------\n")
        for d in domains:
            f.write(d + "\n")

    # 2. IP blocklist (Firewall)
    with open(OUTPUT_TXT_IP, 'w') as f:
        f.write(f"# IP Blocklist\n# Generated: {now} UTC\n#----------------------------------------\n")
        for ip in ips:
            f.write(ip + "\n")

    # 3. JSON Feed (SOAR/API)
    intel = {
        "feed_name": "advanced-phishing-intel",
        "version": "2.0",
        "generated": now,
        "sources": list(SOURCES.keys()),
        "stats": {"domains": len(domains), "ips": len(ips), "total": len(domains)+len(ips)},
        "whitelist_applied": True,
        "iocs": [{"type": "domain", "value": d, "tags": ["phishing"]} for d in domains[:200]] +
                [{"type": "ip", "value": i, "tags": ["malware"]} for i in ips[:100]]
    }
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(intel, f, indent=2)

    print(f"\n[+] SUCCESS: {len(domains)} domains + {len(ips)} IPs saved.")
    print(f"    -> {OUTPUT_TXT_DOMAIN}, {OUTPUT_TXT_IP}, {OUTPUT_JSON}")

if __name__ == "__main__":
    main()