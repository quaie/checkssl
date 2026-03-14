#!/usr/bin/env python3
import argparse
import sys
import json
from pathlib import Path
from typing import List, Dict, Any
from sslyze import ScannableServer, ServerScanRequest
from sslyze.scanner.scanner import Scanner
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.errors import ConnectionToServerError
import socket

def resolve_ips(domain: str) -> str:
    try:
        ips = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        return ", ".join(ip[4][0] for ip in ips if ip[4][0])
    except:
        return ""

def scan_domain(domain: str) -> Dict[str, str]:
    target = f"{domain}:443"
    ips = resolve_ips(domain)
    
    try:
        tester = ServerConnectivityTester()
        server_info = tester.perform(target, sni=domain)
    except ConnectionToServerError:
        return {"domain": domain, "ip_addresses": ips, "tls_versions_supported": "", "list_of_ciphers": ""}
    
    scanner = Scanner()
    queue = [ServerScanRequest(server_info=server_info)]
    scanner.queue_scans(queue)
    
    for server_scan_result in scanner.get_results():
        tls_versions = ", ".join(p.name for p in server_scan_result.accepted_protocols)
        ciphers = ", ".join(c.name for c in server_scan_result.accepted_ciphers[:20])  # Top 20
        return {
            "domain": domain,
            "ip_addresses": ips,
            "tls_versions_supported": tls_versions,
            "list_of_ciphers": ciphers
        }
    
    return {"domain": domain, "ip_addresses": ips, "tls_versions_supported": "", "list_of_ciphers": ""}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", default="domains.txt", help="Domains file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    
    domains_file = Path(args.domains)
    if not domains_file.exists():
        print(f"Error: {args.domains} not found", file=sys.stderr)
        sys.exit(1)
    
    domains = [line.strip() for line in domains_file.read_text().splitlines() if line.strip()]
    results: List[Dict[str, str]] = []
    
    for domain in domains:
        print(f"Scanning {domain}...")
        result = scan_domain(domain)
        results.append(result)
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(json.dumps(r, indent=2))

if __name__ == "__main__":
    main()
