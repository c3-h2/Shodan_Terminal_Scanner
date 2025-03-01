import shodan
import argparse
import socket
import json
from datetime import datetime
from textwrap import fill

def safe_get(data, keys, default="N/A"):
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return default
    return data

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Target resolution failed: {target}")

def shodan_scan(api_key, target_ip, threshold):
    api = shodan.Shodan(api_key)
    try:
        host = api.host(target_ip)
        if 'data' in host:
            host['data'] = host['data'][:threshold]
        return host
    except shodan.APIError as e:
        raise RuntimeError(f"Shodan error: {e}")

def print_shodan_style(results):
    # Header
    print(f"\n{'═'*55}")
    print(f" Shodan Scan Report: {results['ip_str']}")
    print(f"{'═'*55}")

    # Genel Bilgiler
    print(f"\n▌{'─'*20} Basic Information {'─'*20}▐")
    print(f"  {'IP Address':<15}│ {results['ip_str']}")
    print(f"  {'ASN':<15}│ {safe_get(results, ['asn'])}")
    print(f"  {'Organization':<15}│ {safe_get(results, ['org'])}")
    print(f"  {'Location':<15}│ {safe_get(results, ['city'])} / {safe_get(results, ['country_name'])}")
    print(f"  {'Coordinates':<15}│ {safe_get(results, ['location', 'latitude'])} , {safe_get(results, ['location', 'longitude'])}")
    print(f"  {'Last Update':<15}│ {datetime.strptime(results['last_update'], '%Y-%m-%dT%H:%M:%S.%f').strftime('%d %b %Y %H:%M UTC')}")

    # Port ve Servisler
    print(f"\n▌{'─'*20} Open Ports ({len(results.get('data', []))}) {'─'*18}▐")
    for service in results.get('data', []):
        port = service['port']
        product = safe_get(service, ['product'])
        transport = safe_get(service, ['transport'], 'tcp').upper()
        
        print(f"\n┌──{'Port':<6}{port}/{transport}")
        print(f"│  {'Service':<10}│ {safe_get(service, ['_shodan', 'module'], 'unknown').upper()}")
        print(f"│  {'Product':<10}│ {product}")
        print(f"│  {'Protocol':<10}│ {safe_get(service, ['transport'], 'tcp').upper()}")
        print(f"│  {'Status':<10}│ {safe_get(service, ['http', 'status'])}")
        
        # SSL Bilgileri
        if 'ssl' in service:
            ssl = service['ssl']
            print(f"│\n│  {'SSL Cipher':<10}│ {safe_get(ssl, ['cipher', 'name'])}")
            print(f"│  {'Certificate':<10}│ {safe_get(ssl, ['cert', 'issuer', 'O'])}")
            print(f"│  {'Expiry':<10}│ {datetime.strptime(ssl['cert']['expires'], '%Y%m%d%H%M%SZ').strftime('%d %b %Y')}")

        # Banner
        if 'data' in service:
            print(f"│\n│  {'Banner':<10}◤")
            for line in service['data'].split('\n')[:3]:
                print(f"│  {fill(line.strip(), width=70, subsequent_indent='│  ')}")

        # Zafiyetler
        vulns = safe_get(service, ['opts', 'vulns'], [])
        if vulns:
            print(f"│\n│  {'CVEs':<10}◤")
            for cve in vulns:
                print(f"│   • {cve}")

        print(f"└{'─'*70}")

    # Genel Vulnerabilities
    all_vulns = []
    for service in results.get('data', []):
        all_vulns.extend(safe_get(service, ['opts', 'vulns'], []))
    
    if all_vulns:
        print(f"\n▌{'─'*20} Total Vulnerabilities ({len(all_vulns)}) {'─'*15}▐")
        for cve in list(set(all_vulns)):  # Unique CVEs
            print(f"  • {cve}")

def main():
    parser = argparse.ArgumentParser(description='Shodan Terminal Scanner')
    parser.add_argument('target', help='Target IP or domain')
    parser.add_argument('--api-key', required=True, help='Shodan API key')
    parser.add_argument('--threshold', type=int, default=10, 
                       help='Max results per service (default: 10)')
    parser.add_argument('--output', default='shodan_scan.json', 
                       help='Output file (default: shodan_scan.json)')
    
    args = parser.parse_args()
    
    try:
        target_ip = resolve_target(args.target)
        results = shodan_scan(args.api_key, target_ip, args.threshold)
        print_shodan_style(results)
        
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Results saved to {args.output}")
        
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
