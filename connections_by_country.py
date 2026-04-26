#!/usr/bin/env python3
import sys
import re
import subprocess
from collections import defaultdict
import ipaddress

# ================== CONFIGURATION ==================
DB_PATH = "~/scripts/secmonitoring/GeoLite2-Country.mmdb"
# ===================================================

try:
    import geoip2.database
    reader = geoip2.database.Reader(DB_PATH)
except ImportError:
    print("Error: geoip2 module not found.")
    sys.exit(1)
except FileNotFoundError:
    print(f"Error: GeoIP database not found at {DB_PATH}")
    sys.exit(1)

def extract_ip(remote):
    if remote.startswith('['):
        ip = remote[1:].split(']:')[0]
    else:
        ip = remote.split(':')[0]
    # حذف پیشوند IPv4-mapped (::ffff:) برای خوانایی بهتر
    if ip.startswith("::ffff:"):
        return ip.replace("::ffff:", "")
    return ip

def get_remote_ips():
    ips = []
    # دریافت اتصالات ESTABLISHED و همچنین SYN-RECV برای دیدن حملات نیمه‌باز
    for flag in ['-tn', '-t6n']:
        try:
            result = subprocess.check_output(['ss', flag], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            continue

        for line in result.splitlines():
            if not any(s in line for s in ['ESTAB', 'SYN-RECV']):
                continue
            parts = re.split(r'\s+', line.strip())
            if len(parts) < 5: continue
            
            ip_str = extract_ip(parts[4])
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_loopback or ip_obj.is_private: continue
            except ValueError: continue
            
            ips.append(ip_str)
    return ips

def get_country(ip):
    try:
        response = reader.country(ip)
        return response.country.iso_code, response.country.name
    except Exception:
        return None, None

def main():
    ips = get_remote_ips()
    if not ips:
        print("Warning: No active external connections found.")
        return

    # country_data: code -> {'count': کل اتصالات, 'name': نام, 'ip_counts': {ip: تعداد}}
    country_data = defaultdict(lambda: {'count': 0, 'name': 'Unknown', 'ip_counts': defaultdict(int)})

    for ip in ips:
        code, name = get_country(ip)
        if code:
            country_data[code]['count'] += 1
            country_data[code]['name'] = name if name else "Unknown"
            country_data[code]['ip_counts'][ip] += 1

    if len(sys.argv) == 1:
        print("\nActive Connections by Country (sorted by count):")
        print("-" * 75)
        print(f"{'Code':<8} {'Country Name':<35} {'Connections':<15}")
        print("-" * 75)
        sorted_countries = sorted(country_data.items(), key=lambda x: x[1]['count'], reverse=True)
        for code, data in sorted_countries:
            print(f"{code:<8} {data['name']:<35} {data['count']:<15}")
    else:
        requested_code = sys.argv[1].upper().strip()
        if requested_code in country_data:
            data = country_data[requested_code]
            print(f"\nDetailed IPs from {data['name']} ({requested_code}):")
            print(f"{'IP Address':<40} {'Sessions':<10}")
            print("-" * 55)
            # مرتب‌سازی آی‌پی‌ها بر اساس تعداد اتصال (نزولی)
            sorted_ips = sorted(data['ip_counts'].items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_ips:
                print(f"{ip:<40} {count:<10}")
        else:
            print(f"No connections found for {requested_code}")

if __name__ == "__main__":
    main()
