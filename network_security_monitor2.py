#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Security Monitor - Attack-Resistant Version 2.0
Detects active connections, potential attacks, country stats + nftables drops.
Author: Network Security Expert (Grok)
"""

import subprocess
import json
import sys
from collections import defaultdict
import urllib.request
from datetime import datetime
import os

# ====================== CONFIGURATION ======================
THRESHOLD_CONNECTIONS = 100
THRESHOLD_UNIQUE_IPS   = 30
MAX_NEW_API_LOOKUPS    = 40                    # Safety limit during flood
CACHE_FILE             = "/tmp/ip_country_cache.json"
IMPORTANT_PORTS        = None                  # Example: [22, 80, 443, 8080] or None for all
# ===========================================================

# Load persistent cache
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except:
        pass

ip_cache = load_cache()
new_lookups_count = 0

def get_country(ip):
    global new_lookups_count
    if ip in ip_cache:
        return ip_cache[ip]

    # Local/private IPs
    if (ip.startswith(('127.', '10.', '172.16.', '192.168.', '::1', 'fe80:')) or ip == '0.0.0.0'):
        country = "Local / Private"
    elif new_lookups_count >= MAX_NEW_API_LOOKUPS:
        country = "Lookup limit reached"
    else:
        try:
            with urllib.request.urlopen(f"https://ipapi.co/{ip}/json/", timeout=3) as response:
                data = json.loads(response.read().decode('utf-8'))
                country = data.get('country_name', 'Unknown')
            new_lookups_count += 1
        except:
            country = 'Unknown'
    
    ip_cache[ip] = country
    return country

def get_nft_drops():
    """Simple nftables drop counter (if you have counters in your ruleset)"""
    try:
        output = subprocess.check_output("nft list ruleset 2>/dev/null | grep -o 'counter packets [0-9]*' | awk '{sum += $3} END {print sum}'", 
                                        shell=True).decode().strip()
        return int(output) if output else 0
    except:
        return None

def main():
    print("🚀 Starting Network Security Monitor v2.0 (Attack-Resistant) - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 80)

    # Use fast ss command
    try:
        cmd = "ss -Htn 2>/dev/null | awk '{print $1 \"|\" $2 \"|\" $4 \"|\" $5}'"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
    except Exception:
        print("❌ Error: ss command not available.")
        sys.exit(1)

    port_conn_count = defaultdict(int)
    port_unique_ips = defaultdict(set)
    country_to_ips  = defaultdict(set)
    total_connections = 0

    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            _, state, local, peer = line.split('|')
            if 'LISTEN' in state:
                continue

            # Extract local port
            local_port = local.split(']:')[-1] if ']:' in local else local.split(':')[-1]
            
            # Filter ports if configured
            if IMPORTANT_PORTS and int(local_port) not in IMPORTANT_PORTS:
                continue

            # Extract remote IP
            remote_ip = peer.split('[')[1].split(']')[0] if '[' in peer else peer.split(':')[0]
            if remote_ip in ('*', '0.0.0.0', '::'):
                continue

            port_conn_count[local_port] += 1
            port_unique_ips[local_port].add(remote_ip)
            total_connections += 1

            country = get_country(remote_ip)
            if country not in ('Unknown', 'Lookup limit reached'):
                country_to_ips[country].add(remote_ip)

        except:
            continue

    # Save updated cache
    save_cache(ip_cache)

    # ====================== REPORT ======================
    print(f"📊 Total active connections: {total_connections}")
    print(f"🔍 New API lookups this run: {new_lookups_count}/{MAX_NEW_API_LOOKUPS}\n")

    print("🔌 Connections per port:")
    print("-" * 70)
    under_attack_ports = []

    for port in sorted(port_conn_count.keys(), key=lambda x: int(x) if x.isdigit() else 99999):
        conn_count = port_conn_count[port]
        unique_count = len(port_unique_ips[port])
        
        status = "🟢 Normal"
        if conn_count >= THRESHOLD_CONNECTIONS or unique_count >= THRESHOLD_UNIQUE_IPS:
            status = "🚨 **UNDER ATTACK**"
            under_attack_ports.append((port, conn_count, unique_count))
        
        print(f"Port {port:<6} | {conn_count:4} connections | {unique_count:3} unique IPs | {status}")

    print("\n🌍 Connected IPs by Country (sorted):")
    print("-" * 70)
    for country, ips in sorted(country_to_ips.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{country:<25} → {len(ips):3} IPs")

    # nftables drops
    drops = get_nft_drops()
    if drops is not None:
        print(f"\n🛡️  nftables total dropped packets (since last counter reset): {drops:,}")

    if under_attack_ports:
        print("\n" + "!"*80)
        print("⚠️  WARNING! Ports under heavy attack:")
        print("!"*80)
        for port, conn, unique in under_attack_ports:
            print(f"🚨 Port {port} → {conn} connections | {unique} unique IPs")
        print("💡 Immediate action: Check nftables / Fail2Ban / Cloudflare")
    else:
        print("\n✅ No ports currently under severe attack.")

    print("\n" + "=" * 80)
    print("v2.0 executed successfully. Cache saved.")

if __name__ == "__main__":
    main()
