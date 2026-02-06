#!/bin/bash

# --- Settings ---
#Countries to be blocked
COUNTRIES=("bg" "cn" "ru" "az" "tw")
#Add or remove IP you want to be whitelisted 
WHITELIST_IPS=("123.456.xxx.xxx" "123.xxx.xxx.xxx")

TABLE="geo_block"
SET_V4="blocked_ipv4"
SET_V6="blocked_ipv6"
SET_WHITE="whitelist"
CHAIN="input_block"
TMP_DIR="/tmp/geoip_blocks"
NFT_CONF_FILE="/etc/nftables.d/geo_block.nft"
MAX_AGE=$((7 * 24 * 3600))

# Create directories
mkdir -p /etc/nftables.d
mkdir -p "$TMP_DIR"

echo -e "\e[1;34m[+] Preparing Geo-Block rules...\e[0m"

V4_ALL="$TMP_DIR/all_v4.txt"
V6_ALL="$TMP_DIR/all_v6.txt"
> "$V4_ALL"
> "$V6_ALL"

# 1. Download and Clean Files
for COUNTRY in "${COUNTRIES[@]}"; do
    # IPv4
    V4_FILE="$TMP_DIR/${COUNTRY}-v4.zone"
    if [[ ! -f "$V4_FILE" ]] || [[ $(( $(date +%s) - $(stat -c %Y "$V4_FILE") )) -gt $MAX_AGE ]]; then
        curl -sL --fail -o "$V4_FILE" "https://www.ipdeny.com/ipblocks/data/aggregated/${COUNTRY}-aggregated.zone"
    fi
    if [[ -f "$V4_FILE" ]]; then
        echo "Processing IPv4 for ${COUNTRY^^}..."
        grep -v '^#' "$V4_FILE" | grep -v '^$' >> "$V4_ALL"
    fi

    # IPv6
    V6_FILE="$TMP_DIR/${COUNTRY}-v6.zone"
    if [[ ! -f "$V6_FILE" ]] || [[ $(( $(date +%s) - $(stat -c %Y "$V6_FILE") )) -gt $MAX_AGE ]]; then
        curl -sL --fail -o "$V6_FILE" "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/${COUNTRY}/ipv6-aggregated.txt"
    fi
    if [[ -f "$V6_FILE" ]]; then
        echo "Processing IPv6 for ${COUNTRY^^}..."
        grep -v '^#' "$V6_FILE" | grep -v '^$' >> "$V6_ALL"
    fi
done

# 2. Format lists and remove leading/trailing commas
V4_FINAL=$(sort -u "$V4_ALL" | tr '\n' ',' | sed 's/^,//;s/,$//;s/,,*/,/g')
V6_FINAL=$(sort -u "$V6_ALL" | tr '\n' ',' | sed 's/^,//;s/,$//;s/,,*/,/g')
WHITE_FINAL=$(echo "${WHITELIST_IPS[@]}" | sed 's/ /, /g')

# 3. Create the ruleset file
cat <<EOF > "$TMP_DIR/rules.nft"
table inet $TABLE {
    set $SET_WHITE {
        type ipv4_addr
        flags interval
        elements = { $WHITE_FINAL }
    }

    set $SET_V4 {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { $V4_FINAL }
    }

    set $SET_V6 {
        type ipv6_addr
        flags interval
        auto-merge
        elements = { $V6_FINAL }
    }

    chain $CHAIN {
        type filter hook input priority -150; policy accept;
        ip saddr @$SET_WHITE counter accept
        ip saddr @$SET_V4 counter drop
        ip6 saddr @$SET_V6 counter drop
        tcp dport { 6881-6999, 56312 } counter drop
        udp dport { 6881-6999, 56312 } counter drop
    }
}
EOF

# 4. Apply changes
nft delete table inet $TABLE 2>/dev/null

if nft -f "$TMP_DIR/rules.nft"; then
    cp "$TMP_DIR/rules.nft" "$NFT_CONF_FILE"
    echo -e "\e[1;32m[OK] Geo-Block rules applied successfully.\e[0m"
else
    echo -e "\e[1;31m[Error] Failed to load nftables rules.\e[0m"
fi

# 5. Cleanup
rm -rf "$TMP_DIR"
conntrack -F 2>/dev/null

echo "------------------------------------------------------------"
