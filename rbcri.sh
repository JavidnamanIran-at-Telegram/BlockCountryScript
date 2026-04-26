#!/bin/bash
# ================================================
# Optimized Geo-IP Block with High-Speed Loading
# ================================================

set -euo pipefail

TABLE="geo_block"
SET_NAME="blocked_cn_in_ru"
CONFIG_FILE="/etc/nftables.d/geo-block.nft"
TEMP_DIR="/tmp/geo_block_$$"

mkdir -p "${TEMP_DIR}"
mkdir -p /etc/nftables.d

echo "🚀 Starting High-Speed Geo-Block..."

# 1. Download
COUNTRIES="bg cn in ru hk"
BASE_URL="https://www.ipdeny.com/ipblocks/data/aggregated"
for c in ${COUNTRIES}; do
    curl -s -f -m 30 -o "${TEMP_DIR}/${c}.zone" "${BASE_URL}/${c}-aggregated.zone" || echo "⚠️ Skip ${c}"
done

# 2. Create the base structure (Atomic)
# We use 'add' instead of 'flush' to avoid breaking existing iptables rules
cat > "${CONFIG_FILE}" << EOF
table inet ${TABLE} {
    set ${SET_NAME} {
        type ipv4_addr
        flags interval
        auto-merge
    }

    chain input {
        type filter hook input priority -10; policy accept;
        # High priority (-10) to catch traffic before other filters
        
        ct state established,related accept
        iif lo accept
        ip saddr @${SET_NAME} log prefix "[GEO-BLOCK] " drop
    }
}
EOF

# 3. FAST LOADING: Convert zones to nftables format and load
echo "🔄 Fast-loading IP ranges..."
# Pre-create the table and set
nft -f "${CONFIG_FILE}"

# Build a single batch file for all IPs to avoid the slow loop
BATCH_FILE="${TEMP_DIR}/final_batch.nft"
echo "add element inet ${TABLE} ${SET_NAME} {" > "${BATCH_FILE}"
cat "${TEMP_DIR}"/*.zone | sed 's/$/,/' >> "${BATCH_FILE}"
echo "}" >> "${BATCH_FILE}"

# Fix the last comma and load everything in ONE shot
sed -i '$ s/,$//' "${BATCH_FILE}"
nft -f "${BATCH_FILE}"

# 4. Save without breaking systemd
echo "💾 Applying rules..."
nft list table inet ${TABLE} > "${CONFIG_FILE}"
# Instead of restarting the whole service, we just ensure our config is loaded
echo "include \"${CONFIG_FILE}\"" >> /etc/nftables.conf || true

echo "🎉 Done! Block is active."
rm -rf "${TEMP_DIR}"
# Log the update results (Improved version)
# This counts the actual number of IP ranges loaded in the set
COUNT=$(nft list set inet geo_block blocked_cn_in_ru | grep -c "\." || echo "0")
echo "[$(date)] Geo-IP database updated. Total blocked: $COUNT ranges." >> /var/log/geo-update.log
