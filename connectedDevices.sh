
# --- Paths ---
DB_DIR="/usr/share/GeoIP"
DB_COUNTRY="$DB_DIR/GeoLite2-Country.mmdb"
SERVER_IPS=$(hostname -I | tr ' ' '\n')

# 1. Check for required dependencies
if ! command -v mmdblookup &> /dev/null || ! command -v conntrack &> /dev/null; then
    echo -e "\e[1;33m[!] Installing dependencies (mmdb-bin, conntrack)...\e[0m"
    sudo apt update && sudo apt install -y mmdb-bin conntrack wget
fi

# 2. Smart database update (If not exists or older than 7 days)
update_db() {
    sudo mkdir -p "$DB_DIR"
    if [[ ! -f "$DB_COUNTRY" || $(find "$DB_COUNTRY" -mtime +7 -print) ]]; then
        echo -e "\e[1;35m[!] Updating GeoIP Database...\e[0m"
        sudo wget -q "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" -O "$DB_COUNTRY"
        sudo chmod 644 "$DB_COUNTRY"
    fi
}
update_db

echo -e "\e[1;34m[+] Analyzing Unique Inbound Users (Aggregated)...\e[0m"

# 3. Extract unique inbound IP addresses
unique_ips=$(sudo conntrack -L 2>/dev/null | awk -v s_ips="$SERVER_IPS" '
    BEGIN { split(s_ips, arr, "\n"); for (i in arr) hosts[arr[i]]=1 }
    {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^dst=/) {
                dst_ip = substr($i, 5)
                if (dst_ip in hosts) {
                    for (j=1; j<=NF; j++) {
                        if ($j ~ /^src=/) {
                            src_ip = substr($j, 5)
                            if (src_ip != "127.0.0.1" && src_ip != "::1") print src_ip
                            break
                        }
                    }
                    break
                }
            }
        }
    }' | sort -u)

# 4. Processing and Grouping
declare -A country_stats
total_users=0

while read -r ip; do
    [[ -z "$ip" ]] && continue
    country=$(mmdblookup --file "$DB_COUNTRY" --ip "$ip" country names en 2>/dev/null | grep -oP '(?<=").*(?=")' | head -1)
    country=${country:-"Unknown"}
    ((country_stats["$country"]++))
    ((total_users++))
done <<< "$unique_ips"

# 5. Display output with requested color coding
echo "------------------------------------------------------------"
echo -e "\e[1;33mUsers | Country\e[0m"
echo "------------------------------------------------------------"

# Sort by user count (descending)
for country in "${!country_stats[@]}"; do
    echo "${country_stats["$country"]} $country"
done | sort -rn | while read -r count country; do
    
    case "$country" in
        "Iran")          COLOR="\e[1;32m" ;; # Green
        "China")         COLOR="\e[1;33m" ;; # Yellow
        "Russia")        COLOR="\e[1;37m" ;; # White
        "United States") COLOR="\e[1;34m" ;; # Blue
        *)               COLOR="\e[1;31m" ;; # Red (Others)
    esac
    
    echo -e "${COLOR}$(printf "%-5s" "$count") | $country\e[0m"
done

echo "------------------------------------------------------------"
echo -e "\e[1;36m[#] Total Unique Active Users: $total_users\e[0m"
