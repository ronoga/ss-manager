#!/bin/bash

CONFIG_DIR="/etc/shadowsocks-libev"
LOG_FILE="/var/log/ss-manager.log"
USED_PORTS_FILE="/etc/shadowsocks-libev/used-ports.txt"
TRAFFIC_DIR="/etc/shadowsocks-libev/traffic"

# رنگ‌ها
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RED='\033[1;31m'
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
NC='\033[0m' # No Color

function header() {
    echo -e "${CYAN}"
    echo "==============================================="
    echo "   🚀  ${BLUE}Shadowsocks-libev Manager${CYAN}  🚀   "
    echo "==============================================="
    echo -e "${NC}"
}

function log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

function check_installed() {
    if ! command -v ss-server &>/dev/null; then
        echo "not_installed"
    else
        echo "installed"
    fi
}

function install_ss() {
    echo -e "${YELLOW}📦 Installing required packages...${NC}"
    apt update
    apt install -y shadowsocks-libev curl jq vnstat bc iptables-persistent netfilter-persistent qrencode
    systemctl enable vnstat
    systemctl start vnstat
    echo -e "${GREEN}✔ Installation completed.${NC}"
    log "Installed shadowsocks-libev and dependencies"
    read -p "Press Enter to continue..."
}

function is_active() {
    systemctl is-active --quiet ss-server* && echo "active" || echo "inactive"
}

function start_service() {
    systemctl enable shadowsocks-libev
    systemctl restart shadowsocks-libev
    log "Service started or restarted"
}

function show_status() {
    local status=$(is_active)
    if [[ "$status" == "active" ]]; then
        echo -e "${GREEN}✅ Service status: $status${NC}"
    else
        echo -e "${RED}❌ Service status: $status${NC}"
    fi
}

function list_configs_as_links() {
    echo -e "${YELLOW}📄 Available Configurations:${NC}"
    files=$(ls $CONFIG_DIR/config-*.json 2>/dev/null)
    if [[ -z "$files" ]]; then
        echo -e "${RED}⚠️ No configs found.${NC}"
        read -p "Press Enter to return to menu..."
        return
    fi
    for file in $files; do
        server=$(jq -r '.server' "$file")
        port=$(jq -r '.server_port' "$file")
        password=$(jq -r '.password' "$file")
        method=$(jq -r '.method' "$file")
        if [[ "$server" =~ ":" ]]; then
            server_bracket="[$server]"
        else
            server_bracket="$server"
        fi
        encoded=$(echo -n "$method:$password@$server_bracket:$port" | base64 -w 0)
        link="ss://$encoded"
        name=$(basename "$file" .json)
        limit=$(jq -r '.limit_gb // empty' "$file")
        expire=$(jq -r '.expire_days // empty' "$file")
        created_date=$(jq -r '.created_date' "$file")
        limit_info=""
        if [[ -n "$limit" ]]; then
            limit_info+=" | 📊 Limit: ${limit} GB"
        fi
        if [[ -n "$expire" && "$expire" != "null" ]]; then
            now=$(date +%s)
            expire_sec=$((expire * 86400))
            first_connection=$(jq -r '.first_connection' "$file")
            if [[ "$first_connection" != "null" ]]; then
                elapsed_sec=$((now - first_connection))
                remaining_days=$(( (expire_sec - elapsed_sec) / 86400 ))
                if (( remaining_days < 0 )); then
                    limit_info+=" | ⏳ Expired"
                else
                    limit_info+=" | ⏳ ${remaining_days} days remaining"
                fi
            else
                limit_info+=" | ⏳ ${expire} days (Not started)"
            fi
        fi
        current_usage=$(get_port_traffic "$port")
        echo -e "${GREEN}🔗 ${name}:${NC}"
        echo -e "${PURPLE}$link${NC}"
        echo -e "${YELLOW}${limit_info}${NC}"
        echo -e "${CYAN}📊 Current Usage: ${current_usage}GB${NC}"
        if command -v qrencode &>/dev/null; then
            echo -e "${BLUE}QR Code:${NC}"
            echo "$link" | qrencode -s 2 -l L -t ANSIUTF8
        else
            echo -e "${YELLOW}⚠️ qrencode not installed. To show QR code: sudo apt install qrencode${NC}"
        fi
        echo "-----------------------------------------------"
    done
    read -p "Press Enter to return to menu..."
}

function get_public_ip() {
    # گرفتن آی‌پی عمومی به صورت مطمئن
    for url in "https://api.ipify.org" "https://ifconfig.co" "https://icanhazip.com"; do
        ip=$(curl -s "$url")
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done
    echo ""
}

function update_main_config_json() {
    # جمع‌آوری همه کانفیگ‌های فعال و ساخت آرایه
    configs=()
    files=$(ls $CONFIG_DIR/config-*.json 2>/dev/null)
    for file in $files; do
        configs+=("$(cat "$file")")
    done
    if [[ ${#configs[@]} -eq 0 ]]; then
        echo "[]" > $CONFIG_DIR/config.json
    else
        printf '%s\n' "[" > $CONFIG_DIR/config.json
        for i in "${!configs[@]}"; do
            printf '%s' "${configs[$i]}" >> $CONFIG_DIR/config.json
            [[ $i -lt $((${#configs[@]}-1)) ]] && printf ',\n' >> $CONFIG_DIR/config.json
        done
        printf '\n]' >> $CONFIG_DIR/config.json
    fi
}

function ensure_ss_server_unit() {
    local unit_file="/etc/systemd/system/ss-server@.service"
    if [[ ! -f "/lib/systemd/system/ss-server@.service" && ! -f "$unit_file" ]]; then
        cat > "$unit_file" <<EOF
[Unit]
Description=Shadowsocks-Libev Custom Server Instance %I
After=network.target

[Service]
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config-%i.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        echo -e "${GREEN}✔ Created systemd unit: ss-server@.service${NC}"
    fi
}

function create_config() {
    echo -e "${YELLOW}⚙️ Create New Configuration${NC}"
    read -p "Enter port [leave empty for random]: " port
    mkdir -p $(dirname "$USED_PORTS_FILE")
    touch "$USED_PORTS_FILE"
    if [[ -z "$port" ]]; then
        while true; do
            port=$((RANDOM % 16383 + 49152))
            if ! grep -q "^$port$" "$USED_PORTS_FILE" && ! lsof -i:$port &>/dev/null && [ ! -f "$CONFIG_DIR/config-$port.json" ]; then
                echo "$port" >> "$USED_PORTS_FILE"
                break
            fi
        done
        echo -e "${BLUE}🎲 Random port selected: $port${NC}"
    else
        # اگر پورت دستی وارد شد، چک کن قبلاً ثبت نشده باشد
        if grep -q "^$port$" "$USED_PORTS_FILE" || [ -f "$CONFIG_DIR/config-$port.json" ] || lsof -i:$port &>/dev/null; then
            echo -e "${RED}❌ Port $port is already in use or assigned. Choose another.${NC}"
            read -p "Press Enter to return to menu..."
            return
        fi
        echo "$port" >> "$USED_PORTS_FILE"
    fi

    if [[ "$port" == "22" || "$port" == "443" ]]; then
        echo -e "${RED}❌ Port $port is reserved for system services. Choose another.${NC}"
        read -p "Press Enter to return to menu..."
        return
    fi

    read -p "Use random password? [y/N]: " rand_pass
    if [[ "$rand_pass" =~ ^[Yy]$ ]]; then
        password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
        echo -e "${BLUE}🔐 Generated random password: $password${NC}"
    else
        read -p "Enter password [default mypassword123]: " password
        password=${password:-mypassword123}
    fi

    read -p "Enter method [default aes-256-gcm]: " method
    method=${method:-aes-256-gcm}
    read -p "Enter server address (IP, IPv6 or domain) [default current server IP]: " server
    if [[ -z "$server" ]]; then
        server=$(get_public_ip)
        if [[ -z "$server" ]]; then
            echo -e "${RED}❌ Could not detect public IP. Please enter manually.${NC}"
            read -p "Enter server address: " server
        else
            echo -e "${BLUE}🌐 Detected server IP: $server${NC}"
        fi
    fi

    # پشتیبانی از IPv6 در تست‌ها و ذخیره
    is_ipv6=false
    if [[ "$server" =~ ":" ]]; then
        is_ipv6=true
        # تست پینگ IPv6
        if command -v ping6 &>/dev/null; then
            ping6 -c 1 "$server" &>/dev/null
            if [[ $? -ne 0 ]]; then
                echo -e "${YELLOW}⚠️ Warning: Cannot ping IPv6 address $server${NC}"
            fi
        fi
    fi

    # حذف کامل تست سرور موقت و تست‌های اتصال

    if [[ "$server" != "127.0.0.1" && "$server" != "localhost" ]]; then
        # اگر دامنه وارد شده باشد، تست‌های لازم را انجام می‌دهیم
        if [[ $server =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${YELLOW}🔄 Testing domain configuration...${NC}"
            
            if ! test_connection "$server" "$port" 15; then
                echo -e "${YELLOW}⚠️ Connection issues detected. Attempting to fix...${NC}"
                fix_common_issues "$port" "$server"
                
                # تست مجدد بعد از رفع مشکلات
                if ! test_connection "$server" "$port" 15; then
                    echo -e "${RED}⚠️ Connection still failing after fixes.${NC}"
                    read -p "Continue anyway? [y/N]: " continue_anyway
                    if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
                        echo -e "${YELLOW}🔄 Configuration cancelled.${NC}"
                        return 1
                    fi
                fi
            fi
            echo -e "${YELLOW}🔄 Checking domain DNS...${NC}"
            
            # تست DNS با چندین سرور DNS
            dns_servers=("8.8.8.8" "1.1.1.1" "9.9.9.9")
            resolved=false
            
            for dns in "${dns_servers[@]}"; do
                domain_ip=$(dig @$dns +short "$server" 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n 1)
                if [[ -n "$domain_ip" ]]; then
                    echo -e "${GREEN}✅ Domain resolved to: $domain_ip (using DNS $dns)${NC}"
                    resolved=true
                    break
                fi
            done
            
            if ! $resolved; then
                echo -e "${RED}⚠️ Error: Could not resolve domain with any DNS server.${NC}"
                read -p "Continue anyway? [y/N]: " continue_anyway
                if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
                    echo -e "${YELLOW}🔄 Configuration cancelled.${NC}"
                    return 1
                fi
            fi
            
            # تست کانکشن IP اگر رزولو شده باشد
            if $resolved; then
                echo -e "${YELLOW}🔄 Testing direct IP connection...${NC}"
                if ! test_connection "$domain_ip" "$port" 10; then
                    echo -e "${RED}⚠️ Warning: Cannot connect to IP $domain_ip:$port directly.${NC}"
                    read -p "Continue anyway? [y/N]: " continue_anyway
                    if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
                        echo -e "${YELLOW}🔄 Configuration cancelled.${NC}"
                        return 1
                    fi
                else
                    echo -e "${GREEN}✅ Successfully connected to IP $domain_ip:$port${NC}"
                fi
            fi
            
            # تست کانکشن دامنه
            echo -e "${YELLOW}🔄 Testing domain connection...${NC}"
            if ! test_connection "$server" "$port" 10; then
                echo -e "${RED}⚠️ Warning: Cannot connect using domain $server:$port${NC}"
                read -p "Continue anyway? [y/N]: " continue_anyway
                if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
                    echo -e "${YELLOW}🔄 Configuration cancelled.${NC}"
                    return 1
                fi
            else
                echo -e "${GREEN}✅ Successfully connected to domain $server:$port${NC}"
            fi
        fi
    fi

    read -p "Enter data limit in GB (e.g. 30) [leave empty for no limit]: " limit_gb
    if [[ ! -z "$limit_gb" ]]; then
        if ! [[ "$limit_gb" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}❌ Invalid number for data limit.${NC}"
            limit_gb=""
        fi
    fi

    read -p "Enter expiration time in days (e.g. 30) [leave empty for no expiration]: " expire_days
    if [[ ! -z "$expire_days" ]]; then
        if ! [[ "$expire_days" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}❌ Invalid number for expiration days.${NC}"
            expire_days=""
        fi
    fi

    mkdir -p "$CONFIG_DIR"
    filename="$CONFIG_DIR/config-$port.json"
    cat > "$filename" <<EOF
{
    "server": "$server",
    "server_port": $port,
    "password": "$password",
    "timeout": 300,
    "method": "$method",
    "fast_open": false,
    "no_delay": true,
    "reuse_port": true,
    "limit_gb": ${limit_gb:-null},
    "expire_days": ${expire_days:-null},
    "created_date": "$(date +%s)",
    "first_connection": null
}
EOF

    echo -e "${GREEN}✅ Config saved to $filename${NC}"

    # ساخت لینک با پشتیبانی از IPv6
    if [[ "$server" =~ ":" ]]; then
        server_bracket="[$server]"
    else
        server_bracket="$server"
    fi
    encoded=$(echo -n "$method:$password@$server_bracket:$port" | base64 -w 0)
    link="ss://$encoded"
    echo -e "${YELLOW}🔗 SS Link:${NC} ${GREEN}$link${NC}"

    # قبل از فعال‌سازی سرویس systemd مخصوص پورت، فایل unit را چک و ایجاد کن
    ensure_ss_server_unit
    # فعال‌سازی و ریستارت سرویس systemd مخصوص این پورت
    systemctl enable --now ss-server@$port
    systemctl restart ss-server@$port
    log "Service started/restarted for ss-server@$port"
    echo -e "${BLUE}🔄 Service ss-server@$port started/restarted.${NC}"

    # راه‌اندازی مانیتورینگ ترافیک
    setup_traffic_monitor $port

    read -p "Press Enter to return to menu..."
}

function setup_traffic_monitor() {
    local port=$1
    # ایجاد قوانین iptables
    iptables -N SS_TRAFFIC_$port 2>/dev/null || true
    iptables -F SS_TRAFFIC_$port
    iptables -A SS_TRAFFIC_$port -j RETURN
    
    # اضافه کردن قوانین ورودی و خروجی
    iptables -I INPUT -p tcp --dport $port -j SS_TRAFFIC_$port
    iptables -I OUTPUT -p tcp --sport $port -j SS_TRAFFIC_$port
    
    # ایجاد دایرکتوری برای ذخیره آمار
    mkdir -p "$TRAFFIC_DIR"
    touch "$TRAFFIC_DIR/$port.bytes"
    
    # ثبت اولین اتصال در کانفیگ
    filename="$CONFIG_DIR/config-$port.json"
    temp_file=$(mktemp)
    jq --arg now "$(date +%s)" '.first_connection = $now' "$filename" > "$temp_file"
    mv "$temp_file" "$filename"
    
    log "Setup traffic monitoring for port $port"
}

function get_port_traffic() {
    local port=$1
    local bytes=0
    # اگر chain وجود نداشت، مقدار 0 برگردان
    if ! iptables -L SS_TRAFFIC_$port -vnx &>/dev/null; then
        echo "0"
        return
    fi
    # خواندن بایت‌های ورودی و خروجی از iptables
    local input=$(iptables -L SS_TRAFFIC_$port -vnx 2>/dev/null | grep "RETURN" | awk '{print $2}' | head -n1)
    local output=$(iptables -L SS_TRAFFIC_$port -vnx 2>/dev/null | grep "RETURN" | awk '{print $2}' | tail -n1)
    input=${input:-0}
    output=${output:-0}
    bytes=$((input + output))
    # مقداردهی first_connection اگر null بود و ترافیک ثبت شد
    if (( bytes > 0 )); then
        filename="$CONFIG_DIR/config-$port.json"
        if [[ -f "$filename" ]]; then
            fc=$(jq -r '.first_connection' "$filename")
            if [[ "$fc" == "null" ]]; then
                temp_file=$(mktemp)
                jq --arg now "$(date +%s)" '.first_connection = $now' "$filename" > "$temp_file"
                mv "$temp_file" "$filename"
                update_main_config_json
            fi
        fi
    fi
    # تبدیل به گیگابایت با دو رقم اعشار
    echo "scale=2; $bytes/1024/1024/1024" | bc
}

function check_limits() {
    files=$(ls $CONFIG_DIR/config-*.json 2>/dev/null)
    now=$(date +%s)
    limit_reached=0
    for file in $files; do
        port=$(jq -r '.server_port' "$file")
        limit_gb=$(jq -r '.limit_gb // empty' "$file")
        expire_days=$(jq -r '.expire_days // empty' "$file")
        created_date=$(jq -r '.created_date' "$file")

        # چک کردن محدودیت ترافیک
        if [[ -n "$limit_gb" && "$limit_gb" != "null" ]]; then
            current_usage=$(get_port_traffic "$port")
            if (( $(echo "$current_usage > $limit_gb" | bc -l) )); then
                echo -e "${RED}⚠️ Traffic limit reached for port $port. Stopping...${NC}"
                SERVICE_NAME="ss-server@$port.service"
                systemctl stop "$SERVICE_NAME"
                systemctl disable "$SERVICE_NAME"
                rm -f "$file"
                sed -i "/^$port$/d" "$USED_PORTS_FILE"
                limit_reached=1
                log "Traffic limit reached for port $port - Service stopped"
                continue
            fi
        fi

        # چک انقضا
        if [[ -n "$expire_days" && "$expire_days" != "null" ]]; then
            expire_sec=$((expire_days * 86400))
            first_connection=$(jq -r '.first_connection' "$file")
            
            if [[ "$first_connection" != "null" ]]; then
                elapsed_sec=$((now - first_connection))
                if (( elapsed_sec > expire_sec )); then
                    echo -e "${RED}⚠️ Configuration on port $port expired. Deleting...${NC}"
                    SERVICE_NAME="ss-server@$port.service"
                    systemctl stop "$SERVICE_NAME"
                    systemctl disable "$SERVICE_NAME"
                    rm -f "$file"
                    sed -i "/^$port$/d" "$USED_PORTS_FILE"
                    limit_reached=1
                    log "Config expired for port $port - Service stopped"
                fi
            fi
        fi
    done
    if [[ $limit_reached -eq 1 ]]; then
        echo -e "${YELLOW}🔄 Reloaded configs after expiration cleanup.${NC}"
    fi
}

function delete_config() {
    echo -e "${YELLOW}🗑️ Delete Configuration${NC}"
    files=$(ls $CONFIG_DIR/config-*.json 2>/dev/null)
    if [[ -z "$files" ]]; then
        echo -e "${RED}⚠️ No configs found.${NC}"
        read -p "Press Enter to return to menu..."
        return
    fi
    declare -A config_map
    counter=1
    echo -e "${CYAN}Available Configurations:${NC}"
    for file in $files; do
        port=$(jq -r '.server_port' "$file")
        method=$(jq -r '.method' "$file")
        # اگر port یا method خالی بود، رد کن
        if [[ -z "$port" || -z "$method" || "$port" == "null" ]]; then
            continue
        fi
        limit=$(jq -r '.limit_gb // empty' "$file")
        expire=$(jq -r '.expire_days // empty' "$file")
        created_date=$(jq -r '.created_date' "$file")
        remaining_days=""
        if [[ -n "$expire" && "$expire" != "null" ]]; then
            now=$(date +%s)
            expire_sec=$((expire * 86400))
            elapsed_sec=$((now - created_date))
            remaining_days=$(( (expire_sec - elapsed_sec) / 86400 ))
        fi
        current_usage=$(get_port_traffic "$port")
        echo -e "${GREEN}$counter)${NC} Port: ${BLUE}$port${NC} | Method: $method"
        [[ -n "$limit" ]] && echo -e "   📊 Limit: ${limit}GB | Current Usage: ${current_usage}GB"
        [[ -n "$remaining_days" ]] && echo -e "   ⏳ ${remaining_days} days remaining"
        echo "   ----------------------------------------"
        config_map[$counter]=$port
        ((counter++))
    done
    if [[ $counter -eq 1 ]]; then
        echo -e "${RED}⚠️ No valid configs found.${NC}"
        read -p "Press Enter to return to menu..."
        return
    fi
    read -p "Enter number to delete (0 to cancel): " choice
    if [[ "$choice" == "0" ]]; then
        return
    fi
    if [[ -n "${config_map[$choice]}" ]]; then
        port=${config_map[$choice]}
        filename="$CONFIG_DIR/config-$port.json"
        # توقف و غیرفعال‌سازی سرویس systemd مخصوص این پورت
        systemctl stop ss-server@$port
        systemctl disable ss-server@$port
        rm -f "$filename"
        # حذف پورت از USED_PORTS_FILE
        sed -i "/^$port$/d" "$USED_PORTS_FILE"
        echo -e "${GREEN}✅ Deleted config for port $port and stopped service.${NC}"
        log "Deleted config $filename and stopped ss-server@$port"
    else
        echo -e "${RED}❌ Invalid selection.${NC}"
    fi
    read -p "Press Enter to return to menu..."
}

function save_iptables_rules() {
    netfilter-persistent save
    netfilter-persistent reload
    log "Saved iptables rules"
}

function test_connection() {
    local host=$1
    local port=$2
    local timeout=$3
    local retries=3
    local retry_delay=2
    timeout=${timeout:-5}
    
    echo -e "${YELLOW}🔄 Running connection diagnostics for $host:$port...${NC}"
    
    # اگر تست روی localhost است، فقط پورت را چک کن
    if [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]]; then
        if ss -tln | grep -q ":$port"; then
            echo -e "${RED}❌ Port $port is already in use${NC}"
            return 1
        fi
        echo -e "${GREEN}✅ Port $port is available${NC}"
        return 0
    fi
    
    # تست 1: بررسی آیا آدرس IP است یا دامنه
    if [[ ! "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${BLUE}📡 Testing DNS resolution...${NC}"
        local resolved_ip=""
        # تست DNS با چند سرور مختلف
        for dns in "8.8.8.8" "1.1.1.1" "9.9.9.9"; do
            resolved_ip=$(dig @$dns +short +time=3 +tries=1 "$host" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
            if [[ -n "$resolved_ip" ]]; then
                echo -e "${GREEN}✅ DNS resolution successful using $dns: $host -> $resolved_ip${NC}"
                host=$resolved_ip  # استفاده از IP به جای دامنه برای تست
                break
            fi
        done
        if [[ -z "$resolved_ip" ]]; then
            echo -e "${RED}❌ DNS resolution failed for $host${NC}"
            return 1
        fi
    fi
    
    # تست 2: بررسی فایروال
    echo -e "${BLUE}📡 Checking firewall rules...${NC}"
    if ! iptables -L INPUT -n | grep -q "dpt:$port"; then
        echo -e "${YELLOW}⚠️ Warning: No firewall rule found for port $port${NC}"
        echo -e "${BLUE}🔄 Adding temporary firewall rule...${NC}"
        iptables -I INPUT -p tcp --dport $port -j ACCEPT
        echo -e "${GREEN}✅ Temporary firewall rule added${NC}"
    else
        echo -e "${GREEN}✅ Firewall rule exists for port $port${NC}"
    fi
    
    # تست 3: تست پورت با چند روش مختلف
    echo -e "${BLUE}📡 Testing port connectivity...${NC}"
    for ((i=1; i<=$retries; i++)); do
        # تست با netcat
        if nc -zv -w $timeout "$host" "$port" 2>/dev/null; then
            echo -e "${GREEN}✅ Port $port is accessible with netcat (attempt $i)${NC}"
            return 0
        fi
        
        # تست با curl
        if curl -s --connect-timeout $timeout "http://$host:$port" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Port $port is accessible with curl (attempt $i)${NC}"
            return 0
        fi
        
        # تست با اتصال مستقیم به سوکت با timeout
        if timeout $timeout bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
            echo -e "${GREEN}✅ Port $port is accessible with direct socket (attempt $i)${NC}"
            
            # تست 4: تست سرویس شدوساکس
            echo -e "${BLUE}📡 Testing Shadowsocks service...${NC}"
            local ss_status=$(systemctl is-active ss-server@$port)
            if [[ "$ss_status" == "active" ]]; then
                echo -e "${GREEN}✅ Shadowsocks service is running on port $port${NC}"
                return 0
            else
                echo -e "${RED}❌ Shadowsocks service is not running on port $port${NC}"
                return 1
            fi
        else
            if [ $i -lt $retries ]; then
                echo -e "${YELLOW}⚠️ Connection attempt $i failed, retrying in ${retry_delay}s...${NC}"
                sleep $retry_delay
            else
                echo -e "${RED}❌ All connection attempts failed${NC}"
                
                # تست 5: نمایش اطلاعات عیب‌یابی
                echo -e "${BLUE}📡 Debug information:${NC}"
                echo -e "1. Current firewall rules for port $port:"
                iptables -L INPUT -n | grep "$port"
                echo -e "2. Active listeners on port $port:"
                ss -tln | grep ":$port"
                echo -e "3. Service status:"
                systemctl status ss-server@$port --no-pager
            fi
        fi
    done
    
    return 1
}

function fix_common_issues() {
    local port=$1
    local domain=$2
    local fixed=false

    echo -e "${YELLOW}🔧 Checking for common issues...${NC}"

    # بررسی و اصلاح سرویس systemd
    if ! systemctl is-active --quiet ss-server@$port; then
        echo -e "${BLUE}🔄 Restarting Shadowsocks service...${NC}"
        systemctl restart ss-server@$port
        sleep 2
        if systemctl is-active --quiet ss-server@$port; then
            echo -e "${GREEN}✅ Service successfully restarted${NC}"
            fixed=true
        fi
    fi

    # بررسی و اصلاح قوانین فایروال
    if ! iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
        echo -e "${BLUE}🔄 Adding firewall rule...${NC}"
        iptables -I INPUT -p tcp --dport $port -j ACCEPT
        echo -e "${GREEN}✅ Firewall rule added${NC}"
        fixed=true
    fi

    # بررسی DNS
    if [[ -n "$domain" ]] && [[ "$domain" =~ ^[a-zA-Z] ]]; then
        if ! dig +short "$domain" >/dev/null; then
            echo -e "${BLUE}🔄 Testing alternative DNS servers...${NC}"
            for dns in "8.8.8.8" "1.1.1.1" "9.9.9.9"; do
                if dig @$dns +short "$domain" >/dev/null; then
                    echo -e "${GREEN}✅ Domain resolves using $dns${NC}"
                    fixed=true
                    break
                fi
            done
        fi
    fi

    # بررسی پورت
    if ! ss -tln | grep -q ":$port"; then
        echo -e "${RED}⚠️ Port $port is not listening${NC}"
        echo -e "${BLUE}🔄 Checking for port conflicts...${NC}"
        if lsof -i :$port; then
            echo -e "${RED}❌ Port $port is used by another process${NC}"
        else
            echo -e "${GREEN}✅ Port $port is available${NC}"
        fi
    fi

    # نمایش نتیجه
    if $fixed; then
        echo -e "${GREEN}✅ Some issues were fixed${NC}"
        save_iptables_rules
    else
        echo -e "${YELLOW}⚠️ No fixable issues found${NC}"
    fi
}

# --- اجرای اسکریپت با دسترسی روت در صورت نیاز ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}⚠️ This script must be run as root. Trying with sudo...${NC}"
    exec sudo "$0" "$@"
    exit 1
fi

# تابع نصب اسکریپت در /usr/local/bin
function install_to_bin() {
    local target="/usr/local/bin/ss-manager"
    echo -e "${YELLOW}📤 This will copy the script to $target and make it executable.${NC}"
    echo -e "${CYAN}You can then run 'ss-manager' from anywhere as root or with sudo.${NC}"
    echo -e "${YELLOW}Installing qrencode for QR code support...${NC}"
    sudo apt update && sudo apt install -y qrencode
    sudo cp "$0" "$target" && sudo chmod +x "$target"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ Script installed as $target${NC}"
        echo -e "${CYAN}Now you can run: ${GREEN}sudo ss-manager${NC}"
    else
        echo -e "${RED}❌ Failed to install script.${NC}"
    fi
    read -p "Press Enter to return to menu..."
}

function show_realtime_traffic() {
    while true; do
        clear
        echo -e "${YELLOW}=== Real-time Traffic & Active Users ===${NC}"
        echo -e "${BLUE}Port      Traffic(GB)   Active Users${NC}"
        echo "------------------------------------------"
        files=$(ls $CONFIG_DIR/config-*.json 2>/dev/null)
        for file in $files; do
            port=$(jq -r '.server_port' "$file")
            usage=$(get_port_traffic "$port")
            active=$(ss -tn sport = :$port | grep ESTAB | wc -l)
            printf "${GREEN}%-10s${NC} %-13s %-10s\n" "$port" "$usage" "$active"
        done
        echo "------------------------------------------"
        echo -e "[R]efresh   [M]ain menu   [E]xit"
        read -n1 -p "Choose an option: " opt
        echo
        case $opt in
            [Rr]) continue;;
            [Mm]) break;;
            [Ee]) echo -e "${PURPLE}Bye!${NC}"; exit 0;;
            *) echo "Invalid option!"; sleep 1;;
        esac
    done
}

function manage_logs() {
    while true; do
        clear
        echo -e "${YELLOW}Log Management${NC}"
        echo -e "1) Show last 50 lines of script log ($LOG_FILE)"
        echo -e "2) Clear script log ($LOG_FILE)"
        echo -e "3) Show last 50 lines of Shadowsocks service log"
        echo -e "4) Clear Shadowsocks service log"
        echo -e "0) Back to menu"
        read -p "Select an option: " logopt
        case $logopt in
            1)
                echo -e "${CYAN}--- Last 50 lines of $LOG_FILE ---${NC}"
                tail -n 50 "$LOG_FILE" || echo "(No log file)"
                read -p "Press Enter to continue...";;
            2)
                > "$LOG_FILE"
                echo -e "${GREEN}✔ Script log cleared.${NC}"
                read -p "Press Enter to continue...";;
            3)
                echo -e "${CYAN}--- Last 50 lines of Shadowsocks service log ---${NC}"
                journalctl -u shadowsocks-libev -n 50 --no-pager || echo "(No service log)"
                read -p "Press Enter to continue...";;
            4)
                journalctl --rotate
                journalctl --vacuum-time=1s
                echo -e "${GREEN}✔ Service log cleared (systemd journal).${NC}"
                read -p "Press Enter to continue...";;
            0) break;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1;;
        esac
    done
}

function main_menu() {
    while true; do
        clear
        header
        # بررسی نصب بودن ss-server
        if [[ $(check_installed) == "not_installed" ]]; then
            echo -e "${YELLOW}⚠️ Required packages are not installed.${NC}"
            echo -e "1) 📦 Install Shadowsocks-libev and dependencies"
            echo -e "0) 🚪 Exit"
            read -p "Select an option: " opt
            case $opt in
                1) install_ss ;;
                0) echo -e "${PURPLE}👋 Bye!${NC}"; exit 0 ;;
                *) echo -e "${RED}❌ Invalid option!${NC}"; sleep 1 ;;
            esac
            continue
        fi
        # اجرای چک محدودیت‌ها و انقضا بدون توقف
        check_limits
        # اگر اسکریپت در /usr/local/bin/ss-manager اجرا می‌شود، گزینه نصب را نمایش نده
        local self_path=$(readlink -f "$0")
        local bin_path="/usr/local/bin/ss-manager"
        if [[ "$self_path" == "$bin_path" ]]; then
            echo -e "${CYAN}1) 📊 Real-time traffic & active users"
            echo -e "2) 🔍 Show service status"
            echo -e "3) ✨ Create new config"
            echo -e "4) 📂 List configs and SS links"
            echo -e "5) 📝 Log management"
            echo -e "6) 🗑️ Delete a config"
            echo -e "7) 🧹 Clean up expired configs"
            echo -e "0) 🚪 Exit${NC}"
            read -p "Select an option: " opt
            case $opt in
                1) show_realtime_traffic ;;
                2) show_status; read -p "Press Enter to continue..." ;;
                3) create_config ;;
                4) list_configs_as_links ;;
                5) manage_logs ;;
                6) delete_config ;;
                7) check_limits ;;
                0) echo -e "${PURPLE}👋 Bye!${NC}"; exit 0 ;;
                *) echo -e "${RED}❌ Invalid option!${NC}"; sleep 1 ;;
            esac
        else
            echo -e "${CYAN}1) 📊 Real-time traffic & active users"
            echo -e "2) 🔍 Show service status"
            echo -e "3) ✨ Create new config"
            echo -e "4) 📂 List configs and SS links"
            echo -e "5) 📝 Log management"
            echo -e "6) 🗑️ Delete a config"
            echo -e "7) 🧹 Clean up expired configs"
            echo -e "8) 📤 Install ss-manager to /usr/local/bin (as 'ss-manager')"
            echo -e "0) 🚪 Exit${NC}"
            read -p "Select an option: " opt
            case $opt in
                1) show_realtime_traffic ;;
                2) show_status; read -p "Press Enter to continue..." ;;
                3) create_config ;;
                4) list_configs_as_links ;;
                5) manage_logs ;;
                6) delete_config ;;
                7) check_limits ;;
                8) install_to_bin ;;
                0) echo -e "${PURPLE}👋 Bye!${NC}"; exit 0 ;;
                *) echo -e "${RED}❌ Invalid option!${NC}"; sleep 1 ;;
            esac
        fi
    done
}

main_menu

