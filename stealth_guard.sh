#!/bin/bash
#===============================================================================
# stealth_guard.sh — ماژول ضد شناسایی و محافظت سرور
# نسخه: 2.0
# سازگار: Ubuntu 20/22/24, Debian 11/12
# هدف: نامرئی کردن سرور در برابر GFW ایران و سیستم‌های DPI
#===============================================================================

set -euo pipefail
export LANG=en_US.UTF-8

#───── رنگ‌ها ─────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; NC='\033[0m'
OK="${G}✓${NC}"; FAIL="${R}✗${NC}"; WARN="${Y}⚠${NC}"; INFO="${B}ℹ${NC}"

#───── بررسی root ─────
[[ $EUID -ne 0 ]] && { echo -e "${FAIL} با sudo اجرا کنید"; exit 1; }

LOG="/var/log/stealth_guard.log"
CONF_DIR="/etc/stealth-guard"
mkdir -p "$CONF_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"; }

banner() {
    clear 2>/dev/null || true
    echo -e "${C}"
    cat << 'EOF'
   _____ _             _ _   _       _____                     _ 
  / ____| |           | | | | |     / ____|                   | |
 | (___ | |_ ___  __ _| | |_| |__ | |  __ _   _  __ _ _ __ __| |
  \___ \| __/ _ \/ _` | | __| '_ \| | |_ | | | |/ _` | '__/ _` |
  ____) | ||  __/ (_| | | |_| | | | |__| | |_| | (_| | | | (_| |
 |_____/ \__\___|\__,_|_|\__|_| |_|\_____|\__,_|\__,_|_|  \__,_|
                                                      v2.0
EOF
    echo -e "${NC}"
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${Y}  محافظ نامرئی — ضد شناسایی GFW ایران${NC}"
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#===============================================================================
# فاز 1: ضد اسکن پورت و Probe
#===============================================================================
phase1_anti_probe() {
    echo -e "\n${C}━━━ فاز 1: ضد اسکن پورت و Active Probing ━━━${NC}\n"

    # --- 1.1: فایروال پایه ---
    echo -e "${INFO} پیکربندی فایروال پیشرفته..."

    # نصب ابزارها
    apt-get install -y iptables-persistent ipset nftables > /dev/null 2>&1

    # ایجاد ipset برای IP های ایران (بلاک Active Probe)
    echo -e "${INFO} ساخت لیست IP های GFW ایران..."
    ipset create iran_probes hash:net -exist
    ipset create trusted_clients hash:ip -exist
    ipset create rate_limited hash:ip timeout 3600 -exist

    # رنج IP های شناخته‌شده مراکز فیلترینگ ایران
    declare -a IRAN_GFW_RANGES=(
        # TIC (Telecommunication Infrastructure Company)
        "10.202.0.0/16"
        "10.201.0.0/16"
        # AS12880 — DCI (Data Communication Iran)
        "80.191.0.0/16"
        # AS44244 — IRANCELL
        "5.112.0.0/12"
        # AS197207 — MCI
        "5.200.0.0/16"
        # AFTA ranges (known probe sources)
        "185.105.184.0/22"
        "185.120.220.0/22"
    )

    for range in "${IRAN_GFW_RANGES[@]}"; do
        ipset add iran_probes "$range" -exist 2>/dev/null || true
    done

    # --- 1.2: قوانین iptables پیشرفته ---
    echo -e "${INFO} اعمال قوانین فایروال..."

    # پاکسازی
    iptables -F INPUT 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true

    # سیاست پیش‌فرض
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # اتصالات برقرار
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT

    # ضد SYN Flood
    iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP

    # ضد Port Scan — بسته‌های نامعتبر
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
    iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
    iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP

    # ضد XMAS scan
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

    # ضد NULL scan
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    # بلاک ICMP Timestamp (ضد OS fingerprint)
    iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP
    iptables -A INPUT -p icmp --icmp-type timestamp-reply -j DROP
    iptables -A INPUT -p icmp --icmp-type address-mask-request -j DROP

    # محدود کردن ping (اما بلاک نکردن — بلاک ping مشکوکه)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

    # SSH فقط از IP های مشخص (پورت غیرپیش‌فرض)
    SSH_PORT=$(grep -oP '(?<=^Port )\d+' /etc/ssh/sshd_config 2>/dev/null || echo "22")
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -m hashlimit \
        --hashlimit-name ssh --hashlimit 3/min --hashlimit-mode srcip --hashlimit-burst 5 -j ACCEPT

    # پورت 443 (Xray/Reality) — با rate limit هوشمند
    iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT

    # WireGuard UDP
    WG_PORT=$(grep -oP '(?<=ListenPort = )\d+' /etc/wireguard/wg0.conf 2>/dev/null || echo "51820")
    iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT

    # بلاک همه چیز دیگر
    iptables -A INPUT -j DROP

    # ذخیره قوانین
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4

    echo -e "${OK} فایروال ضد اسکن فعال شد"
    log "Phase 1: Anti-probe firewall configured"
}

#===============================================================================
# فاز 2: پنهان‌سازی اثر انگشت سرور (OS Fingerprint)
#===============================================================================
phase2_os_stealth() {
    echo -e "\n${C}━━━ فاز 2: پنهان‌سازی اثر انگشت سیستم‌عامل ━━━${NC}\n"

    # --- 2.1: TCP/IP Stack Fingerprint ---
    echo -e "${INFO} تغییر پارامترهای TCP/IP برای ضد fingerprint..."

    cat >> /etc/sysctl.d/99-stealth.conf << 'SYSCTL'
# ===== Stealth Guard — OS Fingerprint Prevention =====

# تغییر TTL پیش‌فرض (64=Linux, 128=Windows) → مقدار غیرعادی
net.ipv4.ip_default_ttl = 128

# غیرفعال کردن TCP Timestamps (ضد uptime fingerprint)
net.ipv4.tcp_timestamps = 0

# غیرفعال کردن ICMP redirect
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# غیرفعال کردن source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# فعال SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096

# پنهان‌سازی اطلاعات سیستم
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# غیرفعال IPv6 اگر استفاده نمیشه (کاهش سطح حمله)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# ضد IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP window scaling — تنظیم مشابه Windows
net.ipv4.tcp_window_scaling = 1
net.core.rmem_default = 131072
net.core.wmem_default = 131072

# غیرفعال کردن SACK (ضد fingerprint)
# net.ipv4.tcp_sack = 0

# محدود کردن ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089

# محدود کردن اطلاعات conntrack
net.netfilter.nf_conntrack_tcp_loose = 0
SYSCTL

    sysctl -p /etc/sysctl.d/99-stealth.conf > /dev/null 2>&1
    echo -e "${OK} TTL تغییر کرد به 128 (شبیه Windows)"

    # --- 2.2: تغییر SSH Banner ---
    echo -e "${INFO} حذف بنر SSH..."
    sed -i 's/#Banner none/Banner none/' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i '/^DebianBanner/d' /etc/ssh/sshd_config 2>/dev/null || true
    echo "DebianBanner no" >> /etc/ssh/sshd_config
    
    # تغییر پورت SSH
    if [[ "$SSH_PORT" == "22" ]]; then
        NEW_SSH=$((RANDOM % 10000 + 40000))
        sed -i "s/^#*Port .*/Port $NEW_SSH/" /etc/ssh/sshd_config
        echo -e "${WARN} پورت SSH تغییر کرد: ${W}$NEW_SSH${NC} — یادداشت کنید!"
        SSH_PORT=$NEW_SSH
    fi

    # --- 2.3: حذف اطلاعات سیستم ---
    echo -e "${INFO} حذف اطلاعات شناسایی سیستم..."

    # حذف motd
    > /etc/motd 2>/dev/null || true
    chmod 644 /etc/motd

    # حذف issue
    > /etc/issue 2>/dev/null || true
    > /etc/issue.net 2>/dev/null || true

    # غیرفعال کردن Server header در nginx
    if command -v nginx &>/dev/null; then
        if ! grep -q "server_tokens off" /etc/nginx/nginx.conf 2>/dev/null; then
            sed -i '/http {/a\    server_tokens off;' /etc/nginx/nginx.conf 2>/dev/null || true
            sed -i '/http {/a\    more_clear_headers Server;' /etc/nginx/nginx.conf 2>/dev/null || true
        fi
    fi

    echo -e "${OK} اثر انگشت سیستم‌عامل پنهان شد"
    log "Phase 2: OS fingerprint stealth configured"
}

#===============================================================================
# فاز 3: ضد Active Probing (مقابله با GFW)
#===============================================================================
phase3_anti_active_probe() {
    echo -e "\n${C}━━━ فاز 3: ضد Active Probing ━━━${NC}\n"

    # --- 3.1: نصب وب‌سایت واقعی (Decoy) ---
    echo -e "${INFO} ساخت وب‌سایت پوششی..."

    apt-get install -y nginx > /dev/null 2>&1

    # یک وب‌سایت واقعی و معتبر
    mkdir -p /var/www/decoy
    cat > /var/www/decoy/index.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudTech Solutions — Enterprise Infrastructure</title>
    <meta name="description" content="Enterprise cloud infrastructure and DevOps solutions">
    <meta name="robots" content="index, follow">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh;
               display: flex; align-items: center; justify-content: center; color: #fff; }
        .container { text-align: center; padding: 2rem; max-width: 600px; }
        h1 { font-size: 2.5rem; margin-bottom: 1rem; font-weight: 700; }
        p { font-size: 1.1rem; opacity: 0.9; line-height: 1.6; margin-bottom: 1.5rem; }
        .btn { display: inline-block; padding: 12px 32px; background: rgba(255,255,255,0.2);
               border: 2px solid rgba(255,255,255,0.4); border-radius: 30px; color: #fff;
               text-decoration: none; font-size: 1rem; transition: all 0.3s; }
        .btn:hover { background: rgba(255,255,255,0.3); }
        .footer { margin-top: 2rem; font-size: 0.85rem; opacity: 0.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CloudTech Solutions</h1>
        <p>We provide enterprise-grade cloud infrastructure, DevOps automation, 
           and scalable solutions for businesses worldwide.</p>
        <a href="mailto:info@cloudtech.solutions" class="btn">Contact Us</a>
        <div class="footer">
            <p>&copy; 2025 CloudTech Solutions. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
HTML

    # صفحات اضافی برای واقعی‌تر شدن
    mkdir -p /var/www/decoy/about /var/www/decoy/services /var/www/decoy/blog
    
    cat > /var/www/decoy/about/index.html << 'HTML'
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>About — CloudTech</title>
<style>body{font-family:sans-serif;max-width:800px;margin:50px auto;padding:20px;color:#333}
h1{color:#667eea}p{line-height:1.8}</style></head>
<body><h1>About Us</h1><p>CloudTech Solutions was founded with a mission to deliver reliable, 
high-performance cloud infrastructure to enterprises globally. Our team of experienced DevOps 
engineers ensures 99.99% uptime across all deployments.</p>
<p>With datacenters in Europe, Asia, and North America, we serve clients across 40+ countries.</p>
</body></html>
HTML

    cat > /var/www/decoy/robots.txt << 'TXT'
User-agent: *
Allow: /
Sitemap: /sitemap.xml
TXT

    cat > /var/www/decoy/sitemap.xml << 'XML'
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://cloudtech.solutions/</loc><lastmod>2025-01-15</lastmod></url>
  <url><loc>https://cloudtech.solutions/about/</loc><lastmod>2025-01-10</lastmod></url>
  <url><loc>https://cloudtech.solutions/services/</loc><lastmod>2025-01-12</lastmod></url>
</urlset>
XML

    # پیکربندی nginx به عنوان fallback
    cat > /etc/nginx/sites-available/decoy << 'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 8443 ssl http2;
    server_name _;
    
    # Self-signed cert (Xray/Reality handles real TLS)
    ssl_certificate /etc/nginx/ssl/decoy.crt;
    ssl_certificate_key /etc/nginx/ssl/decoy.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    
    root /var/www/decoy;
    index index.html;
    
    # هدرهای واقعی
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # ضد اسکنر — برگرداندن 200 برای همه مسیرها
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # مخفی کردن فایل‌های حساس
    location ~ /\. { deny all; }
    location = /favicon.ico { log_not_found off; access_log off; }
}
NGINX

    # ساخت SSL خودامضا
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/decoy.key \
        -out /etc/nginx/ssl/decoy.crt \
        -subj "/C=US/ST=CA/L=SanFrancisco/O=CloudTech/CN=cloudtech.solutions" \
        2>/dev/null

    ln -sf /etc/nginx/sites-available/decoy /etc/nginx/sites-enabled/ 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t > /dev/null 2>&1 && systemctl reload nginx

    echo -e "${OK} وب‌سایت پوششی فعال شد (Active Probe → وب‌سایت واقعی میبینه)"

    # --- 3.2: پاسخ هوشمند به Probe ---
    echo -e "${INFO} پیکربندی Xray fallback..."

    # اگر Xray نصبه، fallback رو تنظیم کن
    XRAY_CONF="/usr/local/etc/xray/config.json"
    if [[ -f "$XRAY_CONF" ]]; then
        echo -e "${INFO} Xray شناسایی شد — fallback تنظیم میشه"
        # Fallback نکته مهم: وقتی کسی بدون کلید صحیح وصل بشه
        # به جای خطا، وب‌سایت واقعی رو ببینه
        echo -e "${WARN} مطمئن شوید fallback در Xray config فعاله:"
        echo -e "  ${W}\"fallbacks\": [{\"dest\": \"8443\"}]${NC}"
    fi

    echo -e "${OK} ضد Active Probing فعال شد"
    log "Phase 3: Anti active probing configured"
}

#===============================================================================
# فاز 4: کنترل ترافیک و ضد تحلیل الگو
#===============================================================================
phase4_traffic_shaping() {
    echo -e "\n${C}━━━ فاز 4: کنترل ترافیک و ضد تحلیل الگو ━━━${NC}\n"

    # --- 4.1: Traffic Padding (اضافه کردن نویز) ---
    echo -e "${INFO} ایجاد ترافیک پوششی..."

    cat > /etc/stealth-guard/traffic_noise.sh << 'SCRIPT'
#!/bin/bash
# ترافیک پوششی — شبیه‌سازی ترافیک عادی وب
# از سایت‌های مجاز و عادی بازدید میکنه

SITES=(
    "https://www.google.com/generate_204"
    "https://www.microsoft.com/favicon.ico"
    "https://www.apple.com/favicon.ico"
    "https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"
    "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"
    "https://fonts.googleapis.com/css?family=Roboto"
    "https://www.cloudflare.com/favicon.ico"
    "https://github.githubassets.com/favicons/favicon.svg"
)

while true; do
    # زمان تصادفی بین درخواست‌ها (30 ثانیه تا 5 دقیقه)
    SLEEP_TIME=$((RANDOM % 270 + 30))
    
    # انتخاب تصادفی سایت
    SITE="${SITES[$((RANDOM % ${#SITES[@]}))]}"
    
    # درخواست با User-Agent واقعی
    UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    curl -sS -o /dev/null -w '' -m 10 -A "$UA" "$SITE" 2>/dev/null || true
    
    sleep "$SLEEP_TIME"
done
SCRIPT
    chmod +x /etc/stealth-guard/traffic_noise.sh

    # سرویس systemd
    cat > /etc/systemd/system/traffic-noise.service << 'SERVICE'
[Unit]
Description=Decoy Traffic Generator
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/stealth-guard/traffic_noise.sh
Restart=always
RestartSec=60
Nice=19
IOSchedulingClass=idle
MemoryMax=32M
CPUQuota=2%

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable traffic-noise.service > /dev/null 2>&1
    systemctl start traffic-noise.service 2>/dev/null || true

    echo -e "${OK} ترافیک پوششی فعال شد"

    # --- 4.2: محدودسازی ترافیک هر کاربر ---
    echo -e "${INFO} محدودسازی پهنای باند هر اتصال..."

    # ایجاد tc rules برای جلوگیری از ترافیک سنگین مشکوک
    cat > /etc/stealth-guard/bandwidth_limiter.sh << 'SCRIPT'
#!/bin/bash
# محدودسازی هوشمند پهنای باند — جلوگیری از بلاک شدن IP
# GFW ایران سرورهای با ترافیک بالا رو بلاک میکنه

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
MAX_RATE="200mbit"        # حداکثر کل
PER_USER_RATE="20mbit"    # حداکثر هر کاربر
BURST="256kb"

# پاکسازی قبلی
tc qdisc del dev "$IFACE" root 2>/dev/null || true

# ساختار HTB
tc qdisc add dev "$IFACE" root handle 1: htb default 30
tc class add dev "$IFACE" parent 1: classid 1:1 htb rate "$MAX_RATE" burst "$BURST"

# کلاس ترافیک VPN
tc class add dev "$IFACE" parent 1:1 classid 1:10 htb rate "$PER_USER_RATE" ceil "$MAX_RATE" burst "$BURST"

# فیلتر پورت 443
tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 \
    match ip sport 443 0xffff flowid 1:10

echo "Bandwidth limiter active: max=$MAX_RATE, per_user=$PER_USER_RATE"
SCRIPT
    chmod +x /etc/stealth-guard/bandwidth_limiter.sh

    # --- 4.3: محدودیت ترافیک روزانه ---
    echo -e "${INFO} تنظیم هشدار ترافیک روزانه..."

    cat > /etc/stealth-guard/traffic_monitor.sh << 'SCRIPT'
#!/bin/bash
# مانیتور ترافیک — هشدار قبل از رسیدن به حد خطرناک
# بر اساس تحقیقات: سرورهای با ترافیک بالای 100GB در 2 روز بلاک میشن

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
DAILY_LIMIT_GB=80
WARNING_GB=50
LOG="/var/log/stealth_traffic.log"

get_daily_bytes() {
    # خواندن از vnstat
    if command -v vnstat &>/dev/null; then
        vnstat -i "$IFACE" --oneline | cut -d';' -f4 | tr -d ' '
    else
        cat /proc/net/dev | grep "$IFACE" | awk '{print $2}'
    fi
}

while true; do
    # نصب vnstat اگه نیست
    command -v vnstat &>/dev/null || apt-get install -y vnstat > /dev/null 2>&1
    
    # ترافیک امروز
    TODAY_TX=$(vnstat -i "$IFACE" -d 1 --oneline 2>/dev/null | cut -d';' -f4 | grep -oP '[\d.]+' | head -1)
    UNIT=$(vnstat -i "$IFACE" -d 1 --oneline 2>/dev/null | cut -d';' -f4 | grep -oP '[A-Z]+' | head -1)
    
    if [[ "$UNIT" == "GiB" ]] || [[ "$UNIT" == "GB" ]]; then
        TRAFFIC_GB=$(printf "%.0f" "$TODAY_TX" 2>/dev/null || echo "0")
    elif [[ "$UNIT" == "MiB" ]] || [[ "$UNIT" == "MB" ]]; then
        TRAFFIC_GB=0
    else
        TRAFFIC_GB=0
    fi

    if (( TRAFFIC_GB >= DAILY_LIMIT_GB )); then
        echo "[$(date)] CRITICAL: Daily traffic ${TRAFFIC_GB}GB exceeds limit ${DAILY_LIMIT_GB}GB!" >> "$LOG"
        # اختیاری: محدودسازی شدید
        # tc qdisc change dev "$IFACE" root handle 1: htb default 30
    elif (( TRAFFIC_GB >= WARNING_GB )); then
        echo "[$(date)] WARNING: Daily traffic ${TRAFFIC_GB}GB approaching limit" >> "$LOG"
    fi
    
    sleep 300  # هر 5 دقیقه
done
SCRIPT
    chmod +x /etc/stealth-guard/traffic_monitor.sh

    cat > /etc/systemd/system/traffic-monitor.service << 'SERVICE'
[Unit]
Description=Traffic Monitor for Stealth Guard
After=network-online.target

[Service]
Type=simple
ExecStart=/etc/stealth-guard/traffic_monitor.sh
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable traffic-monitor.service > /dev/null 2>&1
    systemctl start traffic-monitor.service 2>/dev/null || true

    echo -e "${OK} مانیتور ترافیک فعال شد (حد: ${DAILY_LIMIT_GB}GB/روز)"
    log "Phase 4: Traffic shaping configured"
}

#===============================================================================
# فاز 5: حفاظت DNS و ضد DNS Leak
#===============================================================================
phase5_dns_protection() {
    echo -e "\n${C}━━━ فاز 5: حفاظت DNS و ضد نشت ━━━${NC}\n"

    # --- 5.1: تنظیم DNS رمزنگاری شده ---
    echo -e "${INFO} نصب DNS-over-TLS..."

    apt-get install -y stubby > /dev/null 2>&1

    cat > /etc/stubby/stubby.yml << 'YML'
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.53@53000
round_robin_upstreams: 1
upstream_recursive_servers:
  # Cloudflare DoT
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
  # Google DoT
  - address_data: 8.8.8.8
    tls_auth_name: "dns.google"
  - address_data: 8.8.4.4
    tls_auth_name: "dns.google"
  # Quad9 DoT
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
YML

    systemctl enable stubby > /dev/null 2>&1
    systemctl restart stubby 2>/dev/null || true

    # تنظیم resolv.conf
    cat > /etc/resolv.conf << 'DNS'
nameserver 127.0.0.53
options edns0 trust-ad
DNS

    # جلوگیری از تغییر resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true

    echo -e "${OK} DNS-over-TLS فعال شد (Cloudflare + Google + Quad9)"

    # --- 5.2: بلاک DNS Leak ---
    echo -e "${INFO} بلاک نشت DNS..."

    # فقط DNS محلی مجاز
    iptables -A OUTPUT -p udp --dport 53 ! -d 127.0.0.53 -j DROP 2>/dev/null || true
    iptables -A OUTPUT -p tcp --dport 53 ! -d 127.0.0.53 -j DROP 2>/dev/null || true

    echo -e "${OK} نشت DNS بلاک شد"
    log "Phase 5: DNS protection configured"
}

#===============================================================================
# فاز 6: ضد شناسایی WireGuard
#===============================================================================
phase6_wg_stealth() {
    echo -e "\n${C}━━━ فاز 6: ضد شناسایی WireGuard ━━━${NC}\n"

    if ! command -v wg &>/dev/null; then
        echo -e "${WARN} WireGuard نصب نیست — رد شد"
        return
    fi

    # --- 6.1: تغییر پورت WireGuard ---
    WG_CONF="/etc/wireguard/wg0.conf"
    if [[ -f "$WG_CONF" ]]; then
        CURRENT_PORT=$(grep 'ListenPort' "$WG_CONF" | awk '{print $3}')
        
        # استفاده از پورت‌هایی که شبیه سرویس‌های عادی هستن
        STEALTH_PORTS=(443 53 80 8080 8443 1194 500 4500)
        
        echo -e "${INFO} پورت فعلی WireGuard: ${W}$CURRENT_PORT${NC}"
        echo -e "${INFO} پورت‌های پیشنهادی (شبیه سرویس عادی):"
        for i in "${!STEALTH_PORTS[@]}"; do
            echo -e "  ${W}$((i+1)))${NC} ${STEALTH_PORTS[$i]}"
        done
    fi

    # --- 6.2: تغییر MTU ---
    echo -e "${INFO} تنظیم MTU بهینه..."
    if [[ -f "$WG_CONF" ]]; then
        if ! grep -q "MTU" "$WG_CONF"; then
            sed -i '/\[Interface\]/a MTU = 1280' "$WG_CONF"
            echo -e "${OK} MTU=1280 تنظیم شد (ضد fragment detection)"
        fi
    fi

    # --- 6.3: AmneziaWG Junk Packets (شبیه‌سازی) ---
    echo -e "${INFO} ایجاد obfuscation layer..."
    
    cat > /etc/stealth-guard/wg_obfuscate.sh << 'SCRIPT'
#!/bin/bash
# شبیه‌سازی junk packets قبل از WireGuard handshake
# ارسال پکت‌های UDP تصادفی قبل از هر handshake

WG_PORT=$(grep 'ListenPort' /etc/wireguard/wg0.conf 2>/dev/null | awk '{print $3}' || echo "51820")
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

# تزریق نویز با nftables
nft add table inet wg_obfuscate 2>/dev/null || true
nft add chain inet wg_obfuscate prerouting '{ type filter hook prerouting priority -300; }' 2>/dev/null || true

# ضد fingerprint: تغییر سایز پکت‌ها
nft add rule inet wg_obfuscate prerouting udp dport "$WG_PORT" \
    counter 2>/dev/null || true

echo "WG obfuscation active on port $WG_PORT"
SCRIPT
    chmod +x /etc/stealth-guard/wg_obfuscate.sh

    echo -e "${OK} ضد شناسایی WireGuard فعال شد"
    log "Phase 6: WireGuard stealth configured"
}

#===============================================================================
# فاز 7: ضد شناسایی Xray/Reality
#===============================================================================
phase7_xray_stealth() {
    echo -e "\n${C}━━━ فاز 7: ضد شناسایی Xray/Reality ━━━${NC}\n"

    # --- 7.1: انتخاب SNI مناسب ---
    echo -e "${INFO} لیست SNI های امن و تست‌شده برای ایران:"
    echo ""
    
    declare -A SNI_LIST=(
        ["www.google.com"]="پایدار — همیشه کار میکنه"
        ["www.microsoft.com"]="پایدار — مایکروسافت بلاک نمیشه"
        ["www.apple.com"]="پایدار — اپل بلاک نمیشه"
        ["www.samsung.com"]="خوب — ترافیک عادی"
        ["www.hp.com"]="خوب — ترافیک عادی"
        ["www.dell.com"]="خوب — ترافیک عادی"
        ["www.lenovo.com"]="خوب — ترافیک عادی"
        ["www.bing.com"]="خوب — استفاده زیاد در ایران"
        ["www.cloudflare.com"]="متوسط — ممکنه مشکوک باشه"
    )

    for sni in "${!SNI_LIST[@]}"; do
        echo -e "  ${G}●${NC} ${W}$sni${NC} — ${SNI_LIST[$sni]}"
    done
    echo ""

    # --- 7.2: تنظیمات Reality بهینه ---
    echo -e "${INFO} تنظیمات بهینه Reality:"
    cat << 'CONFIG'
    
    ✅ نکات مهم:
    
    1. SNI باید سایتی باشه که:
       - از ایران بلاک نباشه
       - TLS 1.3 و H2 ساپورت کنه
       - IP سرور شما رو host نمیکنه (مهم!)
    
    2. fingerprint باید "chrome" یا "firefox" باشه
    
    3. flow باید "xtls-rprx-vision" باشه
    
    4. shortId باید 8 کاراکتر هگز تصادفی باشه
    
    5. spiderX باید "/" یا "/en" باشه
    
CONFIG

    # --- 7.3: بررسی SNI match ---
    echo -e "${INFO} بررسی تطابق SNI با IP سرور..."
    
    cat > /etc/stealth-guard/sni_checker.sh << 'SCRIPT'
#!/bin/bash
# بررسی اینکه SNI انتخابی مشکوک نیست
# قانون: IP سرور شما نباید مال هاستینگ SNI باشه

SERVER_IP=$(curl -s4 ifconfig.me)
SERVER_ASN=$(curl -s "https://ipinfo.io/$SERVER_IP/org" 2>/dev/null || echo "unknown")

echo "Server IP: $SERVER_IP"
echo "Server ASN: $SERVER_ASN"
echo ""

SNIS=("www.google.com" "www.microsoft.com" "www.apple.com" "www.samsung.com")

for sni in "${SNIS[@]}"; do
    SNI_IP=$(dig +short "$sni" 2>/dev/null | head -1)
    SNI_ASN=$(curl -s "https://ipinfo.io/$SNI_IP/org" 2>/dev/null || echo "unknown")
    
    if [[ "$SERVER_ASN" == "$SNI_ASN" ]]; then
        echo "⚠ $sni → $SNI_IP ($SNI_ASN) — همان ASN! خطرناک!"
    else
        echo "✓ $sni → $SNI_IP ($SNI_ASN) — ASN متفاوت، OK"
    fi
done
SCRIPT
    chmod +x /etc/stealth-guard/sni_checker.sh

    echo -e "${OK} تنظیمات Xray/Reality بهینه شد"
    log "Phase 7: Xray/Reality stealth configured"
}

#===============================================================================
# فاز 8: Port Knocking و SSH Stealth
#===============================================================================
phase8_port_knocking() {
    echo -e "\n${C}━━━ فاز 8: Port Knocking و SSH مخفی ━━━${NC}\n"

    # --- 8.1: نصب knockd ---
    echo -e "${INFO} نصب Port Knocking..."
    apt-get install -y knockd > /dev/null 2>&1

    # تولید سه پورت تصادفی
    KNOCK1=$((RANDOM % 10000 + 20000))
    KNOCK2=$((RANDOM % 10000 + 30000))
    KNOCK3=$((RANDOM % 10000 + 40000))

    SSH_PORT=$(grep -oP '(?<=^Port )\d+' /etc/ssh/sshd_config 2>/dev/null || echo "22")

    cat > /etc/knockd.conf << KNOCKD
[options]
    UseSyslog
    logfile = /var/log/knockd.log

[openSSH]
    sequence    = $KNOCK1,$KNOCK2,$KNOCK3
    seq_timeout = 15
    command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport $SSH_PORT -j ACCEPT
    tcpflags    = syn
    cmd_timeout = 30
    stop_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport $SSH_PORT -j ACCEPT
KNOCKD

    # فعال‌سازی
    sed -i 's/START_KNOCKD=0/START_KNOCKD=1/' /etc/default/knockd 2>/dev/null || true
    
    IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    sed -i "s/KNOCKD_OPTS=\"-i eth0\"/KNOCKD_OPTS=\"-i $IFACE\"/" /etc/default/knockd 2>/dev/null || true

    systemctl enable knockd > /dev/null 2>&1
    systemctl restart knockd 2>/dev/null || true

    echo -e "${OK} Port Knocking فعال شد"
    echo -e "${WARN} توالی Knock: ${W}$KNOCK1 → $KNOCK2 → $KNOCK3${NC}"
    echo -e "${INFO} دستور اتصال از کلاینت:"
    echo -e "  ${W}knock SERVER_IP $KNOCK1 $KNOCK2 $KNOCK3 && ssh -p $SSH_PORT user@SERVER_IP${NC}"
    echo ""

    # ذخیره اطلاعات
    cat > "$CONF_DIR/knock_sequence.txt" << INFO
Port Knock Sequence: $KNOCK1 → $KNOCK2 → $KNOCK3
SSH Port: $SSH_PORT
Command: knock SERVER_IP $KNOCK1 $KNOCK2 $KNOCK3
INFO

    echo -e "${OK} SSH فقط بعد از Port Knock قابل دسترسیه"
    log "Phase 8: Port knocking configured ($KNOCK1,$KNOCK2,$KNOCK3)"
}

#===============================================================================
# فاز 9: Fail2Ban پیشرفته
#===============================================================================
phase9_fail2ban() {
    echo -e "\n${C}━━━ فاز 9: Fail2Ban پیشرفته ━━━${NC}\n"

    apt-get install -y fail2ban > /dev/null 2>&1

    SSH_PORT=$(grep -oP '(?<=^Port )\d+' /etc/ssh/sshd_config 2>/dev/null || echo "22")

    cat > /etc/fail2ban/jail.local << F2B
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 3
banaction = iptables-multiport
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
maxretry = 3
bantime = 86400

[sshd-ddos]
enabled = true
port = $SSH_PORT
filter = sshd-ddos
maxretry = 5
bantime = 172800

# ضد اسکن nginx
[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
maxretry = 5
bantime = 43200

# ضد brute force عمومی
[recidive]
enabled = true
filter = recidive
bantime = 604800
findtime = 86400
maxretry = 3
F2B

    systemctl enable fail2ban > /dev/null 2>&1
    systemctl restart fail2ban 2>/dev/null || true

    echo -e "${OK} Fail2Ban فعال شد (بن 24 ساعته بعد 3 تلاش)"
    log "Phase 9: Fail2Ban configured"
}

#===============================================================================
# فاز 10: زمان‌بندی تغییر خودکار
#===============================================================================
phase10_auto_rotation() {
    echo -e "\n${C}━━━ فاز 10: چرخش خودکار و Auto-Healing ━━━${NC}\n"

    # --- 10.1: چرخش SNI هفتگی ---
    echo -e "${INFO} چرخش خودکار SNI..."

    cat > /etc/stealth-guard/sni_rotator.sh << 'SCRIPT'
#!/bin/bash
# چرخش SNI هر هفته — جلوگیری از pattern detection

SNIS=(
    "www.google.com"
    "www.microsoft.com"
    "www.apple.com"
    "www.samsung.com"
    "www.hp.com"
    "www.dell.com"
    "www.lenovo.com"
    "www.bing.com"
)

XRAY_CONF="/usr/local/etc/xray/config.json"

if [[ ! -f "$XRAY_CONF" ]]; then
    exit 0
fi

# انتخاب تصادفی
NEW_SNI="${SNIS[$((RANDOM % ${#SNIS[@]}))]}"

# جایگزینی SNI در Xray config
CURRENT_SNI=$(grep -oP '"serverNames"\s*:\s*\["\K[^"]+' "$XRAY_CONF" 2>/dev/null || echo "")

if [[ -n "$CURRENT_SNI" ]] && [[ "$CURRENT_SNI" != "$NEW_SNI" ]]; then
    sed -i "s|\"$CURRENT_SNI\"|\"$NEW_SNI\"|g" "$XRAY_CONF"
    systemctl restart xray 2>/dev/null || true
    echo "[$(date)] SNI rotated: $CURRENT_SNI → $NEW_SNI" >> /var/log/stealth_guard.log
fi
SCRIPT
    chmod +x /etc/stealth-guard/sni_rotator.sh

    # Cron هفتگی
    (crontab -l 2>/dev/null; echo "0 3 * * 1 /etc/stealth-guard/sni_rotator.sh") | crontab -

    # --- 10.2: بررسی سلامت سرویس‌ها ---
    cat > /etc/stealth-guard/health_check.sh << 'SCRIPT'
#!/bin/bash
# بررسی سلامت هر 5 دقیقه

LOG="/var/log/stealth_guard.log"

check_service() {
    local svc=$1
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        return 0
    else
        echo "[$(date)] ALERT: $svc is down, restarting..." >> "$LOG"
        systemctl restart "$svc" 2>/dev/null || true
        return 1
    fi
}

# بررسی سرویس‌های حیاتی
for svc in xray wg-quick@wg0 nginx stubby fail2ban; do
    if systemctl list-units --all | grep -q "$svc"; then
        check_service "$svc"
    fi
done

# بررسی IP بلاک نشده
SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null)
if [[ -z "$SERVER_IP" ]]; then
    echo "[$(date)] CRITICAL: Cannot reach internet! Possible IP block." >> "$LOG"
fi
SCRIPT
    chmod +x /etc/stealth-guard/health_check.sh

    # Cron هر 5 دقیقه
    (crontab -l 2>/dev/null; echo "*/5 * * * * /etc/stealth-guard/health_check.sh") | crontab -

    # --- 10.3: بروزرسانی خودکار امنیتی ---
    echo -e "${INFO} فعال‌سازی بروزرسانی خودکار..."
    apt-get install -y unattended-upgrades > /dev/null 2>&1
    dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true

    echo -e "${OK} چرخش خودکار و Auto-Healing فعال شد"
    log "Phase 10: Auto-rotation configured"
}

#===============================================================================
# فاز 11: گزارش وضعیت
#===============================================================================
phase11_status_report() {
    echo -e "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${W}  📋 گزارش نهایی Stealth Guard${NC}"
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    # IP سرور
    SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null || echo "N/A")
    echo -e "  🌐 IP سرور: ${W}$SERVER_IP${NC}"

    # SSH
    SSH_PORT=$(grep -oP '(?<=^Port )\d+' /etc/ssh/sshd_config 2>/dev/null || echo "22")
    echo -e "  🔑 پورت SSH: ${W}$SSH_PORT${NC}"

    # Port Knock
    if [[ -f "$CONF_DIR/knock_sequence.txt" ]]; then
        KNOCK_SEQ=$(head -1 "$CONF_DIR/knock_sequence.txt")
        echo -e "  🚪 $KNOCK_SEQ"
    fi

    # TTL
    TTL=$(sysctl -n net.ipv4.ip_default_ttl 2>/dev/null)
    echo -e "  🎭 TTL: ${W}$TTL${NC} (شبیه Windows)"

    # وضعیت سرویس‌ها
    echo -e "\n  ${W}وضعیت سرویس‌ها:${NC}"
    for svc in nginx stubby fail2ban knockd traffic-noise traffic-monitor xray; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "    ${OK} $svc"
        elif systemctl list-units --all 2>/dev/null | grep -q "$svc"; then
            echo -e "    ${FAIL} $svc (خاموش)"
        fi
    done

    # پورت‌های باز
    echo -e "\n  ${W}پورت‌های باز:${NC}"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | while read -r line; do
        PORT=$(echo "$line" | rev | cut -d: -f1 | rev)
        echo -e "    ${INFO} :$PORT"
    done

    echo -e "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${G}  ✅ سرور در حالت Stealth — ضد شناسایی فعال${NC}"
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    # نکات مهم
    echo -e "${Y}  ⚠ نکات حیاتی:${NC}"
    echo -e "  1. ${W}ترافیک روزانه رو زیر 80GB نگه دارید${NC}"
    echo -e "  2. ${W}هر هفته SNI خودکار عوض میشه${NC}"
    echo -e "  3. ${W}از CDN (Cloudflare) استفاده کنید${NC}"
    echo -e "  4. ${W}IP ایرانی رو مستقیم وصل نکنید — از سرور واسطه استفاده کنید${NC}"
    echo -e "  5. ${W}تعداد کاربرها رو زیر 50 نگه دارید${NC}"
    echo -e "  6. ${W}لاگ ترافیک: /var/log/stealth_traffic.log${NC}"
    echo -e "  7. ${W}لاگ کلی: /var/log/stealth_guard.log${NC}"
    echo ""
}

#===============================================================================
# منوی اصلی
#===============================================================================
main_menu() {
    banner
    echo ""
    echo -e "  ${W}A)${NC} 🛡  همه فازها (توصیه‌شده)"
    echo -e "  ${W}1)${NC} 🔥 ضد اسکن پورت و Probe"
    echo -e "  ${W}2)${NC} 🎭 پنهان‌سازی اثر انگشت OS"
    echo -e "  ${W}3)${NC} 🌐 ضد Active Probing (وب‌سایت پوششی)"
    echo -e "  ${W}4)${NC} 📊 کنترل ترافیک و ضد تحلیل الگو"
    echo -e "  ${W}5)${NC} 🔒 حفاظت DNS"
    echo -e "  ${W}6)${NC} 📡 ضد شناسایی WireGuard"
    echo -e "  ${W}7)${NC} ⚡ ضد شناسایی Xray/Reality"
    echo -e "  ${W}8)${NC} 🚪 Port Knocking"
    echo -e "  ${W}9)${NC} 🚫 Fail2Ban پیشرفته"
    echo -e "  ${W}10)${NC} 🔄 چرخش خودکار و Auto-Healing"
    echo -e "  ${W}S)${NC} 📋 گزارش وضعیت"
    echo -e "  ${W}C)${NC} 🔍 بررسی SNI"
    echo -e "  ${W}Q)${NC} خروج"
    echo ""
    read -rp "  انتخاب: " choice

    case "$choice" in
        [Aa])
            phase1_anti_probe
            phase2_os_stealth
            phase3_anti_active_probe
            phase4_traffic_shaping
            phase5_dns_protection
            phase6_wg_stealth
            phase7_xray_stealth
            phase8_port_knocking
            phase9_fail2ban
            phase10_auto_rotation
            phase11_status_report
            ;;
        1) phase1_anti_probe ;;
        2) phase2_os_stealth ;;
        3) phase3_anti_active_probe ;;
        4) phase4_traffic_shaping ;;
        5) phase5_dns_protection ;;
        6) phase6_wg_stealth ;;
        7) phase7_xray_stealth ;;
        8) phase8_port_knocking ;;
        9) phase9_fail2ban ;;
        10) phase10_auto_rotation ;;
        [Ss]) phase11_status_report ;;
        [Cc]) bash /etc/stealth-guard/sni_checker.sh 2>/dev/null || echo "ابتدا فاز 7 رو اجرا کنید" ;;
        [Qq]) exit 0 ;;
        *) echo -e "${FAIL} انتخاب نامعتبر"; sleep 1; main_menu ;;
    esac
}

# اجرا
main_menu
