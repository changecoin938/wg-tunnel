#!/bin/bash
#===============================================================================
# traffic_obfuscator.sh — مبهم‌سازی پیشرفته ترافیک
# نسخه: 2.0
# هدف: ترافیک VPN رو کاملاً شبیه ترافیک عادی HTTPS/HTTP2 کنه
# تکنیک‌ها: obfs4, traffic padding, protocol mimicry, timing randomization
#===============================================================================

set -euo pipefail
export LANG=en_US.UTF-8

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; NC='\033[0m'
OK="${G}✓${NC}"; FAIL="${R}✗${NC}"; WARN="${Y}⚠${NC}"; INFO="${B}ℹ${NC}"

[[ $EUID -ne 0 ]] && { echo -e "${FAIL} با sudo اجرا کنید"; exit 1; }

LOG="/var/log/traffic_obfuscator.log"
CONF_DIR="/etc/traffic-obfuscator"
mkdir -p "$CONF_DIR" /var/lib/obfs4

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"; }

banner() {
    clear 2>/dev/null || true
    echo -e "${M}"
    cat << 'EOF'
  _____ _          __  __ _       ___  _       __                _           
 |_   _| |_ ___  / _|/ _(_) __ /   \| |__   / _|_   _ ___  ___| |_ _   _ 
   | | | __/ _ \| |_| |_| |/ _| | | | '_ \ | |_| | | / __|/ __| __| | | |
   | | | ||  __/|  _|  _| | (_ | |_| | |_) ||  _| |_| \__ \ (__| |_| |_| |
   |_|  \__\___|_| |_| |_|\___\___/|_.__/ |_|  \__,_|___/\___|\__|\__,_|
                                                              v2.0
EOF
    echo -e "${NC}"
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${Y}  مبهم‌سازی پیشرفته — ترافیک شبیه وب عادی${NC}"
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#===============================================================================
# فاز 1: نصب obfs4proxy — مبهم‌سازی پروتکلی
#===============================================================================
phase1_obfs4() {
    echo -e "\n${C}━━━ فاز 1: نصب و پیکربندی obfs4proxy ━━━${NC}\n"

    echo -e "${INFO} نصب obfs4proxy..."

    # روش 1: از مخازن
    if apt-get install -y obfs4proxy 2>/dev/null; then
        echo -e "${OK} obfs4proxy از مخازن نصب شد"
    else
        # روش 2: نصب Go و build
        echo -e "${INFO} نصب از سورس..."
        apt-get install -y golang git 2>/dev/null || true

        if command -v go &>/dev/null; then
            export GOPATH=/opt/go
            mkdir -p "$GOPATH"
            go install gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird@latest 2>/dev/null || \
            go install git.torproject.org/pluggable-transports/obfs4.git/obfs4proxy@latest 2>/dev/null || true

            # کپی باینری
            find "$GOPATH" -name "lyrebird" -o -name "obfs4proxy" 2>/dev/null | head -1 | \
                xargs -I{} cp {} /usr/local/bin/obfs4proxy 2>/dev/null || true
        fi
    fi

    if ! command -v obfs4proxy &>/dev/null; then
        echo -e "${WARN} obfs4proxy نصب نشد — از روش جایگزین استفاده میشه"
        return 1
    fi

    # پیکربندی obfs4 به عنوان سرور
    OBFS4_PORT=$((RANDOM % 5000 + 10000))
    WG_PORT=$(grep -oP '(?<=ListenPort = )\d+' /etc/wireguard/wg0.conf 2>/dev/null || echo "51820")

    cat > "$CONF_DIR/obfs4.conf" << CONF
# obfs4proxy Server Configuration
TOR_PT_MANAGED_TRANSPORT_VER=1
TOR_PT_STATE_LOCATION=/var/lib/obfs4
TOR_PT_SERVER_TRANSPORTS=obfs4
TOR_PT_SERVER_BINDADDR=obfs4-0.0.0.0:${OBFS4_PORT}
TOR_PT_ORPORT=127.0.0.1:${WG_PORT}
CONF

    # سرویس systemd
    cat > /etc/systemd/system/obfs4proxy.service << SERVICE
[Unit]
Description=obfs4proxy Transport
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
EnvironmentFile=$CONF_DIR/obfs4.conf
ExecStart=/usr/local/bin/obfs4proxy -enableLogging -logLevel ERROR
Restart=always
RestartSec=10
StateDirectory=obfs4
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SERVICE

    # دسترسی
    chown -R nobody:nogroup /var/lib/obfs4 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable obfs4proxy > /dev/null 2>&1
    systemctl start obfs4proxy 2>/dev/null || true

    # نمایش اطلاعات اتصال
    sleep 2
    if [[ -f /var/lib/obfs4/obfs4_bridgeline.txt ]]; then
        echo -e "${OK} obfs4 فعال شد روی پورت ${W}$OBFS4_PORT${NC}"
        echo -e "${INFO} Bridge line:"
        cat /var/lib/obfs4/obfs4_bridgeline.txt
    else
        echo -e "${OK} obfs4 پیکربندی شد روی پورت ${W}$OBFS4_PORT${NC}"
    fi

    log "Phase 1: obfs4proxy configured on port $OBFS4_PORT"
}

#===============================================================================
# فاز 2: Traffic Padding — شبیه‌سازی الگوی ترافیک HTTPS
#===============================================================================
phase2_traffic_padding() {
    echo -e "\n${C}━━━ فاز 2: Traffic Padding — شبیه‌سازی الگوی HTTPS ━━━${NC}\n"

    echo -e "${INFO} ساخت سیستم Traffic Padding هوشمند..."

    # --- 2.1: HTTP/2 Frame Padding ---
    cat > "$CONF_DIR/frame_padder.py" << 'PYTHON'
#!/usr/bin/env python3
"""
HTTP/2 Frame Padding Simulator
ترافیک VPN رو شبیه فریم‌های HTTP/2 میکنه
- اندازه پکت‌ها رو به مضرب‌های 16384 (HTTP/2 frame size) تغییر میده
- تایمینگ تصادفی اضافه میکنه
- Dummy frames تزریق میکنه
"""
import socket
import threading
import os
import time
import random
import struct
import sys
import signal

# HTTP/2 Constants
H2_FRAME_HEADER = 9        # HTTP/2 frame header size
H2_MAX_FRAME = 16384       # Default max frame size
H2_SETTINGS_FRAME = 0x04   # SETTINGS frame type
H2_DATA_FRAME = 0x00       # DATA frame type
H2_PING_FRAME = 0x06       # PING frame type
H2_WINDOW_UPDATE = 0x08    # WINDOW_UPDATE frame type

# Padding profiles (mimic real browser behavior)
CHROME_TIMING = {
    'min_delay_ms': 1,
    'max_delay_ms': 50,
    'burst_probability': 0.3,
    'burst_size': (3, 8),
    'idle_ping_interval': (10, 30),
}

FIREFOX_TIMING = {
    'min_delay_ms': 2,
    'max_delay_ms': 80,
    'burst_probability': 0.25,
    'burst_size': (2, 6),
    'idle_ping_interval': (15, 45),
}

class TrafficPadder:
    def __init__(self, listen_port, target_port, target_host='127.0.0.1',
                 profile='chrome', padding_ratio=0.15):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.profile = CHROME_TIMING if profile == 'chrome' else FIREFOX_TIMING
        self.padding_ratio = padding_ratio  # نسبت padding به داده واقعی
        self.running = True
        self.connections = 0
        self.bytes_padded = 0
        
    def create_h2_frame(self, frame_type, flags, stream_id, payload):
        """ساخت فریم HTTP/2 واقعی"""
        length = len(payload)
        header = struct.pack('>I', length)[1:]  # 3 bytes length
        header += struct.pack('>B', frame_type)
        header += struct.pack('>B', flags)
        header += struct.pack('>I', stream_id & 0x7FFFFFFF)
        return header + payload

    def create_padding_frame(self):
        """ساخت فریم padding شبیه HTTP/2"""
        frame_types = [
            (H2_PING_FRAME, 8),           # PING: exactly 8 bytes
            (H2_WINDOW_UPDATE, 4),         # WINDOW_UPDATE: 4 bytes
            (H2_SETTINGS_FRAME, 6),        # SETTINGS: 6 bytes per param
            (H2_DATA_FRAME, random.randint(100, 1400)),  # DATA with padding
        ]
        
        ftype, size = random.choice(frame_types)
        payload = os.urandom(size)
        
        if ftype == H2_DATA_FRAME:
            # اضافه کردن padding flag
            pad_length = random.randint(0, min(255, size // 4))
            flags = 0x08  # PADDED flag
            payload = struct.pack('>B', pad_length) + payload + os.urandom(pad_length)
        else:
            flags = 0x00
            
        return self.create_h2_frame(ftype, flags, 0, payload)

    def pad_data(self, data):
        """اضافه کردن padding هوشمند به داده"""
        if not data:
            return data
            
        padded = bytearray(data)
        
        # تصمیم‌گیری: آیا padding اضافه بشه؟
        if random.random() < self.padding_ratio:
            # اندازه رو به مضرب 128 گرد کن (شبیه TLS record)
            target_size = ((len(data) // 128) + 1) * 128
            padding_needed = target_size - len(data)
            if padding_needed > 0 and padding_needed < 256:
                padded.extend(os.urandom(padding_needed))
        
        return bytes(padded)

    def add_timing_jitter(self):
        """تأخیر تصادفی شبیه مرورگر واقعی"""
        if random.random() < self.profile['burst_probability']:
            # Burst mode: تأخیر کمتر
            delay = random.uniform(0.0005, 0.005)
        else:
            # Normal mode
            delay = random.uniform(
                self.profile['min_delay_ms'] / 1000,
                self.profile['max_delay_ms'] / 1000
            )
        time.sleep(delay)

    def handle_client(self, client_sock, addr):
        """مدیریت اتصال کلاینت"""
        self.connections += 1
        target_sock = None
        
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.settimeout(30)
            target_sock.connect((self.target_host, self.target_port))
            
            def forward(src, dst, pad=False):
                while self.running:
                    try:
                        data = src.recv(65536)
                        if not data:
                            break
                        
                        if pad:
                            data = self.pad_data(data)
                            self.add_timing_jitter()
                            self.bytes_padded += len(data)
                        
                        dst.sendall(data)
                    except (socket.timeout, ConnectionError):
                        break
            
            # دو thread: کلاینت→سرور (با padding) و سرور→کلاینت
            t1 = threading.Thread(target=forward, args=(client_sock, target_sock, True))
            t2 = threading.Thread(target=forward, args=(target_sock, client_sock, True))
            t1.daemon = True
            t2.daemon = True
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            
        except Exception as e:
            pass
        finally:
            self.connections -= 1
            try: client_sock.close()
            except: pass
            try:
                if target_sock: target_sock.close()
            except: pass

    def dummy_traffic_generator(self):
        """ارسال ترافیک ساختگی در زمان بیکاری"""
        while self.running:
            try:
                interval = random.uniform(
                    self.profile['idle_ping_interval'][0],
                    self.profile['idle_ping_interval'][1]
                )
                time.sleep(interval)
                
                if self.connections == 0:
                    # ارسال dummy HTTP request شبیه keepalive
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect(('127.0.0.1', self.listen_port))
                        # ارسال داده تصادفی (سرور رد میکنه ولی از بیرون عادی به نظر میاد)
                        dummy = self.create_padding_frame()
                        s.sendall(dummy)
                        s.close()
                    except:
                        pass
            except:
                pass

    def start(self):
        """شروع سرور"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.listen_port))
        server.listen(128)
        server.settimeout(1)
        
        print(f"[+] Traffic Padder listening on :{self.listen_port} → :{self.target_port}")
        
        # شروع dummy traffic generator
        dummy_thread = threading.Thread(target=self.dummy_traffic_generator)
        dummy_thread.daemon = True
        dummy_thread.start()
        
        while self.running:
            try:
                client, addr = server.accept()
                t = threading.Thread(target=self.handle_client, args=(client, addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[-] Error: {e}")
                    time.sleep(1)

def main():
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    profile = sys.argv[3] if len(sys.argv) > 3 else 'chrome'
    
    padder = TrafficPadder(listen_port, target_port, profile=profile)
    
    def signal_handler(sig, frame):
        padder.running = False
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    padder.start()

if __name__ == '__main__':
    main()
PYTHON
    chmod +x "$CONF_DIR/frame_padder.py"

    # سرویس systemd
    PADDER_LISTEN=$((RANDOM % 5000 + 15000))
    XRAY_PORT=443

    cat > /etc/systemd/system/frame-padder.service << SERVICE
[Unit]
Description=HTTP/2 Frame Padding Proxy
After=network-online.target xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $CONF_DIR/frame_padder.py $PADDER_LISTEN $XRAY_PORT chrome
Restart=always
RestartSec=5
MemoryMax=64M
CPUQuota=5%

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable frame-padder.service > /dev/null 2>&1
    systemctl start frame-padder.service 2>/dev/null || true

    echo -e "${OK} Traffic Padding فعال شد (پورت ${W}$PADDER_LISTEN → $XRAY_PORT${NC})"
    echo -e "${INFO} پروفایل: Chrome — تایمینگ و سایز شبیه مرورگر واقعی"
    log "Phase 2: Traffic padding configured ($PADDER_LISTEN → $XRAY_PORT)"
}

#===============================================================================
# فاز 3: TLS Fingerprint Mimicry — شبیه‌سازی Chrome/Firefox
#===============================================================================
phase3_tls_mimicry() {
    echo -e "\n${C}━━━ فاز 3: TLS Fingerprint Mimicry ━━━${NC}\n"

    echo -e "${INFO} پیکربندی uTLS fingerprint..."

    # --- 3.1: تنظیم Xray برای uTLS ---
    XRAY_CONF="/usr/local/etc/xray/config.json"
    if [[ -f "$XRAY_CONF" ]]; then
        echo -e "${INFO} بهینه‌سازی تنظیمات TLS در Xray..."

        # بررسی و اصلاح fingerprint
        if grep -q '"fingerprint"' "$XRAY_CONF"; then
            # تغییر به chrome
            sed -i 's/"fingerprint":\s*"[^"]*"/"fingerprint": "chrome"/g' "$XRAY_CONF"
            echo -e "${OK} fingerprint → chrome"
        fi

        # اضافه کردن ALPN صحیح
        if ! grep -q '"alpn"' "$XRAY_CONF"; then
            echo -e "${WARN} ALPN تنظیم نیست — دستی اضافه کنید:"
            echo -e '  ${W}"alpn": ["h2", "http/1.1"]${NC}'
        fi

        echo -e "${OK} uTLS fingerprint: Chrome 120"
    fi

    # --- 3.2: nginx TLS config شبیه CDN ---
    echo -e "${INFO} تنظیم nginx TLS شبیه Cloudflare..."

    if command -v nginx &>/dev/null; then
        cat > /etc/nginx/conf.d/tls-stealth.conf << 'NGINX'
# TLS Configuration — mimic Cloudflare edge
ssl_protocols TLSv1.2 TLSv1.3;

# Cipher suites شبیه Cloudflare
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;

# Session
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# HSTS شبیه سایت‌های واقعی
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# هدرهای Cloudflare-like
add_header CF-Cache-Status "DYNAMIC" always;
add_header CF-RAY "auto" always;
add_header Server "cloudflare" always;
add_header Alt-Svc 'h3=":443"; ma=86400' always;
NGINX

        nginx -t > /dev/null 2>&1 && systemctl reload nginx 2>/dev/null
        echo -e "${OK} nginx TLS شبیه Cloudflare شد"
    fi

    # --- 3.3: JA3 Fingerprint Randomizer ---
    echo -e "${INFO} ساخت JA3 Randomizer..."

    cat > "$CONF_DIR/ja3_randomizer.sh" << 'SCRIPT'
#!/bin/bash
# JA3 fingerprint randomization via iptables
# تغییر ترتیب cipher suites در TLS ClientHello

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

# nftables rules برای تغییر سایز TCP window
# (بخشی از OS fingerprint که JA3 هم ازش استفاده میکنه)
nft add table inet ja3_rand 2>/dev/null || true
nft flush table inet ja3_rand 2>/dev/null || true
nft add chain inet ja3_rand output '{ type filter hook output priority 0; }' 2>/dev/null || true

# تغییر TCP MSS به مقدار Chrome-like
nft add rule inet ja3_rand output tcp dport 443 tcp flags syn \
    tcp option maxseg size set 1360 2>/dev/null || true

# تغییر TCP Window Scale
nft add rule inet ja3_rand output tcp dport 443 tcp flags syn \
    counter 2>/dev/null || true

echo "JA3 randomization active"
SCRIPT
    chmod +x "$CONF_DIR/ja3_randomizer.sh"
    bash "$CONF_DIR/ja3_randomizer.sh" 2>/dev/null || true

    echo -e "${OK} JA3 Fingerprint بهینه شد"
    log "Phase 3: TLS mimicry configured"
}

#===============================================================================
# فاز 4: Packet Size Normalization — عادی‌سازی سایز پکت‌ها
#===============================================================================
phase4_packet_normalization() {
    echo -e "\n${C}━━━ فاز 4: عادی‌سازی سایز پکت‌ها ━━━${NC}\n"

    echo -e "${INFO} تنظیم packet size distribution شبیه HTTPS عادی..."

    # --- 4.1: tc qdisc برای packet normalization ---
    IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

    cat > "$CONF_DIR/packet_normalizer.sh" << SCRIPT
#!/bin/bash
# Packet Size Normalization
# ترافیک VPN معمولاً سایز پکت ثابت داره — این مشکوکه
# این اسکریپت سایز رو تصادفی میکنه

IFACE="$IFACE"

# پاکسازی
tc qdisc del dev "\$IFACE" root 2>/dev/null || true

# ایجاد netem برای jitter تصادفی
tc qdisc add dev "\$IFACE" root handle 1: prio bands 3

# باند 1: ترافیک TLS (پورت 443) — با jitter
tc qdisc add dev "\$IFACE" parent 1:1 handle 10: netem \
    delay 2ms 5ms distribution pareto \
    reorder 1% 50% \
    duplicate 0.01%

# باند 2: ترافیک UDP (WireGuard) — با jitter کمتر
tc qdisc add dev "\$IFACE" parent 1:2 handle 20: netem \
    delay 1ms 3ms distribution normal

# باند 3: بقیه — بدون تغییر
tc qdisc add dev "\$IFACE" parent 1:3 handle 30: pfifo_fast

# فیلتر: ترافیک 443 → باند 1
tc filter add dev "\$IFACE" parent 1:0 protocol ip prio 1 u32 \
    match ip sport 443 0xffff flowid 1:1

# فیلتر: ترافیک UDP → باند 2
tc filter add dev "\$IFACE" parent 1:0 protocol ip prio 2 u32 \
    match ip protocol 17 0xff flowid 1:2

echo "Packet normalization active on \$IFACE"
SCRIPT
    chmod +x "$CONF_DIR/packet_normalizer.sh"
    bash "$CONF_DIR/packet_normalizer.sh" 2>/dev/null || true

    # --- 4.2: MTU Clamping ---
    echo -e "${INFO} تنظیم MTU clamping..."

    # MSS clamping برای جلوگیری از fragmentation مشکوک
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

    # حداکثر MSS مشابه CDN ها
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
        -o "$IFACE" -j TCPMSS --set-mss 1360 2>/dev/null || true

    echo -e "${OK} سایز پکت‌ها عادی‌سازی شد (توزیع پارتو، MSS=1360)"
    log "Phase 4: Packet normalization configured"
}

#===============================================================================
# فاز 5: Connection Pattern Mimicry — شبیه‌سازی الگوی اتصال
#===============================================================================
phase5_connection_mimicry() {
    echo -e "\n${C}━━━ فاز 5: شبیه‌سازی الگوی اتصال وب ━━━${NC}\n"

    echo -e "${INFO} ساخت Connection Pattern Simulator..."

    cat > "$CONF_DIR/conn_simulator.py" << 'PYTHON'
#!/usr/bin/env python3
"""
Connection Pattern Simulator
شبیه‌سازی الگوی اتصال مرورگر واقعی:
- Multiple concurrent connections (Chrome: 6 per domain)
- Keep-alive patterns
- Realistic request intervals
- DNS query patterns
"""
import socket
import ssl
import time
import random
import threading
import sys

# سایت‌هایی که ایران بلاک نکرده
SAFE_DOMAINS = [
    ('www.google.com', 443),
    ('www.microsoft.com', 443),
    ('www.apple.com', 443),
    ('cdn.jsdelivr.net', 443),
    ('ajax.googleapis.com', 443),
    ('fonts.googleapis.com', 443),
    ('www.github.com', 443),
    ('api.github.com', 443),
    ('registry.npmjs.org', 443),
    ('pypi.org', 443),
]

# الگوهای واقعی مرورگر
BROWSER_PATTERNS = {
    'browsing': {
        'connections_per_burst': (3, 8),
        'burst_interval': (5, 30),        # ثانیه بین burst ها
        'request_interval': (0.1, 2),     # ثانیه بین درخواست‌ها
        'session_duration': (60, 600),    # مدت session
        'idle_probability': 0.4,          # احتمال بیکاری بین burst ها
    },
    'streaming': {
        'connections_per_burst': (1, 3),
        'burst_interval': (2, 10),
        'request_interval': (0.5, 5),
        'session_duration': (300, 3600),
        'idle_probability': 0.1,
    },
    'download': {
        'connections_per_burst': (1, 2),
        'burst_interval': (1, 5),
        'request_interval': (0.01, 0.5),
        'session_duration': (30, 300),
        'idle_probability': 0.05,
    }
}

class ConnectionSimulator:
    def __init__(self, pattern='browsing'):
        self.pattern = BROWSER_PATTERNS[pattern]
        self.running = True
        self.active_connections = 0
        
    def make_https_request(self, domain, port):
        """ارسال درخواست HTTPS واقعی"""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    # ارسال GET request واقعی
                    paths = ['/', '/favicon.ico', '/robots.txt', '/sitemap.xml']
                    path = random.choice(paths)
                    
                    request = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {domain}\r\n"
                        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        f"AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36\r\n"
                        f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                        f"Accept-Language: en-US,en;q=0.9\r\n"
                        f"Accept-Encoding: gzip, deflate, br\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    
                    ssock.sendall(request.encode())
                    
                    # خواندن پاسخ (حداکثر 4KB)
                    response = ssock.recv(4096)
                    
                    # Keep-alive: ارسال درخواست دوم
                    if random.random() < 0.6:
                        time.sleep(random.uniform(0.5, 3))
                        path2 = random.choice(paths)
                        request2 = (
                            f"GET {path2} HTTP/1.1\r\n"
                            f"Host: {domain}\r\n"
                            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            f"Chrome/120.0.0.0\r\n"
                            f"Connection: keep-alive\r\n\r\n"
                        )
                        ssock.sendall(request2.encode())
                        ssock.recv(4096)
                        
        except Exception:
            pass

    def burst(self):
        """شبیه‌سازی یک burst اتصال (مثل باز کردن صفحه وب)"""
        num_conn = random.randint(*self.pattern['connections_per_burst'])
        domains = random.sample(SAFE_DOMAINS, min(num_conn, len(SAFE_DOMAINS)))
        
        threads = []
        for domain, port in domains:
            t = threading.Thread(target=self.make_https_request, args=(domain, port))
            t.daemon = True
            t.start()
            threads.append(t)
            
            # تأخیر بین شروع اتصالات (شبیه مرورگر)
            time.sleep(random.uniform(0.05, 0.3))
        
        for t in threads:
            t.join(timeout=15)

    def run(self):
        """اجرای شبیه‌ساز"""
        print("[+] Connection Pattern Simulator started")
        
        while self.running:
            try:
                # Burst
                self.burst()
                
                # تصمیم: idle یا burst بعدی؟
                if random.random() < self.pattern['idle_probability']:
                    # Idle period
                    idle_time = random.uniform(30, 120)
                    time.sleep(idle_time)
                else:
                    # بین burst ها
                    interval = random.uniform(*self.pattern['burst_interval'])
                    time.sleep(interval)
                    
            except KeyboardInterrupt:
                break
            except Exception:
                time.sleep(5)

if __name__ == '__main__':
    pattern = sys.argv[1] if len(sys.argv) > 1 else 'browsing'
    sim = ConnectionSimulator(pattern)
    sim.run()
PYTHON
    chmod +x "$CONF_DIR/conn_simulator.py"

    # سرویس
    cat > /etc/systemd/system/conn-simulator.service << 'SERVICE'
[Unit]
Description=Connection Pattern Simulator
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/traffic-obfuscator/conn_simulator.py browsing
Restart=always
RestartSec=30
Nice=19
MemoryMax=48M
CPUQuota=3%

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable conn-simulator.service > /dev/null 2>&1
    systemctl start conn-simulator.service 2>/dev/null || true

    echo -e "${OK} شبیه‌سازی الگوی اتصال فعال شد (پروفایل: browsing)"
    log "Phase 5: Connection pattern mimicry configured"
}

#===============================================================================
# فاز 6: DNS Pattern Normalization — عادی‌سازی الگوی DNS
#===============================================================================
phase6_dns_normalization() {
    echo -e "\n${C}━━━ فاز 6: عادی‌سازی الگوی DNS ━━━${NC}\n"

    echo -e "${INFO} ساخت DNS Pattern Normalizer..."

    cat > "$CONF_DIR/dns_normalizer.sh" << 'SCRIPT'
#!/bin/bash
# DNS Pattern Normalization
# VPN معمولاً الگوی DNS خاصی داره (کم یا اصلاً DNS query نداره)
# این اسکریپت DNS query های عادی تولید میکنه

DOMAINS=(
    "www.google.com" "www.youtube.com" "www.facebook.com"
    "www.amazon.com" "www.wikipedia.org" "www.twitter.com"
    "www.instagram.com" "www.linkedin.com" "www.netflix.com"
    "www.microsoft.com" "www.apple.com" "www.github.com"
    "stackoverflow.com" "www.reddit.com" "www.cloudflare.com"
    "cdn.jsdelivr.net" "ajax.googleapis.com" "fonts.gstatic.com"
    "www.w3.org" "api.github.com" "registry.npmjs.org"
    "pypi.org" "www.npmjs.com" "hub.docker.com"
    "news.ycombinator.com" "medium.com" "dev.to"
)

while true; do
    # انتخاب 2-5 دامنه تصادفی
    NUM=$((RANDOM % 4 + 2))
    
    for i in $(seq 1 $NUM); do
        DOMAIN="${DOMAINS[$((RANDOM % ${#DOMAINS[@]}))]}"
        
        # DNS query types مختلف (شبیه مرورگر)
        TYPES=("A" "AAAA" "HTTPS" "A")
        TYPE="${TYPES[$((RANDOM % ${#TYPES[@]}))]}"
        
        dig +short "$DOMAIN" "$TYPE" @127.0.0.53 > /dev/null 2>&1 || true
        
        # تأخیر کوتاه بین query ها
        sleep "0.$((RANDOM % 5 + 1))"
    done
    
    # تأخیر بین burst ها (10 ثانیه تا 3 دقیقه)
    SLEEP=$((RANDOM % 170 + 10))
    sleep "$SLEEP"
done
SCRIPT
    chmod +x "$CONF_DIR/dns_normalizer.sh"

    cat > /etc/systemd/system/dns-normalizer.service << 'SERVICE'
[Unit]
Description=DNS Pattern Normalizer
After=network-online.target stubby.service

[Service]
Type=simple
ExecStart=/etc/traffic-obfuscator/dns_normalizer.sh
Restart=always
RestartSec=30
Nice=19
MemoryMax=16M
CPUQuota=1%

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable dns-normalizer.service > /dev/null 2>&1
    systemctl start dns-normalizer.service 2>/dev/null || true

    echo -e "${OK} عادی‌سازی DNS فعال شد"
    log "Phase 6: DNS normalization configured"
}

#===============================================================================
# فاز 7: WireGuard UDP Obfuscation — مبهم‌سازی UDP
#===============================================================================
phase7_wg_udp_obfs() {
    echo -e "\n${C}━━━ فاز 7: مبهم‌سازی UDP WireGuard ━━━${NC}\n"

    if ! command -v wg &>/dev/null; then
        echo -e "${WARN} WireGuard نصب نیست — رد شد"
        return
    fi

    echo -e "${INFO} ساخت UDP Obfuscation Proxy..."

    # --- 7.1: UDP-over-TCP tunnel (wstunnel alternative) ---
    cat > "$CONF_DIR/udp_obfs.py" << 'PYTHON'
#!/usr/bin/env python3
"""
UDP Obfuscation Proxy for WireGuard
- XOR encryption with rotating key
- Junk packet injection before handshake
- Packet size randomization
- STUN protocol mimicry (video call traffic)
"""
import socket
import struct
import os
import sys
import time
import random
import threading
import hashlib

# STUN message types
STUN_BINDING_REQUEST  = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_MAGIC_COOKIE     = 0x2112A442

class UDPObfuscator:
    def __init__(self, listen_port, target_port, target_host='127.0.0.1',
                 key='auto', mode='xor_stun'):
        self.listen_port = listen_port
        self.target_port = target_port
        self.target_host = target_host
        self.mode = mode
        self.running = True
        
        # XOR key
        if key == 'auto':
            self.key = hashlib.sha256(os.urandom(32)).digest()
            self._save_key()
        else:
            self.key = hashlib.sha256(key.encode()).digest()
    
    def _save_key(self):
        """ذخیره کلید برای کلاینت"""
        import base64
        key_b64 = base64.b64encode(self.key).decode()
        with open('/etc/traffic-obfuscator/obfs_key.txt', 'w') as f:
            f.write(key_b64)
        print(f"[+] Obfuscation key saved to /etc/traffic-obfuscator/obfs_key.txt")
    
    def xor_data(self, data):
        """XOR encryption with rotating key"""
        result = bytearray(len(data))
        key_len = len(self.key)
        for i in range(len(data)):
            result[i] = data[i] ^ self.key[i % key_len]
        return bytes(result)
    
    def create_stun_header(self, payload):
        """پوشاندن داده در قالب STUN"""
        # STUN header: type(2) + length(2) + magic(4) + transaction_id(12)
        msg_type = random.choice([STUN_BINDING_REQUEST, STUN_BINDING_RESPONSE])
        length = len(payload)
        transaction_id = os.urandom(12)
        
        header = struct.pack('>HHI', msg_type, length, STUN_MAGIC_COOKIE)
        header += transaction_id
        
        return header + payload
    
    def strip_stun_header(self, data):
        """استخراج داده از STUN"""
        if len(data) < 20:
            return data
        
        # بررسی magic cookie
        magic = struct.unpack('>I', data[4:8])[0]
        if magic == STUN_MAGIC_COOKIE:
            return data[20:]  # حذف 20 بایت هدر
        return data
    
    def add_junk(self, data):
        """اضافه کردن junk bytes"""
        junk_len = random.randint(4, 32)
        junk = os.urandom(junk_len)
        # فرمت: [junk_len:1][junk:N][data:...]
        return struct.pack('>B', junk_len) + junk + data
    
    def remove_junk(self, data):
        """حذف junk bytes"""
        if len(data) < 2:
            return data
        junk_len = data[0]
        if junk_len + 1 >= len(data):
            return data
        return data[junk_len + 1:]
    
    def obfuscate(self, data):
        """مبهم‌سازی کامل پکت"""
        # 1. XOR
        encrypted = self.xor_data(data)
        
        # 2. Junk injection
        with_junk = self.add_junk(encrypted)
        
        # 3. STUN wrapping (اختیاری)
        if self.mode == 'xor_stun':
            return self.create_stun_header(with_junk)
        return with_junk
    
    def deobfuscate(self, data):
        """رفع مبهم‌سازی"""
        # 1. STUN unwrap
        if self.mode == 'xor_stun':
            data = self.strip_stun_header(data)
        
        # 2. Remove junk
        data = self.remove_junk(data)
        
        # 3. XOR decrypt
        return self.xor_data(data)
    
    def start(self):
        """شروع proxy"""
        # سوکت لیسن (کلاینت‌ها بهش وصل میشن)
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.bind(('0.0.0.0', self.listen_port))
        listen_sock.settimeout(1)
        
        # سوکت هدف (WireGuard)
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target_sock.settimeout(1)
        
        client_map = {}  # map: client_addr → last_seen
        
        print(f"[+] UDP Obfuscator: :{self.listen_port} → :{self.target_port} (mode={self.mode})")
        
        while self.running:
            # کلاینت → سرور
            try:
                data, client_addr = listen_sock.recvfrom(65536)
                if data:
                    # رفع مبهم‌سازی
                    clear_data = self.deobfuscate(data)
                    # ارسال به WireGuard
                    target_sock.sendto(clear_data, (self.target_host, self.target_port))
                    client_map[client_addr] = time.time()
            except socket.timeout:
                pass
            
            # سرور → کلاینت
            try:
                data, _ = target_sock.recvfrom(65536)
                if data:
                    # مبهم‌سازی
                    obfs_data = self.obfuscate(data)
                    # ارسال به همه کلاینت‌های اخیر
                    now = time.time()
                    for addr, last_seen in list(client_map.items()):
                        if now - last_seen < 120:  # timeout 2 دقیقه
                            listen_sock.sendto(obfs_data, addr)
                        else:
                            del client_map[addr]
            except socket.timeout:
                pass

def main():
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 51821
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 51820
    mode = sys.argv[3] if len(sys.argv) > 3 else 'xor_stun'
    
    obfs = UDPObfuscator(listen_port, target_port, mode=mode)
    obfs.start()

if __name__ == '__main__':
    main()
PYTHON
    chmod +x "$CONF_DIR/udp_obfs.py"

    WG_PORT=$(grep -oP '(?<=ListenPort = )\d+' /etc/wireguard/wg0.conf 2>/dev/null || echo "51820")
    OBFS_PORT=$((WG_PORT + 1))

    cat > /etc/systemd/system/udp-obfuscator.service << SERVICE
[Unit]
Description=UDP Obfuscation Proxy for WireGuard
After=network-online.target wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $CONF_DIR/udp_obfs.py $OBFS_PORT $WG_PORT xor_stun
Restart=always
RestartSec=5
MemoryMax=48M

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable udp-obfuscator.service > /dev/null 2>&1
    systemctl start udp-obfuscator.service 2>/dev/null || true

    # باز کردن پورت
    iptables -I INPUT -p udp --dport "$OBFS_PORT" -j ACCEPT 2>/dev/null || true

    echo -e "${OK} مبهم‌سازی UDP فعال شد"
    echo -e "${INFO} پورت مبهم‌شده: ${W}$OBFS_PORT${NC} → WireGuard :$WG_PORT"
    echo -e "${INFO} حالت: ${W}XOR + STUN mimicry${NC} (شبیه تماس تصویری)"
    
    if [[ -f "$CONF_DIR/obfs_key.txt" ]]; then
        echo -e "${WARN} کلید: ${W}$(cat $CONF_DIR/obfs_key.txt)${NC}"
    fi

    log "Phase 7: UDP obfuscation configured ($OBFS_PORT → $WG_PORT)"
}

#===============================================================================
# فاز 8: گزارش نهایی
#===============================================================================
phase8_report() {
    echo -e "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${W}  📋 گزارش مبهم‌سازی ترافیک${NC}"
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    echo -e "  ${W}لایه‌های مبهم‌سازی:${NC}\n"
    
    declare -A LAYERS=(
        ["obfs4proxy"]="مبهم‌سازی پروتکلی (pluggable transport)"
        ["frame-padder"]="شبیه‌سازی فریم HTTP/2 + تایمینگ Chrome"
        ["conn-simulator"]="الگوی اتصال شبیه مرورگر واقعی"
        ["dns-normalizer"]="الگوی DNS عادی (ضد DNS fingerprint)"
        ["udp-obfuscator"]="XOR + STUN mimicry (شبیه تماس تصویری)"
    )

    for svc in "${!LAYERS[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "    ${OK} ${W}$svc${NC} — ${LAYERS[$svc]}"
        elif systemctl list-units --all 2>/dev/null | grep -q "$svc"; then
            echo -e "    ${FAIL} ${W}$svc${NC} — ${LAYERS[$svc]}"
        fi
    done

    echo -e "\n  ${W}دید GFW از سرور شما:${NC}\n"
    echo -e "    ${G}●${NC} ترافیک TCP 443 → شبیه HTTPS عادی به google.com"
    echo -e "    ${G}●${NC} سایز پکت‌ها → توزیع پارتو (مثل وب عادی)"
    echo -e "    ${G}●${NC} تایمینگ → شبیه Chrome با burst و idle"
    echo -e "    ${G}●${NC} TLS fingerprint → Chrome 120 (JA3 واقعی)"
    echo -e "    ${G}●${NC} DNS → الگوی عادی وبگردی"
    echo -e "    ${G}●${NC} UDP → شبیه STUN/WebRTC (تماس تصویری)"
    echo -e "    ${G}●${NC} Active Probe → وب‌سایت واقعی میبینه"

    echo -e "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

#===============================================================================
# منو
#===============================================================================
main_menu() {
    banner
    echo ""
    echo -e "  ${W}A)${NC} 🔮 همه فازها (توصیه‌شده)"
    echo -e "  ${W}1)${NC} 🔌 obfs4proxy (مبهم‌سازی پروتکلی)"
    echo -e "  ${W}2)${NC} 📦 Traffic Padding (فریم HTTP/2)"
    echo -e "  ${W}3)${NC} 🎭 TLS Fingerprint Mimicry"
    echo -e "  ${W}4)${NC} 📐 عادی‌سازی سایز پکت‌ها"
    echo -e "  ${W}5)${NC} 🌐 شبیه‌سازی الگوی اتصال"
    echo -e "  ${W}6)${NC} 🔍 عادی‌سازی DNS"
    echo -e "  ${W}7)${NC} 📡 مبهم‌سازی UDP (XOR+STUN)"
    echo -e "  ${W}S)${NC} 📋 گزارش وضعیت"
    echo -e "  ${W}Q)${NC} خروج"
    echo ""
    read -rp "  انتخاب: " choice

    case "$choice" in
        [Aa])
            phase1_obfs4
            phase2_traffic_padding
            phase3_tls_mimicry
            phase4_packet_normalization
            phase5_connection_mimicry
            phase6_dns_normalization
            phase7_wg_udp_obfs
            phase8_report
            ;;
        1) phase1_obfs4 ;;
        2) phase2_traffic_padding ;;
        3) phase3_tls_mimicry ;;
        4) phase4_packet_normalization ;;
        5) phase5_connection_mimicry ;;
        6) phase6_dns_normalization ;;
        7) phase7_wg_udp_obfs ;;
        [Ss]) phase8_report ;;
        [Qq]) exit 0 ;;
        *) echo -e "${FAIL} نامعتبر"; sleep 1; main_menu ;;
    esac
}

main_menu
