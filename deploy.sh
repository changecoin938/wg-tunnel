#!/bin/bash
# ============================================================================
# deploy.sh — استقرار تانل نامرئی
# ============================================================================
# سرور خارج:  sudo ./deploy.sh server [PSK] [PORT]
# سرور ایران: sudo ./deploy.sh relay FOREIGN_IP [PSK] [REMOTE_PORT] [LOCAL_PORT]
# حذف:        sudo ./deploy.sh remove
# وضعیت:      sudo ./deploy.sh status
# ============================================================================

set -euo pipefail

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; W='\033[1;37m'; NC='\033[0m'
OK="${G}✓${NC}"; FAIL="${R}✗${NC}"; WARN="${Y}⚠${NC}"

BIN="cloud-agent"
CONF="/etc/cloud-agent"
SVC="cloud-agent"
INSTALL="/usr/local/bin"

log() { echo -e "  $1 $2"; }

banner() {
    clear 2>/dev/null || true
    echo -e "${C}"
    echo "  ┌──────────────────────────────────┐"
    echo "  │       Cloud Agent Deploy          │"
    echo "  └──────────────────────────────────┘"
    echo -e "${NC}"
}

check_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${FAIL} sudo لازمه"; exit 1; }
}

check_systemd() {
    command -v systemctl >/dev/null 2>&1 || { echo -e "${FAIL} systemctl پیدا نشد (نیاز به systemd)"; exit 1; }
}

install_deps() {
    log "$OK" "نصب پیش‌نیازها..."
    export DEBIAN_FRONTEND=noninteractive
    command -v apt-get >/dev/null 2>&1 || { echo -e "${FAIL} فقط Debian/Ubuntu (apt-get) پشتیبانی میشه"; exit 1; }
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq gcc make libssl-dev openssl curl iptables ca-certificates binutils >/dev/null 2>&1
    log "$OK" "نصب شد"
}

compile() {
    log "$OK" "کامپایل..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SRC=""
    [[ -f "$SCRIPT_DIR/stealth_tunnel.c" ]] && SRC="$SCRIPT_DIR/stealth_tunnel.c"
    [[ -z "$SRC" && -f "./stealth_tunnel.c" ]] && SRC="./stealth_tunnel.c"
    [[ -z "$SRC" ]] && { echo -e "${FAIL} stealth_tunnel.c پیدا نشد"; exit 1; }

    TMPDIR=$(mktemp -d)
    cp "$SRC" "$TMPDIR/"
    cd "$TMPDIR"
    gcc -O2 -Wall -pthread -D_GNU_SOURCE -o "$BIN" stealth_tunnel.c -lssl -lcrypto -lpthread
    strip -s "$BIN" 2>/dev/null || true
    install -d "$INSTALL"
    install -m 755 "$BIN" "${INSTALL}/${BIN}"
    cd / && rm -rf "$TMPDIR"

    log "$OK" "باینری: ${INSTALL}/${BIN} ($(du -h ${INSTALL}/${BIN} | cut -f1))"
    if command -v strings >/dev/null 2>&1; then
        if strings "${INSTALL}/${BIN}" | grep -qiE 'wireguard|vpn|wg0'; then
            log "$WARN" "string مشکوک!"
        else
            log "$OK" "باینری تمیز"
        fi
    else
        log "$WARN" "strings پیدا نشد (binutils)"
    fi
}

generate_cert() {
    mkdir -p "$CONF"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CONF/key.pem" -out "$CONF/cert.pem" \
        -days 3650 -nodes \
        -subj "/C=US/O=CloudTech Solutions/CN=cloudtech.solutions" 2>/dev/null
    chmod 600 "$CONF/key.pem"
    log "$OK" "سرتیفیکیت TLS ساخته شد"
}

setup_server() {
    local PSK="${1:-$(openssl rand -hex 32)}"
    local PORT="${2:-443}"
    local TARGET="${3:-51820}"

    mkdir -p "$CONF"
    generate_cert
    echo "$PSK" > "$CONF/psk.txt"
    chmod 600 "$CONF/psk.txt"

    cat > /etc/systemd/system/${SVC}.service << EOF
[Unit]
Description=Cloud Agent Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL}/${BIN} -m server -l ${PORT} -t ${TARGET} -f ${CONF}/psk.txt -P
Restart=always
RestartSec=10
LimitNOFILE=65535
StandardOutput=append:/var/log/cloud-agent.log
StandardError=append:/var/log/cloud-agent.log
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SVC" >/dev/null 2>&1
    systemctl start "$SVC"
    iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true

    sleep 2
    if systemctl is-active --quiet "$SVC"; then
        log "$OK" "سرور فعال شد"
    else
        log "$FAIL" "خطا"
        journalctl -u "$SVC" --no-pager -n 5
    fi

    IP=$(curl -s4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    echo ""
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${W}  اطلاعات اتصال${NC}"
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  IP:   ${G}${IP}${NC}"
    echo -e "  Port: ${G}${PORT}${NC}"
    echo -e "  PSK:  ${Y}${PSK}${NC}"
    echo -e ""
    echo -e "  ${W}دستور نصب سرور ایران:${NC}"
    echo -e "  sudo ./deploy.sh relay ${IP} ${PSK}"
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

setup_relay() {
    local REMOTE="${1:?IP سرور خارج لازمه}"
    local PSK="${2:-}"
    local RPORT="${3:-443}"
    local LPORT="${4:-51820}"

    mkdir -p "$CONF"
    [[ -n "$PSK" ]] && echo "$PSK" > "$CONF/psk.txt" && chmod 600 "$CONF/psk.txt"
    local PSK_ARG=""
    [[ -n "$PSK" ]] && PSK_ARG="-f ${CONF}/psk.txt"

    cat > /etc/systemd/system/${SVC}.service << EOF
[Unit]
Description=Cloud Agent Service
After=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL}/${BIN} -m client -r ${REMOTE}:${RPORT} -l ${LPORT} ${PSK_ARG} -P
Restart=always
RestartSec=10
LimitNOFILE=65535
StandardOutput=append:/var/log/cloud-agent.log
StandardError=append:/var/log/cloud-agent.log
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SVC" >/dev/null 2>&1
    systemctl start "$SVC"
    iptables -C INPUT -p udp --dport "$LPORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p udp --dport "$LPORT" -j ACCEPT 2>/dev/null || true

    sleep 2
    systemctl is-active --quiet "$SVC" && log "$OK" "ریلی فعال شد" || log "$FAIL" "خطا"

    echo ""
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Local:  ${G}UDP :${LPORT}${NC}"
    echo -e "  Remote: ${G}TLS ${REMOTE}:${RPORT}${NC}"
    echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # بررسی امنیتی
    echo ""
    command -v wg &>/dev/null && log "$WARN" "WireGuard نصبه! حذفش کن" || log "$OK" "بدون WireGuard"
    ps aux | grep -E 'wg-quick|wireguard|openvpn|xray|v2ray' | grep -v grep >/dev/null 2>&1 \
        && log "$WARN" "پروسس VPN مشکوک!" || log "$OK" "پروسس تمیز"
}

remove_all() {
    systemctl stop "$SVC" 2>/dev/null || true
    systemctl disable "$SVC" 2>/dev/null || true
    rm -f /etc/systemd/system/${SVC}.service
    systemctl daemon-reload
    rm -f "${INSTALL}/${BIN}"
    rm -rf "$CONF"
    rm -f /var/log/cloud-agent.log
    log "$OK" "حذف شد"
}

show_status() {
    echo ""
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SVC" 2>/dev/null; then
        echo -e "  سرویس: ${G}فعال${NC}"
    else
        echo -e "  سرویس: ${R}غیرفعال${NC}"
    fi
    pgrep -x "$BIN" >/dev/null 2>&1 && echo -e "  PID: ${G}$(pgrep -x $BIN | head -1)${NC}"
    if [[ -r /var/log/cloud-agent.log ]]; then
        echo ""
        tail -5 /var/log/cloud-agent.log 2>/dev/null | sed 's/^/    /' || true
    elif [[ -f /var/log/cloud-agent.log ]]; then
        echo ""
        echo -e "    ${Y}(برای دیدن لاگ با sudo اجرا کنید)${NC}"
    fi
    echo ""
}

cleanup_traces() {
    [[ "${CLEANUP_TRACES:-0}" == "1" ]] || return 0
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    rm -f "${SCRIPT_DIR}/stealth_tunnel.c" "${SCRIPT_DIR}/Makefile" 2>/dev/null || true
}

banner

case "${1:-}" in
    server)  check_root; check_systemd; install_deps; compile; setup_server "${2:-}" "${3:-443}" "${4:-51820}"; cleanup_traces ;;
    relay)   check_root; check_systemd; install_deps; compile; setup_relay "${2:-}" "${3:-}" "${4:-443}" "${5:-51820}"; cleanup_traces ;;
    remove)  check_root; check_systemd; remove_all ;;
    status)  show_status ;;
    *)
        echo "استفاده:"
        echo "  سرور خارج:  sudo ./deploy.sh server [PSK] [PORT] [WG_PORT]"
        echo "  سرور ایران: sudo ./deploy.sh relay FOREIGN_IP [PSK] [REMOTE_PORT] [LOCAL_PORT]"
        echo "  وضعیت:      sudo ./deploy.sh status"
        echo "  حذف:        sudo ./deploy.sh remove"
        echo ""
        echo "  (اختیاری) پاکسازی سورس بعد از نصب:"
        echo "    CLEANUP_TRACES=1 sudo ./deploy.sh server"
        ;;
esac
