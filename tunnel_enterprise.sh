#!/usr/bin/env bash
# ============================================================================
#  tunnel_enterprise.sh — Enterprise Private Network Installer
#  Version : 2.0.0
#  License : MIT
#  Repo    : https://github.com/changecoin938/wg-tunnel
#
#  Architecture:
#
#   ┌──────────┐    Trojan/TLS    ┌────────────────┐   WireGuard    ┌────────────────┐
#   │  Client   │ ──────────────► │  Entry Server   │ ────────────► │  Exit Server    │
#   │ (v2rayNG) │    TCP:443      │  (Iran Node)    │   UDP:51820   │ (Foreign Node)  │
#   └──────────┘                  │                 │               │                 │
#                                 │ • Trojan Inbound│               │ • VLESS Reality │
#                                 │ • WG Client     │               │ • WG Server     │
#                                 │ • Traffic Fwd   │               │ • NAT Masquerade│
#                                 └────────────────┘               └────────────────┘
#
#  Usage:
#    bash tunnel_enterprise.sh
#    Option 1 → On Foreign/Exit server
#    Option 2 → On Iran/Entry server (paste pairing token from step 1)
#
# ============================================================================

set -euo pipefail

# ========================== CONSTANTS =======================================
readonly VERSION="2.0.0"
readonly CONFIG_DIR="/root/tunnel-config"
readonly LOG_FILE="/var/log/tunnel.log"
readonly WG_INTERFACE="wg0"
readonly WG_PORT=51820
readonly WG_SUBNET="10.66.66"
readonly WG_SERVER_IP="${WG_SUBNET}.1"
readonly WG_CLIENT_IP="${WG_SUBNET}.2"
readonly WG_MASK="24"
readonly MTU_DEFAULT=1300
readonly XRAY_CONFIG_DIR="/usr/local/etc/xray"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly REALITY_SNI="microsoft.com"
readonly REALITY_DEST="microsoft.com:443"
readonly TROJAN_PORT=443
readonly VLESS_PORT=8443
readonly HEALTH_CHECK_INTERVAL=300
readonly MAX_RESTART_ATTEMPTS=5

# ========================== COLORS ==========================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# ========================== LOGGING =========================================
log() {
    local level="$1"; shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
    case "${level}" in
        INFO)  echo -e "${GREEN}[✓]${NC} ${msg}" ;;
        WARN)  echo -e "${YELLOW}[!]${NC} ${msg}" ;;
        ERROR) echo -e "${RED}[✗]${NC} ${msg}" ;;
        DEBUG) [[ "${DEBUG:-0}" == "1" ]] && echo -e "${CYAN}[D]${NC} ${msg}" ;;
        STEP)  echo -e "${BLUE}[→]${NC} ${BOLD}${msg}${NC}" ;;
    esac
}

log_info()  { log INFO "$@"; }
log_warn()  { log WARN "$@"; }
log_error() { log ERROR "$@"; }
log_debug() { log DEBUG "$@"; }
log_step()  { log STEP "$@"; }

# ========================== UTILITIES =======================================
die() {
    log_error "$@"
    exit 1
}

check_root() {
    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root. Use: sudo bash $0"
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        die "Unsupported operating system"
    fi
    source /etc/os-release
    case "${ID}" in
        ubuntu|debian) PKG_MANAGER="apt" ;;
        centos|almalinux|rocky|fedora) PKG_MANAGER="yum" ;;
        *) die "Unsupported distribution: ${ID}" ;;
    esac
    log_info "Detected OS: ${PRETTY_NAME} (${PKG_MANAGER})"
}

get_public_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me"
        "https://icanhazip.com"
        "https://ipinfo.io/ip"
    )
    for svc in "${services[@]}"; do
        ip=$(curl -s --max-time 5 "${svc}" 2>/dev/null) && break
    done
    [[ -n "${ip}" ]] && echo "${ip}" || die "Cannot detect public IP address"
}

get_default_interface() {
    ip route show default | awk '/default/ {print $5}' | head -1
}

generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

generate_random_hex() {
    local length="${1:-16}"
    openssl rand -hex "$((length / 2))"
}

generate_short_id() {
    openssl rand -hex 4
}

base64_encode() {
    echo -n "$1" | base64 -w0
}

base64_decode() {
    echo -n "$1" | base64 -d
}

confirm() {
    local msg="${1:-Continue?}"
    echo -en "${YELLOW}${msg} [y/N]: ${NC}"
    read -r ans
    [[ "${ans}" =~ ^[Yy]$ ]]
}

wait_spinner() {
    local pid=$1
    local msg="${2:-Processing}"
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while kill -0 "$pid" 2>/dev/null; do
        for ((i=0; i<${#spinstr}; i++)); do
            echo -ne "\r${CYAN}${spinstr:$i:1}${NC} ${msg}..."
            sleep 0.1
        done
    done
    echo -ne "\r"
}

# ========================== SYSTEM PREPARATION ==============================
install_dependencies() {
    log_step "Installing system dependencies..."

    if [[ "${PKG_MANAGER}" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq \
            curl wget unzip jq openssl \
            iptables net-tools \
            wireguard wireguard-tools \
            fail2ban cron \
            qrencode \
            2>&1 | tail -5
    else
        yum install -y -q \
            curl wget unzip jq openssl \
            iptables net-tools \
            wireguard-tools \
            fail2ban cronie \
            qrencode \
            2>&1 | tail -5
    fi

    log_info "Dependencies installed successfully"
}

install_xray() {
    log_step "Installing Xray-core..."

    if [[ -f "${XRAY_BIN}" ]]; then
        local current_ver
        current_ver=$("${XRAY_BIN}" version 2>/dev/null | head -1 | awk '{print $2}') || true
        log_info "Xray already installed (v${current_ver})"
        return 0
    fi

    bash <(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) \
        2>&1 | tail -3

    if [[ ! -f "${XRAY_BIN}" ]]; then
        die "Xray installation failed"
    fi

    mkdir -p "${XRAY_CONFIG_DIR}"
    log_info "Xray-core installed successfully"
}

# ========================== PERFORMANCE TUNING ==============================
apply_sysctl_tuning() {
    log_step "Applying kernel performance tuning..."

    cat > /etc/sysctl.d/99-tunnel-enterprise.conf << 'SYSCTL'
# ============================================================================
# Tunnel Enterprise — Kernel Performance Tuning
# ============================================================================

# --- IP Forwarding ---
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# --- BBR Congestion Control ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- TCP Fast Open ---
net.ipv4.tcp_fastopen = 3

# --- TCP Buffer Tuning ---
net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216

# --- Connection Tuning ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_orphans = 65535
net.ipv4.tcp_syncookies = 1

# --- File Descriptors ---
fs.file-max = 1048576
fs.nr_open = 1048576

# --- Network Optimization ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- UDP Buffer (for WireGuard) ---
net.core.rmem_default = 26214400
net.core.rmem_max = 26214400
SYSCTL

    sysctl --system > /dev/null 2>&1
    log_info "Kernel tuning applied (BBR, TCP Fast Open, buffer optimization)"
}

increase_file_limits() {
    log_step "Increasing system file limits..."

    cat > /etc/security/limits.d/99-tunnel-enterprise.conf << 'LIMITS'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS

    if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session 2>/dev/null || true
    fi

    log_info "File limits increased to 1048576"
}

# ========================== WIREGUARD =======================================
generate_wg_keys() {
    local prefix="$1"
    local private_key public_key preshared_key

    private_key=$(wg genkey)
    public_key=$(echo "${private_key}" | wg pubkey)
    preshared_key=$(wg genpsk)

    echo "${private_key}" > "${CONFIG_DIR}/${prefix}_private.key"
    echo "${public_key}" > "${CONFIG_DIR}/${prefix}_public.key"
    echo "${preshared_key}" > "${CONFIG_DIR}/${prefix}_preshared.key"

    chmod 600 "${CONFIG_DIR}"/*.key

    log_info "WireGuard keys generated for ${prefix}"
}

setup_wg_server() {
    log_step "Configuring WireGuard server..."

    generate_wg_keys "server"

    local server_privkey client_pubkey preshared_key
    server_privkey=$(cat "${CONFIG_DIR}/server_private.key")

    # Client keys will be generated and paired later
    generate_wg_keys "client"
    client_pubkey=$(cat "${CONFIG_DIR}/client_public.key")
    preshared_key=$(cat "${CONFIG_DIR}/server_preshared.key")

    local default_iface
    default_iface=$(get_default_interface)

    cat > "/etc/wireguard/${WG_INTERFACE}.conf" << WG_SERVER
# ============================================================================
# WireGuard Server — Tunnel Enterprise
# Generated: $(date -Iseconds)
# ============================================================================
[Interface]
Address = ${WG_SERVER_IP}/${WG_MASK}
ListenPort = ${WG_PORT}
PrivateKey = ${server_privkey}
MTU = ${MTU_DEFAULT}

PostUp = iptables -t nat -A POSTROUTING -o ${default_iface} -j MASQUERADE
PostUp = iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT
PostUp = iptables -A FORWARD -o ${WG_INTERFACE} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${default_iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT
PostDown = iptables -D FORWARD -o ${WG_INTERFACE} -j ACCEPT

[Peer]
# Iran Entry Server
PublicKey = ${client_pubkey}
PresharedKey = ${preshared_key}
AllowedIPs = ${WG_CLIENT_IP}/32
PersistentKeepalive = 25
WG_SERVER

    chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"

    systemctl enable wg-quick@${WG_INTERFACE}
    systemctl start wg-quick@${WG_INTERFACE} || {
        log_warn "WireGuard failed to start, attempting module load..."
        modprobe wireguard 2>/dev/null || true
        systemctl start wg-quick@${WG_INTERFACE}
    }

    log_info "WireGuard server running on ${WG_SERVER_IP}:${WG_PORT}"
}

setup_wg_client() {
    local foreign_ip="$1"
    local server_pubkey="$2"
    local client_privkey="$3"
    local preshared_key="$4"

    log_step "Configuring WireGuard client..."

    local default_iface
    default_iface=$(get_default_interface)

    cat > "/etc/wireguard/${WG_INTERFACE}.conf" << WG_CLIENT
# ============================================================================
# WireGuard Client — Tunnel Enterprise
# Generated: $(date -Iseconds)
# ============================================================================
[Interface]
Address = ${WG_CLIENT_IP}/${WG_MASK}
PrivateKey = ${client_privkey}
MTU = ${MTU_DEFAULT}

# Keep source NAT for return traffic
PostUp = iptables -t nat -A POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE

[Peer]
# Foreign Exit Server
PublicKey = ${server_pubkey}
PresharedKey = ${preshared_key}
Endpoint = ${foreign_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
WG_CLIENT

    chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"

    systemctl enable wg-quick@${WG_INTERFACE}
    systemctl start wg-quick@${WG_INTERFACE} || {
        log_warn "WireGuard client failed to start, retrying..."
        sleep 2
        systemctl restart wg-quick@${WG_INTERFACE}
    }

    log_info "WireGuard client connected to ${foreign_ip}:${WG_PORT}"
}

# ========================== XRAY / VLESS REALITY ============================
setup_vless_reality() {
    log_step "Configuring VLESS Reality (Exit Node)..."

    local uuid short_id
    uuid=$(generate_uuid)
    short_id=$(generate_short_id)

    # Generate Reality X25519 key pair
    local reality_keys private_key public_key
    reality_keys=$("${XRAY_BIN}" x25519 2>/dev/null)
    private_key=$(echo "${reality_keys}" | grep "Private key:" | awk '{print $3}')
    public_key=$(echo "${reality_keys}" | grep "Public key:" | awk '{print $3}')

    # Save credentials
    cat > "${CONFIG_DIR}/vless_reality.json" << CREDS
{
    "uuid": "${uuid}",
    "reality_private_key": "${private_key}",
    "reality_public_key": "${public_key}",
    "short_id": "${short_id}",
    "sni": "${REALITY_SNI}",
    "dest": "${REALITY_DEST}",
    "port": ${VLESS_PORT}
}
CREDS

    # Xray server config
    cat > "${XRAY_CONFIG_DIR}/config.json" << XRAY_CONFIG
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "dns": {
        "servers": [
            "https+local://1.1.1.1/dns-query",
            "https+local://8.8.8.8/dns-query",
            "localhost"
        ]
    },
    "inbounds": [
        {
            "tag": "vless-reality-in",
            "listen": "0.0.0.0",
            "port": ${VLESS_PORT},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "${REALITY_DEST}",
                    "xver": 0,
                    "serverNames": [
                        "${REALITY_SNI}",
                        "www.${REALITY_SNI}"
                    ],
                    "privateKey": "${private_key}",
                    "shortIds": [
                        "${short_id}",
                        ""
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            }
        },
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {
                "response": {
                    "type": "http"
                }
            }
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "outboundTag": "block",
                "protocol": ["bittorrent"]
            },
            {
                "type": "field",
                "outboundTag": "direct",
                "network": "udp,tcp"
            }
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "bufferSize": 4
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true,
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }
    },
    "stats": {}
}
XRAY_CONFIG

    mkdir -p /var/log/xray

    systemctl enable xray
    systemctl restart xray

    log_info "VLESS Reality configured on port ${VLESS_PORT}"
    log_info "UUID: ${uuid}"
    log_info "Public Key: ${public_key}"
    log_info "Short ID: ${short_id}"
}

# ========================== TROJAN (ENTRY NODE) =============================
setup_trojan_inbound() {
    local trojan_password="$1"
    local foreign_wg_ip="${WG_SERVER_IP}"

    log_step "Configuring Trojan inbound (Entry Node)..."

    # Generate self-signed certificate
    local cert_dir="${CONFIG_DIR}/certs"
    mkdir -p "${cert_dir}"

    if [[ ! -f "${cert_dir}/server.crt" ]]; then
        log_info "Generating self-signed TLS certificate..."
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "${cert_dir}/server.key" \
            -out "${cert_dir}/server.crt" \
            -days 3650 \
            -subj "/CN=microsoft.com/O=Enterprise/C=US" \
            2>/dev/null
        chmod 600 "${cert_dir}/server.key"
    fi

    # Xray config for Iran entry node
    cat > "${XRAY_CONFIG_DIR}/config.json" << XRAY_TROJAN
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "tag": "trojan-in",
            "listen": "0.0.0.0",
            "port": ${TROJAN_PORT},
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${trojan_password}"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "${cert_dir}/server.crt",
                            "keyFile": "${cert_dir}/server.key"
                        }
                    ],
                    "minVersion": "1.2",
                    "alpn": ["h2", "http/1.1"]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        }
    ],
    "outbounds": [
        {
            "tag": "wg-tunnel",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4",
                "redirect": "${foreign_wg_ip}:0"
            },
            "streamSettings": {
                "sockopt": {
                    "mark": 255
                }
            }
        },
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {}
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "outboundTag": "block",
                "protocol": ["bittorrent"]
            },
            {
                "type": "field",
                "inboundTag": ["trojan-in"],
                "outboundTag": "wg-tunnel"
            }
        ]
    }
}
XRAY_TROJAN

    mkdir -p /var/log/xray

    systemctl enable xray
    systemctl restart xray

    log_info "Trojan inbound configured on port ${TROJAN_PORT}"
}

# ========================== FIREWALL ========================================
configure_firewall_foreign() {
    log_step "Configuring firewall (Exit Server)..."

    # Ensure iptables-persistent or use direct rules
    if command -v ufw &>/dev/null; then
        ufw allow ${WG_PORT}/udp comment "WireGuard"
        ufw allow ${VLESS_PORT}/tcp comment "VLESS Reality"
        ufw allow 22/tcp comment "SSH"
        ufw --force enable
    else
        iptables -A INPUT -p udp --dport ${WG_PORT} -j ACCEPT
        iptables -A INPUT -p tcp --dport ${VLESS_PORT} -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT

        # Save rules
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save
        elif command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
            iptables-save > /etc/iptables.rules 2>/dev/null || true
        fi
    fi

    log_info "Firewall configured: WG=${WG_PORT}/udp, VLESS=${VLESS_PORT}/tcp, SSH=22/tcp"
}

configure_firewall_iran() {
    log_step "Configuring firewall (Entry Server)..."

    if command -v ufw &>/dev/null; then
        ufw allow ${TROJAN_PORT}/tcp comment "Trojan"
        ufw allow 22/tcp comment "SSH"
        ufw --force enable
    else
        iptables -A INPUT -p tcp --dport ${TROJAN_PORT} -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT

        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save
        fi
    fi

    log_info "Firewall configured: Trojan=${TROJAN_PORT}/tcp, SSH=22/tcp"
}

# ========================== FAIL2BAN ========================================
setup_fail2ban() {
    log_step "Configuring Fail2ban..."

    cat > /etc/fail2ban/jail.d/tunnel-enterprise.conf << 'F2B'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600

[trojan-auth]
enabled = true
port = 443
filter = trojan-auth
logpath = /var/log/xray/access.log
maxretry = 10
bantime = 1800
findtime = 300
F2B

    # Custom filter for Trojan auth failures
    cat > /etc/fail2ban/filter.d/trojan-auth.conf << 'F2B_FILTER'
[Definition]
failregex = ^.*rejected.*from <HOST>.*$
             ^.*invalid user.*from <HOST>.*$
ignoreregex =
F2B_FILTER

    systemctl enable fail2ban
    systemctl restart fail2ban

    log_info "Fail2ban configured for SSH and Trojan"
}

# ========================== SSH HARDENING ===================================
harden_ssh() {
    log_step "Hardening SSH configuration..."

    local sshd_config="/etc/ssh/sshd_config"
    local backup="${sshd_config}.bak.$(date +%s)"

    cp "${sshd_config}" "${backup}"

    # Apply hardening (non-destructive, preserves custom settings)
    declare -A ssh_settings=(
        ["PermitRootLogin"]="prohibit-password"
        ["PasswordAuthentication"]="yes"
        ["MaxAuthTries"]="5"
        ["LoginGraceTime"]="60"
        ["ClientAliveInterval"]="120"
        ["ClientAliveCountMax"]="3"
        ["X11Forwarding"]="no"
        ["AllowTcpForwarding"]="yes"
    )

    for key in "${!ssh_settings[@]}"; do
        local val="${ssh_settings[$key]}"
        if grep -q "^${key}" "${sshd_config}"; then
            sed -i "s/^${key}.*/${key} ${val}/" "${sshd_config}"
        elif grep -q "^#${key}" "${sshd_config}"; then
            sed -i "s/^#${key}.*/${key} ${val}/" "${sshd_config}"
        else
            echo "${key} ${val}" >> "${sshd_config}"
        fi
    done

    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true

    log_info "SSH hardened (backup: ${backup})"
}

# ========================== WATCHDOG & HEALTH ===============================
create_watchdog_service() {
    log_step "Creating watchdog service..."

    cat > /usr/local/bin/tunnel-watchdog.sh << 'WATCHDOG'
#!/usr/bin/env bash
# Tunnel Enterprise Watchdog — Auto-healing service monitor
set -euo pipefail

LOG="/var/log/tunnel.log"
MAX_RETRIES=5
RETRY_DELAY=10

log_wd() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHDOG] $*" >> "${LOG}"
}

restart_service() {
    local svc="$1"
    local attempt=0

    while [[ $attempt -lt $MAX_RETRIES ]]; do
        ((attempt++))
        log_wd "Restarting ${svc} (attempt ${attempt}/${MAX_RETRIES})"
        systemctl restart "${svc}" && {
            log_wd "${svc} restarted successfully"
            return 0
        }
        sleep "${RETRY_DELAY}"
    done

    log_wd "CRITICAL: ${svc} failed after ${MAX_RETRIES} attempts"
    return 1
}

# Check WireGuard
if systemctl is-enabled wg-quick@wg0 &>/dev/null; then
    if ! systemctl is-active --quiet wg-quick@wg0; then
        log_wd "WireGuard is down"
        restart_service wg-quick@wg0
    fi

    # Check WireGuard handshake freshness (> 5 min = stale)
    if command -v wg &>/dev/null; then
        latest_handshake=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
        if [[ -n "${latest_handshake}" && "${latest_handshake}" != "0" ]]; then
            now=$(date +%s)
            age=$(( now - latest_handshake ))
            if [[ $age -gt 300 ]]; then
                log_wd "WireGuard handshake stale (${age}s), restarting..."
                restart_service wg-quick@wg0
            fi
        fi
    fi
fi

# Check Xray
if systemctl is-enabled xray &>/dev/null; then
    if ! systemctl is-active --quiet xray; then
        log_wd "Xray is down"
        restart_service xray
    fi
fi

# Check connectivity through tunnel
if ip link show wg0 &>/dev/null; then
    if ! ping -c 2 -W 5 -I wg0 10.66.66.1 &>/dev/null 2>&1; then
        if ! ping -c 2 -W 5 -I wg0 10.66.66.2 &>/dev/null 2>&1; then
            log_wd "Tunnel connectivity lost, restarting WireGuard..."
            restart_service wg-quick@wg0
        fi
    fi
fi

log_wd "Health check completed — all services operational"
WATCHDOG

    chmod +x /usr/local/bin/tunnel-watchdog.sh

    # Systemd timer for watchdog
    cat > /etc/systemd/system/tunnel-watchdog.service << 'SVC'
[Unit]
Description=Tunnel Enterprise Watchdog
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tunnel-watchdog.sh
StandardOutput=journal
StandardError=journal
SVC

    cat > /etc/systemd/system/tunnel-watchdog.timer << 'TIMER'
[Unit]
Description=Tunnel Enterprise Watchdog Timer

[Timer]
OnBootSec=60
OnUnitActiveSec=300
AccuracySec=30

[Install]
WantedBy=timers.target
TIMER

    systemctl daemon-reload
    systemctl enable tunnel-watchdog.timer
    systemctl start tunnel-watchdog.timer

    log_info "Watchdog service created (checks every 5 minutes)"
}

create_health_check_script() {
    log_step "Creating health check script..."

    cat > /usr/local/bin/tunnel-health.sh << 'HEALTH'
#!/usr/bin/env bash
# Tunnel Enterprise — Health Check & Diagnostics
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
warn() { echo -e "  ${YELLOW}!${NC} $*"; }

echo ""
echo "═══════════════════════════════════════════════"
echo "   Tunnel Enterprise — Health Report"
echo "   $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════════"
echo ""

# --- System ---
echo "▸ System"
ok "Uptime: $(uptime -p)"
ok "Load: $(cat /proc/loadavg | awk '{print $1, $2, $3}')"
ok "Memory: $(free -h | awk '/^Mem:/ {printf "%s / %s (%.1f%%)", $3, $2, $3/$2*100}')"

# --- WireGuard ---
echo ""
echo "▸ WireGuard"
if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
    ok "Service: running"
    if command -v wg &>/dev/null; then
        wg show wg0 2>/dev/null | while read -r line; do
            echo "    ${line}"
        done
        # Transfer stats
        rx=$(wg show wg0 transfer 2>/dev/null | awk '{sum+=$2} END {printf "%.2f MB", sum/1048576}')
        tx=$(wg show wg0 transfer 2>/dev/null | awk '{sum+=$3} END {printf "%.2f MB", sum/1048576}')
        ok "Transfer: RX=${rx}, TX=${tx}"
    fi
    if ping -c 1 -W 3 10.66.66.1 &>/dev/null; then
        ok "Tunnel: reachable (10.66.66.1)"
    elif ping -c 1 -W 3 10.66.66.2 &>/dev/null; then
        ok "Tunnel: reachable (10.66.66.2)"
    else
        fail "Tunnel: unreachable"
    fi
else
    fail "Service: stopped"
fi

# --- Xray ---
echo ""
echo "▸ Xray"
if systemctl is-active --quiet xray 2>/dev/null; then
    ok "Service: running"
    local_ports=$(ss -tlnp | grep xray | awk '{print $4}' | sed 's/.*://' | sort -u | tr '\n' ', ' | sed 's/,$//')
    ok "Listening: ${local_ports:-none}"
else
    fail "Service: stopped"
fi

# --- Firewall ---
echo ""
echo "▸ Firewall"
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ok "UFW: active"
elif iptables -L INPUT -n 2>/dev/null | grep -q "ACCEPT"; then
    ok "iptables: configured"
else
    warn "Firewall: not detected"
fi

# --- Fail2ban ---
echo ""
echo "▸ Fail2ban"
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | xargs)
    ok "Active jails: ${jails:-none}"
else
    warn "Not running"
fi

# --- BBR ---
echo ""
echo "▸ Performance"
cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
[[ "$cc" == "bbr" ]] && ok "TCP CC: BBR" || warn "TCP CC: ${cc} (BBR recommended)"
tfo=$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)
[[ "$tfo" -ge 3 ]] && ok "TCP Fast Open: enabled" || warn "TCP Fast Open: ${tfo}"

# --- Disk ---
echo ""
echo "▸ Disk"
ok "Usage: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"

# --- Recent Logs ---
echo ""
echo "▸ Recent Log Entries"
if [[ -f /var/log/tunnel.log ]]; then
    tail -5 /var/log/tunnel.log | while read -r line; do
        echo "    ${line}"
    done
else
    warn "No log file found"
fi

echo ""
echo "═══════════════════════════════════════════════"
HEALTH

    chmod +x /usr/local/bin/tunnel-health.sh

    log_info "Health check script: /usr/local/bin/tunnel-health.sh"
}

# ========================== PAIRING TOKEN ===================================
generate_pairing_token() {
    log_step "Generating pairing token..."

    local public_ip server_pubkey client_privkey preshared_key
    public_ip=$(get_public_ip)
    server_pubkey=$(cat "${CONFIG_DIR}/server_public.key")
    client_privkey=$(cat "${CONFIG_DIR}/client_private.key")
    preshared_key=$(cat "${CONFIG_DIR}/server_preshared.key")

    # Load VLESS Reality creds
    local uuid reality_pub_key short_id
    uuid=$(jq -r '.uuid' "${CONFIG_DIR}/vless_reality.json")
    reality_pub_key=$(jq -r '.reality_public_key' "${CONFIG_DIR}/vless_reality.json")
    short_id=$(jq -r '.short_id' "${CONFIG_DIR}/vless_reality.json")

    local token_json
    token_json=$(cat << TOKEN_JSON
{
    "v": "${VERSION}",
    "foreign_ip": "${public_ip}",
    "wg_port": ${WG_PORT},
    "wg_server_pubkey": "${server_pubkey}",
    "wg_client_privkey": "${client_privkey}",
    "wg_preshared_key": "${preshared_key}",
    "vless_uuid": "${uuid}",
    "vless_port": ${VLESS_PORT},
    "reality_public_key": "${reality_pub_key}",
    "reality_short_id": "${short_id}",
    "reality_sni": "${REALITY_SNI}"
}
TOKEN_JSON
)

    local token
    token=$(base64_encode "${token_json}")

    echo "${token}" > "${CONFIG_DIR}/pairing_token.txt"
    echo "${token_json}" > "${CONFIG_DIR}/pairing_data.json"

    log_info "Pairing token generated and saved"
    echo "${token}"
}

parse_pairing_token() {
    local token="$1"

    log_step "Parsing pairing token..."

    local json
    json=$(base64_decode "${token}") || die "Invalid pairing token (base64 decode failed)"

    # Validate JSON
    echo "${json}" | jq . > /dev/null 2>&1 || die "Invalid pairing token (JSON parse failed)"

    # Extract fields
    FOREIGN_IP=$(echo "${json}" | jq -r '.foreign_ip')
    WG_SERVER_PUBKEY=$(echo "${json}" | jq -r '.wg_server_pubkey')
    WG_CLIENT_PRIVKEY=$(echo "${json}" | jq -r '.wg_client_privkey')
    WG_PRESHARED_KEY=$(echo "${json}" | jq -r '.wg_preshared_key')
    VLESS_UUID=$(echo "${json}" | jq -r '.vless_uuid')
    VLESS_PORT_PARSED=$(echo "${json}" | jq -r '.vless_port')
    REALITY_PUB_KEY=$(echo "${json}" | jq -r '.reality_public_key')
    REALITY_SHORT_ID=$(echo "${json}" | jq -r '.reality_short_id')
    REALITY_SNI_PARSED=$(echo "${json}" | jq -r '.reality_sni')

    # Validate critical fields
    [[ -n "${FOREIGN_IP}" && "${FOREIGN_IP}" != "null" ]] || die "Missing foreign_ip in token"
    [[ -n "${WG_SERVER_PUBKEY}" && "${WG_SERVER_PUBKEY}" != "null" ]] || die "Missing WG pubkey in token"

    log_info "Token parsed: Foreign IP = ${FOREIGN_IP}"
    echo "${json}" > "${CONFIG_DIR}/pairing_data.json"
}

# ========================== CONNECTION INFO =================================
print_connection_details() {
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           Tunnel Enterprise — Connection Details            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if [[ -f "${CONFIG_DIR}/pairing_data.json" ]]; then
        local data="${CONFIG_DIR}/pairing_data.json"

        echo -e "${BOLD}▸ Server Information${NC}"
        echo "  Foreign IP     : $(jq -r '.foreign_ip // "N/A"' "${data}")"
        echo "  WireGuard Port : $(jq -r '.wg_port // "N/A"' "${data}")"
        echo "  VLESS Port     : $(jq -r '.vless_port // "N/A"' "${data}")"
        echo ""
    fi

    if [[ -f "${CONFIG_DIR}/vless_reality.json" ]]; then
        local vless="${CONFIG_DIR}/vless_reality.json"
        local public_ip
        public_ip=$(get_public_ip 2>/dev/null || echo "UNKNOWN")

        local uuid pub_key sid port
        uuid=$(jq -r '.uuid' "${vless}")
        pub_key=$(jq -r '.reality_public_key' "${vless}")
        sid=$(jq -r '.short_id' "${vless}")
        port=$(jq -r '.port' "${vless}")

        echo -e "${BOLD}▸ VLESS Reality URI${NC}"
        local vless_uri="vless://${uuid}@${public_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${pub_key}&sid=${sid}&type=tcp#Tunnel-Enterprise-VLESS"
        echo "  ${vless_uri}"
        echo ""

        # Generate QR if available
        if command -v qrencode &>/dev/null; then
            echo -e "${BOLD}▸ QR Code (scan with v2rayNG/Shadowrocket):${NC}"
            qrencode -t ANSIUTF8 "${vless_uri}" 2>/dev/null || true
            echo ""
        fi
    fi

    if [[ -f "${CONFIG_DIR}/pairing_token.txt" ]]; then
        echo -e "${BOLD}▸ Pairing Token (copy to Iran server):${NC}"
        echo -e "${YELLOW}"
        cat "${CONFIG_DIR}/pairing_token.txt"
        echo -e "${NC}"
        echo ""
    fi

    # Trojan info
    if [[ -f "${CONFIG_DIR}/trojan_info.json" ]]; then
        local trojan="${CONFIG_DIR}/trojan_info.json"
        echo -e "${BOLD}▸ Trojan Connection (for clients):${NC}"
        echo "  Server   : $(jq -r '.server' "${trojan}")"
        echo "  Port     : $(jq -r '.port' "${trojan}")"
        echo "  Password : $(jq -r '.password' "${trojan}")"
        echo ""

        local trojan_uri
        local t_server t_port t_pass
        t_server=$(jq -r '.server' "${trojan}")
        t_port=$(jq -r '.port' "${trojan}")
        t_pass=$(jq -r '.password' "${trojan}")
        trojan_uri="trojan://${t_pass}@${t_server}:${t_port}?security=tls&sni=${t_server}&allowInsecure=1#Tunnel-Enterprise-Trojan"
        echo -e "${BOLD}▸ Trojan URI:${NC}"
        echo "  ${trojan_uri}"
        echo ""
    fi

    # WireGuard status
    echo -e "${BOLD}▸ WireGuard Status${NC}"
    wg show "${WG_INTERFACE}" 2>/dev/null || echo "  WireGuard not active"
    echo ""
}

# ========================== UNINSTALL =======================================
uninstall_all() {
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║        WARNING: This will remove all tunnel components   ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    confirm "Are you sure you want to uninstall everything?" || {
        log_info "Uninstall cancelled"
        return 0
    }

    log_step "Stopping services..."
    systemctl stop wg-quick@${WG_INTERFACE} 2>/dev/null || true
    systemctl disable wg-quick@${WG_INTERFACE} 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    systemctl stop tunnel-watchdog.timer 2>/dev/null || true
    systemctl disable tunnel-watchdog.timer 2>/dev/null || true

    log_step "Removing configurations..."
    rm -f "/etc/wireguard/${WG_INTERFACE}.conf"
    rm -rf "${XRAY_CONFIG_DIR}"
    rm -f /etc/sysctl.d/99-tunnel-enterprise.conf
    rm -f /etc/security/limits.d/99-tunnel-enterprise.conf
    rm -f /etc/fail2ban/jail.d/tunnel-enterprise.conf
    rm -f /etc/fail2ban/filter.d/trojan-auth.conf
    rm -f /usr/local/bin/tunnel-watchdog.sh
    rm -f /usr/local/bin/tunnel-health.sh
    rm -f /etc/systemd/system/tunnel-watchdog.service
    rm -f /etc/systemd/system/tunnel-watchdog.timer

    log_step "Removing Xray..."
    bash <(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove 2>/dev/null || true

    # Reload sysctl
    sysctl --system > /dev/null 2>&1 || true
    systemctl daemon-reload

    log_step "Backing up config directory..."
    if [[ -d "${CONFIG_DIR}" ]]; then
        local backup="/root/tunnel-config-backup-$(date +%s).tar.gz"
        tar -czf "${backup}" -C /root tunnel-config 2>/dev/null || true
        rm -rf "${CONFIG_DIR}"
        log_info "Config backed up to: ${backup}"
    fi

    echo ""
    log_info "Uninstall complete. Reboot recommended."
}

# ========================== MAIN INSTALLERS =================================
install_foreign_server() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          Installing Foreign Exit Server                     ║"
    echo "║          WireGuard Server + VLESS Reality                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    check_os
    mkdir -p "${CONFIG_DIR}" /var/log

    log_step "Phase 1: System Preparation"
    install_dependencies
    apply_sysctl_tuning
    increase_file_limits

    log_step "Phase 2: WireGuard Server"
    setup_wg_server

    log_step "Phase 3: Xray + VLESS Reality"
    install_xray
    setup_vless_reality

    log_step "Phase 4: Security"
    configure_firewall_foreign
    setup_fail2ban
    harden_ssh

    log_step "Phase 5: Reliability"
    create_watchdog_service
    create_health_check_script

    log_step "Phase 6: Generate Pairing Token"
    echo ""
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  Foreign Exit Server installed successfully!${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}▸ PAIRING TOKEN (copy this entire string to Iran server):${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    generate_pairing_token
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    print_connection_details

    log_info "Run 'tunnel-health.sh' anytime to check system status"
    log_info "Config directory: ${CONFIG_DIR}"
}

install_iran_server() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          Installing Iran Entry Server                       ║"
    echo "║          Trojan Inbound + WireGuard Client                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    check_os
    mkdir -p "${CONFIG_DIR}" /var/log

    # Get pairing token
    echo ""
    echo -e "${YELLOW}Paste the pairing token from the Foreign server:${NC}"
    echo -en "${CYAN}Token: ${NC}"
    read -r PAIRING_TOKEN

    [[ -n "${PAIRING_TOKEN}" ]] || die "No pairing token provided"

    parse_pairing_token "${PAIRING_TOKEN}"

    log_step "Phase 1: System Preparation"
    install_dependencies
    apply_sysctl_tuning
    increase_file_limits

    log_step "Phase 2: WireGuard Client"
    setup_wg_client "${FOREIGN_IP}" "${WG_SERVER_PUBKEY}" "${WG_CLIENT_PRIVKEY}" "${WG_PRESHARED_KEY}"

    # Verify tunnel
    log_step "Verifying WireGuard tunnel..."
    sleep 3
    if ping -c 3 -W 5 "${WG_SERVER_IP}" &>/dev/null; then
        log_info "WireGuard tunnel is UP and reachable"
    else
        log_warn "WireGuard tunnel not reachable yet (may need time to establish)"
    fi

    log_step "Phase 3: Xray + Trojan Inbound"
    install_xray

    # Generate Trojan password
    local trojan_password
    trojan_password=$(generate_random_hex 32)

    setup_trojan_inbound "${trojan_password}"

    # Save Trojan info
    local iran_ip
    iran_ip=$(get_public_ip)

    cat > "${CONFIG_DIR}/trojan_info.json" << TROJAN_INFO
{
    "server": "${iran_ip}",
    "port": ${TROJAN_PORT},
    "password": "${trojan_password}",
    "sni": "${iran_ip}",
    "allow_insecure": true
}
TROJAN_INFO

    log_step "Phase 4: Traffic Forwarding Rules"
    setup_traffic_forwarding

    log_step "Phase 5: Security"
    configure_firewall_iran
    setup_fail2ban
    harden_ssh

    log_step "Phase 6: Reliability"
    create_watchdog_service
    create_health_check_script

    echo ""
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  Iran Entry Server installed successfully!${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""

    print_connection_details

    log_info "Run 'tunnel-health.sh' anytime to check system status"
    log_info "Config directory: ${CONFIG_DIR}"
}

setup_traffic_forwarding() {
    log_step "Configuring traffic forwarding through WireGuard tunnel..."

    local default_iface
    default_iface=$(get_default_interface)

    # Route traffic from Trojan through WireGuard tunnel
    # Exclude WireGuard endpoint from tunnel routing
    ip route add "${FOREIGN_IP}/32" via "$(ip route show default | awk '{print $3}')" dev "${default_iface}" 2>/dev/null || true

    # iptables DNAT for forwarding
    # Trojan decrypts -> Xray routes -> WireGuard tunnel -> Foreign server
    iptables -t nat -A PREROUTING -p tcp --dport ${TROJAN_PORT} -j DNAT --to-destination "${WG_CLIENT_IP}:${TROJAN_PORT}" 2>/dev/null || true

    # Mark-based routing for Xray traffic through WireGuard
    if ! ip rule show | grep -q "fwmark 0xff"; then
        ip rule add fwmark 0xff table 100 2>/dev/null || true
        ip route add default via "${WG_SERVER_IP}" dev "${WG_INTERFACE}" table 100 2>/dev/null || true
    fi

    iptables -t mangle -A OUTPUT -m mark --mark 0xff -j RETURN 2>/dev/null || true

    # Persist routing rules
    cat > /etc/networkd-dispatcher/routable.d/50-tunnel-routes.sh 2>/dev/null << ROUTES || true
#!/bin/bash
ip rule add fwmark 0xff table 100 2>/dev/null || true
ip route add default via ${WG_SERVER_IP} dev ${WG_INTERFACE} table 100 2>/dev/null || true
ip route add ${FOREIGN_IP}/32 via $(ip route show default | awk '{print $3}') dev ${default_iface} 2>/dev/null || true
ROUTES
    chmod +x /etc/networkd-dispatcher/routable.d/50-tunnel-routes.sh 2>/dev/null || true

    log_info "Traffic forwarding configured"
}

# ========================== MAIN MENU =======================================
show_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}"
    cat << 'BANNER'

  ╔════════════════════════════════════════════════════════════════╗
  ║                                                                ║
  ║   ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗           ║
  ║   ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║           ║
  ║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║           ║
  ║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║           ║
  ║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗      ║
  ║      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝      ║
  ║                                                                ║
  ║           Enterprise Private Network Platform                  ║
  ║                    Version 2.0.0                               ║
  ║                                                                ║
  ╚════════════════════════════════════════════════════════════════╝

BANNER
    echo -e "${NC}"
}

show_menu() {
    echo -e "${BOLD}  Select an option:${NC}"
    echo ""
    echo -e "    ${GREEN}1${NC}) Install Foreign Exit Server    (WireGuard + VLESS Reality)"
    echo -e "    ${GREEN}2${NC}) Install Iran Entry Server       (Trojan + WireGuard Client)"
    echo -e "    ${GREEN}3${NC}) Show Connection Details"
    echo -e "    ${GREEN}4${NC}) Health Check & Diagnostics"
    echo -e "    ${RED}5${NC}) Uninstall Everything"
    echo -e "    ${YELLOW}0${NC}) Exit"
    echo ""
    echo -en "  ${CYAN}Enter choice [0-5]: ${NC}"
}

main() {
    # Initialize
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    touch "${LOG_FILE}" 2>/dev/null || true

    show_banner

    while true; do
        show_menu
        read -r choice
        echo ""

        case "${choice}" in
            1)
                check_root
                install_foreign_server
                ;;
            2)
                check_root
                install_iran_server
                ;;
            3)
                print_connection_details
                ;;
            4)
                if [[ -x /usr/local/bin/tunnel-health.sh ]]; then
                    /usr/local/bin/tunnel-health.sh
                else
                    log_warn "Health check not installed yet. Install a server first."
                fi
                ;;
            5)
                check_root
                uninstall_all
                ;;
            0)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                log_warn "Invalid option: ${choice}"
                ;;
        esac

        echo ""
        echo -en "${YELLOW}Press Enter to continue...${NC}"
        read -r
        show_banner
    done
}

# Run
main "$@"
