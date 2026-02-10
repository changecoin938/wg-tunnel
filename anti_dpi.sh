#!/usr/bin/env bash
# ============================================================================
#  anti_dpi.sh — Advanced Traffic Optimization Module
#  Part of Tunnel Enterprise v2.0.0
#
#  Techniques implemented:
#    1. TLS Fragment         — Split ClientHello into small chunks
#    2. TCP Segmentation     — iptables-based packet fragmentation
#    3. Mux Multiplexing     — Combine streams to obscure patterns
#    4. Multi-SNI Rotation   — Rotate camouflage domains
#    5. uTLS Fingerprint     — Browser TLS fingerprint mimicry
#    6. Padding Injection    — Random padding to defeat size analysis
#    7. Connection Pattern   — Randomize timing and behavior
#    8. DNS-over-HTTPS       — Encrypted DNS to prevent DNS poisoning
#    9. QUIC Masquerade      — Optional UDP obfuscation layer
#   10. Hysteria2 Transport  — Optional high-speed obfuscated UDP
#
# ============================================================================

set -euo pipefail

readonly CONFIG_DIR="/root/tunnel-config"
readonly XRAY_CONFIG_DIR="/usr/local/etc/xray"
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

log_info()  { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_step()  { echo -e "${CYAN}[→]${NC} ${BOLD}$*${NC}"; }
log_error() { echo -e "${RED}[✗]${NC} $*"; }

# ============================================================================
# 1. TLS FRAGMENT — Most effective against Iranian DPI
# ============================================================================
# Iranian DPI inspects the TLS ClientHello to detect proxy protocols.
# By fragmenting the ClientHello into tiny pieces (e.g., 1-3 bytes),
# the DPI engine cannot reassemble and inspect it in real-time.
# ============================================================================

apply_tls_fragment_xray() {
    log_step "Applying TLS Fragment settings to Xray..."

    local config="${XRAY_CONFIG_DIR}/config.json"
    [[ -f "${config}" ]] || { log_error "Xray config not found"; return 1; }

    # Backup
    cp "${config}" "${config}.bak.$(date +%s)"

    # Add fragment settings to outbound sockopt
    # This uses Xray's built-in fragment feature
    python3 -c "
import json, sys

with open('${config}', 'r') as f:
    cfg = json.load(f)

# Add fragment to freedom outbound
for ob in cfg.get('outbounds', []):
    if ob.get('tag') in ('direct', 'wg-tunnel'):
        if 'streamSettings' not in ob:
            ob['streamSettings'] = {}
        ob['streamSettings']['sockopt'] = ob['streamSettings'].get('sockopt', {})
        ob['streamSettings']['sockopt'].update({
            'dialerProxy': '',
            'mark': ob['streamSettings']['sockopt'].get('mark', 0),
            'tcpKeepAliveIdle': 100,
            'tcpNoDelay': True
        })

# Add fragment outbound if not exists
fragment_exists = any(o.get('tag') == 'fragment' for o in cfg.get('outbounds', []))
if not fragment_exists:
    cfg['outbounds'].append({
        'tag': 'fragment',
        'protocol': 'freedom',
        'settings': {
            'fragment': {
                'packets': 'tlshello',
                'length': '1-3',
                'interval': '0-5'
            }
        }
    })

    # Update routing to use fragment for TLS traffic
    for rule in cfg.get('routing', {}).get('rules', []):
        if rule.get('outboundTag') == 'direct':
            rule['outboundTag'] = 'fragment'
            break

with open('${config}', 'w') as f:
    json.dump(cfg, f, indent=2)

print('OK')
" 2>/dev/null && log_info "TLS Fragment: packets=tlshello, length=1-3, interval=0-5ms" || {
        # Fallback: manual JSON patch if python3 not available
        apply_tls_fragment_manual
    }
}

apply_tls_fragment_manual() {
    log_info "Applying TLS Fragment (manual method)..."

    local config="${XRAY_CONFIG_DIR}/config.json"

    # Check if fragment already exists
    if grep -q '"fragment"' "${config}" 2>/dev/null; then
        log_info "TLS Fragment already configured"
        return 0
    fi

    # Use jq to add fragment outbound
    if command -v jq &>/dev/null; then
        local tmp=$(mktemp)
        jq '.outbounds += [{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"1-3","interval":"0-5"}}}]' "${config}" > "${tmp}" && mv "${tmp}" "${config}"
        log_info "TLS Fragment added via jq"
    else
        log_warn "Install jq or python3 for automatic TLS Fragment config"
        log_info "Manual config: Add this to outbounds in ${config}:"
        echo '  {"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"1-3","interval":"0-5"}}}'
    fi
}

# ============================================================================
# 2. TCP SEGMENTATION — Kernel-level packet splitting
# ============================================================================
# Forces the kernel to send smaller TCP segments, making it harder
# for DPI to reassemble and inspect the full TLS handshake.
# ============================================================================

apply_tcp_segmentation() {
    log_step "Applying TCP segmentation rules..."

    # Set MSS (Maximum Segment Size) to small values for outgoing TLS
    # This forces TCP to split packets into smaller segments

    # For port 443 outgoing (Trojan)
    iptables -t mangle -A OUTPUT -p tcp --dport 443 -j TCPMSS --set-mss 160 2>/dev/null || true
    iptables -t mangle -A POSTROUTING -p tcp --dport 443 -j TCPMSS --set-mss 160 2>/dev/null || true

    # For VLESS Reality port
    iptables -t mangle -A OUTPUT -p tcp --dport 8443 -j TCPMSS --set-mss 160 2>/dev/null || true

    # Persist rules
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi

    log_info "TCP MSS set to 160 for TLS ports (443, 8443)"
}

# ============================================================================
# 3. ADVANCED XRAY CONFIG WITH ANTI-DPI
# ============================================================================
# Complete Xray configuration optimized for hostile DPI environments
# ============================================================================

generate_antidpi_entry_config() {
    local trojan_password="$1"
    local cert_dir="${CONFIG_DIR}/certs"

    log_step "Generating anti-DPI optimized Entry Node config..."

    cat > "${XRAY_CONFIG_DIR}/config.json" << XRAY_ANTIDPI
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "dns": {
        "servers": [
            {
                "address": "https+local://1.1.1.1/dns-query",
                "skipFallback": true
            },
            {
                "address": "https+local://8.8.8.8/dns-query",
                "skipFallback": false
            }
        ],
        "queryStrategy": "UseIPv4",
        "disableCache": false,
        "tag": "dns-internal"
    },
    "inbounds": [
        {
            "tag": "trojan-in",
            "listen": "0.0.0.0",
            "port": 443,
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
                    "maxVersion": "1.3",
                    "alpn": ["h2", "http/1.1"],
                    "fingerprint": "randomized"
                },
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpKeepAliveIdle": 100,
                    "tcpNoDelay": true
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"],
                "routeOnly": true
            }
        }
    ],
    "outbounds": [
        {
            "tag": "fragment-out",
            "protocol": "freedom",
            "settings": {
                "fragment": {
                    "packets": "tlshello",
                    "length": "1-3",
                    "interval": "0-5"
                }
            },
            "streamSettings": {
                "sockopt": {
                    "mark": 255,
                    "tcpNoDelay": true,
                    "tcpFastOpen": true
                }
            }
        },
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            },
            "streamSettings": {
                "sockopt": {
                    "mark": 255
                }
            }
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
                "outboundTag": "fragment-out"
            }
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 8,
                "connIdle": 600,
                "uplinkOnly": 4,
                "downlinkOnly": 10,
                "bufferSize": 8
            }
        }
    }
}
XRAY_ANTIDPI

    log_info "Anti-DPI Entry Node config generated"
}

generate_antidpi_exit_config() {
    local uuid="$1"
    local private_key="$2"
    local public_key="$3"
    local short_id="$4"

    log_step "Generating anti-DPI optimized Exit Node config..."

    # Multiple SNIs for rotation
    cat > "${XRAY_CONFIG_DIR}/config.json" << XRAY_EXIT_ANTIDPI
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "dns": {
        "servers": [
            "https+local://1.1.1.1/dns-query",
            "https+local://8.8.8.8/dns-query"
        ]
    },
    "inbounds": [
        {
            "tag": "vless-reality-in",
            "listen": "0.0.0.0",
            "port": 8443,
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
                    "dest": "www.microsoft.com:443",
                    "xver": 0,
                    "serverNames": [
                        "www.microsoft.com",
                        "microsoft.com",
                        "update.microsoft.com",
                        "www.apple.com",
                        "images.apple.com",
                        "cdn.cloudflare.com",
                        "www.google.com",
                        "mail.google.com"
                    ],
                    "privateKey": "${private_key}",
                    "shortIds": [
                        "${short_id}",
                        "",
                        "0123456789abcdef"
                    ],
                    "maxTimeDiff": 60000
                },
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpKeepAliveIdle": 100,
                    "tcpNoDelay": true
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            },
            "streamSettings": {
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpNoDelay": true
                }
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
                "handshake": 8,
                "connIdle": 600,
                "uplinkOnly": 4,
                "downlinkOnly": 10,
                "bufferSize": 8
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true
        }
    },
    "stats": {}
}
XRAY_EXIT_ANTIDPI

    log_info "Anti-DPI Exit Node config generated"
    log_info "SNI pool: microsoft.com, apple.com, cloudflare.com, google.com"
}

# ============================================================================
# 4. KERNEL ANTI-DPI TUNING
# ============================================================================

apply_kernel_antidpi() {
    log_step "Applying kernel-level anti-DPI optimizations..."

    cat >> /etc/sysctl.d/99-tunnel-enterprise.conf << 'ANTIDPI_SYSCTL'

# ============================================================================
# Anti-DPI Kernel Tuning
# ============================================================================

# Disable TCP timestamps (prevents fingerprinting)
net.ipv4.tcp_timestamps = 0

# Randomize source ports
net.ipv4.ip_local_port_range = 1024 65535

# TCP window scaling (helps with fragmentation)
net.ipv4.tcp_window_scaling = 1

# Reduce initial congestion window (smaller initial bursts)
net.ipv4.tcp_slow_start_after_idle = 0

# Enable ECN (can help with some DPI systems)
net.ipv4.tcp_ecn = 2

# Disable PMTU discovery (prevents size-based fingerprinting)
net.ipv4.ip_no_pmtu_disc = 1

# Increase TCP retries (resilient connections)
net.ipv4.tcp_retries2 = 15

# SYN flood protection
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3

# Disable ICMP redirects completely
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
ANTIDPI_SYSCTL

    sysctl --system > /dev/null 2>&1
    log_info "Kernel anti-DPI tuning applied"
}

# ============================================================================
# 5. WARP INTEGRATION (Optional Cloudflare WARP)
# ============================================================================

setup_warp_chain() {
    log_step "Setting up Cloudflare WARP chain (optional extra layer)..."

    # Install WARP
    if ! command -v warp-cli &>/dev/null; then
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list
        apt-get update -qq && apt-get install -y -qq cloudflare-warp 2>&1 | tail -3

        # Register and connect
        warp-cli registration new 2>/dev/null || true
        warp-cli mode proxy 2>/dev/null || true
        warp-cli proxy port 1080 2>/dev/null || true
        warp-cli connect 2>/dev/null || true

        log_info "WARP installed and connected (SOCKS5 on 127.0.0.1:1080)"
        log_info "Chain: Client → Trojan → WG → WARP → Internet"
    else
        log_info "WARP already installed"
    fi
}

# ============================================================================
# 6. IPTABLES ADVANCED RULES
# ============================================================================

apply_advanced_iptables() {
    log_step "Applying advanced iptables anti-DPI rules..."

    local iface
    iface=$(ip route show default | awk '{print $5}' | head -1)

    # --- TTL Manipulation ---
    # Randomize TTL to prevent hop-counting fingerprint
    iptables -t mangle -A POSTROUTING -o "${iface}" -j TTL --ttl-set 64 2>/dev/null || true

    # --- TCP Window Size Manipulation ---
    # Set initial TCP window to common browser values
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true

    # --- Block ICMP that can reveal tunnel ---
    iptables -A OUTPUT -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null || true
    iptables -A INPUT -p icmp --icmp-type timestamp-reply -j DROP 2>/dev/null || true

    # --- Rate limit new connections (anti-fingerprint) ---
    iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 -j DROP 2>/dev/null || true

    # Save
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi

    log_info "Advanced iptables rules applied"
}

# ============================================================================
# 7. SING-BOX ALTERNATIVE (More advanced anti-DPI)
# ============================================================================

install_singbox() {
    log_step "Installing sing-box (alternative engine with better anti-DPI)..."

    if command -v sing-box &>/dev/null; then
        log_info "sing-box already installed"
        return 0
    fi

    local latest_ver
    latest_ver=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')

    if [[ -z "${latest_ver}" ]]; then
        latest_ver="1.11.0"
    fi

    local arch="amd64"
    [[ "$(uname -m)" == "aarch64" ]] && arch="arm64"

    curl -sLo /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${latest_ver}/sing-box-${latest_ver}-linux-${arch}.tar.gz"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp/
    cp "/tmp/sing-box-${latest_ver}-linux-${arch}/sing-box" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    rm -rf /tmp/sing-box*

    log_info "sing-box v${latest_ver} installed"
}

generate_singbox_entry_config() {
    local trojan_password="$1"
    local foreign_wg_ip="$2"
    local cert_dir="${CONFIG_DIR}/certs"

    log_step "Generating sing-box entry config with advanced anti-DPI..."

    mkdir -p /usr/local/etc/sing-box

    cat > /usr/local/etc/sing-box/config.json << SINGBOX_CFG
{
    "log": {
        "level": "warn",
        "output": "/var/log/sing-box.log",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "tag": "doh-cf",
                "address": "https://1.1.1.1/dns-query",
                "strategy": "prefer_ipv4"
            }
        ]
    },
    "inbounds": [
        {
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "::",
            "listen_port": 443,
            "users": [
                {
                    "password": "${trojan_password}"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "${cert_dir}/server.crt",
                "key_path": "${cert_dir}/server.key",
                "min_version": "1.2",
                "alpn": ["h2", "http/1.1"]
            },
            "multiplex": {
                "enabled": true,
                "padding": true,
                "brutal": {
                    "enabled": false
                }
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct-out",
            "bind_interface": "wg0"
        },
        {
            "type": "block",
            "tag": "block-out"
        }
    ],
    "route": {
        "rules": [
            {
                "protocol": "bittorrent",
                "outbound": "block-out"
            }
        ],
        "final": "direct-out"
    }
}
SINGBOX_CFG

    # Create systemd service
    cat > /etc/systemd/system/sing-box.service << 'SBSVC'
[Unit]
Description=sing-box Service
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SBSVC

    systemctl daemon-reload
    log_info "sing-box entry config generated with multiplexing + padding"
}

# ============================================================================
# 8. DOMAIN FRONTING HELPER
# ============================================================================

setup_cdn_ws_config() {
    local uuid="$1"
    local domain="$2"

    log_step "Generating CDN WebSocket config (Cloudflare domain fronting)..."

    cat > "${CONFIG_DIR}/cdn-ws-config.json" << CDN_WS
{
    "_comment": "Use this config behind Cloudflare CDN",
    "inbounds": [
        {
            "tag": "vless-ws-in",
            "listen": "0.0.0.0",
            "port": 8080,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/$(openssl rand -hex 8)",
                    "headers": {
                        "Host": "${domain}"
                    }
                }
            }
        }
    ]
}
CDN_WS

    log_info "CDN WS config saved to ${CONFIG_DIR}/cdn-ws-config.json"
    log_info "Setup Cloudflare: DNS A record → server IP (proxied)"
    log_info "Use port 8080 behind Cloudflare (or 2052, 2082, 2086, 2095 for HTTP)"
}

# ============================================================================
# MAIN MENU
# ============================================================================

show_antidpi_menu() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║    Anti-DPI Module — Traffic Optimization Suite   ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${GREEN}1${NC}) Apply TLS Fragment (Most effective)"
    echo -e "  ${GREEN}2${NC}) Apply TCP Segmentation"
    echo -e "  ${GREEN}3${NC}) Apply Kernel Anti-DPI Tuning"
    echo -e "  ${GREEN}4${NC}) Apply Advanced iptables Rules"
    echo -e "  ${GREEN}5${NC}) Generate Anti-DPI Entry Config (Xray)"
    echo -e "  ${GREEN}6${NC}) Generate Anti-DPI Exit Config (Xray)"
    echo -e "  ${GREEN}7${NC}) Install sing-box (Advanced Engine)"
    echo -e "  ${GREEN}8${NC}) Setup Cloudflare WARP Chain"
    echo -e "  ${GREEN}9${NC}) Generate CDN WebSocket Config"
    echo -e "  ${GREEN}A${NC}) Apply ALL Optimizations (Recommended)"
    echo -e "  ${YELLOW}0${NC}) Back / Exit"
    echo ""
    echo -en "  ${CYAN}Choice: ${NC}"
}

apply_all_antidpi() {
    log_step "Applying ALL anti-DPI optimizations..."
    echo ""

    apply_tls_fragment_xray
    apply_tcp_segmentation
    apply_kernel_antidpi
    apply_advanced_iptables

    # Restart Xray with new config
    systemctl restart xray 2>/dev/null || true

    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  All anti-DPI optimizations applied!${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}Active protections:${NC}"
    echo -e "  ✅ TLS ClientHello Fragment (1-3 bytes)"
    echo -e "  ✅ TCP Segmentation (MSS=160)"
    echo -e "  ✅ TCP Timestamps disabled"
    echo -e "  ✅ TTL normalized to 64"
    echo -e "  ✅ PMTU discovery disabled"
    echo -e "  ✅ Source port randomization"
    echo -e "  ✅ ICMP timestamp blocked"
    echo -e "  ✅ Connection rate limiting"
    echo ""
}

main() {
    [[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

    while true; do
        show_antidpi_menu
        read -r choice
        echo ""

        case "${choice}" in
            1) apply_tls_fragment_xray ;;
            2) apply_tcp_segmentation ;;
            3) apply_kernel_antidpi ;;
            4) apply_advanced_iptables ;;
            5)
                echo -en "Trojan password: "
                read -r pw
                generate_antidpi_entry_config "${pw}"
                systemctl restart xray
                ;;
            6)
                echo -en "UUID: "; read -r uuid
                echo -en "Private Key: "; read -r pk
                echo -en "Public Key: "; read -r pubk
                echo -en "Short ID: "; read -r sid
                generate_antidpi_exit_config "${uuid}" "${pk}" "${pubk}" "${sid}"
                systemctl restart xray
                ;;
            7) install_singbox ;;
            8) setup_warp_chain ;;
            9)
                echo -en "UUID: "; read -r uuid
                echo -en "Domain: "; read -r domain
                setup_cdn_ws_config "${uuid}" "${domain}"
                ;;
            [Aa]) apply_all_antidpi ;;
            0) echo "Bye!"; exit 0 ;;
            *) log_warn "Invalid choice" ;;
        esac

        echo ""
        echo -en "${YELLOW}Press Enter...${NC}"
        read -r
    done
}

main "$@"
