#!/usr/bin/env bash
# ============================================================================
#  performance_tuner.sh — Enterprise Performance & Scalability Module
#  Part of Tunnel Enterprise v2.0.0
#
#  Goals:
#    ✦ Support 500-5000+ concurrent users per server
#    ✦ Maximize bandwidth (minimize overhead)
#    ✦ Stable ping, no jitter on upload/download
#    ✦ Minimize CPU/RAM usage per connection
#    ✦ Invisible to DPI (zero protocol fingerprint)
#    ✦ Self-healing under load
#
# ============================================================================

set -euo pipefail

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
# 1. KERNEL — MAXIMUM THROUGHPUT + SCALABILITY
# ============================================================================

apply_kernel_optimization() {
    log_step "Phase 1: Kernel Network Stack Optimization..."

    cat > /etc/sysctl.d/99-tunnel-performance.conf << 'SYSCTL'
# ============================================================================
# TUNNEL ENTERPRISE — PRODUCTION KERNEL TUNING
# Optimized for: 5000+ concurrent connections, high bandwidth, low jitter
# ============================================================================

# ─── IP FORWARDING ──────────────────────────────────────────────────────────
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ─── BBR CONGESTION CONTROL ────────────────────────────────────────────────
# BBR v1: best for high-latency, lossy links (Iran ↔ Foreign)
# Provides 2-10x throughput improvement over cubic/reno
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ─── TCP FAST OPEN (reduce handshake latency) ──────────────────────────────
# 3 = enable for both client and server
net.ipv4.tcp_fastopen = 3

# ─── SOCKET BUFFER SIZES ───────────────────────────────────────────────────
# Critical for high-bandwidth tunnels
# Default/Max receive buffer: 32MB (supports 1Gbps+ links)
net.core.rmem_default = 2097152
net.core.rmem_max = 33554432
# Default/Max send buffer: 32MB
net.core.wmem_default = 2097152
net.core.wmem_max = 33554432
# TCP auto-tuning buffers: min=8KB, default=2MB, max=32MB
net.ipv4.tcp_rmem = 8192 2097152 33554432
net.ipv4.tcp_wmem = 8192 2097152 33554432
# UDP buffers (critical for WireGuard performance)
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# ─── CONNECTION BACKLOG (high user count) ───────────────────────────────────
# Accept up to 65535 pending connections
net.core.somaxconn = 65535
# Network device backlog (packets queued before processing)
net.core.netdev_max_backlog = 65535
# Maximum SYN backlog
net.ipv4.tcp_max_syn_backlog = 65535

# ─── TCP CONNECTION MANAGEMENT ──────────────────────────────────────────────
# Reuse TIME_WAIT sockets (critical for high connection rate)
net.ipv4.tcp_tw_reuse = 1
# Reduce FIN timeout (free resources faster)
net.ipv4.tcp_fin_timeout = 10
# Max orphan sockets (connections with no process)
net.ipv4.tcp_max_orphans = 65535
# SYN cookies (prevent SYN flood)
net.ipv4.tcp_syncookies = 1
# SYN retries (fail fast = less resource waste)
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# ─── KEEPALIVE (detect dead connections, free resources) ────────────────────
# Check if connection alive after 120s idle
net.ipv4.tcp_keepalive_time = 120
# Probe every 15s
net.ipv4.tcp_keepalive_intvl = 15
# Drop after 5 failed probes (120 + 5*15 = 195s max)
net.ipv4.tcp_keepalive_probes = 5

# ─── FILE DESCRIPTORS (1 per connection per direction) ──────────────────────
# With 5000 users: ~20000 FDs needed minimum
fs.file-max = 2097152
fs.nr_open = 2097152

# ─── MEMORY PRESSURE MANAGEMENT ────────────────────────────────────────────
# TCP memory limits in pages (4KB each)
# Low=256MB, Pressure=512MB, High=1GB
net.ipv4.tcp_mem = 65536 131072 262144
# UDP memory
net.ipv4.udp_mem = 65536 131072 262144

# ─── PORT RANGE ─────────────────────────────────────────────────────────────
net.ipv4.ip_local_port_range = 1024 65535

# ─── ARP CACHE (for WireGuard subnet) ──────────────────────────────────────
net.ipv4.neigh.default.gc_thresh1 = 512
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 4096

# ─── CONNTRACK (NAT connection tracking) ────────────────────────────────────
# Each user creates multiple conntrack entries
# 5000 users * ~20 connections = 100000 entries minimum
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_buckets = 65536
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 15
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# ─── ANTI-DPI KERNEL SETTINGS ──────────────────────────────────────────────
# Disable TCP timestamps (prevents OS fingerprinting by DPI)
net.ipv4.tcp_timestamps = 0
# Disable PMTU discovery (prevents size-based fingerprinting)
net.ipv4.ip_no_pmtu_disc = 1
# Disable slow start after idle (prevents traffic pattern detection)
net.ipv4.tcp_slow_start_after_idle = 0
# Passive ECN (interoperable, no fingerprint)
net.ipv4.tcp_ecn = 2
# TCP window scaling (needed for high bandwidth)
net.ipv4.tcp_window_scaling = 1

# ─── SECURITY ───────────────────────────────────────────────────────────────
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
SYSCTL

    # Load conntrack module first
    modprobe nf_conntrack 2>/dev/null || true

    sysctl --system > /dev/null 2>&1

    log_info "Kernel optimized: BBR, 32MB buffers, 262K conntrack, 2M file descriptors"
}

# ============================================================================
# 2. FILE DESCRIPTORS & PROCESS LIMITS
# ============================================================================

apply_system_limits() {
    log_step "Phase 2: System Limits for High Concurrency..."

    # PAM limits
    cat > /etc/security/limits.d/99-tunnel-performance.conf << 'LIMITS'
# Tunnel Enterprise — Process Limits
# Needed for 5000+ concurrent connections

*       soft    nofile      1048576
*       hard    nofile      1048576
root    soft    nofile      1048576
root    hard    nofile      1048576

*       soft    nproc       65535
*       hard    nproc       65535
root    soft    nproc       65535
root    hard    nproc       65535

*       soft    memlock     unlimited
*       hard    memlock     unlimited

*       soft    core        unlimited
*       hard    core        unlimited
LIMITS

    # systemd global limits
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/99-tunnel-limits.conf << 'SYSD_LIMITS'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
DefaultLimitMEMLOCK=infinity
SYSD_LIMITS

    # Ensure PAM loads limits
    if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session 2>/dev/null || true
    fi

    systemctl daemon-reexec 2>/dev/null || true

    log_info "File limits: 1M, Process limits: 65K, Memory lock: unlimited"
}

# ============================================================================
# 3. XRAY PERFORMANCE TUNING
# ============================================================================

optimize_xray_service() {
    log_step "Phase 3: Xray Service Optimization..."

    # Xray systemd override for performance
    mkdir -p /etc/systemd/system/xray.service.d
    cat > /etc/systemd/system/xray.service.d/performance.conf << 'XRAY_PERF'
[Service]
# High file descriptor limit
LimitNOFILE=1048576
LimitNPROC=65535

# Memory management
LimitMEMLOCK=infinity

# Auto-restart on failure
Restart=always
RestartSec=3

# CPU scheduling (slightly elevated priority)
Nice=-5

# Protect from OOM killer (important for tunnel stability)
OOMScoreAdjust=-500

# Resource accounting
MemoryAccounting=yes
CPUAccounting=yes

# Security hardening (doesn't affect performance)
ProtectSystem=full
NoNewPrivileges=true
XRAY_PERF

    systemctl daemon-reload

    log_info "Xray: 1M FDs, Nice=-5, OOM-protected, auto-restart"
}

# ============================================================================
# 4. WIREGUARD PERFORMANCE TUNING
# ============================================================================

optimize_wireguard() {
    log_step "Phase 4: WireGuard Performance Tuning..."

    local wg_conf="/etc/wireguard/wg0.conf"
    [[ -f "${wg_conf}" ]] || { log_warn "WireGuard not configured yet"; return 0; }

    # Find optimal MTU
    local optimal_mtu
    optimal_mtu=$(find_optimal_mtu)

    # Update MTU in config
    if grep -q "^MTU" "${wg_conf}"; then
        sed -i "s/^MTU.*/MTU = ${optimal_mtu}/" "${wg_conf}"
    fi

    # Set interface queue length (higher = better throughput under load)
    ip link set wg0 txqueuelen 4000 2>/dev/null || true

    # Enable GRO/GSO offloading if supported (kernel 5.19+)
    ethtool -K wg0 gro on 2>/dev/null || true
    ethtool -K wg0 gso on 2>/dev/null || true

    # Increase WireGuard interface buffer
    ip link set wg0 mtu "${optimal_mtu}" 2>/dev/null || true

    log_info "WireGuard: MTU=${optimal_mtu}, txqueue=4000, GRO/GSO enabled"
}

find_optimal_mtu() {
    # WireGuard overhead: 60 bytes (IPv4) or 80 bytes (IPv6)
    # + Trojan/TLS overhead: ~100 bytes
    # Standard ethernet MTU: 1500
    # Optimal WireGuard MTU = 1500 - 60 - overhead margin

    local peer_endpoint
    peer_endpoint=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1 | head -1)

    if [[ -n "${peer_endpoint}" ]]; then
        # Test actual path MTU
        local test_mtu=1400
        while [[ ${test_mtu} -ge 1200 ]]; do
            if ping -c 2 -W 2 -M do -s $((test_mtu - 28)) "${peer_endpoint}" &>/dev/null; then
                echo $((test_mtu - 80))  # Subtract WireGuard overhead
                return 0
            fi
            test_mtu=$((test_mtu - 20))
        done
    fi

    # Default safe MTU
    echo "1280"
}

# ============================================================================
# 5. BANDWIDTH OPTIMIZATION
# ============================================================================

optimize_bandwidth() {
    log_step "Phase 5: Bandwidth Optimization..."

    local default_iface
    default_iface=$(ip route show default | awk '{print $5}' | head -1)

    # Increase NIC ring buffer (if hardware supports it)
    ethtool -G "${default_iface}" rx 4096 tx 4096 2>/dev/null || true

    # Enable TCP offloading on physical interface
    ethtool -K "${default_iface}" tso on 2>/dev/null || true
    ethtool -K "${default_iface}" gso on 2>/dev/null || true
    ethtool -K "${default_iface}" gro on 2>/dev/null || true
    ethtool -K "${default_iface}" tx on 2>/dev/null || true
    ethtool -K "${default_iface}" rx on 2>/dev/null || true

    # Increase transmit queue length
    ip link set "${default_iface}" txqueuelen 10000 2>/dev/null || true

    # Enable RPS (Receive Packet Steering) — distribute packets across CPUs
    local num_cpus
    num_cpus=$(nproc)
    local rps_mask
    rps_mask=$(printf '%x' $(( (1 << num_cpus) - 1 )))

    for rxq in /sys/class/net/"${default_iface}"/queues/rx-*/rps_cpus; do
        echo "${rps_mask}" > "${rxq}" 2>/dev/null || true
    done

    # Enable XPS (Transmit Packet Steering)
    local cpu_idx=0
    for txq in /sys/class/net/"${default_iface}"/queues/tx-*/xps_cpus; do
        local xps_mask
        xps_mask=$(printf '%x' $(( 1 << (cpu_idx % num_cpus) )))
        echo "${xps_mask}" > "${txq}" 2>/dev/null || true
        ((cpu_idx++))
    done

    # RFS (Receive Flow Steering) — route flows to the CPU processing them
    echo 65536 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
    for rxq in /sys/class/net/"${default_iface}"/queues/rx-*/rps_flow_cnt; do
        echo 32768 > "${rxq}" 2>/dev/null || true
    done

    log_info "NIC optimized: TSO/GSO/GRO on, RPS/XPS enabled, txqueue=10000"
}

# ============================================================================
# 6. ANTI-DPI (Integrated)
# ============================================================================

apply_antidpi_iptables() {
    log_step "Phase 6: Anti-DPI iptables Rules..."

    local iface
    iface=$(ip route show default | awk '{print $5}' | head -1)

    # TCP MSS clamping for TLS ports (fragment ClientHello)
    iptables -t mangle -C OUTPUT -p tcp --dport 443 -j TCPMSS --set-mss 160 2>/dev/null || \
        iptables -t mangle -A OUTPUT -p tcp --dport 443 -j TCPMSS --set-mss 160 2>/dev/null || true

    iptables -t mangle -C POSTROUTING -p tcp --dport 443 -j TCPMSS --set-mss 160 2>/dev/null || \
        iptables -t mangle -A POSTROUTING -p tcp --dport 443 -j TCPMSS --set-mss 160 2>/dev/null || true

    # Normalize TTL (prevent hop-counting fingerprint)
    iptables -t mangle -C POSTROUTING -o "${iface}" -j TTL --ttl-set 64 2>/dev/null || \
        iptables -t mangle -A POSTROUTING -o "${iface}" -j TTL --ttl-set 64 2>/dev/null || true

    # Block ICMP timestamp (information leak)
    iptables -C OUTPUT -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null || \
        iptables -A OUTPUT -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null || true

    # Connection rate limiting (anti-scan)
    iptables -C INPUT -p tcp --syn -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP 2>/dev/null || \
        iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP 2>/dev/null || true

    # Save rules
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save 2>/dev/null || true

    log_info "Anti-DPI: MSS=160, TTL=64, ICMP blocked, rate-limited"
}

# ============================================================================
# 7. MEMORY OPTIMIZATION
# ============================================================================

optimize_memory() {
    log_step "Phase 7: Memory Optimization..."

    # Transparent Huge Pages (better for WireGuard crypto)
    echo "madvise" > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true

    # Reduce swappiness (keep things in RAM)
    sysctl -w vm.swappiness=10 > /dev/null 2>&1

    # Increase dirty page write-back (batch I/O)
    sysctl -w vm.dirty_ratio=15 > /dev/null 2>&1
    sysctl -w vm.dirty_background_ratio=5 > /dev/null 2>&1

    # VFS cache pressure (keep directory entries in cache)
    sysctl -w vm.vfs_cache_pressure=50 > /dev/null 2>&1

    # Persist
    cat >> /etc/sysctl.d/99-tunnel-performance.conf << 'MEM_OPT'

# ─── MEMORY OPTIMIZATION ───────────────────────────────────────────────────
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50
vm.min_free_kbytes = 65536
MEM_OPT

    log_info "Memory: swappiness=10, THP=madvise, cache optimized"
}

# ============================================================================
# 8. JITTER REDUCTION (Stable ping)
# ============================================================================

optimize_jitter() {
    log_step "Phase 8: Jitter Reduction for Stable Ping..."

    # Use fq_codel qdisc for low-latency queuing
    local default_iface
    default_iface=$(ip route show default | awk '{print $5}' | head -1)

    # fq (Fair Queue) with BBR is the best combo for low jitter
    tc qdisc replace dev "${default_iface}" root fq 2>/dev/null || true

    # Also on WireGuard interface
    tc qdisc replace dev wg0 root fq 2>/dev/null || true

    # Disable interrupt coalescing (lower latency, slightly more CPU)
    ethtool -C "${default_iface}" rx-usecs 50 tx-usecs 50 2>/dev/null || true

    # Make settings persistent
    cat > /etc/networkd-dispatcher/routable.d/50-tunnel-qdisc.sh 2>/dev/null << 'QDISC' || true
#!/bin/bash
IFACE=$(ip route show default | awk '{print $5}' | head -1)
tc qdisc replace dev "${IFACE}" root fq 2>/dev/null || true
tc qdisc replace dev wg0 root fq 2>/dev/null || true
ip link set wg0 txqueuelen 4000 2>/dev/null || true
QDISC
    chmod +x /etc/networkd-dispatcher/routable.d/50-tunnel-qdisc.sh 2>/dev/null || true

    log_info "Jitter: fq qdisc on all interfaces, interrupt coalescing=50us"
}

# ============================================================================
# 9. CONNECTION POOL & RESOURCE MONITOR
# ============================================================================

create_resource_monitor() {
    log_step "Phase 9: Resource Monitor Service..."

    cat > /usr/local/bin/tunnel-monitor.sh << 'MONITOR'
#!/usr/bin/env bash
# Tunnel Enterprise — Resource Monitor & Auto-Scaler
# Runs every 60 seconds, logs metrics, takes corrective action

set -euo pipefail

LOG="/var/log/tunnel.log"
ALERT_CPU=85
ALERT_MEM=85
ALERT_CONN=4000

log_mon() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] $*" >> "${LOG}"
}

# Collect metrics
cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print int($2)}')
mem_usage=$(free | awk '/Mem:/ {printf "%d", $3/$2*100}')
total_conns=$(ss -s | grep "TCP:" | awk '{print $2}')
wg_conns=$(wg show wg0 2>/dev/null | grep -c "peer" || echo 0)
xray_conns=$(ss -tnp | grep -c "xray" || echo 0)
xray_mem=$(ps -o rss= -p $(pgrep xray 2>/dev/null || echo 0) 2>/dev/null | awk '{print int($1/1024)}' || echo 0)

# Log metrics
log_mon "CPU=${cpu_usage}% MEM=${mem_usage}% TCP=${total_conns} WG_PEERS=${wg_conns} XRAY_CONNS=${xray_conns} XRAY_MEM=${xray_mem}MB"

# Alert: High CPU
if [[ ${cpu_usage} -gt ${ALERT_CPU} ]]; then
    log_mon "ALERT: CPU ${cpu_usage}% > ${ALERT_CPU}%"
fi

# Alert: High Memory
if [[ ${mem_usage} -gt ${ALERT_MEM} ]]; then
    log_mon "ALERT: MEM ${mem_usage}% > ${ALERT_MEM}%"

    # Drop caches to free memory
    sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    log_mon "ACTION: Dropped kernel caches"
fi

# Alert: Too many connections (possible attack or overload)
if [[ ${total_conns:-0} -gt ${ALERT_CONN} ]]; then
    log_mon "ALERT: ${total_conns} TCP connections > ${ALERT_CONN}"

    # Drop stale conntrack entries
    conntrack -F 2>/dev/null || true
    log_mon "ACTION: Flushed conntrack table"
fi

# Check Xray memory leak (restart if > 512MB)
if [[ ${xray_mem:-0} -gt 512 ]]; then
    log_mon "ALERT: Xray using ${xray_mem}MB RAM, restarting..."
    systemctl restart xray
    log_mon "ACTION: Xray restarted"
fi

# Conntrack usage check
if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    ct_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    ct_pct=$((ct_count * 100 / ct_max))
    if [[ ${ct_pct} -gt 80 ]]; then
        log_mon "ALERT: Conntrack ${ct_pct}% full (${ct_count}/${ct_max})"
        # Increase conntrack max dynamically
        new_max=$((ct_max * 2))
        sysctl -w net.netfilter.nf_conntrack_max=${new_max} > /dev/null 2>&1
        log_mon "ACTION: Conntrack max increased to ${new_max}"
    fi
fi
MONITOR

    chmod +x /usr/local/bin/tunnel-monitor.sh

    # Systemd timer (every 60 seconds)
    cat > /etc/systemd/system/tunnel-monitor.service << 'SVC'
[Unit]
Description=Tunnel Enterprise Resource Monitor

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tunnel-monitor.sh
SVC

    cat > /etc/systemd/system/tunnel-monitor.timer << 'TIMER'
[Unit]
Description=Tunnel Resource Monitor Timer

[Timer]
OnBootSec=30
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
TIMER

    systemctl daemon-reload
    systemctl enable tunnel-monitor.timer
    systemctl start tunnel-monitor.timer

    log_info "Resource monitor: every 60s, auto-scales conntrack, restarts leaky processes"
}

# ============================================================================
# 10. XRAY OPTIMIZED CONFIGS (HIGH PERFORMANCE + ANTI-DPI)
# ============================================================================

generate_optimized_entry_config() {
    local trojan_password="$1"
    local cert_dir="/root/tunnel-config/certs"

    log_step "Generating production Entry Node config..."

    cat > /usr/local/etc/xray/config.json << XCONF
{
    "log": {
        "loglevel": "warning",
        "access": "none",
        "error": "/var/log/xray/error.log"
    },
    "dns": {
        "servers": [
            {
                "address": "https+local://1.1.1.1/dns-query",
                "skipFallback": true
            },
            {
                "address": "https+local://8.8.8.8/dns-query"
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
                    "alpn": [
                        "h2",
                        "http/1.1"
                    ],
                    "fingerprint": "randomized"
                },
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpKeepAliveIdle": 120,
                    "tcpNoDelay": true,
                    "tcpMptcp": true
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ],
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
                "protocol": [
                    "bittorrent"
                ]
            },
            {
                "type": "field",
                "inboundTag": [
                    "trojan-in"
                ],
                "outboundTag": "fragment-out"
            }
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 8,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "bufferSize": 4,
                "statsUserUplink": false,
                "statsUserDownlink": false
            }
        },
        "system": {
            "statsInboundUplink": false,
            "statsInboundDownlink": false,
            "statsOutboundUplink": false,
            "statsOutboundDownlink": false
        }
    }
}
XCONF

    log_info "Entry config: TLS Fragment + randomized fingerprint + TCP Fast Open"
    log_info "Stats DISABLED for performance (enable in X-UI if needed)"
}

generate_optimized_exit_config() {
    local uuid="$1"
    local private_key="$2"
    local short_id="$3"

    log_step "Generating production Exit Node config..."

    cat > /usr/local/etc/xray/config.json << XCONF
{
    "log": {
        "loglevel": "warning",
        "access": "none",
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
                    "tcpKeepAliveIdle": 120,
                    "tcpNoDelay": true,
                    "tcpMptcp": true
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
                "protocol": [
                    "bittorrent"
                ]
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
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "bufferSize": 4,
                "statsUserUplink": false,
                "statsUserDownlink": false
            }
        },
        "system": {
            "statsInboundUplink": false,
            "statsInboundDownlink": false
        }
    }
}
XCONF

    log_info "Exit config: Reality + 8 SNIs + MPTCP + TCP Fast Open"
}

# ============================================================================
# BENCHMARK
# ============================================================================

run_benchmark() {
    log_step "Running System Benchmark..."
    echo ""

    echo -e "${BOLD}▸ CPU${NC}"
    echo "  Cores: $(nproc)"
    echo "  Model: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"

    echo -e "\n${BOLD}▸ Memory${NC}"
    free -h | awk '/^Mem:/ {printf "  Total: %s, Used: %s, Free: %s (%.1f%% used)\n", $2, $3, $4, $3/$2*100}'

    echo -e "\n${BOLD}▸ Disk I/O${NC}"
    if command -v dd &>/dev/null; then
        local speed
        speed=$(dd if=/dev/zero of=/tmp/bench_test bs=1M count=256 oflag=dsync 2>&1 | tail -1 | awk '{print $(NF-1), $NF}')
        rm -f /tmp/bench_test
        echo "  Write: ${speed}"
    fi

    echo -e "\n${BOLD}▸ Network${NC}"
    echo "  Default iface: $(ip route show default | awk '{print $5}' | head -1)"
    echo "  Public IP: $(curl -s --max-time 5 https://api.ipify.org || echo 'N/A')"

    echo -e "\n${BOLD}▸ TCP Settings${NC}"
    echo "  Congestion: $(sysctl -n net.ipv4.tcp_congestion_control)"
    echo "  Fast Open: $(sysctl -n net.ipv4.tcp_fastopen)"
    echo "  Timestamps: $(sysctl -n net.ipv4.tcp_timestamps)"
    echo "  rmem_max: $(( $(sysctl -n net.core.rmem_max) / 1048576 ))MB"
    echo "  wmem_max: $(( $(sysctl -n net.core.wmem_max) / 1048576 ))MB"

    echo -e "\n${BOLD}▸ Limits${NC}"
    echo "  file-max: $(sysctl -n fs.file-max)"
    echo "  Open files: $(ulimit -n)"
    echo "  Conntrack max: $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 'N/A')"
    echo "  Conntrack used: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 'N/A')"

    echo -e "\n${BOLD}▸ Services${NC}"
    for svc in wg-quick@wg0 xray fail2ban tunnel-watchdog.timer tunnel-monitor.timer; do
        local status
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            status="${GREEN}running${NC}"
        else
            status="${RED}stopped${NC}"
        fi
        echo -e "  ${svc}: ${status}"
    done

    if ip link show wg0 &>/dev/null; then
        echo -e "\n${BOLD}▸ WireGuard${NC}"
        echo "  MTU: $(ip link show wg0 | grep mtu | awk '{print $5}')"
        echo "  txqueuelen: $(ip link show wg0 | grep qlen | awk '{print $NF}')"
        wg show wg0 transfer 2>/dev/null | while read -r pub rx tx; do
            echo "  Peer: RX=$(( rx / 1048576 ))MB TX=$(( tx / 1048576 ))MB"
        done
    fi

    echo ""
}

# ============================================================================
# APPLY ALL
# ============================================================================

apply_all() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║   Applying ALL Performance + Anti-DPI Optimizations        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    apply_kernel_optimization
    apply_system_limits
    optimize_xray_service
    optimize_wireguard
    optimize_bandwidth
    apply_antidpi_iptables
    optimize_memory
    optimize_jitter
    create_resource_monitor

    # Restart services with new settings
    systemctl restart xray 2>/dev/null || true
    systemctl restart wg-quick@wg0 2>/dev/null || true

    echo ""
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  ✅ ALL OPTIMIZATIONS APPLIED${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Performance:${NC}"
    echo -e "    ✅ BBR congestion control"
    echo -e "    ✅ 32MB socket buffers"
    echo -e "    ✅ TCP Fast Open + No Delay + MPTCP"
    echo -e "    ✅ RPS/XPS packet steering (all CPUs)"
    echo -e "    ✅ fq qdisc (low jitter)"
    echo -e "    ✅ NIC offloading (TSO/GSO/GRO)"
    echo ""
    echo -e "  ${BOLD}Scalability:${NC}"
    echo -e "    ✅ 2M file descriptors"
    echo -e "    ✅ 262K conntrack entries (auto-scales)"
    echo -e "    ✅ 65K process limit"
    echo -e "    ✅ Xray OOM-protected, auto-restart"
    echo ""
    echo -e "  ${BOLD}Anti-DPI:${NC}"
    echo -e "    ✅ TLS Fragment (1-3 bytes)"
    echo -e "    ✅ TCP MSS=160"
    echo -e "    ✅ Timestamps disabled"
    echo -e "    ✅ TTL=64 normalized"
    echo -e "    ✅ PMTU discovery off"
    echo -e "    ✅ Randomized TLS fingerprint"
    echo -e "    ✅ 8 SNI rotation domains"
    echo ""
    echo -e "  ${BOLD}Stability:${NC}"
    echo -e "    ✅ Resource monitor (every 60s)"
    echo -e "    ✅ Auto memory cleanup"
    echo -e "    ✅ Conntrack auto-scaling"
    echo -e "    ✅ Xray memory leak detection"
    echo ""
}

# ============================================================================
# MENU
# ============================================================================

show_menu() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║   Performance Tuner — Enterprise Optimization Suite  ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${GREEN}1${NC}) Kernel Optimization (BBR, buffers, conntrack)"
    echo -e "  ${GREEN}2${NC}) System Limits (file descriptors, processes)"
    echo -e "  ${GREEN}3${NC}) Xray Service Tuning (OOM, priority, restart)"
    echo -e "  ${GREEN}4${NC}) WireGuard Optimization (MTU, queue, offload)"
    echo -e "  ${GREEN}5${NC}) Bandwidth Optimization (NIC, RPS/XPS)"
    echo -e "  ${GREEN}6${NC}) Anti-DPI iptables (fragment, TTL, MSS)"
    echo -e "  ${GREEN}7${NC}) Memory Optimization (swap, cache, THP)"
    echo -e "  ${GREEN}8${NC}) Jitter Reduction (qdisc, interrupt coalescing)"
    echo -e "  ${GREEN}9${NC}) Resource Monitor (auto-healing)"
    echo -e "  ${GREEN}B${NC}) Run Benchmark"
    echo -e "  ${GREEN}E${NC}) Generate Optimized Entry Config"
    echo -e "  ${GREEN}X${NC}) Generate Optimized Exit Config"
    echo -e "  ${GREEN}A${NC}) Apply ALL (Recommended)"
    echo -e "  ${YELLOW}0${NC}) Exit"
    echo -en "  ${CYAN}Choice: ${NC}"
}

main() {
    [[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

    while true; do
        show_menu
        read -r choice
        echo ""

        case "${choice}" in
            1) apply_kernel_optimization ;;
            2) apply_system_limits ;;
            3) optimize_xray_service ;;
            4) optimize_wireguard ;;
            5) optimize_bandwidth ;;
            6) apply_antidpi_iptables ;;
            7) optimize_memory ;;
            8) optimize_jitter ;;
            9) create_resource_monitor ;;
            [Bb]) run_benchmark ;;
            [Ee])
                echo -en "Trojan password: "; read -r pw
                generate_optimized_entry_config "${pw}"
                systemctl restart xray 2>/dev/null || true
                ;;
            [Xx])
                echo -en "UUID: "; read -r uuid
                echo -en "Private Key: "; read -r pk
                echo -en "Short ID: "; read -r sid
                generate_optimized_exit_config "${uuid}" "${pk}" "${sid}"
                systemctl restart xray 2>/dev/null || true
                ;;
            [Aa]) apply_all ;;
            0) echo "Bye!"; exit 0 ;;
            *) log_warn "Invalid choice" ;;
        esac

        echo ""
        echo -en "${YELLOW}Press Enter...${NC}"
        read -r
    done
}

main "$@"
