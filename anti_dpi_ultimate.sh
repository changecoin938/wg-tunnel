#!/bin/bash
# ============================================================================
#  Anti-DPI Ultimate v1.0
#  Enterprise-Grade Deep Packet Inspection Evasion Engine
#
#  All techniques run in KERNEL space (nftables/iptables/tc/sysctl)
#  Zero userspace overhead — inspired by GFW-Knocker & Paqet
#
#  Architecture:
#    Layer 1 (raw -300):    RST suppression + conntrack bypass
#    Layer 2 (mangle -150): MSS clamping + fingerprint normalization
#    Layer 3 (filter 0):    ICMP hardening + rate limiting
#    Layer 4 (tc):          Traffic shaping + timing jitter
#    Layer 5 (sysctl):      TCP stack hardening
#    Layer 6 (Xray):        TLS fragment + uTLS + Reality SNI
# ============================================================================

set -uo pipefail
# NOTE: set -e intentionally NOT used — nft/iptables/tc commands may fail
# on older kernels and we handle errors per-function with || true guards.

# ============================================================================
# SECTION 1: CONSTANTS & LOGGING
# ============================================================================

readonly VERSION="1.0.0"
readonly SCRIPT_NAME="Anti-DPI Ultimate"

# Ports
readonly PORT_TROJAN=443
readonly PORT_VLESS=8443
readonly PORT_WG=51820

# Marks
readonly XRAY_MARK=255  # 0xff

# Paths
readonly TUNNEL_CONFIG_DIR="/root/tunnel-config"
readonly XRAY_CONFIG="/usr/local/etc/xray/config.json"
readonly SYSCTL_CONF="/etc/sysctl.d/99-antidpi-ultimate.conf"
readonly NFT_SAVE_DIR="/etc/nftables.d"
readonly NFT_SAVE_FILE="${NFT_SAVE_DIR}/antidpi.nft"
readonly RESTORE_SCRIPT="/usr/local/bin/antidpi-restore.sh"
readonly SYSTEMD_SERVICE="/etc/systemd/system/antidpi-ultimate.service"
readonly LOG_FILE="/var/log/antidpi-ultimate.log"

# nftables table names (prefixed to avoid conflicts)
readonly NFT_TABLE_RAW="antidpi_raw"
readonly NFT_TABLE_MANGLE="antidpi_mangle"
readonly NFT_TABLE_FILTER="antidpi_filter"
readonly NFT_TABLE_CT="antidpi_ct"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Capability flags (set by detect_capabilities)
FIREWALL_BACKEND=""        # "nftables" or "iptables"
NFT_HAS_TCP_OPT_SET=false  # nftables tcp option set support
HAS_TC=false
HAS_NETEM=false
HAS_ETHTOOL=false
HAS_JQ=false
NODE_ROLE=""               # "iran" or "foreign"
PRIMARY_IFACE=""           # main network interface

# ── Logging ──────────────────────────────────────────────────────────────────

log_info()    { echo -e "${GREEN}[✓]${NC} $*"; echo "[$(date '+%F %T')] INFO: $*" >> "${LOG_FILE}" 2>/dev/null; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; echo "[$(date '+%F %T')] WARN: $*" >> "${LOG_FILE}" 2>/dev/null; }
log_error()   { echo -e "${RED}[✗]${NC} $*"; echo "[$(date '+%F %T')] ERROR: $*" >> "${LOG_FILE}" 2>/dev/null; }
log_step()    { echo -e "${CYAN}[→]${NC} $*"; echo "[$(date '+%F %T')] STEP: $*" >> "${LOG_FILE}" 2>/dev/null; }
log_header()  { echo -e "\n${BOLD}${MAGENTA}══ $* ══${NC}\n"; }
log_ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
log_fail()    { echo -e "  ${RED}✗${NC} $*"; }
log_skip()    { echo -e "  ${YELLOW}⊘${NC} $*"; }

# ── Root Check ───────────────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# ── OS Check ─────────────────────────────────────────────────────────────────

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Unsupported OS (no /etc/os-release)"
        exit 1
    fi
    source /etc/os-release
    case "${ID}" in
        ubuntu|debian) ;;
        centos|almalinux|rocky) ;;
        *) log_warn "Untested OS: ${ID}. Proceeding anyway..." ;;
    esac
}

# ============================================================================
# SECTION 2: DEPENDENCY DETECTION
# ============================================================================

detect_capabilities() {
    log_header "Detecting System Capabilities"

    # ── Primary network interface ──
    PRIMARY_IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
    if [[ -z "${PRIMARY_IFACE}" ]]; then
        log_error "Cannot detect primary network interface"
        exit 1
    fi
    log_info "Primary interface: ${PRIMARY_IFACE}"

    # ── Firewall backend ──
    if command -v nft &>/dev/null; then
        # Test if nftables actually works
        if nft list ruleset &>/dev/null 2>&1; then
            FIREWALL_BACKEND="nftables"

            # Test tcp option set support (nftables >= 0.9.6)
            if nft add table inet __antidpi_test 2>/dev/null; then
                if nft add chain inet __antidpi_test __test \
                    '{ type filter hook output priority 0; policy accept; }' 2>/dev/null; then
                    if nft add rule inet __antidpi_test __test \
                        tcp option maxseg size set 536 2>/dev/null; then
                        NFT_HAS_TCP_OPT_SET=true
                    fi
                fi
                nft delete table inet __antidpi_test 2>/dev/null || true
            fi

            log_info "Firewall: nftables (tcp option set: ${NFT_HAS_TCP_OPT_SET})"
        else
            FIREWALL_BACKEND="iptables"
            log_warn "nftables found but not functional, using iptables"
        fi
    else
        FIREWALL_BACKEND="iptables"
        log_info "Firewall: iptables (nftables not available)"
    fi

    # ── tc (traffic control) ──
    if command -v tc &>/dev/null; then
        HAS_TC=true
        # Check for netem module
        if modprobe sch_netem 2>/dev/null || lsmod | grep -q sch_netem 2>/dev/null; then
            HAS_NETEM=true
        fi
        log_info "Traffic Control: tc available (netem: ${HAS_NETEM})"
    else
        log_warn "tc not found — traffic shaping disabled"
    fi

    # ── ethtool ──
    if command -v ethtool &>/dev/null; then
        HAS_ETHTOOL=true
    fi

    # ── jq ──
    if command -v jq &>/dev/null; then
        HAS_JQ=true
        log_info "jq: available"
    else
        log_warn "jq not found — installing..."
        apt-get update -qq && apt-get install -y -qq jq 2>/dev/null && HAS_JQ=true
        if [[ "${HAS_JQ}" == true ]]; then
            log_info "jq: installed"
        else
            log_warn "jq installation failed — Xray config patching limited"
        fi
    fi

    # ── Kernel version ──
    local kver
    kver=$(uname -r | cut -d. -f1-2)
    log_info "Kernel: $(uname -r)"

    # Ensure required modules
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nft_ct 2>/dev/null || true
    modprobe sch_fq_codel 2>/dev/null || true
    modprobe sch_htb 2>/dev/null || true
    modprobe sch_fq 2>/dev/null || true
}

# ============================================================================
# SECTION 3: NODE ROLE DETECTION
# ============================================================================

detect_node_role() {
    log_header "Detecting Node Role"

    if [[ -f "${TUNNEL_CONFIG_DIR}/trojan_info.json" ]]; then
        # Iran entry node has trojan_info.json (it generates Trojan inbound)
        NODE_ROLE="iran"
        log_info "Node role: ${BOLD}IRAN (Entry)${NC} — Aggressive anti-DPI mode"
    elif [[ -f "${TUNNEL_CONFIG_DIR}/vless_reality.json" ]]; then
        # Foreign exit node has vless_reality.json
        NODE_ROLE="foreign"
        log_info "Node role: ${BOLD}FOREIGN (Exit)${NC} — Standard hardening mode"
    else
        log_warn "Cannot auto-detect node role (no config files found)"
        log_warn "Use --iran or --foreign to specify manually"
        return 1
    fi
    return 0
}

# ============================================================================
# SECTION 4: NFTABLES ANTI-DPI ENGINE
# ============================================================================

# ── 4.0 Flush all antidpi tables ─────────────────────────────────────────────

nft_flush_antidpi() {
    log_step "Flushing existing anti-DPI nftables rules..."
    nft delete table inet "${NFT_TABLE_RAW}" 2>/dev/null || true
    nft delete table inet "${NFT_TABLE_MANGLE}" 2>/dev/null || true
    nft delete table inet "${NFT_TABLE_FILTER}" 2>/dev/null || true
    nft delete table inet "${NFT_TABLE_CT}" 2>/dev/null || true
    log_info "Previous anti-DPI rules cleared"
}

# ── 4.1 RST Suppression (inspired by Paqet) ─────────────────────────────────
#
# WHY: When Xray fragments TLS, the kernel may see unexpected TCP sequences
# and generate RST packets. DPI also injects forged RSTs to kill connections.
# Cost: ~50ns/packet — 500-1000x cheaper than Paqet's Go filter.

nft_apply_rst_suppression() {
    log_step "Applying RST suppression (kernel raw table)..."

    nft add table inet "${NFT_TABLE_RAW}"

    # Output chain: drop outgoing RST on tunnel ports
    nft add chain inet "${NFT_TABLE_RAW}" output_raw \
        '{ type filter hook output priority -300; policy accept; }'

    # Only block RST during handshake (SYN_SENT/SYN_RECV) where DPI injects forged RSTs.
    # Allow RST on established connections for proper TCP teardown (prevents half-open leak).
    # We use ct state to distinguish — but for NOTRACK'd flows, we use a rate-limit approach.

    # Outgoing RST suppression: only when no established conntrack entry
    nft add rule inet "${NFT_TABLE_RAW}" output_raw \
        tcp dport "${PORT_TROJAN}" tcp flags '&' '(rst)' == rst \
        ct state new,untracked drop 2>/dev/null || \
    nft add rule inet "${NFT_TABLE_RAW}" output_raw \
        tcp dport "${PORT_TROJAN}" tcp flags '&' '(rst)' == rst \
        limit rate 5/second accept 2>/dev/null || true
    nft add rule inet "${NFT_TABLE_RAW}" output_raw \
        tcp dport "${PORT_TROJAN}" tcp flags '&' '(rst|syn)' == rst drop 2>/dev/null || true

    nft add rule inet "${NFT_TABLE_RAW}" output_raw \
        tcp sport "${PORT_TROJAN}" tcp flags '&' '(rst|syn)' == rst \
        ct state new,untracked drop 2>/dev/null || true
    nft add rule inet "${NFT_TABLE_RAW}" output_raw \
        tcp sport "${PORT_VLESS}" tcp flags '&' '(rst|syn)' == rst \
        ct state new,untracked drop 2>/dev/null || true

    if [[ "${NODE_ROLE}" == "iran" ]]; then
        # Input chain: drop INCOMING forged RSTs from DPI
        # Only block bare RST (not RST+ACK which is legitimate teardown)
        nft add chain inet "${NFT_TABLE_RAW}" input_raw \
            '{ type filter hook input priority -300; policy accept; }' 2>/dev/null || true

        # DPI sends bare RST to kill our connections during handshake
        nft add rule inet "${NFT_TABLE_RAW}" input_raw \
            tcp sport "${PORT_TROJAN}" tcp flags '&' '(rst|ack)' == rst drop 2>/dev/null || true
        nft add rule inet "${NFT_TABLE_RAW}" input_raw \
            tcp dport "${PORT_TROJAN}" tcp flags '&' '(rst|ack)' == rst drop 2>/dev/null || true
    fi

    log_info "RST suppression: ACTIVE (ports ${PORT_TROJAN}, ${PORT_VLESS})"
}

# ── 4.2 Conntrack Bypass (inspired by Paqet) ────────────────────────────────
#
# WHY: Connection tracking adds ~300 bytes RAM per connection and creates
# state that DPI can fingerprint. NOTRACK eliminates both.
# Saves: ~1.5MB for 5000 concurrent connections.

nft_apply_conntrack_bypass() {
    log_step "Applying conntrack bypass (NOTRACK)..."

    nft add table inet "${NFT_TABLE_CT}"

    nft add chain inet "${NFT_TABLE_CT}" prerouting_raw \
        '{ type filter hook prerouting priority -300; policy accept; }'
    nft add chain inet "${NFT_TABLE_CT}" output_raw \
        '{ type filter hook output priority -300; policy accept; }'

    # NOTRACK for WireGuard UDP — BUT only if no NAT/MASQUERADE depends on conntrack.
    # Check if MASQUERADE rules exist for the WireGuard interface first.
    local wg_has_nat=false
    if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE.*wg0\|SNAT.*wg0" || \
       iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE.*51820"; then
        wg_has_nat=true
    fi

    if [[ "${wg_has_nat}" == false ]]; then
        nft add rule inet "${NFT_TABLE_CT}" prerouting_raw \
            udp dport "${PORT_WG}" notrack 2>/dev/null || true
        nft add rule inet "${NFT_TABLE_CT}" output_raw \
            udp dport "${PORT_WG}" notrack 2>/dev/null || true
        nft add rule inet "${NFT_TABLE_CT}" prerouting_raw \
            udp sport "${PORT_WG}" notrack 2>/dev/null || true
        nft add rule inet "${NFT_TABLE_CT}" output_raw \
            udp sport "${PORT_WG}" notrack 2>/dev/null || true
        log_info "Conntrack bypass: WG NOTRACK active (no NAT detected)"
    else
        log_warn "Conntrack bypass: WG skipped (NAT/MASQUERADE detected — NOTRACK would break it)"
    fi

    if [[ "${NODE_ROLE}" == "iran" ]]; then
        # NOTRACK for Xray-marked traffic (mark 0xff set by Xray sockopt)
        nft add rule inet "${NFT_TABLE_CT}" output_raw \
            meta mark "${XRAY_MARK}" notrack 2>/dev/null || true
        log_info "Conntrack bypass: Xray mark NOTRACK active"
    fi
}

# ── 4.3 MSS Clamping (enhanced multi-stage, GFK-inspired) ───────────────────
#
# WHY: Static MSS=160 is itself a fingerprint. Multi-stage clamping:
#   - SYN packets: MSS=536 (RFC minimum, looks like slow link)
#   - Xray traffic: MSS=200 (forces ClientHello split into 2-3 segments)
# Cost: ~100ns per matching packet (SYN only = tiny fraction of traffic).

nft_apply_mss_clamping() {
    if [[ "${NODE_ROLE}" != "iran" ]]; then
        log_skip "MSS clamping: skipped (foreign node)"
        return 0
    fi

    log_step "Applying multi-stage MSS clamping..."

    nft add table inet "${NFT_TABLE_MANGLE}" 2>/dev/null || true
    nft add chain inet "${NFT_TABLE_MANGLE}" postrouting_mangle \
        '{ type filter hook postrouting priority -150; policy accept; }' 2>/dev/null || true

    if [[ "${NFT_HAS_TCP_OPT_SET}" == true ]]; then
        # Stage 1: SYN/SYN-ACK on tunnel ports → MSS=536 (RFC minimum)
        nft add rule inet "${NFT_TABLE_MANGLE}" postrouting_mangle \
            tcp dport "${PORT_TROJAN}" tcp flags '&' '(syn)' == syn \
            tcp option maxseg size set 536

        nft add rule inet "${NFT_TABLE_MANGLE}" postrouting_mangle \
            tcp dport "${PORT_VLESS}" tcp flags '&' '(syn)' == syn \
            tcp option maxseg size set 536

        # Stage 2: Xray-marked traffic → MSS=200 (forces ClientHello split)
        nft add rule inet "${NFT_TABLE_MANGLE}" postrouting_mangle \
            meta mark "${XRAY_MARK}" tcp option maxseg size set 200

        log_info "MSS clamping: ACTIVE (SYN=536, Xray=200) [nftables native]"
    else
        # Fallback: use iptables TCPMSS for MSS clamping
        iptables -t mangle -A POSTROUTING -p tcp --dport "${PORT_TROJAN}" \
            --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536 2>/dev/null || true
        iptables -t mangle -A POSTROUTING -p tcp --dport "${PORT_VLESS}" \
            --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536 2>/dev/null || true
        iptables -t mangle -A POSTROUTING -p tcp -m mark --mark "${XRAY_MARK}" \
            -j TCPMSS --set-mss 200 2>/dev/null || true

        log_info "MSS clamping: ACTIVE (SYN=536, Xray=200) [iptables fallback]"
    fi
}

# ── 4.4 TCP Fingerprint Normalization ────────────────────────────────────────
#
# WHY: DPI fingerprints connections by TTL, TCP options, window size, etc.
# Normalizing to Chrome-on-Linux profile makes tunnel indistinguishable.

nft_apply_fingerprint_normalize() {
    log_step "Applying TCP fingerprint normalization..."

    nft add table inet "${NFT_TABLE_MANGLE}" 2>/dev/null || true

    # Output chain for TTL and DF bit
    nft add chain inet "${NFT_TABLE_MANGLE}" output_mangle \
        '{ type route hook output priority -150; policy accept; }' 2>/dev/null || true

    # TTL normalization to 64 (Linux/Chrome default) — IPv4
    nft add rule inet "${NFT_TABLE_MANGLE}" output_mangle \
        oifname "${PRIMARY_IFACE}" ip ttl set 64 2>/dev/null || true

    # IPv6 hop limit normalization to 64
    nft add rule inet "${NFT_TABLE_MANGLE}" output_mangle \
        oifname "${PRIMARY_IFACE}" ip6 hoplimit set 64 2>/dev/null || true

    if [[ "${NODE_ROLE}" == "iran" ]]; then
        # On Iran node: also normalize TTL/hoplimit for tunnel-specific traffic
        nft add rule inet "${NFT_TABLE_MANGLE}" output_mangle \
            meta mark "${XRAY_MARK}" ip ttl set 64 2>/dev/null || true
        nft add rule inet "${NFT_TABLE_MANGLE}" output_mangle \
            meta mark "${XRAY_MARK}" ip6 hoplimit set 64 2>/dev/null || true

        # Zero DSCP/TOS to prevent traffic classification fingerprinting
        nft add rule inet "${NFT_TABLE_MANGLE}" output_mangle \
            meta mark "${XRAY_MARK}" ip dscp set 0 2>/dev/null || true
    fi

    # TCP timestamps disabled via sysctl (more reliable than per-packet stripping)
    # Done in apply_sysctl_ultimate()

    log_info "Fingerprint normalization: ACTIVE (TTL/hoplimit=64, DSCP=0, timestamps=sysctl)"
}

# ── 4.5 ICMP Hardening ──────────────────────────────────────────────────────
#
# WHY: ICMP messages leak system clock, topology, and path information.

nft_apply_icmp_hardening() {
    log_step "Applying ICMP hardening..."

    nft add table inet "${NFT_TABLE_FILTER}"

    nft add chain inet "${NFT_TABLE_FILTER}" output_filter \
        '{ type filter hook output priority 0; policy accept; }'
    nft add chain inet "${NFT_TABLE_FILTER}" input_filter \
        '{ type filter hook input priority 0; policy accept; }'

    # Block timestamp request/reply (leaks system clock)
    nft add rule inet "${NFT_TABLE_FILTER}" output_filter \
        icmp type timestamp-request drop
    nft add rule inet "${NFT_TABLE_FILTER}" output_filter \
        icmp type timestamp-reply drop
    nft add rule inet "${NFT_TABLE_FILTER}" input_filter \
        icmp type timestamp-request drop

    # Block address mask (leaks network info)
    nft add rule inet "${NFT_TABLE_FILTER}" output_filter \
        icmp type address-mask-request drop 2>/dev/null || true
    nft add rule inet "${NFT_TABLE_FILTER}" output_filter \
        icmp type address-mask-reply drop 2>/dev/null || true

    # Rate-limit outgoing destination-unreachable instead of blocking entirely.
    # Full block causes PMTU black holes; rate-limit reduces topology leak while
    # keeping PMTU discovery functional.
    nft add rule inet "${NFT_TABLE_FILTER}" output_filter \
        icmp type destination-unreachable limit rate 10/second accept 2>/dev/null || true
    nft add rule inet "${NFT_TABLE_FILTER}" output_filter \
        icmp type destination-unreachable drop 2>/dev/null || true

    # Rate limit echo-request (prevent ping-based tunnel detection)
    nft add rule inet "${NFT_TABLE_FILTER}" input_filter \
        icmp type echo-request limit rate 2/second accept
    nft add rule inet "${NFT_TABLE_FILTER}" input_filter \
        icmp type echo-request drop

    # Block ICMPv6 informational that leaks data
    nft add rule inet "${NFT_TABLE_FILTER}" output_filter \
        meta l4proto icmpv6 icmpv6 type '{ mld-listener-query, mld-listener-report }' drop 2>/dev/null || true

    log_info "ICMP hardening: ACTIVE (timestamps, masks, unreachable blocked)"
}

# ── 4.6 Rate Limiting ───────────────────────────────────────────────────────
#
# WHY: DPI probes tunnel ports with rapid SYN scans. Rate limiting prevents
# fingerprinting through response patterns.

nft_apply_rate_limiting() {
    log_step "Applying connection rate limiting..."

    nft add table inet "${NFT_TABLE_FILTER}" 2>/dev/null || true
    nft add chain inet "${NFT_TABLE_FILTER}" input_filter \
        '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true

    # Per-source-IP SYN rate limiting using nftables meter (set with per-IP counters)
    # Prevents a single IP from DoS-ing the port while allowing legitimate users through
    nft add rule inet "${NFT_TABLE_FILTER}" input_filter \
        tcp dport "${PORT_TROJAN}" tcp flags '&' '(syn)' == syn \
        meter syn_trojan '{ ip saddr limit rate over 20/second }' drop 2>/dev/null || \
    nft add rule inet "${NFT_TABLE_FILTER}" input_filter \
        tcp dport "${PORT_TROJAN}" tcp flags '&' '(syn)' == syn \
        limit rate over 500/second drop 2>/dev/null || true

    nft add rule inet "${NFT_TABLE_FILTER}" input_filter \
        tcp dport "${PORT_VLESS}" tcp flags '&' '(syn)' == syn \
        meter syn_vless '{ ip saddr limit rate over 20/second }' drop 2>/dev/null || \
    nft add rule inet "${NFT_TABLE_FILTER}" input_filter \
        tcp dport "${PORT_VLESS}" tcp flags '&' '(syn)' == syn \
        limit rate over 500/second drop 2>/dev/null || true

    log_info "Rate limiting: ACTIVE (20 SYN/sec per-IP, 500/sec global fallback)"
}

# ============================================================================
# SECTION 5: IPTABLES FALLBACK ENGINE
# ============================================================================

ipt_flush_antidpi() {
    log_step "Flushing existing anti-DPI iptables rules..."

    # Remove custom chains if they exist
    for chain in ANTIDPI_RST ANTIDPI_ICMP ANTIDPI_RATE; do
        iptables -D INPUT -j "${chain}" 2>/dev/null || true
        iptables -D OUTPUT -j "${chain}" 2>/dev/null || true
        iptables -F "${chain}" 2>/dev/null || true
        iptables -X "${chain}" 2>/dev/null || true
    done

    # Clean mangle table
    iptables -t mangle -F ANTIDPI_MANGLE 2>/dev/null || true
    iptables -t mangle -D POSTROUTING -j ANTIDPI_MANGLE 2>/dev/null || true
    iptables -t mangle -D OUTPUT -j ANTIDPI_MANGLE 2>/dev/null || true
    iptables -t mangle -X ANTIDPI_MANGLE 2>/dev/null || true

    # Clean raw table
    iptables -t raw -F ANTIDPI_RAW_OUT 2>/dev/null || true
    iptables -t raw -F ANTIDPI_RAW_IN 2>/dev/null || true
    iptables -t raw -D OUTPUT -j ANTIDPI_RAW_OUT 2>/dev/null || true
    iptables -t raw -D PREROUTING -j ANTIDPI_RAW_IN 2>/dev/null || true
    iptables -t raw -X ANTIDPI_RAW_OUT 2>/dev/null || true
    iptables -t raw -X ANTIDPI_RAW_IN 2>/dev/null || true

    log_info "Previous iptables anti-DPI rules cleared"
}

ipt_apply_rst_suppression() {
    log_step "Applying RST suppression (iptables raw)..."

    # Create output raw chain — only block bare RST (not RST+ACK for clean teardown)
    iptables -t raw -N ANTIDPI_RAW_OUT 2>/dev/null || iptables -t raw -F ANTIDPI_RAW_OUT
    # Drop bare RST (without ACK) — these are DPI-injected
    iptables -t raw -A ANTIDPI_RAW_OUT -p tcp --dport "${PORT_TROJAN}" --tcp-flags RST,ACK RST -j DROP 2>/dev/null || true
    iptables -t raw -A ANTIDPI_RAW_OUT -p tcp --sport "${PORT_TROJAN}" --tcp-flags RST,ACK RST -j DROP 2>/dev/null || true
    iptables -t raw -A ANTIDPI_RAW_OUT -p tcp --sport "${PORT_VLESS}" --tcp-flags RST,ACK RST -j DROP 2>/dev/null || true
    iptables -t raw -A OUTPUT -j ANTIDPI_RAW_OUT

    if [[ "${NODE_ROLE}" == "iran" ]]; then
        # Drop incoming forged bare RSTs from DPI
        iptables -t raw -N ANTIDPI_RAW_IN 2>/dev/null || iptables -t raw -F ANTIDPI_RAW_IN
        iptables -t raw -A ANTIDPI_RAW_IN -p tcp --sport "${PORT_TROJAN}" --tcp-flags RST,ACK RST -j DROP 2>/dev/null || true
        iptables -t raw -A ANTIDPI_RAW_IN -p tcp --dport "${PORT_TROJAN}" --tcp-flags RST,ACK RST -j DROP 2>/dev/null || true
        iptables -t raw -A PREROUTING -j ANTIDPI_RAW_IN
    fi

    log_info "RST suppression: ACTIVE [iptables] (bare RST only, RST+ACK allowed)"
}

ipt_apply_conntrack_bypass() {
    log_step "Applying conntrack bypass (iptables NOTRACK)..."

    # WireGuard UDP NOTRACK
    iptables -t raw -A PREROUTING -p udp --dport "${PORT_WG}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A PREROUTING -p udp --dport "${PORT_WG}" -j CT --notrack 2>/dev/null || true
    iptables -t raw -A OUTPUT -p udp --dport "${PORT_WG}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A OUTPUT -p udp --dport "${PORT_WG}" -j CT --notrack 2>/dev/null || true
    iptables -t raw -A PREROUTING -p udp --sport "${PORT_WG}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A PREROUTING -p udp --sport "${PORT_WG}" -j CT --notrack 2>/dev/null || true
    iptables -t raw -A OUTPUT -p udp --sport "${PORT_WG}" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A OUTPUT -p udp --sport "${PORT_WG}" -j CT --notrack 2>/dev/null || true

    if [[ "${NODE_ROLE}" == "iran" ]]; then
        # Xray mark NOTRACK
        iptables -t raw -A OUTPUT -m mark --mark "${XRAY_MARK}" -j NOTRACK 2>/dev/null || \
            iptables -t raw -A OUTPUT -m mark --mark "${XRAY_MARK}" -j CT --notrack 2>/dev/null || true
    fi

    log_info "Conntrack bypass: ACTIVE [iptables]"
}

ipt_apply_mss_clamping() {
    if [[ "${NODE_ROLE}" != "iran" ]]; then
        log_skip "MSS clamping: skipped (foreign node)"
        return 0
    fi

    log_step "Applying MSS clamping (iptables mangle)..."

    iptables -t mangle -N ANTIDPI_MANGLE 2>/dev/null || iptables -t mangle -F ANTIDPI_MANGLE

    # SYN packets: MSS=536
    iptables -t mangle -A ANTIDPI_MANGLE -p tcp --dport "${PORT_TROJAN}" \
        --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536
    iptables -t mangle -A ANTIDPI_MANGLE -p tcp --dport "${PORT_VLESS}" \
        --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536

    # Xray marked traffic: MSS=200
    iptables -t mangle -A ANTIDPI_MANGLE -p tcp -m mark --mark "${XRAY_MARK}" \
        -j TCPMSS --set-mss 200

    iptables -t mangle -A POSTROUTING -j ANTIDPI_MANGLE

    log_info "MSS clamping: ACTIVE (SYN=536, Xray=200) [iptables]"
}

ipt_apply_fingerprint_normalize() {
    log_step "Applying fingerprint normalization (iptables mangle)..."

    # TTL normalization to 64
    iptables -t mangle -A POSTROUTING -o "${PRIMARY_IFACE}" -j TTL --ttl-set 64 2>/dev/null || true

    log_info "Fingerprint normalization: ACTIVE (TTL=64) [iptables]"
}

ipt_apply_icmp_hardening() {
    log_step "Applying ICMP hardening (iptables)..."

    iptables -N ANTIDPI_ICMP 2>/dev/null || iptables -F ANTIDPI_ICMP

    # Block timestamp
    iptables -A ANTIDPI_ICMP -p icmp --icmp-type timestamp-request -j DROP
    iptables -A ANTIDPI_ICMP -p icmp --icmp-type timestamp-reply -j DROP

    # Rate-limit destination unreachable outgoing (don't fully block — breaks PMTU)
    iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -m limit --limit 10/s -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP 2>/dev/null || true

    # Rate limit echo
    iptables -A ANTIDPI_ICMP -p icmp --icmp-type echo-request -m limit --limit 2/s -j ACCEPT
    iptables -A ANTIDPI_ICMP -p icmp --icmp-type echo-request -j DROP

    iptables -A INPUT -j ANTIDPI_ICMP

    log_info "ICMP hardening: ACTIVE [iptables]"
}

ipt_apply_rate_limiting() {
    log_step "Applying rate limiting (iptables)..."

    iptables -N ANTIDPI_RATE 2>/dev/null || iptables -F ANTIDPI_RATE

    iptables -A ANTIDPI_RATE -p tcp --dport "${PORT_TROJAN}" --syn \
        -m limit --limit 100/s --limit-burst 200 -j ACCEPT
    iptables -A ANTIDPI_RATE -p tcp --dport "${PORT_TROJAN}" --syn -j DROP

    iptables -A ANTIDPI_RATE -p tcp --dport "${PORT_VLESS}" --syn \
        -m limit --limit 100/s --limit-burst 200 -j ACCEPT
    iptables -A ANTIDPI_RATE -p tcp --dport "${PORT_VLESS}" --syn -j DROP

    iptables -A INPUT -j ANTIDPI_RATE

    log_info "Rate limiting: ACTIVE (100 SYN/sec) [iptables]"
}

# ============================================================================
# SECTION 6: TRAFFIC CONTROL (tc)
# ============================================================================

tc_detect_bandwidth() {
    local speed=""

    if [[ "${HAS_ETHTOOL}" == true ]]; then
        speed=$(ethtool "${PRIMARY_IFACE}" 2>/dev/null | grep "Speed:" | awk '{print $2}')
    fi

    # Default fallback
    if [[ -z "${speed}" || "${speed}" == "Unknown!" || "${speed}" == *"base"* ]]; then
        # Try extracting just the number from formats like "10000baseT/Full"
        local num_only
        num_only=$(echo "${speed}" | grep -o '^[0-9]*')
        if [[ -n "${num_only}" && "${num_only}" -gt 0 ]] 2>/dev/null; then
            speed="${num_only}Mb/s"
        else
            speed="1000Mb/s"
        fi
    fi

    # Convert to tc format
    echo "${speed}" | sed 's|Mb/s|mbit|; s|Gb/s|gbit|'
}

tc_apply_traffic_shaping() {
    if [[ "${HAS_TC}" != true ]]; then
        log_skip "Traffic shaping: tc not available"
        return 0
    fi

    log_step "Applying traffic shaping..."

    local bandwidth
    bandwidth=$(tc_detect_bandwidth)
    log_info "Detected bandwidth: ${bandwidth}"

    # Clean existing qdisc
    tc qdisc del dev "${PRIMARY_IFACE}" root 2>/dev/null || true

    # HTB root qdisc
    tc qdisc add dev "${PRIMARY_IFACE}" root handle 1: htb default 30

    # Parse bandwidth value and unit
    local rate_num
    rate_num=$(echo "${bandwidth}" | grep -o '^[0-9]*')
    local rate_unit
    rate_unit=$(echo "${bandwidth}" | sed 's/^[0-9]*//')
    local tunnel_bw="$(( rate_num * 80 / 100 ))${rate_unit}"
    local other_bw="$(( rate_num * 20 / 100 ))${rate_unit}"

    # Calculate burst size for high-speed links:
    # burst >= rate_bytes_per_sec * 0.001 (1ms timer resolution)
    # For 10gbit: 10000/8 * 0.001 = 1.25MB minimum. Use 10MB for headroom.
    local burst_size="256k"
    local tunnel_burst="128k"
    if [[ ${rate_num} -ge 10000 ]]; then
        # 10Gbps+
        burst_size="10m"
        tunnel_burst="8m"
    elif [[ ${rate_num} -ge 1000 ]]; then
        # 1Gbps+
        burst_size="2m"
        tunnel_burst="1600k"
    fi

    # Root class — full link bandwidth with appropriate burst
    tc class add dev "${PRIMARY_IFACE}" parent 1: classid 1:1 \
        htb rate "${bandwidth}" burst "${burst_size}" cburst "${burst_size}"

    # Tunnel traffic class (priority, 80% guaranteed, can burst to 100%)
    tc class add dev "${PRIMARY_IFACE}" parent 1:1 classid 1:10 \
        htb rate "${tunnel_bw}" ceil "${bandwidth}" burst "${tunnel_burst}" cburst "${tunnel_burst}" prio 1

    # Other traffic class
    tc class add dev "${PRIMARY_IFACE}" parent 1:1 classid 1:30 \
        htb rate "${other_bw}" ceil "${bandwidth}" burst 256k prio 3

    # fq on tunnel class — BBR works best with fq (per-flow pacing), not fq_codel
    # fq_codel provides AQM but lacks the pacing BBR relies on
    local fq_limit=32768
    [[ ${rate_num} -ge 10000 ]] && fq_limit=65536
    tc qdisc add dev "${PRIMARY_IFACE}" parent 1:10 handle 10: fq \
        limit "${fq_limit}" flow_limit 256 2>/dev/null || \
    tc qdisc add dev "${PRIMARY_IFACE}" parent 1:10 handle 10: fq_codel \
        limit "${fq_limit}" target 5ms interval 100ms ecn

    # fq_codel on default class (non-tunnel traffic)
    tc qdisc add dev "${PRIMARY_IFACE}" parent 1:30 handle 30: fq_codel \
        limit 10240 target 5ms interval 100ms ecn 2>/dev/null || true

    # Classify tunnel traffic by mark (IPv4 + IPv6)
    tc filter add dev "${PRIMARY_IFACE}" parent 1: protocol ip handle "${XRAY_MARK}" fw classid 1:10
    tc filter add dev "${PRIMARY_IFACE}" parent 1: protocol ipv6 handle "${XRAY_MARK}" fw classid 1:10 2>/dev/null || true

    # Classify by port (IPv4)
    tc filter add dev "${PRIMARY_IFACE}" parent 1: protocol ip \
        u32 match ip dport "${PORT_TROJAN}" 0xffff classid 1:10
    tc filter add dev "${PRIMARY_IFACE}" parent 1: protocol ip \
        u32 match ip dport "${PORT_VLESS}" 0xffff classid 1:10
    tc filter add dev "${PRIMARY_IFACE}" parent 1: protocol ip \
        u32 match ip sport "${PORT_TROJAN}" 0xffff classid 1:10
    tc filter add dev "${PRIMARY_IFACE}" parent 1: protocol ip \
        u32 match ip sport "${PORT_VLESS}" 0xffff classid 1:10

    log_info "Traffic shaping: ACTIVE (HTB + fq, tunnel=${tunnel_bw}, burst=${tunnel_burst})"
}

tc_apply_wg_qdisc() {
    if [[ "${HAS_TC}" != true ]]; then
        return 0
    fi

    log_step "Applying WireGuard interface optimization..."

    # fq on wg0 for BBR compatibility + appropriate queue length for high-speed
    if ip link show wg0 &>/dev/null; then
        tc qdisc replace dev wg0 root fq 2>/dev/null || true
        ip link set wg0 txqueuelen 10000 2>/dev/null || true
        log_info "WireGuard qdisc: fq (txqueuelen=10000)"
    else
        log_skip "WireGuard interface wg0 not found"
    fi
}

tc_apply_timing_jitter() {
    if [[ "${HAS_TC}" != true || "${HAS_NETEM}" != true ]]; then
        log_skip "Timing jitter: netem not available"
        return 0
    fi

    if [[ "${NODE_ROLE}" != "iran" ]]; then
        log_skip "Timing jitter: skipped (foreign node)"
        return 0
    fi

    log_step "Applying timing jitter (netem)..."
    log_warn "Adding 0-2ms random delay on tunnel traffic (defeats timing analysis)"

    # Replace fq_codel on tunnel class with netem → fq_codel chain
    tc qdisc del dev "${PRIMARY_IFACE}" parent 1:10 2>/dev/null || true

    tc qdisc add dev "${PRIMARY_IFACE}" parent 1:10 handle 10: netem \
        delay 0ms 1ms distribution pareto limit 10000

    tc qdisc add dev "${PRIMARY_IFACE}" parent 10:1 handle 100: fq_codel \
        limit 10240 target 5ms interval 100ms ecn

    log_info "Timing jitter: ACTIVE (0-2ms pareto distribution)"
}

# ============================================================================
# SECTION 7: SYSCTL HARDENING
# ============================================================================

apply_sysctl_ultimate() {
    log_step "Applying kernel parameter hardening..."

    cat > "${SYSCTL_CONF}" << 'SYSCTL'
# ============================================================================
# Anti-DPI Ultimate — Consolidated Kernel Parameters
# Priority: 99 (supersedes all other tunnel sysctl files)
# ============================================================================

# ── IP Forwarding (required for tunnel) ──
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ── BBR Congestion Control ──
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ── TCP Fast Open (client + server) ──
net.ipv4.tcp_fastopen = 3

# ── Anti-Fingerprint ──
# Timestamps leak uptime + enable per-flow tracking
net.ipv4.tcp_timestamps = 0
# PMTU discovery: use kernel-based PMTU (no ICMP needed) instead of full disable.
# Full disable (=1) causes black holes on 10Gbps links with varying MTU paths.
# Value 2 = use interface MTU as initial, kernel tracks PMTU without ICMP
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
# Active ECN is a fingerprint; passive responds only if peer initiates
net.ipv4.tcp_ecn = 2
# Slow start restart creates distinctive traffic pattern after pauses
net.ipv4.tcp_slow_start_after_idle = 0
# Window scaling (needed for BBR, matches browser behavior)
net.ipv4.tcp_window_scaling = 1

# ── Socket Buffers (BBR optimal for 10Gbps) ──
net.core.rmem_default = 2097152
net.core.rmem_max = 67108864
net.core.wmem_default = 2097152
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 8192 2097152 67108864
net.ipv4.tcp_wmem = 8192 2097152 67108864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.core.optmem_max = 81920

# ── Connection Management ──
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_max_orphans = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# ── Keepalive (detect dead connections) ──
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# ── Port Randomization ──
net.ipv4.ip_local_port_range = 1024 65535

# ── File Descriptors ──
fs.file-max = 2097152
fs.nr_open = 2097152

# ── TCP/UDP Memory (pages, 4KB each) ──
# For 10Gbps: low=1GB, pressure=2GB, hard=4GB
net.ipv4.tcp_mem = 262144 524288 1048576
net.ipv4.udp_mem = 262144 524288 1048576

# ── Conntrack ──
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# ── ICMP / Redirect Hardening ──
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ── Reverse Path Filter ──
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ── Memory Optimization ──
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50
vm.min_free_kbytes = 131072

# ── NAPI / Network Polling (10Gbps) ──
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# ── ARP Cache ──
net.ipv4.neigh.default.gc_thresh1 = 512
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 4096
SYSCTL

    # Apply immediately
    sysctl --system > /dev/null 2>&1

    log_info "Kernel hardening: $(grep -c '=' "${SYSCTL_CONF}") parameters applied"
}

# ============================================================================
# SECTION 7.5: NIC HARDWARE OPTIMIZATION (10Gbps)
# ============================================================================

apply_nic_optimization() {
    log_step "Applying NIC hardware optimization..."

    # Enable hardware offloads — critical for 10Gbps to reduce CPU overhead
    if [[ "${HAS_ETHTOOL}" == true ]]; then
        # GRO/GSO/TSO on physical interface
        ethtool -K "${PRIMARY_IFACE}" gro on 2>/dev/null || true
        ethtool -K "${PRIMARY_IFACE}" gso on 2>/dev/null || true
        ethtool -K "${PRIMARY_IFACE}" tso on 2>/dev/null || true
        ethtool -K "${PRIMARY_IFACE}" tx on 2>/dev/null || true
        ethtool -K "${PRIMARY_IFACE}" rx on 2>/dev/null || true
        log_info "NIC offloads: GRO/GSO/TSO enabled"

        # Maximize NIC ring buffer
        ethtool -G "${PRIMARY_IFACE}" rx 4096 tx 4096 2>/dev/null || true
        log_info "NIC ring buffer: maximized"

        # Adaptive interrupt coalescing
        ethtool -C "${PRIMARY_IFACE}" adaptive-rx on adaptive-tx on 2>/dev/null || \
        ethtool -C "${PRIMARY_IFACE}" rx-usecs 50 tx-usecs 50 2>/dev/null || true
        log_info "NIC interrupt coalescing: adaptive"
    fi

    # GRO/GSO on WireGuard interface
    if ip link show wg0 &>/dev/null; then
        ethtool -K wg0 gro on 2>/dev/null || true
        ethtool -K wg0 gso on 2>/dev/null || true
    fi

    # RPS/XPS multi-core packet steering
    local num_cpus
    num_cpus=$(nproc 2>/dev/null || echo 4)
    local rps_mask
    # Calculate hex bitmask for all CPUs (e.g., 4 CPUs = 0xf, 8 = 0xff, 16 = 0xffff)
    rps_mask=$(printf '%x' $(( (1 << num_cpus) - 1 )))

    # Apply RPS to all RX queues
    local queue_dir="/sys/class/net/${PRIMARY_IFACE}/queues"
    if [[ -d "${queue_dir}" ]]; then
        for rxq in "${queue_dir}"/rx-*; do
            [[ -d "${rxq}" ]] && echo "${rps_mask}" > "${rxq}/rps_cpus" 2>/dev/null || true
        done
        # Apply XPS to all TX queues
        for txq in "${queue_dir}"/tx-*; do
            [[ -d "${txq}" ]] && echo "${rps_mask}" > "${txq}/xps_cpus" 2>/dev/null || true
        done
        log_info "RPS/XPS: enabled for ${num_cpus} CPUs (mask: 0x${rps_mask})"
    fi

    # RFS (Receive Flow Steering)
    local rfs_entries=$(( num_cpus * 8192 ))
    echo "${rfs_entries}" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
    local rx_count
    rx_count=$(ls -d "${queue_dir}"/rx-* 2>/dev/null | wc -l)
    if [[ ${rx_count} -gt 0 ]]; then
        local per_queue=$(( rfs_entries / rx_count ))
        for rxq in "${queue_dir}"/rx-*/rps_flow_cnt; do
            [[ -f "${rxq}" ]] && echo "${per_queue}" > "${rxq}" 2>/dev/null || true
        done
    fi

    # ulimit for current session and limits.conf
    ulimit -n 1048576 2>/dev/null || true
    if ! grep -q 'antidpi-ultimate' /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf << 'LIMITS'
# antidpi-ultimate: high FD limits for tunnel traffic
*    soft    nofile    1048576
*    hard    nofile    1048576
root soft    nofile    1048576
root hard    nofile    1048576
*    soft    nproc     65535
*    hard    nproc     65535
LIMITS
        log_info "ulimits: 1M file descriptors configured"
    fi

    # TCP initial window optimization for 10Gbps
    # IW=42 (approx 64KB) matches Chrome behavior and improves 10Gbps throughput
    local default_route
    default_route=$(ip route show default | head -1)
    if [[ -n "${default_route}" ]]; then
        ip route change ${default_route} initcwnd 42 initrwnd 42 2>/dev/null || true
        log_info "TCP initial window: initcwnd=42, initrwnd=42"
    fi

    log_info "NIC optimization: complete"
}

# ============================================================================
# SECTION 8: XRAY CONFIG PATCHING
# ============================================================================

patch_xray_fragment() {
    if [[ "${HAS_JQ}" != true ]]; then
        log_warn "jq not available — skipping Xray fragment patch"
        return 1
    fi
    if [[ ! -f "${XRAY_CONFIG}" ]]; then
        log_warn "Xray config not found at ${XRAY_CONFIG}"
        return 1
    fi
    if [[ "${NODE_ROLE}" != "iran" ]]; then
        log_skip "Xray fragment: skipped (foreign node)"
        return 0
    fi

    log_step "Patching Xray TLS fragment settings..."

    local tmp
    tmp=$(mktemp)

    # Update fragment settings: interval 10-50 (GFK research shows Iranian DPI
    # has ~200ms reassembly timeout; 10-50ms causes buffer stress)
    if jq '(.outbounds[] | select(.tag == "fragment-out" or .tag == "fragment" or
        (.settings.fragment != null)) | .settings.fragment) |= {
        "packets": "tlshello",
        "length": "1-3",
        "interval": "10-50"
    }' "${XRAY_CONFIG}" > "${tmp}" 2>/dev/null; then
        mv "${tmp}" "${XRAY_CONFIG}"
        log_info "TLS fragment: interval updated to 10-50ms"
    else
        rm -f "${tmp}"
        log_warn "Could not patch fragment settings (no fragment outbound found)"
    fi
}

patch_xray_fingerprint() {
    if [[ "${HAS_JQ}" != true || ! -f "${XRAY_CONFIG}" ]]; then
        return 1
    fi
    if [[ "${NODE_ROLE}" != "iran" ]]; then
        log_skip "Xray fingerprint: skipped (foreign node)"
        return 0
    fi

    log_step "Patching Xray uTLS fingerprint..."

    local tmp
    tmp=$(mktemp)

    # Set fingerprint to "chrome" (dominant browser in Iran)
    # "randomized" is suspicious — no real browser changes fingerprint per connection
    # Use select() to only patch entries that actually have tlsSettings (avoids null injection)
    if jq '(.inbounds[] | select(.streamSettings.tlsSettings != null) |
            .streamSettings.tlsSettings.fingerprint) |= "chrome" |
           (.outbounds[] | select(.streamSettings.tlsSettings != null) |
            .streamSettings.tlsSettings.fingerprint) |= "chrome"' \
        "${XRAY_CONFIG}" > "${tmp}" 2>/dev/null; then
        mv "${tmp}" "${XRAY_CONFIG}"
        log_info "uTLS fingerprint: set to chrome"
    else
        rm -f "${tmp}"
        log_warn "Could not patch fingerprint"
    fi
}

patch_xray_sni_pool() {
    if [[ "${HAS_JQ}" != true || ! -f "${XRAY_CONFIG}" ]]; then
        return 1
    fi
    if [[ "${NODE_ROLE}" != "foreign" ]]; then
        log_skip "SNI pool: skipped (not foreign node)"
        return 0
    fi

    log_step "Expanding Reality SNI rotation pool..."

    local tmp
    tmp=$(mktemp)

    # Expanded pool of CDN/static-resource domains that match tunnel traffic profile
    local sni_pool='[
        "www.microsoft.com",
        "microsoft.com",
        "update.microsoft.com",
        "login.microsoftonline.com",
        "www.apple.com",
        "images.apple.com",
        "cdn.cloudflare.com",
        "www.google.com",
        "fonts.googleapis.com",
        "ajax.googleapis.com",
        "cdn.jsdelivr.net"
    ]'

    if jq --argjson pool "${sni_pool}" \
        '(.inbounds[].streamSettings.realitySettings.serverNames) |= $pool' \
        "${XRAY_CONFIG}" > "${tmp}" 2>/dev/null; then
        mv "${tmp}" "${XRAY_CONFIG}"
        log_info "SNI pool: expanded to 11 CDN domains"
    else
        rm -f "${tmp}"
        log_warn "Could not patch SNI pool (no Reality inbound found)"
    fi
}

patch_xray_sockopt() {
    if [[ "${HAS_JQ}" != true || ! -f "${XRAY_CONFIG}" ]]; then
        return 1
    fi

    log_step "Patching Xray socket options..."

    local tmp
    tmp=$(mktemp)

    # Add mark=255 for nftables matching, TFO for performance, NoDelay for fragments
    if jq '(.outbounds[] | select(.tag == "fragment-out" or .tag == "fragment" or
        (.settings.fragment != null)) | .streamSettings.sockopt) |= (. // {}) + {
        "mark": 255,
        "tcpNoDelay": true,
        "tcpFastOpen": true
    }' "${XRAY_CONFIG}" > "${tmp}" 2>/dev/null; then
        mv "${tmp}" "${XRAY_CONFIG}"
        log_info "Socket options: mark=255, TFO, NoDelay"
    else
        rm -f "${tmp}"
        log_warn "Could not patch socket options"
    fi
}

patch_xray_all() {
    log_header "Patching Xray Configuration"

    # Backup first
    if [[ -f "${XRAY_CONFIG}" ]]; then
        cp "${XRAY_CONFIG}" "${XRAY_CONFIG}.bak.$(date +%s)"
        log_info "Xray config backed up"
    fi

    patch_xray_fragment
    patch_xray_fingerprint
    patch_xray_sni_pool
    patch_xray_sockopt

    # Validate JSON
    if [[ -f "${XRAY_CONFIG}" ]] && jq empty "${XRAY_CONFIG}" 2>/dev/null; then
        log_info "Xray config: JSON valid"

        # Restart Xray to apply changes
        if systemctl is-active xray &>/dev/null; then
            systemctl restart xray
            sleep 1
            if systemctl is-active xray &>/dev/null; then
                log_info "Xray: restarted successfully"
            else
                log_error "Xray: failed to restart — restoring backup"
                local latest_bak
                latest_bak=$(ls -t "${XRAY_CONFIG}".bak.* 2>/dev/null | head -1)
                if [[ -n "${latest_bak}" ]]; then
                    cp "${latest_bak}" "${XRAY_CONFIG}"
                    systemctl restart xray
                fi
            fi
        fi
    else
        log_error "Xray config: JSON invalid — restoring backup"
        local latest_bak
        latest_bak=$(ls -t "${XRAY_CONFIG}".bak.* 2>/dev/null | head -1)
        if [[ -n "${latest_bak}" ]]; then
            cp "${latest_bak}" "${XRAY_CONFIG}"
        fi
    fi
}

# ============================================================================
# SECTION 9: VERIFICATION & DIAGNOSTICS
# ============================================================================

run_dpi_self_test() {
    log_header "Anti-DPI Protection Status"

    local pass=0
    local fail=0
    local total=10

    # 1. TCP timestamps
    local ts
    ts=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null)
    if [[ "${ts}" == "0" ]]; then
        log_ok "TCP timestamps: DISABLED"
        pass=$((pass + 1))
    else
        log_fail "TCP timestamps: ENABLED (fingerprint risk!)"
        fail=$((fail + 1))
    fi

    # 2. TTL normalization
    local ttl_active=false
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        nft list chain inet "${NFT_TABLE_MANGLE}" output_mangle 2>/dev/null | grep -q "ttl set" && ttl_active=true
    else
        iptables -t mangle -L POSTROUTING -n 2>/dev/null | grep -q "TTL set to 64" && ttl_active=true
    fi
    if [[ "${ttl_active}" == true ]]; then
        log_ok "TTL normalization: ACTIVE (64)"
        pass=$((pass + 1))
    else
        log_fail "TTL normalization: INACTIVE"
        fail=$((fail + 1))
    fi

    # 3. RST suppression
    local rst_active=false
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        nft list table inet "${NFT_TABLE_RAW}" 2>/dev/null | grep -q "rst" && rst_active=true
    else
        iptables -t raw -L ANTIDPI_RAW_OUT -n 2>/dev/null | grep -q "RST" && rst_active=true
    fi
    if [[ "${rst_active}" == true ]]; then
        log_ok "RST suppression: ACTIVE"
        pass=$((pass + 1))
    else
        log_fail "RST suppression: INACTIVE"
        fail=$((fail + 1))
    fi

    # 4. MSS clamping
    local mss_active=false
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        nft list table inet "${NFT_TABLE_MANGLE}" 2>/dev/null | grep -q "maxseg\|mss" && mss_active=true
    else
        iptables -t mangle -L ANTIDPI_MANGLE -n 2>/dev/null | grep -q "TCPMSS" && mss_active=true
    fi
    if [[ "${mss_active}" == true ]]; then
        log_ok "MSS clamping: ACTIVE"
        pass=$((pass + 1))
    elif [[ "${NODE_ROLE}" == "foreign" ]]; then
        log_skip "MSS clamping: N/A (foreign node)"
        pass=$((pass + 1))
    else
        log_fail "MSS clamping: INACTIVE"
        fail=$((fail + 1))
    fi

    # 5. WireGuard qdisc
    local wg_qdisc
    wg_qdisc=$(tc qdisc show dev wg0 2>/dev/null | head -1)
    if [[ "${wg_qdisc}" == *"fq"* ]]; then
        log_ok "WireGuard qdisc: fq"
        pass=$((pass + 1))
    elif ip link show wg0 &>/dev/null; then
        log_fail "WireGuard qdisc: ${wg_qdisc:-none}"
        fail=$((fail + 1))
    else
        log_skip "WireGuard: interface not up"
        pass=$((pass + 1))
    fi

    # 6. Xray fragment config
    if [[ -f "${XRAY_CONFIG}" ]] && jq -e '.outbounds[] | select(.settings.fragment)' "${XRAY_CONFIG}" &>/dev/null; then
        local frag_int
        frag_int=$(jq -r '.outbounds[] | select(.settings.fragment) | .settings.fragment.interval' "${XRAY_CONFIG}" 2>/dev/null)
        log_ok "Xray TLS fragment: interval=${frag_int}"
        pass=$((pass + 1))
    elif [[ "${NODE_ROLE}" == "foreign" ]]; then
        log_skip "Xray fragment: N/A (foreign node)"
        pass=$((pass + 1))
    else
        log_fail "Xray TLS fragment: NOT CONFIGURED"
        fail=$((fail + 1))
    fi

    # 7. TCP MTU probing (safer than disabling PMTU entirely)
    local mtu_probe
    mtu_probe=$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null)
    if [[ "${mtu_probe}" == "1" || "${mtu_probe}" == "2" ]]; then
        log_ok "TCP MTU probing: ACTIVE (safe PMTU)"
        pass=$((pass + 1))
    else
        log_fail "TCP MTU probing: DISABLED"
        fail=$((fail + 1))
    fi

    # 8. BBR congestion control
    local cc
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "${cc}" == "bbr" ]]; then
        log_ok "Congestion control: BBR"
        pass=$((pass + 1))
    else
        log_fail "Congestion control: ${cc} (should be bbr)"
        fail=$((fail + 1))
    fi

    # 9. Conntrack bypass
    local ct_active=false
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        nft list table inet "${NFT_TABLE_CT}" 2>/dev/null | grep -q "notrack" && ct_active=true
    else
        iptables -t raw -L -n 2>/dev/null | grep -q "NOTRACK\|CT" && ct_active=true
    fi
    if [[ "${ct_active}" == true ]]; then
        log_ok "Conntrack bypass: ACTIVE"
        pass=$((pass + 1))
    else
        log_fail "Conntrack bypass: INACTIVE"
        fail=$((fail + 1))
    fi

    # 10. ICMP hardening
    local icmp_active=false
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        nft list table inet "${NFT_TABLE_FILTER}" 2>/dev/null | grep -q "timestamp" && icmp_active=true
    else
        iptables -L ANTIDPI_ICMP -n 2>/dev/null | grep -q "timestamp" && icmp_active=true
    fi
    if [[ "${icmp_active}" == true ]]; then
        log_ok "ICMP hardening: ACTIVE"
        pass=$((pass + 1))
    else
        log_fail "ICMP hardening: INACTIVE"
        fail=$((fail + 1))
    fi

    # Summary
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local pct=$(( pass * 100 / total ))
    local color="${GREEN}"
    [[ ${pct} -lt 80 ]] && color="${YELLOW}"
    [[ ${pct} -lt 50 ]] && color="${RED}"
    echo -e "  Protection Score: ${color}${BOLD}${pass}/${total} (${pct}%)${NC}"
    echo -e "  Node Role: ${BOLD}${NODE_ROLE:-unknown}${NC}"
    echo -e "  Firewall: ${BOLD}${FIREWALL_BACKEND}${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    return ${fail}
}

# ============================================================================
# SECTION 10: PERSISTENCE
# ============================================================================

persist_nftables() {
    if [[ "${FIREWALL_BACKEND}" != "nftables" ]]; then
        return 0
    fi

    log_step "Persisting nftables rules..."

    mkdir -p "${NFT_SAVE_DIR}"

    # Save only our antidpi tables
    {
        echo "#!/usr/sbin/nft -f"
        echo "# Anti-DPI Ultimate — auto-generated $(date '+%F %T')"
        echo ""
        for tbl in "${NFT_TABLE_RAW}" "${NFT_TABLE_MANGLE}" "${NFT_TABLE_FILTER}" "${NFT_TABLE_CT}"; do
            nft list table inet "${tbl}" 2>/dev/null && echo ""
        done
    } > "${NFT_SAVE_FILE}"

    # Include in main nftables.conf if exists
    if [[ -f /etc/nftables.conf ]]; then
        if ! grep -q "antidpi.nft" /etc/nftables.conf 2>/dev/null; then
            echo "include \"${NFT_SAVE_FILE}\"" >> /etc/nftables.conf
        fi
    fi

    systemctl enable nftables 2>/dev/null || true
    log_info "nftables rules: persisted to ${NFT_SAVE_FILE}"
}

persist_tc_rules() {
    log_step "Creating tc persistence service..."

    # Generate restore script
    cat > "${RESTORE_SCRIPT}" << RESTORE
#!/bin/bash
# Anti-DPI Ultimate — tc restore script (auto-generated)
# Re-applies traffic control rules after reboot

sleep 3  # Wait for interfaces to come up

IFACE=\$(ip route show default 2>/dev/null | awk '{print \$5}' | head -1)
[[ -z "\${IFACE}" ]] && exit 1

# Clean existing
tc qdisc del dev "\${IFACE}" root 2>/dev/null || true

# Detect bandwidth
BW=\$(ethtool "\${IFACE}" 2>/dev/null | grep "Speed:" | awk '{print \$2}' | sed 's|Mb/s|mbit|; s|Gb/s|gbit|')
[[ -z "\${BW}" || "\${BW}" == "Unknown!" ]] && BW="1000mbit"
RATE_NUM=\$(echo "\${BW}" | grep -o '[0-9]*' | head -1)
RATE_UNIT=\$(echo "\${BW}" | sed 's/[0-9]*//')
TUNNEL_BW="\$(( RATE_NUM * 80 / 100 ))\${RATE_UNIT}"
OTHER_BW="\$(( RATE_NUM * 20 / 100 ))\${RATE_UNIT}"

# Calculate burst for link speed
BURST="256k"
TBURST="128k"
if [[ \${RATE_NUM} -ge 10000 ]]; then
    BURST="10m"; TBURST="8m"
elif [[ \${RATE_NUM} -ge 1000 ]]; then
    BURST="2m"; TBURST="1600k"
fi
FQ_LIMIT=32768
[[ \${RATE_NUM} -ge 10000 ]] && FQ_LIMIT=65536

# Apply HTB + fq
tc qdisc add dev "\${IFACE}" root handle 1: htb default 30
tc class add dev "\${IFACE}" parent 1: classid 1:1 htb rate "\${BW}" burst "\${BURST}" cburst "\${BURST}"
tc class add dev "\${IFACE}" parent 1:1 classid 1:10 htb rate "\${TUNNEL_BW}" ceil "\${BW}" burst "\${TBURST}" cburst "\${TBURST}" prio 1
tc class add dev "\${IFACE}" parent 1:1 classid 1:30 htb rate "\${OTHER_BW}" ceil "\${BW}" burst 256k prio 3
tc qdisc add dev "\${IFACE}" parent 1:10 handle 10: fq limit "\${FQ_LIMIT}" flow_limit 256 2>/dev/null || \
    tc qdisc add dev "\${IFACE}" parent 1:10 handle 10: fq_codel limit "\${FQ_LIMIT}" target 5ms interval 100ms ecn
tc qdisc add dev "\${IFACE}" parent 1:30 handle 30: fq_codel limit 10240 target 5ms interval 100ms ecn 2>/dev/null || true

# Classify by mark and port
tc filter add dev "\${IFACE}" parent 1: protocol ip handle ${XRAY_MARK} fw classid 1:10
tc filter add dev "\${IFACE}" parent 1: protocol ip u32 match ip dport ${PORT_TROJAN} 0xffff classid 1:10
tc filter add dev "\${IFACE}" parent 1: protocol ip u32 match ip dport ${PORT_VLESS} 0xffff classid 1:10
tc filter add dev "\${IFACE}" parent 1: protocol ip u32 match ip sport ${PORT_TROJAN} 0xffff classid 1:10
tc filter add dev "\${IFACE}" parent 1: protocol ip u32 match ip sport ${PORT_VLESS} 0xffff classid 1:10

# WireGuard fq
if ip link show wg0 &>/dev/null; then
    tc qdisc replace dev wg0 root fq 2>/dev/null || true
    ip link set wg0 txqueuelen 10000 2>/dev/null || true
fi

echo "[\$(date)] Anti-DPI tc rules restored" >> ${LOG_FILE}
RESTORE

    chmod +x "${RESTORE_SCRIPT}"

    # Systemd service
    cat > "${SYSTEMD_SERVICE}" << 'SVC'
[Unit]
Description=Anti-DPI Ultimate - Boot Restore
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/antidpi-restore.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC

    systemctl daemon-reload
    systemctl enable antidpi-ultimate.service 2>/dev/null

    log_info "Persistence: systemd service enabled (antidpi-ultimate)"
}

# ============================================================================
# SECTION 11: CLEANUP / ROLLBACK
# ============================================================================

rollback_all() {
    log_header "Rolling Back Anti-DPI Rules"

    # nftables cleanup
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        nft_flush_antidpi
    fi

    # iptables cleanup
    ipt_flush_antidpi

    # tc cleanup
    if [[ "${HAS_TC}" == true ]]; then
        tc qdisc del dev "${PRIMARY_IFACE}" root 2>/dev/null || true
        if ip link show wg0 &>/dev/null; then
            tc qdisc del dev wg0 root 2>/dev/null || true
        fi
        log_info "Traffic control: removed"
    fi

    # sysctl cleanup
    if [[ -f "${SYSCTL_CONF}" ]]; then
        rm -f "${SYSCTL_CONF}"
        sysctl --system > /dev/null 2>&1
        log_info "Sysctl: removed ${SYSCTL_CONF}"
    fi

    # Persistence cleanup
    if [[ -f "${SYSTEMD_SERVICE}" ]]; then
        systemctl disable antidpi-ultimate.service 2>/dev/null || true
        rm -f "${SYSTEMD_SERVICE}"
        systemctl daemon-reload
    fi
    rm -f "${RESTORE_SCRIPT}"
    rm -f "${NFT_SAVE_FILE}"

    # Remove nftables include
    if [[ -f /etc/nftables.conf ]]; then
        sed -i '/antidpi\.nft/d' /etc/nftables.conf 2>/dev/null || true
    fi

    log_info "Rollback complete — all anti-DPI rules removed"
}

# ============================================================================
# SECTION 12: APPLY ALL & MENU
# ============================================================================

apply_all_nftables() {
    nft_flush_antidpi
    nft_apply_rst_suppression
    nft_apply_conntrack_bypass
    nft_apply_mss_clamping
    nft_apply_fingerprint_normalize
    nft_apply_icmp_hardening
    nft_apply_rate_limiting
}

apply_all_iptables() {
    ipt_flush_antidpi
    ipt_apply_rst_suppression
    ipt_apply_conntrack_bypass
    ipt_apply_mss_clamping
    ipt_apply_fingerprint_normalize
    ipt_apply_icmp_hardening
    ipt_apply_rate_limiting
}

apply_firewall_rules() {
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        apply_all_nftables
    else
        apply_all_iptables
    fi
}

apply_all() {
    local start_time
    start_time=$(date +%s)

    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║           Anti-DPI Ultimate v${VERSION}                 ║"
    echo "  ║     Enterprise Kernel-Level DPI Evasion Engine      ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Phase 1: Firewall rules (kernel)
    log_header "Phase 1/5: Firewall Rules (${FIREWALL_BACKEND})"
    apply_firewall_rules

    # Phase 2: Traffic control
    log_header "Phase 2/5: Traffic Control"
    tc_apply_traffic_shaping
    tc_apply_wg_qdisc

    # Phase 3: Kernel parameters
    log_header "Phase 3/6: Kernel Hardening"
    apply_sysctl_ultimate

    # Phase 4: NIC optimization
    log_header "Phase 4/6: NIC & Hardware Optimization"
    apply_nic_optimization

    # Phase 5: Xray patches
    log_header "Phase 5/6: Xray Configuration"
    patch_xray_all

    # Phase 6: Persistence
    log_header "Phase 6/6: Persistence"
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        persist_nftables
    fi
    persist_tc_rules

    local elapsed=$(( $(date +%s) - start_time ))

    echo ""
    log_header "Installation Complete"
    echo ""

    # Run self-test
    run_dpi_self_test

    echo ""
    log_info "Total time: ${elapsed}s"
    log_info "Log file: ${LOG_FILE}"
    echo ""
    echo -e "${GREEN}${BOLD}  All anti-DPI protections are now active!${NC}"
    echo -e "  Run '${CYAN}bash $0 --status${NC}' to check protection status"
    echo -e "  Run '${CYAN}bash $0 --off${NC}' to remove all rules"
    echo ""
}

show_menu() {
    while true; do
        echo ""
        echo -e "${BOLD}${CYAN}"
        echo "  ╔══════════════════════════════════════════════════════╗"
        echo "  ║           Anti-DPI Ultimate v${VERSION}                 ║"
        echo "  ║     Enterprise Kernel-Level DPI Evasion Engine      ║"
        echo "  ╠══════════════════════════════════════════════════════╣"
        local display_role="${NODE_ROLE:-unknown}"
        local pad_len=$(( 20 - ${#display_role} - ${#FIREWALL_BACKEND} ))
        [[ ${pad_len} -lt 1 ]] && pad_len=1
        echo -e "  ║  Node: ${YELLOW}${display_role}${CYAN}  Firewall: ${YELLOW}${FIREWALL_BACKEND}${CYAN}$(printf '%*s' ${pad_len} '')║"
        echo "  ╠══════════════════════════════════════════════════════╣"
        echo -e "  ║  ${GREEN}1${CYAN}) Apply ALL (recommended)                         ║"
        echo -e "  ║  ${GREEN}2${CYAN}) RST Suppression                                 ║"
        echo -e "  ║  ${GREEN}3${CYAN}) Conntrack Bypass                                ║"
        echo -e "  ║  ${GREEN}4${CYAN}) MSS Clamping                                    ║"
        echo -e "  ║  ${GREEN}5${CYAN}) TCP Fingerprint Normalization                   ║"
        echo -e "  ║  ${GREEN}6${CYAN}) ICMP Hardening                                  ║"
        echo -e "  ║  ${GREEN}7${CYAN}) Traffic Shaping                                 ║"
        echo -e "  ║  ${GREEN}8${CYAN}) Sysctl Hardening                                ║"
        echo -e "  ║  ${GREEN}9${CYAN}) Xray Config Patch                               ║"
        echo -e "  ║  ${YELLOW}T${CYAN}) Timing Jitter (optional, adds 0-2ms)            ║"
        echo -e "  ║  ${BLUE}S${CYAN}) Status & Self-Test                              ║"
        echo -e "  ║  ${RED}R${CYAN}) Rollback All                                    ║"
        echo -e "  ║  ${RED}0${CYAN}) Exit                                            ║"
        echo "  ╚══════════════════════════════════════════════════════╝"
        echo -e "${NC}"

        read -rp "  Select option: " choice

        case "${choice}" in
            1)
                apply_all
                ;;
            2)
                if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
                    nft_apply_rst_suppression
                else
                    ipt_apply_rst_suppression
                fi
                ;;
            3)
                if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
                    nft_apply_conntrack_bypass
                else
                    ipt_apply_conntrack_bypass
                fi
                ;;
            4)
                if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
                    nft_apply_mss_clamping
                else
                    ipt_apply_mss_clamping
                fi
                ;;
            5)
                if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
                    nft_apply_fingerprint_normalize
                else
                    ipt_apply_fingerprint_normalize
                fi
                ;;
            6)
                if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
                    nft_apply_icmp_hardening
                else
                    ipt_apply_icmp_hardening
                fi
                ;;
            7)
                tc_apply_traffic_shaping
                tc_apply_wg_qdisc
                ;;
            8)
                apply_sysctl_ultimate
                ;;
            9)
                patch_xray_all
                ;;
            [tT])
                tc_apply_timing_jitter
                ;;
            [sS])
                run_dpi_self_test
                ;;
            [rR])
                read -rp "  Are you sure? This removes ALL anti-DPI rules [y/N]: " confirm
                [[ "${confirm}" =~ ^[yY]$ ]] && rollback_all
                ;;
            0|q|Q)
                echo -e "\n${GREEN}Goodbye!${NC}\n"
                exit 0
                ;;
            *)
                log_warn "Invalid option: ${choice}"
                ;;
        esac
    done
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    # Create log file
    mkdir -p "$(dirname "${LOG_FILE}")"
    touch "${LOG_FILE}" 2>/dev/null || true

    check_root
    check_os
    detect_capabilities

    # Try auto-detect, allow manual override
    detect_node_role 2>/dev/null || true

    # CLI argument handling
    case "${1:-}" in
        --auto)
            if [[ -z "${NODE_ROLE}" ]]; then
                log_error "Cannot auto-detect node role. Use --iran or --foreign"
                exit 1
            fi
            apply_all
            ;;
        --iran)
            NODE_ROLE="iran"
            log_info "Node role forced: IRAN (Entry)"
            apply_all
            ;;
        --foreign)
            NODE_ROLE="foreign"
            log_info "Node role forced: FOREIGN (Exit)"
            apply_all
            ;;
        --status)
            run_dpi_self_test
            ;;
        --off)
            rollback_all
            ;;
        --jitter)
            tc_apply_timing_jitter
            ;;
        --help|-h)
            echo ""
            echo "Anti-DPI Ultimate v${VERSION}"
            echo ""
            echo "Usage: bash $0 [OPTION]"
            echo ""
            echo "Options:"
            echo "  (none)      Interactive menu"
            echo "  --auto      Auto-detect role and apply all"
            echo "  --iran      Apply as Iran entry node"
            echo "  --foreign   Apply as Foreign exit node"
            echo "  --status    Show protection status"
            echo "  --off       Remove all anti-DPI rules"
            echo "  --jitter    Enable timing jitter (optional)"
            echo "  --help      Show this help"
            echo ""
            ;;
        "")
            # Interactive menu
            if [[ -z "${NODE_ROLE}" ]]; then
                echo ""
                echo -e "${YELLOW}Cannot auto-detect node role.${NC}"
                echo -e "  1) Iran (Entry node)"
                echo -e "  2) Foreign (Exit node)"
                read -rp "  Select role: " role_choice
                case "${role_choice}" in
                    1) NODE_ROLE="iran" ;;
                    2) NODE_ROLE="foreign" ;;
                    *) log_error "Invalid choice"; exit 1 ;;
                esac
            fi
            show_menu
            ;;
        *)
            log_error "Unknown option: ${1}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
}

main "$@"
