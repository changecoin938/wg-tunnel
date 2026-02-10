# Tunnel Enterprise v2.0.0

Enterprise-grade distributed private networking with encrypted multi-hop transport and kernel-level anti-DPI.

## Architecture
```
Client --> Trojan TLS (Iran:443) --> WireGuard Tunnel --> VLESS Reality (Foreign:8443) --> Internet
                  |                        |                        |
           TLS Fragment            Encrypted UDP              Domain Camouflage
           MSS Clamping            NOTRACK                    SNI Rotation
           RST Suppression         fq + BBR                   microsoft.com
```

---

## Quick Install (One-Line)

### Step 1: Foreign Exit Server
```bash
curl -sL https://raw.githubusercontent.com/changecoin938/wg-tunnel/main/tunnel_enterprise.sh | sudo bash -s -- 1
```

### Step 2: Iran Entry Server
```bash
curl -sL https://raw.githubusercontent.com/changecoin938/wg-tunnel/main/tunnel_enterprise.sh | sudo bash -s -- 2
```
> Paste the pairing token from Step 1 when prompted.

### Step 3: Anti-DPI Ultimate (Both Servers)

On **Iran** server:
```bash
curl -sL https://raw.githubusercontent.com/changecoin938/wg-tunnel/main/anti_dpi_ultimate.sh | sudo bash -s -- --iran
```

On **Foreign** server:
```bash
curl -sL https://raw.githubusercontent.com/changecoin938/wg-tunnel/main/anti_dpi_ultimate.sh | sudo bash -s -- --foreign
```

---

## Manual Install

```bash
# Download all scripts
git clone https://github.com/changecoin938/wg-tunnel.git
cd wg-tunnel

# 1. Foreign server
sudo bash tunnel_enterprise.sh    # Option 1 -> Copy pairing token

# 2. Iran server
sudo bash tunnel_enterprise.sh    # Option 2 -> Paste token

# 3. Anti-DPI (on both)
sudo bash anti_dpi_ultimate.sh    # Interactive menu -> Apply ALL

# 4. Performance tuning (optional)
sudo bash performance_tuner.sh    # Option A -> Apply ALL
```

---

## Anti-DPI Ultimate

6-layer kernel-level DPI evasion engine. Zero userspace overhead.

| Layer | What It Does | Cost |
|-------|-------------|------|
| **Raw (priority -300)** | RST suppression + conntrack bypass | ~50ns/pkt |
| **Mangle (-150)** | MSS clamping + TTL/hoplimit/DSCP normalization | ~100ns/pkt |
| **Filter (0)** | ICMP hardening + per-IP SYN rate limiting | ~50ns/pkt |
| **tc** | HTB + fq traffic shaping (10Gbps ready) | ~0.1% CPU/Gbps |
| **sysctl** | 50+ anti-fingerprint kernel parameters | 0 (one-time) |
| **Xray** | TLS fragment 10-50ms + uTLS chrome + 11 SNI domains | already running |

### CLI Usage
```bash
sudo bash anti_dpi_ultimate.sh              # Interactive menu
sudo bash anti_dpi_ultimate.sh --auto       # Auto-detect role + apply all
sudo bash anti_dpi_ultimate.sh --iran       # Force Iran mode
sudo bash anti_dpi_ultimate.sh --foreign    # Force Foreign mode
sudo bash anti_dpi_ultimate.sh --status     # Protection self-test (10 checks)
sudo bash anti_dpi_ultimate.sh --off        # Remove all rules
sudo bash anti_dpi_ultimate.sh --jitter     # Enable timing jitter (optional)
```

### Protection Self-Test
```bash
sudo bash anti_dpi_ultimate.sh --status
```
```
  ✓ TCP timestamps: DISABLED
  ✓ TTL normalization: ACTIVE (64)
  ✓ RST suppression: ACTIVE
  ✓ MSS clamping: ACTIVE
  ✓ WireGuard qdisc: fq
  ✓ Xray TLS fragment: interval=10-50
  ✓ TCP MTU probing: ACTIVE
  ✓ Congestion control: BBR
  ✓ Conntrack bypass: ACTIVE
  ✓ ICMP hardening: ACTIVE
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Protection Score: 10/10 (100%)
```

---

## X-UI Panel Integration

Use 3x-ui panel to manage users and generate client configs.

### Install 3x-ui on Foreign Server
```bash
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```
Access: `http://<foreign-ip>:2053` (default: admin/admin)

See [X-UI Guide](docs/x-ui-guide.md) for detailed setup.

---

## Client Support

| Platform | App | Protocol |
|----------|-----|----------|
| Android | v2rayNG | Trojan / VLESS Reality |
| iOS | Shadowrocket | Trojan / VLESS Reality |
| Windows | v2rayN / Nekoray | Trojan / VLESS Reality |
| macOS | V2Box | Trojan / VLESS Reality |
| Linux | Nekoray | Trojan / VLESS Reality |
| Cross-platform | sing-box / Clash Meta | Trojan / VLESS Reality |

See [Client Config](docs/client-config.md) for detailed setup per app.

---

## Server Requirements

| Spec | Minimum | Recommended (10Gbps) |
|------|---------|---------------------|
| OS | Ubuntu 20.04 / Debian 11 | Ubuntu 22.04+ |
| RAM | 512MB | 4GB+ |
| CPU | 1 core | 4+ cores |
| Network | Public IPv4 | 10Gbps NIC |
| Ports | 443/tcp, 51820/udp, 8443/tcp | Same |

---

## Files

| File | Description |
|------|-------------|
| `tunnel_enterprise.sh` | Main deployment script (WireGuard + Xray) |
| `anti_dpi_ultimate.sh` | Kernel-level anti-DPI engine (nftables/iptables/tc/sysctl) |
| `performance_tuner.sh` | Performance optimization for 500-5000+ users |
| `docs/x-ui-guide.md` | X-UI panel integration guide |
| `docs/client-config.md` | Client app configuration |
| `docs/troubleshooting.md` | Common issues and fixes |

---

## Health Check
```bash
sudo bash tunnel_enterprise.sh    # Option 4 -> Health Check
sudo bash anti_dpi_ultimate.sh --status
```

## Uninstall
```bash
sudo bash tunnel_enterprise.sh    # Option 5 -> Uninstall
sudo bash anti_dpi_ultimate.sh --off
```

## License
MIT
