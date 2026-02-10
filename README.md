# Tunnel Enterprise v2.0.0

Enterprise-grade distributed private networking with encrypted multi-hop transport.

## Architecture
```
Client → Trojan TLS (Iran:443) → WireGuard Tunnel → VLESS Reality (Foreign:8443) → Internet
```

## Quick Start

### Step 1: Foreign Exit Server
```bash
bash tunnel_enterprise.sh   # Select option 1, copy PAIRING TOKEN
```

### Step 2: Iran Entry Server
```bash
bash tunnel_enterprise.sh   # Select option 2, paste token
```

## Features
- One-Click Deployment with token-based pairing
- VLESS Reality with domain camouflage
- Trojan TLS on port 443
- WireGuard encrypted transport
- Auto-healing watchdog (every 5 min)
- BBR + TCP Fast Open + buffer tuning
- Fail2ban brute-force protection
- Health check dashboard

## Requirements
- OS: Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- RAM: 512MB+ (1GB recommended)
- Public IPv4 on both servers
- Ports: 443/tcp (Entry), 51820/udp + 8443/tcp (Exit)

## Client Support
- v2rayNG (Android)
- Shadowrocket (iOS)
- sing-box, Nekoray, v2rayN, Clash Meta

## Health Check
```bash
tunnel-health.sh
```

## License
MIT
