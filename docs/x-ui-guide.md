# X-UI Panel Integration Guide

## Overview

3x-ui panel lets you manage users, generate subscription links, and monitor traffic.
Install it on the **Foreign (Exit)** server alongside the tunnel.

```
                        Foreign Server
                   ┌─────────────────────────┐
  Iran Server      │  3x-ui Panel (:2053)    │
  ┌──────────┐     │     │                   │
  │ Trojan   │────>│  WireGuard ──> Xray     │──> Internet
  │ :443     │     │              (VLESS)     │
  └──────────┘     │              :8443       │
                   └─────────────────────────┘
```

---

## Step 1: Install 3x-ui on Foreign Server

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```

After install:
- Panel URL: `http://<foreign-ip>:2053`
- Default login: `admin` / `admin`
- **Change password immediately** in Settings > User

---

## Step 2: Panel Settings

Go to **Settings** in 3x-ui:

### Security
- Change default port from `2053` to a random port (e.g. `39821`)
- Enable HTTPS for panel (optional but recommended)
- Set strong username/password

### Subscription
- Enable subscription service
- Set subscription port (e.g. `2096`)
- This lets clients auto-update their configs

---

## Step 3: Create Inbound (VLESS Reality)

Go to **Inbounds** > **Add Inbound**:

| Field | Value |
|-------|-------|
| Remark | `VLESS-Reality` |
| Protocol | `vless` |
| Listen IP | (leave empty) |
| Port | `8443` |
| **Transmission** | |
| Network | `tcp` |
| Security | `reality` |
| **Reality Settings** | |
| Dest (Target) | `www.microsoft.com:443` |
| Server Names | `www.microsoft.com,microsoft.com,update.microsoft.com,login.microsoftonline.com` |
| Private Key | (auto-generated, or paste from tunnel setup) |
| Short IDs | (auto-generated) |
| **Client Settings** | |
| Flow | `xtls-rprx-vision` |
| Email | `user1@tunnel` |

> **Important:** If the tunnel is already set up with `tunnel_enterprise.sh`, the VLESS Reality inbound is already configured in Xray. In that case, you have two options:
>
> **Option A (Recommended):** Use x-ui as management panel only - set x-ui to read the existing Xray config:
> ```bash
> # Stop x-ui's built-in Xray
> x-ui stop
> # Point x-ui to the existing Xray binary and config
> # Edit /usr/local/x-ui/x-ui.db to match existing config
> ```
>
> **Option B:** Let x-ui manage Xray and recreate the inbound with the same keys from `/root/tunnel-config/vless_reality.json`

---

## Step 4: Create Inbound (Trojan over WireGuard)

If you want x-ui to also manage the Trojan inbound on the **Iran server**, install 3x-ui there too:

```bash
# On Iran server
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```

Create Trojan inbound:

| Field | Value |
|-------|-------|
| Remark | `Trojan-TLS` |
| Protocol | `trojan` |
| Port | `443` |
| **Transmission** | |
| Network | `tcp` |
| Security | `tls` |
| **TLS Settings** | |
| Certificate | Use self-signed or provide your own |
| ALPN | `h2,http/1.1` |
| Fingerprint | `chrome` |
| **Client Settings** | |
| Password | (your trojan password) |
| Email | `user1@tunnel` |

---

## Step 5: Add Users

In each inbound, click **+** to add clients:

1. Set email (for tracking, e.g. `user1@company`)
2. Set traffic limit (optional, e.g. 100GB)
3. Set expiry date (optional)
4. Click **Add**

### Get Client Config
- Click the **QR code** icon next to the user
- Or click the **copy** icon for the connection URL
- Share the QR code or URL with the user

---

## Step 6: Apply Anti-DPI

After setting up x-ui, apply Anti-DPI Ultimate on **both** servers:

```bash
# Iran server
sudo bash anti_dpi_ultimate.sh --iran

# Foreign server
sudo bash anti_dpi_ultimate.sh --foreign
```

This patches the existing Xray config with:
- TLS fragment (10-50ms interval)
- uTLS chrome fingerprint
- Expanded SNI pool (11 domains)
- Socket mark for kernel-level rules

---

## Step 7: Client Connection

### v2rayNG (Android)
1. Open v2rayNG
2. Tap **+** > **Import config from clipboard**
3. Paste the VLESS Reality URL from x-ui
4. Connect

### Shadowrocket (iOS)
1. Open Shadowrocket
2. Scan the QR code from x-ui panel
3. Connect

### Using Subscription Link
1. In x-ui, go to **Subscription** settings
2. Copy subscription URL: `https://<foreign-ip>:<sub-port>/sub/<token>`
3. In client app, add subscription URL
4. Client auto-downloads all configs

---

## Multi-User Management

### Traffic Monitoring
- x-ui dashboard shows real-time traffic per user
- Set alerts for bandwidth limits
- View connection logs

### Reset Traffic
- Go to Inbounds > Client > Reset Traffic

### Disable User
- Go to Inbounds > Client > Toggle enable/disable

### Bulk Add Users
Use x-ui API:
```bash
# Example: Add user via API
curl -X POST "http://localhost:2053/panel/api/inbounds/addClient" \
  -H "Content-Type: application/json" \
  -d '{"id":1,"settings":"{\"clients\":[{\"id\":\"NEW-UUID\",\"flow\":\"xtls-rprx-vision\",\"email\":\"user2@tunnel\"}]}"}'
```

---

## Ports Summary

| Port | Protocol | Where | Purpose |
|------|----------|-------|---------|
| 443/tcp | Trojan TLS | Iran | Client entry point |
| 51820/udp | WireGuard | Both | Encrypted tunnel |
| 8443/tcp | VLESS Reality | Foreign | Exit point |
| 2053/tcp | HTTP(S) | Foreign | x-ui panel |
| 2096/tcp | HTTP(S) | Foreign | Subscription (optional) |

---

## Troubleshooting

### Panel not accessible
```bash
# Check x-ui status
x-ui status

# Check port
ss -tlnp | grep 2053

# Restart
x-ui restart
```

### Clients can't connect after Anti-DPI
```bash
# Check Xray status
systemctl status xray

# Check Xray config is valid JSON
jq empty /usr/local/etc/xray/config.json

# Check Anti-DPI status
sudo bash anti_dpi_ultimate.sh --status

# View Xray logs
journalctl -u xray -f
```

### x-ui conflicts with existing Xray
If `tunnel_enterprise.sh` already installed Xray:
```bash
# Option 1: Use x-ui's Xray (stop the standalone one)
systemctl stop xray
systemctl disable xray

# Option 2: Keep standalone Xray (use x-ui for monitoring only)
# In x-ui settings, point to existing Xray binary
```
