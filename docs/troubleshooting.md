# Troubleshooting

## Quick Check
```bash
tunnel-health.sh
```

## WireGuard Won't Start
```bash
modprobe wireguard
systemctl restart wg-quick@wg0
```

## Xray Won't Start
```bash
xray run -test -config /usr/local/etc/xray/config.json
journalctl -u xray -n 50
```

## Tunnel Not Connecting
```bash
wg show
ping -I wg0 10.66.66.1
nc -uzv <foreign-ip> 51820
```

## Slow Speeds
```bash
sysctl net.ipv4.tcp_congestion_control  # should be bbr
ip link show wg0 | grep mtu             # should be 1300
```

## Complete Reset
```bash
bash tunnel_enterprise.sh  # Select 5: Uninstall
reboot
bash tunnel_enterprise.sh  # Reinstall
```
