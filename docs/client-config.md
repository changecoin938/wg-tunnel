# Client Configuration

## v2rayNG (Android)
- Trojan: server=<iran-ip>, port=443, password=<pass>, TLS=on, allowInsecure=yes
- VLESS: server=<foreign-ip>, port=8443, uuid=<uuid>, flow=xtls-rprx-vision, security=reality, sni=microsoft.com, fp=chrome

## Shadowrocket (iOS)
Scan QR code from connection details or add manually with same params.

## sing-box
```json
{"outbounds":[{"type":"trojan","server":"<iran-ip>","server_port":443,"password":"<pass>","tls":{"enabled":true,"insecure":true}},{"type":"vless","server":"<foreign-ip>","server_port":8443,"uuid":"<uuid>","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"microsoft.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"<key>","short_id":"<id>"}}}]}
```

## Clash Meta
```yaml
proxies:
  - name: Trojan
    type: trojan
    server: "<iran-ip>"
    port: 443
    password: "<pass>"
    skip-cert-verify: true
  - name: VLESS
    type: vless
    server: "<foreign-ip>"
    port: 8443
    uuid: "<uuid>"
    flow: xtls-rprx-vision
    tls: true
    servername: microsoft.com
    reality-opts:
      public-key: "<key>"
      short-id: "<id>"
    client-fingerprint: chrome
```
