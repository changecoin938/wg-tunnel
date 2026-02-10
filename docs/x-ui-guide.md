# X-UI Panel Integration Guide

## Install 3x-ui
```bash
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```
Access: http://<server-ip>:2053 (default: admin/admin)

## Trojan TCP TLS (Entry Node)
```json
{"port":443,"protocol":"trojan","settings":{"clients":[{"password":"YOUR_PASSWORD"}]},"streamSettings":{"network":"tcp","security":"tls"}}
```

## VLESS Reality TCP (Exit Node)
```json
{"port":8443,"protocol":"vless","settings":{"clients":[{"id":"UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"microsoft.com:443","serverNames":["microsoft.com"],"privateKey":"KEY","shortIds":["ID"]}}}
```

## VLESS WebSocket TLS (CDN Compatible)
```json
{"port":2083,"protocol":"vless","settings":{"clients":[{"id":"UUID"}],"decryption":"none"},"streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/ws-tunnel"}}}
```

## VLESS gRPC TLS (High Performance)
```json
{"port":2096,"protocol":"vless","settings":{"clients":[{"id":"UUID"}],"decryption":"none"},"streamSettings":{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"grpc-tunnel","multiMode":true}}}
```
