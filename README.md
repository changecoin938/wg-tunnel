# Stealth Tunnel — تانل اختصاصی نامرئی

تانل سفارشی به زبان C — ترافیک UDP/WireGuard رو داخل TLS 1.3 مخفی میکنه.

## معماری

```
[کلاینت‌ها] ←UDP→ [سرور ایران: cloud-agent] ←TLS 1.3→ [سرور خارج: cloud-agent] ←UDP→ [WireGuard]
                    بدون WireGuard!                        WireGuard اینجاست
```

## ویژگی‌ها

- **TLS 1.3** — ترافیک شبیه HTTPS عادی
- **HTTP Fallback** — Active probe → صفحه وب واقعی
- **Process Disguise** — نام پروسس: `cloud-agent`
- **PSK Auth** — فقط کلاینت‌های مجاز
- **Traffic Padding** — سایز پکت عادی‌شده
- **Auto Reconnect** — قطعی → وصل خودکار
- **No Strings** — صفر string مربوط به VPN در باینری

## نصب سریع

### نصب با یک دستور (Debian/Ubuntu)

```bash
curl -fsSL https://raw.githubusercontent.com/changecoin938/wg-tunnel/main/install.sh | sudo bash
```

بعد از نصب:

```bash
sudo wg-tunnel
```

### اجرای دستی (لوکال)

```bash
# 1. سرور خارج
sudo ./wg-tunnel.sh stealth server
# (یا)
sudo ./deploy.sh server

# 2. سرور ایران (با IP و PSK و PIN از مرحله قبل)
sudo ./wg-tunnel.sh stealth relay FOREIGN_IP PSK 443 51820 PIN
# (یا)
sudo ./deploy.sh relay FOREIGN_IP PSK 443 51820 PIN

# 3. وضعیت
sudo ./wg-tunnel.sh stealth status
# (یا)
sudo ./deploy.sh status
```

## امنیت (خیلی مهم)

اگر ISP/میان‌راهی بتونه **MITM** کنه (TLS رو terminate کنه)، بدون **PIN** ممکنه ترافیک خونده/جایگزین بشه.

- موقع نصب سرور خارج، خروجی `deploy.sh` مقدار `PIN:` رو میده (SHA256 fingerprint).
- همون `PIN` رو روی سرور ایران به‌عنوان آرگومان آخر به `relay` بده.

اختیاری: برای طبیعی‌تر شدن TLS می‌تونی `SNI` هم بدی (آخرین آرگومان بعد از PIN).

## چرا تشخیص نمیدن؟

| چک | نتیجه روی سرور ایران |
|-----|---------------------|
| `ps aux` | فقط `cloud-agent` |
| `strings cloud-agent` | بدون VPN string |
| `netstat -tlnp` | فقط TLS:443 |
| Active Probe | صفحه وب CloudTech |
| `dpkg -l \| grep wire` | نصب نیست |
