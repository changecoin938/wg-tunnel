# Stealth Tunnel — تانل اختصاصی نامرئی

تانل سفارشی به زبان C — ترافیک UDP/WireGuard رو داخل TLS 1.3 مخفی میکنه.

> نکته: منوی `wg-tunnel` عمداً **انگلیسی** است تا در بعضی ترمینال‌ها/SSH مشکل RTL/LTR و بهم‌ریختگی فارسی پیش نیاد. راهنمای کامل فارسی این README هست.

## معماری

```
[کلاینت‌ها] ←UDP→ [سرور ایران: cloud-agent] ←TLS 1.3→ [سرور خارج: cloud-agent] ←UDP→ [WireGuard]
                    بدون WireGuard!                        WireGuard اینجاست
```

## این تانل دقیقاً چی کار می‌کنه؟

- روی **سرور ایران (Relay)** فقط یک سرویس به اسم `cloud-agent` اجرا میشه و روی یک پورت UDP (مثلاً `51820`) گوش میده.
- سرور ایران **هیچ WireGuardی اجرا نمی‌کنه**؛ فقط پکت‌های UDP رو داخل یک اتصال **TLS 1.3** به سرور خارج می‌فرسته.
- روی **سرور خارج (Exit)** `cloud-agent` پکت‌ها رو از TLS خارج می‌کنه و به **WireGuard لوکال** روی همون سرور (مثلاً `127.0.0.1:51820`) تحویل میده.

## محدودیت مهم (برای اینکه به مشکل نخوری)

اگر کلاینت‌ها **مستقیم WireGuard** به UDP سرور ایران وصل بشن، ممکنه در مسیر کلاینت→سرور ایران، خودِ WireGuard قابل تشخیص باشه (بسته به شرایط شبکه).

این پروژه بیشتر برای **مخفی کردن لینک بین سرورها (ایران↔خارج)** طراحی شده. اگر می‌خوای سمت کلاینت هم تا حد ممکن TLS/HTTPS‌نما باشه، از گزینه‌ی `enterprise` استفاده کن.

## ویژگی‌ها

- **TLS 1.3** — ترافیک شبیه HTTPS عادی
- **HTTP Fallback** — Active probe → صفحه وب واقعی
- **Process Disguise** — نام پروسس: `cloud-agent`
- **PSK Auth** — فقط کلاینت‌های مجاز
- **Traffic Padding** — سایز پکت عادی‌شده
- **Auto Reconnect** — قطعی → وصل خودکار
- **No Strings** — صفر string مربوط به VPN در باینری

## پیش‌نیازها

- Debian/Ubuntu + `systemd` (اسکریپت‌ها با `apt-get` و `systemctl` کار می‌کنن)
- ۲ سرور:
  - **Relay (ایران)**: فقط `cloud-agent`
  - **Exit (خارج)**: `cloud-agent` + WireGuard
- پورت‌ها:
  - روی Exit: یک پورت TCP برای TLS (پیشنهادی `443`)
  - روی Relay: یک پورت UDP برای کلاینت‌ها (پیشنهادی `51820`)

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

### معنی آرگومان‌ها (خلاصه)

- `PSK` : یک کلید اشتراکی برای اینکه هر کسی نتونه به سرویس وصل شه (Auth لایه برنامه)
- `PIN` : اثرانگشت SHA256 سرتیفیکیت TLS برای جلوگیری از MITM
- `SNI` : اسم دامنه‌ای که در TLS به‌عنوان SNI ارسال میشه (مثلاً `www.google.com`)

## راه‌اندازی مرحله‌به‌مرحله

### 1) سرور خارج (Exit)

روی سرور خارج اجرا کن:

```bash
sudo wg-tunnel stealth server
```

خروجی بهت این‌ها رو میده:
- `IP`
- `Port`
- `PSK`
- `PIN`

نکته: اگر یک بار نصب کردی و دوباره اجرا کردی، به‌صورت پیش‌فرض از سرتیفیکیت قبلی استفاده می‌کنه. برای ساختن سرتیفیکیت جدید:

```bash
REGENERATE_CERT=1 sudo /opt/wg-tunnel/deploy.sh server
```

### 2) سرور ایران (Relay)

روی سرور ایران (با اطلاعات مرحله قبل) اجرا کن:

```bash
sudo wg-tunnel stealth relay EXIT_IP PSK 443 51820 PIN SNI
```

مثال:

```bash
sudo wg-tunnel stealth relay 1.2.3.4 abcdef... 443 51820 AA:BB:CC:... www.google.com
```

### 3) کلاینت‌ها

اگر کلاینت‌ها مستقیم WireGuard استفاده می‌کنن:
- `Endpoint` را IP سرور ایران بگذار
- `Port` را همان `Local UDP Port` (مثلاً `51820`) بگذار

اگر می‌خوای سمت کلاینت هم TLS‌نما باشه، از `enterprise` استفاده کن:

```bash
sudo wg-tunnel enterprise
```

## رفع اشکال سریع

روی هر سرور:

```bash
sudo systemctl status cloud-agent --no-pager
sudo tail -n 50 /var/log/cloud-agent.log
```

اگر Relay وصل نمی‌شود و `PIN` فعال کردی:
- در لاگ دنبال `TLS cert pin mismatch` بگرد
- مطمئن شو `PIN` دقیقاً همانی است که روی Exit چاپ شده

## آپدیت

اگر با `install.sh` نصب کردی:

```bash
cd /opt/wg-tunnel && sudo git pull --ff-only
```

## چرا تشخیص نمیدن؟

| چک | نتیجه روی سرور ایران |
|-----|---------------------|
| `ps aux` | فقط `cloud-agent` |
| `strings cloud-agent` | بدون VPN string |
| `netstat -tlnp` | فقط TLS:443 |
| Active Probe | صفحه وب CloudTech |
| `dpkg -l \| grep wire` | نصب نیست |
