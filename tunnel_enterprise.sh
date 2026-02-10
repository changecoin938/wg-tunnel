#!/usr/bin/env bash
set -euo pipefail
readonly VERSION="2.0.0"
readonly CONFIG_DIR="/root/tunnel-config"
readonly LOG_FILE="/var/log/tunnel.log"
readonly WG_INTERFACE="wg0"
readonly WG_PORT=51820
readonly WG_SUBNET="10.66.66"
readonly WG_SERVER_IP="${WG_SUBNET}.1"
readonly WG_CLIENT_IP="${WG_SUBNET}.2"
readonly WG_MASK="24"
readonly MTU_DEFAULT=1300
readonly XRAY_CONFIG_DIR="/usr/local/etc/xray"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly REALITY_SNI="microsoft.com"
readonly REALITY_DEST="microsoft.com:443"
readonly TROJAN_PORT=443
readonly VLESS_PORT=8443
readonly HEALTH_CHECK_INTERVAL=300
readonly MAX_RESTART_ATTEMPTS=5
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'
log(){local level="$1";shift;local msg="$*";local timestamp;timestamp=$(date '+%Y-%m-%d %H:%M:%S');echo -e "${timestamp} [${level}] ${msg}">>"${LOG_FILE}" 2>/dev/null||true;case "${level}" in INFO)echo -e "${GREEN}[✓]${NC} ${msg}";;WARN)echo -e "${YELLOW}[!]${NC} ${msg}";;ERROR)echo -e "${RED}[✗]${NC} ${msg}";;DEBUG)[[ "${DEBUG:-0}" == "1" ]]&&echo -e "${CYAN}[D]${NC} ${msg}";;STEP)echo -e "${BLUE}[→]${NC} ${BOLD}${msg}${NC}";;esac;}
log_info(){log INFO "$@";};log_warn(){log WARN "$@";};log_error(){log ERROR "$@";};log_debug(){log DEBUG "$@";};log_step(){log STEP "$@";}
die(){log_error "$@";exit 1;}
check_root(){[[ "$(id -u)" -eq 0 ]]||die "This script must be run as root. Use: sudo bash $0";}
check_os(){if [[ ! -f /etc/os-release ]];then die "Unsupported operating system";fi;source /etc/os-release;case "${ID}" in ubuntu|debian)PKG_MANAGER="apt";;centos|almalinux|rocky|fedora)PKG_MANAGER="yum";;*)die "Unsupported distribution: ${ID}";;esac;log_info "Detected OS: ${PRETTY_NAME} (${PKG_MANAGER})";}
get_public_ip(){local ip="";local services=("https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com" "https://ipinfo.io/ip");for svc in "${services[@]}";do ip=$(curl -s --max-time 5 "${svc}" 2>/dev/null)&&break;done;[[ -n "${ip}" ]]&&echo "${ip}"||die "Cannot detect public IP address";}
get_default_interface(){ip route show default|awk '/default/ {print $5}'|head -1;}
generate_uuid(){cat /proc/sys/kernel/random/uuid;}
generate_random_hex(){local length="${1:-16}";openssl rand -hex "$((length/2))";}
generate_short_id(){openssl rand -hex 4;}
base64_encode(){echo -n "$1"|base64 -w0;}
base64_decode(){echo -n "$1"|base64 -d;}
confirm(){local msg="${1:-Continue?}";echo -en "${YELLOW}${msg} [y/N]: ${NC}";read -r ans;[[ "${ans}" =~ ^[Yy]$ ]];}
install_dependencies(){log_step "Installing system dependencies...";if [[ "${PKG_MANAGER}" == "apt" ]];then export DEBIAN_FRONTEND=noninteractive;apt-get update -qq;apt-get install -y -qq curl wget unzip jq openssl iptables net-tools wireguard wireguard-tools fail2ban cron qrencode 2>&1|tail -5;else yum install -y -q curl wget unzip jq openssl iptables net-tools wireguard-tools fail2ban cronie qrencode 2>&1|tail -5;fi;log_info "Dependencies installed successfully";}
install_xray(){log_step "Installing Xray-core...";if [[ -f "${XRAY_BIN}" ]];then local current_ver;current_ver=$("${XRAY_BIN}" version 2>/dev/null|head -1|awk '{print $2}')||true;log_info "Xray already installed (v${current_ver})";return 0;fi;bash <(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) 2>&1|tail -3;if [[ ! -f "${XRAY_BIN}" ]];then die "Xray installation failed";fi;mkdir -p "${XRAY_CONFIG_DIR}";log_info "Xray-core installed successfully";}
apply_sysctl_tuning(){log_step "Applying kernel performance tuning...";cat>/etc/sysctl.d/99-tunnel-enterprise.conf<<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_default=1048576
net.core.rmem_max=16777216
net.core.wmem_default=1048576
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 131072 16777216
net.core.somaxconn=65535
net.core.netdev_max_backlog=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_max_orphans=65535
net.ipv4.tcp_syncookies=1
fs.file-max=1048576
fs.nr_open=1048576
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
SYSCTL
sysctl --system>/dev/null 2>&1;log_info "Kernel tuning applied (BBR, TCP Fast Open, buffer optimization)";}
increase_file_limits(){log_step "Increasing system file limits...";cat>/etc/security/limits.d/99-tunnel-enterprise.conf<<'LIMITS'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS
if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null;then echo "session required pam_limits.so">>/etc/pam.d/common-session 2>/dev/null||true;fi;log_info "File limits increased to 1048576";}
generate_wg_keys(){local prefix="$1";local private_key public_key preshared_key;private_key=$(wg genkey);public_key=$(echo "${private_key}"|wg pubkey);preshared_key=$(wg genpsk);echo "${private_key}">"${CONFIG_DIR}/${prefix}_private.key";echo "${public_key}">"${CONFIG_DIR}/${prefix}_public.key";echo "${preshared_key}">"${CONFIG_DIR}/${prefix}_preshared.key";chmod 600 "${CONFIG_DIR}"/*.key;log_info "WireGuard keys generated for ${prefix}";}
setup_wg_server(){log_step "Configuring WireGuard server...";generate_wg_keys "server";local server_privkey client_pubkey preshared_key;server_privkey=$(cat "${CONFIG_DIR}/server_private.key");generate_wg_keys "client";client_pubkey=$(cat "${CONFIG_DIR}/client_public.key");preshared_key=$(cat "${CONFIG_DIR}/server_preshared.key");local default_iface;default_iface=$(get_default_interface);cat>"/etc/wireguard/${WG_INTERFACE}.conf"<<WG_SERVER
[Interface]
Address=${WG_SERVER_IP}/${WG_MASK}
ListenPort=${WG_PORT}
PrivateKey=${server_privkey}
MTU=${MTU_DEFAULT}
PostUp=iptables -t nat -A POSTROUTING -o ${default_iface} -j MASQUERADE
PostUp=iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT
PostUp=iptables -A FORWARD -o ${WG_INTERFACE} -j ACCEPT
PostDown=iptables -t nat -D POSTROUTING -o ${default_iface} -j MASQUERADE
PostDown=iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT
PostDown=iptables -D FORWARD -o ${WG_INTERFACE} -j ACCEPT
[Peer]
PublicKey=${client_pubkey}
PresharedKey=${preshared_key}
AllowedIPs=${WG_CLIENT_IP}/32
PersistentKeepalive=25
WG_SERVER
chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf";systemctl enable wg-quick@${WG_INTERFACE};systemctl start wg-quick@${WG_INTERFACE}||{log_warn "WireGuard failed to start, attempting module load...";modprobe wireguard 2>/dev/null||true;systemctl start wg-quick@${WG_INTERFACE};};log_info "WireGuard server running on ${WG_SERVER_IP}:${WG_PORT}";}
setup_wg_client(){local foreign_ip="$1";local server_pubkey="$2";local client_privkey="$3";local preshared_key="$4";log_step "Configuring WireGuard client...";local default_iface;default_iface=$(get_default_interface);cat>"/etc/wireguard/${WG_INTERFACE}.conf"<<WG_CLIENT
[Interface]
Address=${WG_CLIENT_IP}/${WG_MASK}
PrivateKey=${client_privkey}
MTU=${MTU_DEFAULT}
PostUp=iptables -t nat -A POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE
PostDown=iptables -t nat -D POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE
[Peer]
PublicKey=${server_pubkey}
PresharedKey=${preshared_key}
Endpoint=${foreign_ip}:${WG_PORT}
AllowedIPs=0.0.0.0/0
PersistentKeepalive=25
WG_CLIENT
chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf";systemctl enable wg-quick@${WG_INTERFACE};systemctl start wg-quick@${WG_INTERFACE}||{log_warn "WireGuard client failed to start, retrying...";sleep 2;systemctl restart wg-quick@${WG_INTERFACE};};log_info "WireGuard client connected to ${foreign_ip}:${WG_PORT}";}
setup_vless_reality(){log_step "Configuring VLESS Reality (Exit Node)...";local uuid short_id;uuid=$(generate_uuid);short_id=$(generate_short_id);local reality_keys private_key public_key;reality_keys=$("${XRAY_BIN}" x25519 2>/dev/null);private_key=$(echo "${reality_keys}"|grep "Private key:"|awk '{print $3}');public_key=$(echo "${reality_keys}"|grep "Public key:"|awk '{print $3}');cat>"${CONFIG_DIR}/vless_reality.json"<<CREDS
{"uuid":"${uuid}","reality_private_key":"${private_key}","reality_public_key":"${public_key}","short_id":"${short_id}","sni":"${REALITY_SNI}","dest":"${REALITY_DEST}","port":${VLESS_PORT}}
CREDS
cat>"${XRAY_CONFIG_DIR}/config.json"<<XRAY_CONFIG
{"log":{"loglevel":"warning","access":"/var/log/xray/access.log","error":"/var/log/xray/error.log"},"dns":{"servers":["https+local://1.1.1.1/dns-query","https+local://8.8.8.8/dns-query","localhost"]},"inbounds":[{"tag":"vless-reality-in","listen":"0.0.0.0","port":${VLESS_PORT},"protocol":"vless","settings":{"clients":[{"id":"${uuid}","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"show":false,"dest":"${REALITY_DEST}","xver":0,"serverNames":["${REALITY_SNI}","www.${REALITY_SNI}"],"privateKey":"${private_key}","shortIds":["${short_id}",""]}},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}},{"tag":"block","protocol":"blackhole","settings":{"response":{"type":"http"}}}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","outboundTag":"block","protocol":["bittorrent"]},{"type":"field","outboundTag":"direct","network":"udp,tcp"}]},"policy":{"levels":{"0":{"handshake":4,"connIdle":300,"uplinkOnly":2,"downlinkOnly":5,"bufferSize":4}},"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true}},"stats":{}}
XRAY_CONFIG
mkdir -p /var/log/xray;systemctl enable xray;systemctl restart xray;log_info "VLESS Reality configured on port ${VLESS_PORT}";log_info "UUID: ${uuid}";log_info "Public Key: ${public_key}";log_info "Short ID: ${short_id}";}
setup_trojan_inbound(){local trojan_password="$1";local foreign_wg_ip="${WG_SERVER_IP}";log_step "Configuring Trojan inbound (Entry Node)...";local cert_dir="${CONFIG_DIR}/certs";mkdir -p "${cert_dir}";if [[ ! -f "${cert_dir}/server.crt" ]];then log_info "Generating self-signed TLS certificate...";openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "${cert_dir}/server.key" -out "${cert_dir}/server.crt" -days 3650 -subj "/CN=microsoft.com/O=Enterprise/C=US" 2>/dev/null;chmod 600 "${cert_dir}/server.key";fi;cat>"${XRAY_CONFIG_DIR}/config.json"<<XRAY_TROJAN
{"log":{"loglevel":"warning","access":"/var/log/xray/access.log","error":"/var/log/xray/error.log"},"inbounds":[{"tag":"trojan-in","listen":"0.0.0.0","port":${TROJAN_PORT},"protocol":"trojan","settings":{"clients":[{"password":"${trojan_password}"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"${cert_dir}/server.crt","keyFile":"${cert_dir}/server.key"}],"minVersion":"1.2","alpn":["h2","http/1.1"]}},"sniffing":{"enabled":true,"destOverride":["http","tls"]}}],"outbounds":[{"tag":"wg-tunnel","protocol":"freedom","settings":{"domainStrategy":"UseIPv4","redirect":"${foreign_wg_ip}:0"},"streamSettings":{"sockopt":{"mark":255}}},{"tag":"direct","protocol":"freedom","settings":{}},{"tag":"block","protocol":"blackhole","settings":{}}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","outboundTag":"block","protocol":["bittorrent"]},{"type":"field","inboundTag":["trojan-in"],"outboundTag":"wg-tunnel"}]}}
XRAY_TROJAN
mkdir -p /var/log/xray;systemctl enable xray;systemctl restart xray;log_info "Trojan inbound configured on port ${TROJAN_PORT}";}
configure_firewall_foreign(){log_step "Configuring firewall (Exit Server)...";if command -v ufw &>/dev/null;then ufw allow ${WG_PORT}/udp comment "WireGuard";ufw allow ${VLESS_PORT}/tcp comment "VLESS Reality";ufw allow 22/tcp comment "SSH";ufw --force enable;else iptables -A INPUT -p udp --dport ${WG_PORT} -j ACCEPT;iptables -A INPUT -p tcp --dport ${VLESS_PORT} -j ACCEPT;iptables -A INPUT -p tcp --dport 22 -j ACCEPT;iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT;iptables -A INPUT -i lo -j ACCEPT;fi;log_info "Firewall configured";}
configure_firewall_iran(){log_step "Configuring firewall (Entry Server)...";if command -v ufw &>/dev/null;then ufw allow ${TROJAN_PORT}/tcp comment "Trojan";ufw allow 22/tcp comment "SSH";ufw --force enable;else iptables -A INPUT -p tcp --dport ${TROJAN_PORT} -j ACCEPT;iptables -A INPUT -p tcp --dport 22 -j ACCEPT;iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT;iptables -A INPUT -i lo -j ACCEPT;fi;log_info "Firewall configured";}
setup_fail2ban(){log_step "Configuring Fail2ban...";cat>/etc/fail2ban/jail.d/tunnel-enterprise.conf<<'F2B'
[sshd]
enabled=true
port=ssh
filter=sshd
logpath=/var/log/auth.log
maxretry=5
bantime=3600
findtime=600
[trojan-auth]
enabled=true
port=443
filter=trojan-auth
logpath=/var/log/xray/access.log
maxretry=10
bantime=1800
findtime=300
F2B
cat>/etc/fail2ban/filter.d/trojan-auth.conf<<'F2B_FILTER'
[Definition]
failregex=^.*rejected.*from <HOST>.*$
ignoreregex=
F2B_FILTER
systemctl enable fail2ban;systemctl restart fail2ban;log_info "Fail2ban configured";}
harden_ssh(){log_step "Hardening SSH...";local sshd_config="/etc/ssh/sshd_config";cp "${sshd_config}" "${sshd_config}.bak.$(date +%s)";declare -A ssh_settings=(["PermitRootLogin"]="prohibit-password" ["MaxAuthTries"]="5" ["LoginGraceTime"]="60" ["ClientAliveInterval"]="120" ["ClientAliveCountMax"]="3" ["X11Forwarding"]="no");for key in "${!ssh_settings[@]}";do local val="${ssh_settings[$key]}";if grep -q "^${key}" "${sshd_config}";then sed -i "s/^${key}.*/${key} ${val}/" "${sshd_config}";elif grep -q "^#${key}" "${sshd_config}";then sed -i "s/^#${key}.*/${key} ${val}/" "${sshd_config}";else echo "${key} ${val}">>"${sshd_config}";fi;done;systemctl reload sshd 2>/dev/null||systemctl reload ssh 2>/dev/null||true;log_info "SSH hardened";}
create_watchdog_service(){log_step "Creating watchdog service...";cat>/usr/local/bin/tunnel-watchdog.sh<<'WATCHDOG'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/tunnel.log"
log_wd(){echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHDOG] $*">>"${LOG}";}
restart_svc(){local svc="$1" attempt=0;while [[ $attempt -lt 5 ]];do ((attempt++));log_wd "Restarting ${svc} (${attempt}/5)";systemctl restart "${svc}"&&{log_wd "${svc} OK";return 0;};sleep 10;done;log_wd "CRITICAL: ${svc} failed";return 1;}
if systemctl is-enabled wg-quick@wg0 &>/dev/null;then systemctl is-active --quiet wg-quick@wg0||restart_svc wg-quick@wg0;fi
if systemctl is-enabled xray &>/dev/null;then systemctl is-active --quiet xray||restart_svc xray;fi
if ip link show wg0 &>/dev/null;then ping -c 2 -W 5 -I wg0 10.66.66.1 &>/dev/null 2>&1||ping -c 2 -W 5 -I wg0 10.66.66.2 &>/dev/null 2>&1||restart_svc wg-quick@wg0;fi
log_wd "Health check completed"
WATCHDOG
chmod +x /usr/local/bin/tunnel-watchdog.sh;cat>/etc/systemd/system/tunnel-watchdog.service<<'SVC'
[Unit]
Description=Tunnel Enterprise Watchdog
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/tunnel-watchdog.sh
SVC
cat>/etc/systemd/system/tunnel-watchdog.timer<<'TIMER'
[Unit]
Description=Tunnel Enterprise Watchdog Timer
[Timer]
OnBootSec=60
OnUnitActiveSec=300
[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload;systemctl enable tunnel-watchdog.timer;systemctl start tunnel-watchdog.timer;log_info "Watchdog created (every 5min)";}
create_health_check_script(){log_step "Creating health check...";cat>/usr/local/bin/tunnel-health.sh<<'HEALTH'
#!/usr/bin/env bash
G='\033[0;32m';R='\033[0;31m';Y='\033[1;33m';N='\033[0m'
ok(){echo -e "  ${G}✓${N} $*";};fail(){echo -e "  ${R}✗${N} $*";};warn(){echo -e "  ${Y}!${N} $*";}
echo "";echo "═══════════════════════════════════════";echo " Tunnel Enterprise Health Report";echo " $(date)";echo "═══════════════════════════════════════"
echo "▸ System";ok "Uptime: $(uptime -p)";ok "Load: $(cat /proc/loadavg|awk '{print $1,$2,$3}')"
echo "▸ WireGuard";systemctl is-active --quiet wg-quick@wg0 2>/dev/null&&ok "Running"||fail "Stopped"
echo "▸ Xray";systemctl is-active --quiet xray 2>/dev/null&&ok "Running"||fail "Stopped"
echo "▸ Performance";cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null);[[ "$cc" == "bbr" ]]&&ok "BBR"||warn "${cc}"
echo "═══════════════════════════════════════"
HEALTH
chmod +x /usr/local/bin/tunnel-health.sh;log_info "Health check: tunnel-health.sh";}
generate_pairing_token(){log_step "Generating pairing token...";local public_ip server_pubkey client_privkey preshared_key;public_ip=$(get_public_ip);server_pubkey=$(cat "${CONFIG_DIR}/server_public.key");client_privkey=$(cat "${CONFIG_DIR}/client_private.key");preshared_key=$(cat "${CONFIG_DIR}/server_preshared.key");local uuid reality_pub_key short_id;uuid=$(jq -r '.uuid' "${CONFIG_DIR}/vless_reality.json");reality_pub_key=$(jq -r '.reality_public_key' "${CONFIG_DIR}/vless_reality.json");short_id=$(jq -r '.short_id' "${CONFIG_DIR}/vless_reality.json");local token_json="{\"v\":\"${VERSION}\",\"foreign_ip\":\"${public_ip}\",\"wg_port\":${WG_PORT},\"wg_server_pubkey\":\"${server_pubkey}\",\"wg_client_privkey\":\"${client_privkey}\",\"wg_preshared_key\":\"${preshared_key}\",\"vless_uuid\":\"${uuid}\",\"vless_port\":${VLESS_PORT},\"reality_public_key\":\"${reality_pub_key}\",\"reality_short_id\":\"${short_id}\",\"reality_sni\":\"${REALITY_SNI}\"}";local token;token=$(base64_encode "${token_json}");echo "${token}">"${CONFIG_DIR}/pairing_token.txt";echo "${token_json}">"${CONFIG_DIR}/pairing_data.json";log_info "Pairing token generated";echo "${token}";}
parse_pairing_token(){local token="$1";log_step "Parsing pairing token...";local json;json=$(base64_decode "${token}")||die "Invalid token";echo "${json}"|jq .>/dev/null 2>&1||die "Invalid JSON";FOREIGN_IP=$(echo "${json}"|jq -r '.foreign_ip');WG_SERVER_PUBKEY=$(echo "${json}"|jq -r '.wg_server_pubkey');WG_CLIENT_PRIVKEY=$(echo "${json}"|jq -r '.wg_client_privkey');WG_PRESHARED_KEY=$(echo "${json}"|jq -r '.wg_preshared_key');VLESS_UUID=$(echo "${json}"|jq -r '.vless_uuid');REALITY_PUB_KEY=$(echo "${json}"|jq -r '.reality_public_key');REALITY_SHORT_ID=$(echo "${json}"|jq -r '.reality_short_id');[[ -n "${FOREIGN_IP}" && "${FOREIGN_IP}" != "null" ]]||die "Missing foreign_ip";log_info "Token parsed: Foreign IP = ${FOREIGN_IP}";echo "${json}">"${CONFIG_DIR}/pairing_data.json";}
print_connection_details(){echo "";echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════╗";echo "║     Tunnel Enterprise — Connection Details     ║";echo -e "╚════════════════════════════════════════════════╝${NC}";if [[ -f "${CONFIG_DIR}/vless_reality.json" ]];then local vless="${CONFIG_DIR}/vless_reality.json";local public_ip;public_ip=$(get_public_ip 2>/dev/null||echo "UNKNOWN");local uuid pub_key sid port;uuid=$(jq -r '.uuid' "${vless}");pub_key=$(jq -r '.reality_public_key' "${vless}");sid=$(jq -r '.short_id' "${vless}");port=$(jq -r '.port' "${vless}");echo -e "${BOLD}▸ VLESS Reality URI${NC}";echo "vless://${uuid}@${public_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${pub_key}&sid=${sid}&type=tcp#Tunnel-Enterprise";echo "";fi;if [[ -f "${CONFIG_DIR}/pairing_token.txt" ]];then echo -e "${BOLD}▸ Pairing Token:${NC}";cat "${CONFIG_DIR}/pairing_token.txt";echo "";fi;if [[ -f "${CONFIG_DIR}/trojan_info.json" ]];then local trojan="${CONFIG_DIR}/trojan_info.json";local t_s t_po t_pa;t_s=$(jq -r '.server' "${trojan}");t_po=$(jq -r '.port' "${trojan}");t_pa=$(jq -r '.password' "${trojan}");echo -e "${BOLD}▸ Trojan URI:${NC}";echo "trojan://${t_pa}@${t_s}:${t_po}?security=tls&allowInsecure=1#Tunnel-Enterprise-Trojan";echo "";fi;wg show "${WG_INTERFACE}" 2>/dev/null||true;echo "";}
setup_traffic_forwarding(){log_step "Configuring traffic forwarding...";local default_iface;default_iface=$(get_default_interface);ip route add "${FOREIGN_IP}/32" via "$(ip route show default|awk '{print $3}')" dev "${default_iface}" 2>/dev/null||true;if ! ip rule show|grep -q "fwmark 0xff";then ip rule add fwmark 0xff table 100 2>/dev/null||true;ip route add default via "${WG_SERVER_IP}" dev "${WG_INTERFACE}" table 100 2>/dev/null||true;fi;iptables -t mangle -A OUTPUT -m mark --mark 0xff -j RETURN 2>/dev/null||true;log_info "Traffic forwarding configured";}
uninstall_all(){echo -e "${RED}${BOLD}WARNING: Removing all tunnel components${NC}";confirm "Are you sure?"||return 0;systemctl stop wg-quick@${WG_INTERFACE} xray tunnel-watchdog.timer 2>/dev/null||true;systemctl disable wg-quick@${WG_INTERFACE} xray tunnel-watchdog.timer 2>/dev/null||true;rm -f "/etc/wireguard/${WG_INTERFACE}.conf";rm -rf "${XRAY_CONFIG_DIR}";rm -f /etc/sysctl.d/99-tunnel-enterprise.conf /etc/security/limits.d/99-tunnel-enterprise.conf;rm -f /usr/local/bin/tunnel-watchdog.sh /usr/local/bin/tunnel-health.sh;rm -f /etc/systemd/system/tunnel-watchdog.*;bash <(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove 2>/dev/null||true;systemctl daemon-reload;if [[ -d "${CONFIG_DIR}" ]];then tar -czf "/root/tunnel-backup-$(date +%s).tar.gz" -C /root tunnel-config 2>/dev/null||true;rm -rf "${CONFIG_DIR}";fi;log_info "Uninstall complete";}
install_foreign_server(){echo -e "${CYAN}${BOLD}Installing Foreign Exit Server (WireGuard + VLESS Reality)${NC}";check_os;mkdir -p "${CONFIG_DIR}" /var/log;install_dependencies;apply_sysctl_tuning;increase_file_limits;setup_wg_server;install_xray;setup_vless_reality;configure_firewall_foreign;setup_fail2ban;harden_ssh;create_watchdog_service;create_health_check_script;echo -e "${GREEN}${BOLD}✅ Foreign Exit Server installed!${NC}";echo -e "${YELLOW}▸ PAIRING TOKEN:${NC}";generate_pairing_token;print_connection_details;}
install_iran_server(){echo -e "${CYAN}${BOLD}Installing Iran Entry Server (Trojan + WireGuard Client)${NC}";check_os;mkdir -p "${CONFIG_DIR}" /var/log;echo -en "${YELLOW}Paste pairing token: ${NC}";read -r PAIRING_TOKEN;[[ -n "${PAIRING_TOKEN}" ]]||die "No token";parse_pairing_token "${PAIRING_TOKEN}";install_dependencies;apply_sysctl_tuning;increase_file_limits;setup_wg_client "${FOREIGN_IP}" "${WG_SERVER_PUBKEY}" "${WG_CLIENT_PRIVKEY}" "${WG_PRESHARED_KEY}";sleep 3;ping -c 3 -W 5 "${WG_SERVER_IP}" &>/dev/null&&log_info "WireGuard tunnel UP"||log_warn "Tunnel not reachable yet";install_xray;local trojan_password;trojan_password=$(generate_random_hex 32);setup_trojan_inbound "${trojan_password}";local iran_ip;iran_ip=$(get_public_ip);echo "{\"server\":\"${iran_ip}\",\"port\":${TROJAN_PORT},\"password\":\"${trojan_password}\",\"allow_insecure\":true}">"${CONFIG_DIR}/trojan_info.json";setup_traffic_forwarding;configure_firewall_iran;setup_fail2ban;harden_ssh;create_watchdog_service;create_health_check_script;echo -e "${GREEN}${BOLD}✅ Iran Entry Server installed!${NC}";print_connection_details;}
show_banner(){clear;echo -e "${CYAN}";echo "╔═══════════════════════════════════════════╗";echo "║  TUNNEL ENTERPRISE v2.0.0                 ║";echo "║  Enterprise Private Network Platform      ║";echo "╚═══════════════════════════════════════════╝";echo -e "${NC}";}
show_menu(){echo -e "${BOLD}Select an option:${NC}";echo -e "  ${GREEN}1${NC}) Install Foreign Exit Server";echo -e "  ${GREEN}2${NC}) Install Iran Entry Server";echo -e "  ${GREEN}3${NC}) Show Connection Details";echo -e "  ${GREEN}4${NC}) Health Check";echo -e "  ${RED}5${NC}) Uninstall";echo -e "  ${YELLOW}0${NC}) Exit";echo -en "${CYAN}Choice [0-5]: ${NC}";}
main(){mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null||true;touch "${LOG_FILE}" 2>/dev/null||true;show_banner;while true;do show_menu;read -r choice;echo "";case "${choice}" in 1)check_root;install_foreign_server;;2)check_root;install_iran_server;;3)print_connection_details;;4)[[ -x /usr/local/bin/tunnel-health.sh ]]&&/usr/local/bin/tunnel-health.sh||log_warn "Install first";;5)check_root;uninstall_all;;0)echo "Goodbye!";exit 0;;*)log_warn "Invalid: ${choice}";;esac;echo -en "${YELLOW}Press Enter...${NC}";read -r;show_banner;done;}
main "$@"
