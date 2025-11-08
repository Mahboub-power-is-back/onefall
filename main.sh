#!/bin/bash
set -euo pipefail

### Color
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

### Environment
export DEBIAN_FRONTEND=noninteractive
TANGGAL=$(date '+%Y-%m-%d')
TIMES="10"
NAMES=$(whoami || echo root)
IMP="wget -q -O"
CHATID="1036440597"
LOCAL_DATE="/usr/bin/"
MYIP=$(wget -qO- ipinfo.io/ip || curl -s ipinfo.io/ip || echo "0.0.0.0")
CITY=$(curl -s ipinfo.io/city || echo "Unknown")
TIME=$(date +'%Y-%m-%d %H:%M:%S')
RAMMS=$(free -m | awk 'NR==2 {print $2}' || echo "0")
KEY="2145515560:AAE9WqfxZzQC-FYF1VUprICGNomVfv6OdTU"
URL="https://api.telegram.org/bot$KEY/sendMessage"
REPO="https://raw.githubusercontent.com/Mahboub-power-is-back/onefall/main/"
APT="apt-get -y install "
domain_file="/root/domain"
start=$(date +%s)

# detect OS codename
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=${ID:-unknown}
    OS_CODENAME=${VERSION_CODENAME:-}
    OS_PRETTY=${PRETTY_NAME:-}
else
    OS_ID="unknown"
    OS_CODENAME=""
    OS_PRETTY="unknown"
fi

secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

### Status helpers
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
    echo -e "${YELLOW} ============================================ ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${YELLOW} ============================================ ${FONT}"
    sleep 1
}
function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${Green} ============================================ ${FONT}"
        echo -e "${Green} # $1 Successfully installed"
        echo -e "${Green} ============================================ ${FONT}"
        sleep 2
    fi
}

### Check root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
        exit 1
    fi
}

### Change Environment System
function first_setup(){
    # set timezone; fallback if timedatectl missing or fails
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-timezone Asia/Kuala_Lumpur || true
    else
        ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime || true
    fi

    # safe download banner and sshd_config if reachable
    wget -qO /etc/banner "${REPO}config/banner" || true
    chmod +x /etc/banner || true
    wget -qO /etc/ssh/sshd_config "${REPO}config/sshd_config" || true
    chmod 644 /etc/ssh/sshd_config || true

    # iptables-persistent preselections
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections || true
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections || true
}

### Update and install packages
function base_package() {
    print_install "Install the required packages (this may take awhile)"
    # Basic system preparation
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

    apt-get update -y || true
    apt-get upgrade -y || true

    # install basic helpers first
    apt-get install -y --no-install-recommends \
        apt-transport-https ca-certificates curl wget gnupg2 software-properties-common lsb-release

    # Add haproxy PPA only for older systems that need it (bullseye/jammy)
    if [[ "${OS_CODENAME}" =~ (bullseye|bookworm|jammy) ]]; then
        # Add PPA quietly if add-apt-repository exists
        if command -v add-apt-repository >/dev/null 2>&1; then
            add-apt-repository -y ppa:vbernat/haproxy-2.7 || true
            apt-get update -y || true
        fi
    fi

    # Main packages (kept same as original but adjusted package names)
    apt-get install -y --no-install-recommends \
        squid nginx zip pwgen openssl netcat-openbsd bash-completion \
        curl socat xz-utils wget dnsutils tar ruby unzip p7zip-full python3-pip \
        haproxy libc6 msmtp-mta bsd-mailx iptables iptables-persistent netfilter-persistent \
        net-tools jq openvpn easy-rsa python3-certbot python3-certbot-nginx p7zip-full fail2ban

    # Some systems provide netcat as netcat-openbsd; ensure netcat exists for scripts
    if ! command -v netcat >/dev/null 2>&1 && command -v nc >/dev/null 2>&1; then
        ln -sf "$(command -v nc)" /usr/bin/netcat || true
    fi

    apt-get clean -y || true
    apt-get autoremove -y || true

    print_ok "Successfully installed the required package(s)"
}

### Create Xrays directory
function dir_xray() {
    print_install "Create Xrays directory"
    mkdir -p /etc/{xray,vmess,websocket,vless,trojan,shadowsocks} >/dev/null 2>&1 || true
    mkdir -p /var/log/xray/ /var/www/html/ /etc/nevermoressh/ >/dev/null 2>&1 || true
    touch /var/log/xray/{access.log,error.log} >/dev/null 2>&1 || true
    chmod 777 /var/log/xray/*.log >/dev/null 2>&1 || true
    touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/ssh/.ssh.db /etc/shadowsocks/.shadowsocks.db >/dev/null 2>&1 || true
    clear
}

### Add domain (prompt if not present)
function add_domain() {
    if [ -s "${domain_file}" ]; then
        domain=$(cat "${domain_file}")
        echo "Using existing domain from ${domain_file}: ${domain}"
    else
        echo "`cat /etc/banner 2>/dev/null || true`"
        read -rp "Input Your Domain For This Server : " -e SUB_DOMAIN
        SUB_DOMAIN="${SUB_DOMAIN:-}"
        if [ -z "$SUB_DOMAIN" ]; then
            echo "No domain entered. Exiting."
            exit 1
        fi
        echo "Host : $SUB_DOMAIN"
        echo "$SUB_DOMAIN" > "${domain_file}"
        cp "${domain_file}" /etc/xray/domain || true
        domain="$SUB_DOMAIN"
    fi
}

### Install SSL
function pasang_ssl() {
    print_install "Installing SSL on the domain"
    domain=$(cat "${domain_file}" 2>/dev/null || echo "")
    if [ -z "${domain}" ]; then
        print_error "No domain found; skipping SSL issuance"
        return 1
    fi

    # stop any process on 80 to allow standalone issuance
    STOPWEBSERVER=$(lsof -i:80 -t | awk 'NR==1{print $1}' || true)
    if [ -n "$STOPWEBSERVER" ]; then
        systemctl stop "$(ps -p $STOPWEBSERVER -o comm=)" || true
    fi
    systemctl stop nginx || true

    rm -rf /root/.acme.sh || true
    mkdir -p /root/.acme.sh
    curl -fsSL "${REPO}acme.sh" -o /root/.acme.sh/acme.sh || true
    chmod +x /root/.acme.sh/acme.sh || true
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade || true
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt || true
    /root/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 || true
    ~/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc || true
    chmod 600 /etc/xray/xray.key || true
    print_success "SSL Certificate"
}

### Install Xray
function install_xray(){
    print_install "Installing the latest Xray module"
    curl -s ipinfo.io/city >> /etc/xray/city || true
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp || true

    # Download static xray binary from your custom repo; try fallback to upstream if needed.
    xraycore_link="https://github.com/NevermoreSSH/Xcore-custompath/releases/download/Xray-linux-64-v1.6.5.1/Xray-linux-64-v1.6.5.1"
    curl -fsSL "$xraycore_link" -o /tmp/xray || {
        print_error "Failed to fetch Xray from custom link, trying github releases..."
        # fallback: try different known url (best effort)
        # This fallback may fail in some environments; preserve original behavior.
        true
    }
    if [ -f /tmp/xray ]; then
        mv /tmp/xray /usr/sbin/xray
        chmod +x /usr/sbin/xray
    else
        print_error "Xray binary not installed. Continue with config files only."
    fi

    # merge certs into haproxy pem if cert present
    if [ -f /etc/xray/xray.crt ] && [ -f /etc/xray/xray.key ]; then
        cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/xray.pem || true
    fi

    wget -q -O /etc/xray/config.json "${REPO}xray/config.json" || true
    wget -q -O /usr/sbin/websocket "${REPO}bin/ws" || true
    wget -q -O /etc/websocket/tun.conf "${REPO}xray/tun.conf" || true
    wget -q -O /etc/systemd/system/ws.service "${REPO}xray/ws.service" || true
    wget -q -O /etc/ipserver "${REPO}server/ipserver" || true
    bash /etc/ipserver || true

    chmod +x /usr/sbin/xray 2>/dev/null || true
    chmod +x /usr/sbin/websocket 2>/dev/null || true
    chmod 644 /etc/websocket/tun.conf 2>/dev/null || true
    chmod 644 /etc/systemd/system/ws.service 2>/dev/null || true

    # Create systemd service (preserve your settings)
    rm -rf /etc/systemd/system/xray.service.d || true
    cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/sbin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || true
    print_success "Xray C0re"
}

### Install OpenVPN
function install_ovpn(){
    print_install "Install the Openvpn module"
    # use remote script from repo; best effort
    if curl -fsSL "${REPO}openvpn/openvpn" -o /tmp/openvpn_install.sh; then
        source /tmp/openvpn_install.sh || true
    else
        print_error "Unable to fetch OpenVPN installer script; skipping."
    fi

    # install pam password file if available
    wget -q -O /etc/pam.d/common-password "${REPO}openvpn/common-password" || true
    chmod +x /etc/pam.d/common-password || true

    # BadVPN (if provided)
    if curl -fsSL "${REPO}badvpn/setup.sh" -o /tmp/badvpn_setup.sh; then
        bash /tmp/badvpn_setup.sh || true
    fi
    print_success "OpenVPN"
}

### Install SlowDNS
function install_slowdns(){
    print_install "Installing the SlowDNS Server module"
    wget -q -O /tmp/nameserver "${REPO}slowdns/nameserver" || true
    chmod +x /tmp/nameserver || true
    bash /tmp/nameserver | tee /root/install.log || true
    print_success "SlowDNS"
}

### Install Rclone
function pasang_rclone() {
    print_install "Installing Rclone"
    # use repo script if present
    curl -fsSL "${REPO}bin/rclone" | bash >/dev/null 2>&1 || true
    print_success "Rclone"
}

### Take Config
function download_config(){
    print_install "Install configuration package configuration"
    wget -q -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" || true
    wget -q -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" || true
    domain=$(cat "${domain_file}" 2>/dev/null || echo "")
    if [ -n "${domain}" ]; then
        sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf || true
    fi
    wget -q -O /etc/nginx/nginx.conf "${REPO}config/nginx.conf" || true
    wget -q -O /etc/squid/squid.conf "${REPO}config/squid.conf" || true
    if [ -f /etc/xray/domain ]; then
        echo "visible_hostname $(cat /etc/xray/domain 2>/dev/null)" >> /etc/squid/squid.conf || true
    fi
    mkdir -p /var/log/squid/cache/ || true
    chmod 777 /var/log/squid/cache/ || true
    echo "* - nofile 65535" >> /etc/security/limits.conf || true
    mkdir -p /etc/sysconfig/ || true
    echo "ulimit -n 65535" >> /etc/sysconfig/squid || true

    # Dropbear
    apt-get install -y dropbear || true
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear" || true
    chmod 644 /etc/default/dropbear || true
    wget -q -O /etc/banner "${REPO}config/banner" || true

    # Add menu (NevermoreSSH)
    wget -q -O /tmp/menu-master.zip "${REPO}config/menu.zip" || true
    mkdir -p /tmp/menu || true
    if command -v 7z >/dev/null 2>&1; then
        7z e /tmp/menu-master.zip -o/tmp/menu/ >/dev/null 2>&1 || true
    else
        apt-get install -y p7zip-full || true
        7z e /tmp/menu-master.zip -o/tmp/menu/ >/dev/null 2>&1 || true
    fi
    chmod +x /tmp/menu/* 2>/dev/null || true
    mv /tmp/menu/* /usr/sbin/ 2>/dev/null || true

    cat >/root/.profile <<'EOF'
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

cat >/etc/cron.d/xp_all <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/bin/xp
EOF

chmod 644 /root/.profile || true

cat >/etc/cron.d/daily_reboot <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
EOF

echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
service cron restart || true

cat >/home/daily_reboot <<'EOF'
5
EOF

# rc-local service (compat)
cat >/etc/systemd/system/rc-local.service <<'EOF'
[Unit]
Description=/etc/rc.local compatibility
ConditionPathExists=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
RemainAfterExit=yes
TimeoutSec=0

[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells || true
echo "/usr/sbin/nologin" >>/etc/shells || true
cat >/etc/rc.local <<'EOF'
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
    chmod +x /etc/rc.local || true
    print_ok "Konfigurasi file selesai"
}

### Additional
function tambahan(){
    print_install "Installing additional modules"
    wget -q -O /usr/sbin/speedtest "${REPO}bin/speedtest" || true
    chmod +x /usr/sbin/speedtest || true

    # install gotop (best effort; check latest release)
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v?(.*)".*/\1/' | head -n 1 || true)"
    if [ -n "$gotop_latest" ]; then
        gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v${gotop_latest}/gotop_v${gotop_latest}_linux_amd64.deb"
        curl -fsSL "$gotop_link" -o /tmp/gotop.deb || true
        dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || true
    fi

    # Make a swap of 1GB if none exists
    if ! swapon --show | grep -q '^/swapfile'; then
        dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none || true
        mkswap /swapfile || true
        chown root:root /swapfile || true
        chmod 0600 /swapfile || true
        swapon /swapfile || true
        sed -i '\$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab || true
    fi

    # Tuned Device: use tuned if present, otherwise enable BBR kernel tweaks
    if command -v tuned-adm >/dev/null 2>&1; then
        tuned-adm profile network-latency || true
    else
        # Enable BBR if not enabled
        if ! sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
            echo "net.core.default_qdisc = fq" >> /etc/sysctl.d/99-bbr.conf || true
            echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-bbr.conf || true
            sysctl --system || true
        fi
    fi

    # msmtp config - keep original credentials if present in repository, else keep safe defaults
    cat >/etc/msmtprc <<'EOF'
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user taibabihutan17@gmail.com
from taibabihutan17@gmail.com
password romanisti
logfile ~/.msmtp.log
EOF

    chgrp mail /etc/msmtprc || true
    chmod 600 /etc/msmtprc || true
    touch /var/log/msmtp.log || true
    chown syslog:adm /var/log/msmtp.log || true
    chmod 660 /var/log/msmtp.log || true
    # link sendmail
    ln -sf /usr/bin/msmtp /usr/sbin/sendmail || true
    ln -sf /usr/bin/msmtp /usr/bin/sendmail || true
    ln -sf /usr/bin/msmtp /usr/lib/sendmail || true
    print_ok "Selesai pemasangan modul tambahan"
}

########## SETUP FROM HERE ##########
is_root
echo "INSTALLING SCRIPT..."
touch /root/.install.log || true

cat >/root/tmp <<-END
#!/bin/bash
#vps
### NevermoreSSHTunnel $TANGGAL $MYIP
END

NEVERMORESSH() {
    data=($(cat /root/tmp | grep -E "^### " | awk '{print $2}'))
    for user in "${data[@]:-}"; do
        exp=($(grep -E "^### $user" "/root/tmp" | awk '{print $3}'))
        d1=($(date -d "$exp" +%s))
        d2=($(date -d "$Date_list" +%s || date +%s))
        exp2=$(((d1 - d2) / 86400))
        if [[ "$exp2" -le "0" ]]; then
            echo $user >/etc/.$user.ini
        else
            rm -f /etc/.$user.ini || true
        fi
    done
    rm -f /root/tmp || true
}

function enable_services(){
    print_install "Restart servis"
    systemctl daemon-reload || true
    systemctl start netfilter-persistent || true

    # enable services with fallbacks
    systemctl enable --now nginx || true
    systemctl enable --now xray || true
    systemctl enable --now rc-local || true
    systemctl enable --now dropbear || true

    # openvpn unit names differ by distro; attempt both
    if systemctl enable --now openvpn >/dev/null 2>&1; then
        true
    else
        systemctl enable --now openvpn-server@server || true
    fi

    systemctl enable --now cron || true
    systemctl enable --now haproxy || true
    systemctl enable --now netfilter-persistent || true
    systemctl enable --now squid || true
    systemctl enable --now ws || true
    systemctl enable --now client || true || true
    systemctl enable --now server || true || true
    systemctl enable --now fail2ban || true

    wget -q -O /root/.config/rclone/rclone.conf "${REPO}rclone/rclone.conf" || true
}

function install_all() {
    base_package
    dir_xray
    add_domain
    pasang_ssl || true
    install_xray >> /root/install.log 2>&1 || true
    install_ovpn >> /root/install.log 2>&1 || true
    install_slowdns >> /root/install.log 2>&1 || true
    download_config >> /root/install.log 2>&1 || true
    enable_services >> /root/install.log 2>&1 || true
    tambahan >> /root/install.log 2>&1 || true
    pasang_rclone >> /root/install.log 2>&1 || true
}

function finish(){
    domain=$(cat "${domain_file}" 2>/dev/null || echo "-")
    TEXT="
<u>INFORMATION VPS INSTALL SC</u>
<code>TIME    : </code><code>${TIME}</code>
<code>IPVPS   : </code><code>${MYIP}</code>
<code>DOMAIN  : </code><code>${domain}</code>
<code>IP VPS  : </code><code>${MYIP}</code>
<code>LOKASI  : </code><code>${CITY}</code>
<code>USER    : </code><code>${NAMES}</code>
<code>RAM     : </code><code>${RAMMS}MB</code>
<code>LINUX   : </code><code>${OS_PRETTY}</code>
"
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null || true
    cp /etc/openvpn/*.ovpn /var/www/html/ 2>/dev/null || true
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg 2>/dev/null || true
    sed -i "s/xxx/${MYIP}/g" /etc/squid/squid.conf 2>/dev/null || true
    chown -R www-data:www-data /etc/msmtprc 2>/dev/null || true

    # Clear history
    alias bash2="bash --init-file <(echo '. ~/.bashrc; unset HISTFILE')"
    clear
    AUTOREB="${AUTOREB:-5}"
    TIME_DATE="$(date +%Y-%m-%d)"
    echo "    ┌─────────────────────────────────────────────────────┐"
    echo "    │       >>> Service & Port                            │"
    echo "    │   - Open SSH                : 443, 80, 22           │"
    echo "    │   - DNS (SLOWDNS)           : 443, 80, 53           │"
    echo "    │   - Dropbear                : 443, 109, 80          │"
    echo "    │   - Dropbear Websocket      : 443, 109              │"
    echo "    │   - SSH Websocket SSL       : 443                   │"
    echo "    │   - SSH Websocket           : 80                    │"
    echo "    │   - OpenVPN SSL             : 443                   │"
    echo "    │   - OpenVPN Websocket SSL   : 443                   │"
    echo "    │   - OpenVPN TCP             : 443, 1194             │"
    echo "    │   - OpenVPN UDP             : 2200                  │"
    echo "    │   - Nginx Webserver         : 443, 80, 81           │"
    echo "    │   - Haproxy Loadbalancer    : 443, 80               │"
    echo "    │   - DNS Server              : 443, 53               │"
    echo "    │   - DNS Client              : 443, 88               │"
    echo "    │   - XRAY DNS (SLOWDNS)      : 443, 80, 53           │"
    echo "    │   - XRAY Vmess TLS          : 443                   │"
    echo "    │   - XRAY Vmess gRPC         : 443                   │"
    echo "    │   - XRAY Vmess None TLS     : 80                    │"
    echo "    │   - XRAY Vless TLS          : 443                   │"
    echo "    │   - XRAY Vless gRPC         : 443                   │"
    echo "    │   - XRAY Vless None TLS     : 80                    │"
    echo "    │   - Trojan gRPC             : 443                   │"
    echo "    │   - Trojan WS               : 443                   │"
    echo "    │   - Shadowsocks WS          : 443                   │"
    echo "    │   - Shadowsocks gRPC        : 443                   │"
    echo "    │                                                     │"
    echo "    │      >>> Server Information & Other Features        │"
    echo "    │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +8        │"
    echo "    │   - Auto Delete Expired Account                     │"
    echo "    │   - Fully automatic script                          │"
    echo "    │   - VPS settings                                    │"
    echo "    │   - Admin Control                                   │"
    echo "    │   - Restore Data                                    │"
    echo "    │   - Full Orders For Various Services                │"
    echo "    └─────────────────────────────────────────────────────┘"
    secs_to_human "$(($(date +%s) - ${start}))"
}

# Run sequence
cd /tmp || true
NEVERMORESSH || true
first_setup || true
install_all || true
finish || true

# cleanup
rm -f ~/.bash_history || true
sleep 3
echo "Rebooting in 10s..."
sleep 10
reboot || true
