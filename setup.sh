#!/bin/bash

# ==========================================================================
# Скрипт автоматической настройки сервера (VPN + Docker Website + Security)
# GitHub-ready version
# ==========================================================================

# Строгий режим
set -euo pipefail
trap 'echo "Ошибка в строке $LINENO. Скрипт прерван."; exit 1' ERR

# --- ИНТЕРАКТИВНЫЕ НАСТРОЙКИ ---
echo "--- Настройка параметров сервера ---"
read -p "Введите домен (например, example.com): " DOMAIN
read -p "Введите ваш Email для SSL (например, admin@gmail.com): " EMAIL
read -p "Введите URL репозитория с сайтом (GitHub): " GITHUB_REPO_URL

# Константы путей
SWAP_SIZE="1G"
PROJECT_DIR="/root/server-setup"
CONFIG_DIR="${PROJECT_DIR}/configs"
WEBSITE_DIR="${PROJECT_DIR}/website"

# Создание необходимых директорий
mkdir -p "$CONFIG_DIR" "$WEBSITE_DIR"

# Журналирование
LOG_FILE="/var/log/server-setup-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# --- ФУНКЦИИ-ПОМОЩНИКИ ---
log() {
    echo -e "\033[1;32m[$(date '+%Y-%m-%d %H:%M:%S')] $*\033[0m"
}

warn() {
    echo -e "\033[1;33m[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️ $*\033[0m"
}

error() {
    echo -e "\033[1;31m[$(date '+%Y-%m-%d %H:%M:%S')] ❌ $*\033[0m"
    exit 1
}

add_cron_if_not_exists() {
    local job="$1"
    crontab -l 2>/dev/null | grep -F "$job" >/dev/null || {
        (crontab -l 2>/dev/null; echo "$job") | crontab -
        log "Задание cron добавлено"
    }
}

# Проверка root
if [ "$EUID" -ne 0 ]; then 
    error "Запустите скрипт от root: sudo $0"
fi

log "=== НАЧАЛО УСТАНОВКИ ==="
log "Логирование в $LOG_FILE"

# --- 1. ОБНОВЛЕНИЕ И ЗАВИСИМОСТИ ---
log "Обновление системы и установка пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y
apt-get install -y curl git unzip ufw socat htop nano cron \
    software-properties-common bc jq yamllint acl systemd-timesyncd

# Настройка времени
timedatectl set-timezone Europe/Moscow
systemctl enable --now systemd-timesyncd

# --- 2. СИСТЕМНЫЕ ОПТИМИЗАЦИИ ---
log "Настройка BBR и Swap..."

# BBR
if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    log "BBR включен"
fi

# Swap
if [ ! -f /swapfile ]; then
    log "Создание swap файла ${SWAP_SIZE}..."
    fallocate -l "${SWAP_SIZE}" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024
    chmod 600 /swapfile
    mkswap /swapfile && swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
    
    # Оптимизация работы с памятью
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
    sysctl -p
fi

# --- 3. БЕЗОПАСНОСТЬ (UFW) ---
log "Настройка фаервола UFW..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 443/udp comment 'Hysteria2'
ufw limit 22/tcp comment 'SSH-protection'
ufw --force enable

# Создание пользователя для VPN
if ! id -u vpnuser >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -M vpnuser
fi

# --- 4. УСТАНОВКА VPN (Xray & Hysteria2) ---
log "Установка VPN сервисов..."

# Xray
if [ ! -f "/usr/local/bin/xray" ]; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

# Hysteria2
if [ ! -f "/usr/local/bin/hysteria" ]; then
    bash <(curl -fsSL https://get.hy2.sh/)
fi

# Создание конфига Hysteria2
cat > "${CONFIG_DIR}/hysteria.yaml" << EOF
listen: :38271
tls:
  cert: /etc/letsencrypt/live/${DOMAIN}/fullchain.pem
  key: /etc/letsencrypt/live/${DOMAIN}/privkey.pem
auth:
  type: password
  password: $(openssl rand -base64 16) # Генерируем случайный пароль
masquerade:
  type: proxy
  proxy:
    url: https://127.0.0.1:8443/
    rewriteHost: true
EOF

# Настройка прав для конфигов
mkdir -p /usr/local/etc/xray /etc/hysteria
cp "${CONFIG_DIR}/hysteria.yaml" /etc/hysteria/config.yaml
chown -R vpnuser:vpnuser /usr/local/etc/xray /etc/hysteria
chmod 600 /etc/hysteria/config.yaml

# Создание Systemd сервиса для Hysteria (с ограничением прав)
cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
User=vpnuser
Group=vpnuser
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=always
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray hysteria-server

# --- 5. SSL СЕРТИФИКАТЫ ---
log "Получение SSL сертификата..."
apt-get install -y certbot

if [ ! -d "/etc/letsencrypt/live/${DOMAIN}" ]; then
    systemctl stop xray hysteria-server || true
    certbot certonly --standalone --preferred-challenges http \
        -d "${DOMAIN}" --email "${EMAIL}" --agree-tos --non-interactive
    systemctl start xray hysteria-server || true
fi

# Права доступа для vpnuser к сертификатам
setfacl -R -m u:vpnuser:rx /etc/letsencrypt/live
setfacl -R -m u:vpnuser:rx /etc/letsencrypt/archive

# Автопродление
add_cron_if_not_exists "0 3 * * * /usr/bin/certbot renew --quiet --deploy-hook \"systemctl restart xray hysteria-server\""

# --- 6. УСТАНОВКА DOCKER & WEBSITE ---
log "Настройка Docker и сайта..."
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh && rm get-docker.sh
fi

if [ -n "$GITHUB_REPO_URL" ]; then
    rm -rf "${WEBSITE_DIR}"/* 2>/dev/null || true
    git clone "$GITHUB_REPO_URL" "$WEBSITE_DIR"
    
    if [ -f "${WEBSITE_DIR}/docker-compose.yml" ]; then
        cd "$WEBSITE_DIR"
        docker compose up -d --build
        cd -
    fi
fi

# --- 7. HARDENING SSH ---
log "Усиление защиты SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

if sshd -t; then
    systemctl restart ssh
else
    warn "Ошибка в конфиге SSH, восстановление..."
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    systemctl restart ssh
fi

# --- 8. ФИНАЛ ---
PUBLIC_IP=$(curl -s -4 ifconfig.co || echo "не определён")

log "=========================================="
log "   НАСТРОЙКА ЗАВЕРШЕНА! 🚀"
log "   IP сервера: $PUBLIC_IP"
log "   Домен: $DOMAIN"
log "   Пароль Hysteria (сгенерирован): $(grep 'password:' /etc/hysteria/config.yaml | awk '{print $2}')"
log "   Лог файл: $LOG_FILE"
log "=========================================="
warn "УБЕДИТЕСЬ, ЧТО ВЫ ДОБАВИЛИ SSH-КЛЮЧ, ТАК КАК ВХОД ПО ПАРОЛЮ ОТКЛЮЧЕН!"
