#!/bin/bash

# ==========================================================================
# ФИНАЛЬНЫЙ СКРИПТ: Docker Website + Xray (VLESS+Reality) + Hysteria2 + Security
# Версия 3.0 | Идемпотентный, безопасный, production-ready
# ==========================================================================

set -euo pipefail
trap 'echo "Ошибка в строке $LINENO. Команда: $BASH_COMMAND"; exit 1' ERR

# --- КОНСТАНТЫ И НАСТРОЙКИ ---
readonly SWAP_SIZE="1G"
readonly PROJECT_DIR="/root/server-setup"
readonly CONFIG_DIR="${PROJECT_DIR}/configs"
readonly WEBSITE_DIR="${PROJECT_DIR}/website"
readonly BACKUP_DIR="${PROJECT_DIR}/backups/$(date +%Y%m%d-%H%M%S)"
readonly LOG_FILE="/var/log/server-setup-$(date +%Y%m%d-%H%M%S).log"

# --- ИНТЕРАКТИВНЫЕ ПАРАМЕТРЫ ---
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           НАСТРОЙКА СЕРВЕРА (PRODUCTION-READY)           ║"
echo "╚══════════════════════════════════════════════════════════╝"

read -p "Введите домен (example.com): " DOMAIN
read -p "Введите Email для сертификатов: " EMAIL
read -p "GitHub URL сайта (оставьте пустым, если не нужно): " GITHUB_REPO_URL

# Порт для Hysteria2 (не 443, чтобы не конфликтовать с Xray)
read -p "Порт для Hysteria2 [38271]: " HYSTERIA_PORT_INPUT
HYSTERIA_PORT=${HYSTERIA_PORT_INPUT:-38271}

# Выбор протокола для Xray
echo -e "\nПротокол для Xray:"
echo "1) VLESS + TLS (стандартный)"
echo "2) VLESS + Reality (рекомендуется)"
read -p "Выберите [1/2]: " -n 1 XRAY_PROTOCOL_CHOICE
echo

# Проверка root
if [[ $EUID -ne 0 ]]; then
    echo "❌ Запустите скрипт от root (sudo)" >&2
    exit 1
fi

# Создание директорий
mkdir -p "$CONFIG_DIR" "$WEBSITE_DIR" "$BACKUP_DIR"

# --- ЛОГИРОВАНИЕ ---
exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo -e "\033[1;32m[$(date '+%Y-%m-%d %H:%M:%S')] ▶ $*\033[0m"; }
warn() { echo -e "\033[1;33m[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ $*\033[0m"; }
error() { echo -e "\033[1;31m[$(date '+%Y-%m-%d %H:%M:%S')] ✗ $*\033[0m"; exit 1; }

# --- ФУНКЦИИ ПОМОЩНИКИ ---
backup_config() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${BACKUP_DIR}/$(basename "$file").backup-$(date +%s)"
        log "Бэкап создан: $file"
    fi
}

check_port() {
    local port="$1"
    local protocol="${2:-tcp}"
    
    case $protocol in
        tcp) if ss -ltn | grep -q ":${port} "; then return 1; fi ;;
        udp) if ss -lun | grep -q ":${port} "; then return 1; fi ;;
    esac
    return 0
}

add_sysctl() {
    local key_val="$1"
    if ! grep -qF "$key_val" /etc/sysctl.conf; then
        echo "$key_val" >> /etc/sysctl.conf
        log "Добавлено в sysctl: $key_val"
    fi
}

add_cron_job() {
    local job="$1"
    if ! (crontab -l 2>/dev/null | grep -F "$job" >/dev/null); then
        (crontab -l 2>/dev/null; echo "$job") | crontab -
        log "Добавлена задача в cron"
    fi
}

# --- НАЧАЛО УСТАНОВКИ ---
log "=== НАЧАЛО УСТАНОВКИ СЕРВЕРА ==="

# 1. ОБНОВЛЕНИЕ СИСТЕМЫ
log "1. Обновление системы и установка пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y
apt-get install -y \
    curl git unzip ufw socat htop nano cron \
    software-properties-common bc jq acl \
    systemd-timesyncd fail2ban prometheus-node-exporter \
    docker.io docker-compose-plugin

# Настройка времени
timedatectl set-timezone Europe/Moscow
systemctl enable --now systemd-timesyncd

# 2. СИСТЕМНЫЕ ОПТИМИЗАЦИИ
log "2. Настройка оптимизаций ядра и swap..."
add_sysctl "net.core.default_qdisc=fq"
add_sysctl "net.ipv4.tcp_congestion_control=bbr"
add_sysctl "vm.swappiness=10"
add_sysctl "vm.vfs_cache_pressure=50"
add_sysctl "net.core.rmem_max=67108864"
add_sysctl "net.core.wmem_max=67108864"
add_sysctl "net.ipv4.tcp_rmem=4096 87380 67108864"
add_sysctl "net.ipv4.tcp_wmem=4096 65536 67108864"
sysctl -p

# Swap файл
if [[ ! -f /swapfile ]]; then
    log "Создание swap файла ${SWAP_SIZE}..."
    fallocate -l "${SWAP_SIZE}" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi

# 3. БАЗОВАЯ БЕЗОПАСНОСТЬ
log "3. Настройка базовой безопасности..."

# UFW
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP (Certbot)'
ufw allow 443/tcp comment 'HTTPS (Xray)'
ufw allow "${HYSTERIA_PORT}"/udp comment 'Hysteria2'
ufw allow 9100/tcp comment 'Node Exporter'
ufw limit 22/tcp comment 'SSH brute-force protection'
ufw --force enable

# Fail2ban базовая настройка
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600

[sshd-ddos]
enabled = true
maxretry = 10
bantime = 86400
EOF

systemctl enable --now fail2ban

# 4. ПОЛУЧЕНИЕ SSL СЕРТИФИКАТОВ
log "4. Получение SSL сертификатов..."

# Проверка доступности домена
if ! dig +short "$DOMAIN" &>/dev/null; then
    warn "Домен $DOMAIN не резолвится. Продолжаем, но сертификат может не выдавться."
fi

# Установка certbot если нет
if ! command -v certbot &>/dev/null; then
    apt-get install -y certbot python3-certbot-nginx
fi

# Остановка сервисов, занимающих 80 порт
systemctl stop nginx xray hysteria-server 2>/dev/null || true

# Получение сертификата
if [[ ! -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
    if certbot certonly --standalone --preferred-challenges http \
        -d "${DOMAIN}" --email "${EMAIL}" --agree-tos --non-interactive; then
        log "Сертификат успешно получен"
    else
        error "Не удалось получить сертификат. Проверьте домен и сеть."
    fi
fi

# Создание пользователя для VPN сервисов
if ! id -u vpnuser &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -M vpnuser
fi

# Права доступа
setfacl -R -m u:vpnuser:rx /etc/letsencrypt/live
setfacl -R -m u:vpnuser:rx /etc/letsencrypt/archive

# 5. УСТАНОВКА И НАСТРОЙКА XRAY
log "5. Установка и настройка Xray..."

# Генерация UUID
XRAY_UUID=$(cat /proc/sys/kernel/random/uuid)

# Установка Xray
if [[ ! -f "/usr/local/bin/xray" ]]; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

backup_config "/usr/local/etc/xray/config.json"

# Конфиг в зависимости от выбора протокола
if [[ "$XRAY_PROTOCOL_CHOICE" == "2" ]]; then
    # VLESS + Reality
    XRAY_PRIVATE_KEY=$(/usr/local/bin/xray x25519 | awk '/Private/{print $3}')
    XRAY_PUBLIC_KEY=$(/usr/local/bin/xray x25519 | awk '/Public/{print $3}')
    XRAY_SHORT_ID=$(openssl rand -hex 8)
    
    cat > "/usr/local/etc/xray/config.json" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "tag": "vless-in",
    "settings": {
      "clients": [{
        "id": "$XRAY_UUID",
        "flow": "xtls-rprx-vision"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "www.google.com:443",
        "serverNames": ["www.google.com", "$DOMAIN"],
        "privateKey": "$XRAY_PRIVATE_KEY",
        "shortIds": ["$XRAY_SHORT_ID"]
      }
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls"]
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "tag": "direct"
  }, {
    "protocol": "blackhole",
    "tag": "blocked"
  }]
}
EOF
    log "Xray настроен с Reality протоколом"
else
    # VLESS + TLS (стандартный)
    cat > "/usr/local/etc/xray/config.json" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "tag": "vless-in",
    "settings": {
      "clients": [{
        "id": "$XRAY_UUID",
        "flow": "xtls-rprx-vision"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "$DOMAIN",
        "alpn": ["h2", "http/1.1"],
        "certificates": [{
          "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
          "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        }]
      }
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls"]
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "tag": "direct"
  }, {
    "protocol": "blackhole",
    "tag": "blocked"
  }]
}
EOF
    log "Xray настроен с TLS протоколом"
fi

# Создание лог директории
mkdir -p /var/log/xray
chown -R nobody:nogroup /var/log/xray

# Systemd service для Xray
cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

# 6. УСТАНОВКА И НАСТРОЙКА HYSTERIA2
log "6. Установка и настройка Hysteria2..."

# Проверка порта
if ! check_port "$HYSTERIA_PORT" udp; then
    error "Порт $HYSTERIA_PORT/UDP уже занят. Выберите другой порт."
fi

# Установка
if [[ ! -f "/usr/local/bin/hysteria" ]]; then
    bash <(curl -fsSL https://get.hy2.sh/)
fi

# Генерация пароля
HY_PASSWORD=$(openssl rand -base64 16)

backup_config "/etc/hysteria/config.yaml" 2>/dev/null || true

cat > "/etc/hysteria/config.yaml" << EOF
listen: :$HYSTERIA_PORT
tls:
  cert: /etc/letsencrypt/live/${DOMAIN}/fullchain.pem
  key: /etc/letsencrypt/live/${DOMAIN}/privkey.pem
auth:
  type: password
  password: $HY_PASSWORD
masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:80/
    rewriteHost: true
bandwidth:
  up: 1 gbps
  down: 1 gbps
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
ignoreClientBandwidth: false
disableUDP: false
udpIdleTimeout: 60s
resolver:
  type: udp
  tcp:
    addr: 8.8.8.8:53
    timeout: 4s
  udp:
    addr: 8.8.8.8:53
    timeout: 4s
  tls:
    addr: 1.1.1.1:853
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false
  https:
    addr: 1.1.1.1:443
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false
EOF

chown -R vpnuser:vpnuser /etc/hysteria
chmod 600 /etc/hysteria/config.yaml

# Systemd сервис
cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria2 Server
After=network.target
Requires=network.target

[Service]
Type=simple
User=vpnuser
Group=vpnuser
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# 7. ДЕПЛОЙ САЙТА (DOCKER)
log "7. Деплой сайта из Docker..."

# Создание docker-сети если не существует
if ! docker network ls | grep -q webnet; then
    docker network create webnet
fi

if [[ -n "$GITHUB_REPO_URL" ]]; then
    if [[ -d "$WEBSITE_DIR/.git" ]]; then
        log "Сайт уже существует, обновляем..."
        cd "$WEBSITE_DIR" && git pull && cd - >/dev/null
    else
        git clone "$GITHUB_REPO_URL" "$WEBSITE_DIR"
    fi
    
    if [[ -f "${WEBSITE_DIR}/docker-compose.yml" ]]; then
        cd "$WEBSITE_DIR"
        
        # Проверяем порт сайта в docker-compose.yml
        if grep -q "ports:" "${WEBSITE_DIR}/docker-compose.yml"; then
            log "Запускаем docker-compose..."
            docker compose up -d --build --remove-orphans
            
            # Проверяем, что контейнер запустился
            sleep 5
            if docker compose ps | grep -q "Up"; then
                log "Docker контейнер успешно запущен"
            else
                warn "Docker контейнер возможно не запустился. Проверьте логи."
            fi
        else
            warn "Не найден блок ports в docker-compose.yml. Убедитесь, что сайт слушает порт 80."
        fi
        cd - >/dev/null
    else
        warn "Файл docker-compose.yml не найден. Сайт не будет запущен в Docker."
    fi
fi

# 8. НАСТРОЙКА ОБНОВЛЕНИЯ СЕРТИФИКАТОВ
log "8. Настройка автоматического обновления сертификатов..."

# Создание скрипта для обновления сертификатов
cat > /usr/local/bin/update-certs.sh << 'EOF'
#!/bin/bash
set -e

echo "[$(date)] Начало обновления сертификатов"

# Останавливаем сервисы
systemctl stop xray hysteria-server

# Обновляем сертификаты
if certbot renew --quiet --standalone; then
    echo "[$(date)] Сертификаты успешно обновлены"
    
    # Перезапускаем сервисы
    systemctl start xray hysteria-server
    
    # Перезапускаем Docker контейнеры если есть
    if [ -f /root/server-setup/website/docker-compose.yml ]; then
        cd /root/server-setup/website
        docker compose restart
    fi
    
    echo "[$(date)] Все сервисы перезапущены"
else
    echo "[$(date)] Ошибка при обновлении сертификатов" >&2
    # Возвращаем сервисы
    systemctl start xray hysteria-server
    exit 1
fi
EOF

chmod +x /usr/local/bin/update-certs.sh

# Добавляем в cron
add_cron_job "0 3 * * * /usr/local/bin/update-certs.sh"

# 9. УСИЛЕНИЕ БЕЗОПАСНОСТИ SSH
log "9. Настройка безопасности SSH..."

backup_config "/etc/ssh/sshd_config"

# Проверяем наличие SSH ключей
if [[ -f /root/.ssh/authorized_keys && -s /root/.ssh/authorized_keys ]]; then
    log "SSH ключи найдены, отключаем вход по парню..."
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.new
    
    # Настройки безопасности SSH
    sed -i 's/^#Port 22/Port 22/' /etc/ssh/sshd_config.new
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config.new
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config.new
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config.new
    sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config.new
    sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config.new
    sed -i 's/^#UsePAM.*/UsePAM no/' /etc/ssh/sshd_config.new
    sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config.new
    sed -i 's/^#ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config.new
    sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config.new
    sed -i 's/^#LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config.new
    
    # Валидация конфига перед применением
    if sshd -t -f /etc/ssh/sshd_config.new; then
        mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
        systemctl restart ssh
        log "SSH безопасно настроен"
    else
        warn "Ошибка в конфигурации SSH, откат изменений"
        rm -f /etc/ssh/sshd_config.new
    fi
else
    warn "SSH ключи не найдены! Вход по парню оставлен включенным."
    warn "Добавьте SSH ключи в /root/.ssh/authorized_keys и перезапустите скрипт."
fi

# 10. ЗАПУСК СЕРВИСОВ
log "10. Запуск всех сервисов..."

systemctl daemon-reload
systemctl enable --now xray hysteria-server prometheus-node-exporter

# Проверка статусов
sleep 2

echo -e "\n╔══════════════════════════════════════════════════════════╗"
echo "║                    СТАТУС СЕРВИСОВ                     ║"
echo "╚══════════════════════════════════════════════════════════╝"

check_service() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        echo -e "  ✅ $service: \033[1;32mACTIVE\033[0m"
    else
        echo -e "  ❌ $service: \033[1;31mFAILED\033[0m"
        journalctl -u "$service" -n 10 --no-pager
    fi
}

check_service xray
check_service hysteria-server
check_service fail2ban
check_service prometheus-node-exporter

# 11. ФИНАЛЬНЫЙ ВЫВОД ИНФОРМАЦИИ
log "=== УСТАНОВКА ЗАВЕРШЕНА ==="

# Получение публичного IP
PUBLIC_IP=$(curl -s -4 ifconfig.co || curl -s -4 icanhazip.com || echo "не определён")

echo -e "\n╔══════════════════════════════════════════════════════════╗"
echo "║                    ИНФОРМАЦИЯ ДЛЯ КЛИЕНТОВ                ║"
echo "╚══════════════════════════════════════════════════════════╝"

echo -e "\n📡 \033[1;36mОСНОВНЫЕ ДАННЫЕ:\033[0m"
echo "  • Сервер: $PUBLIC_IP"
echo "  • Домен: $DOMAIN"

echo -e "\n🔐 \033[1;36mXRAY (VLESS):\033[0m"
echo "  • UUID: $XRAY_UUID"
echo "  • Порт: 443 (TCP)"
if [[ "$XRAY_PROTOCOL_CHOICE" == "2" ]]; then
    echo "  • Протокол: Reality"
    echo "  • Public Key: $XRAY_PUBLIC_KEY"
    echo "  • Short ID: $XRAY_SHORT_ID"
else
    echo "  • Протокол: TLS"
fi
echo "  • Flow: xtls-rprx-vision"

echo -e "\n⚡ \033[1;36mHYSTERIA2:\033[0m"
echo "  • Пароль: $HY_PASSWORD"
echo "  • Порт: $HYSTERIA_PORT (UDP)"
echo "  • SNI: $DOMAIN"

echo -e "\n🌐 \033[1;36mВЕБ-САЙТ:\033[0m"
echo "  • URL: https://$DOMAIN"
if [[ -n "$GITHUB_REPO_URL" ]]; then
    echo "  • Репозиторий: $GITHUB_REPO_URL"
fi

echo -e "\n🛡️  \033[1;36mБЕЗОПАСНОСТЬ:\033[0m"
echo "  • Fail2ban: активен"
echo "  • SSH защита: включена"
echo "  • Мониторинг: http://$PUBLIC_IP:9100/metrics"

echo -e "\n📋 \033[1;36mКОМАНДЫ ДЛЯ ПРОВЕРКИ:\033[0m"
echo "  • Статус сервисов: systemctl status xray hysteria-server"
echo "  • Логи Xray: journalctl -u xray -f"
echo "  • Логи Hysteria: journalctl -u hysteria-server -f"
echo "  • Проверить порты: ss -tulpn | grep -E '(443|$HYSTERIA_PORT)'"

echo -e "\n⚠️  \033[1;33mВАЖНО:\033[0m"
echo "  • Сохраните UUID и пароль в безопасном месте!"
echo "  • Добавьте SSH ключ для доступа к серверу"
echo "  • Логи установки: $LOG_FILE"
echo "  • Бэкапы конфигов: $BACKUP_DIR"

echo -e "\n\033[1;32m✅ Настройка сервера успешно завершена!\033[0m\n"
