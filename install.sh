#!/usr/bin/env bash
# Установщик singbox-panel для Debian/Ubuntu.
# Запускать от root. Безопасно запускать повторно: обновит код, настройки сохранит.
set -euo pipefail

INSTALL_DIR=/opt/singbox-panel
ENV_FILE=/etc/default/singbox-panel
UNIT=/etc/systemd/system/singbox-panel.service
DATA_DIR=/var/lib/singbox-panel
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

P_PORT=8088
P_HOST=0.0.0.0
P_GROUPS=sudo
P_USERS=""
P_CONFIG=/etc/sing-box/config.json
P_SERVICE=""
P_TUN=""
CONFIGURE=0   # 1 = перезаписать /etc/default/singbox-panel
START=1
ACTION=install
PURGE=0

usage() {
  cat <<EOF
Использование: $0 [опции]

  --port N          порт панели (по умолчанию 8088)
  --host ADDR       адрес привязки (по умолчанию 0.0.0.0; можно IP из локальной сети)
  --groups a,b      группы, которым разрешён вход (по умолчанию sudo)
  --users a,b       отдельные пользователи, которым разрешён вход
  --config PATH     путь к конфигу sing-box (по умолчанию /etc/sing-box/config.json)
  --service NAME    имя systemd-службы sing-box (по умолчанию определяется сам)
  --tun NAME        имя TUN-интерфейса (по умолчанию определяется сам)
  --no-start        установить, но не запускать
  --uninstall       удалить панель (настройки и бэкапы остаются)
  --purge           вместе с --uninstall: удалить и $DATA_DIR (бэкапы, подписку)
  -h, --help        эта справка

Без опций повторный запуск обновляет код панели и не трогает ранее заданные настройки.
Если передана хотя бы одна опция настройки, файл $ENV_FILE создаётся заново.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port)      P_PORT="${2:?}"; CONFIGURE=1; shift 2 ;;
    --host)      P_HOST="${2:?}"; CONFIGURE=1; shift 2 ;;
    --groups)    P_GROUPS="${2:?}"; CONFIGURE=1; shift 2 ;;
    --users)     P_USERS="${2:?}"; CONFIGURE=1; shift 2 ;;
    --config)    P_CONFIG="${2:?}"; CONFIGURE=1; shift 2 ;;
    --service)   P_SERVICE="${2:?}"; CONFIGURE=1; shift 2 ;;
    --tun)       P_TUN="${2:?}"; CONFIGURE=1; shift 2 ;;
    --no-start)  START=0; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    --purge)     PURGE=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "Неизвестная опция: $1" >&2; usage; exit 1 ;;
  esac
done

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }
STEP=0; STEPS=6
step() {   # прогресс установки: [#####-----] 3/6 текст
  STEP=$((STEP + 1)); local w=20 f=$((STEP * 20 / STEPS)) bar
  bar="$(printf '%*s' "$f" '' | tr ' ' '#')$(printf '%*s' "$((w - f))" '' | tr ' ' '-')"
  printf '\033[1;32m[%s]\033[0m %d/%d  %s\n' "$bar" "$STEP" "$STEPS" "$*"
}

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo $0)"
command -v systemctl >/dev/null || die "нужен systemd"

# ------------------------------------------------------------------ удаление
if [ "$ACTION" = uninstall ]; then
  log "Останавливаю и удаляю службу"
  systemctl disable --now singbox-panel 2>/dev/null || true
  rm -f "$UNIT" "$ENV_FILE" /usr/local/bin/singbox-panel
  rm -rf "$INSTALL_DIR"
  systemctl daemon-reload
  if [ "$PURGE" -eq 1 ]; then rm -rf "$DATA_DIR"; log "Данные $DATA_DIR удалены"; else log "Данные оставлены в $DATA_DIR (--purge удалит)"; fi
  log "Готово"
  exit 0
fi

# ------------------------------------------------------------------ установка
[ -f "$SRC/app.py" ] && [ -f "$SRC/index.html" ] || die "рядом со скриптом нет app.py и index.html"

step "Устанавливаю зависимости (python3, PAM)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 libpam0g iproute2 >/dev/null

step "Копирую файлы в $INSTALL_DIR"
install -d -m 755 "$INSTALL_DIR"
install -m 644 "$SRC/app.py" "$SRC/index.html" "$INSTALL_DIR/"

# файл настроек
step "Настройки $ENV_FILE"
if [ "$CONFIGURE" -eq 1 ] || [ ! -f "$ENV_FILE" ]; then
  if [ -z "$P_SERVICE" ]; then
    P_SERVICE="$(systemctl list-unit-files --no-legend 'sing-box*.service' 2>/dev/null | awk 'NR==1{sub(/\.service$/,"",$1); print $1}')"
    P_SERVICE="${P_SERVICE:-sing-box}"
  fi
  log "Записываю новые настройки"
  {
    echo "SBP_PORT=$P_PORT"
    echo "SBP_HOST=$P_HOST"
    echo "SBP_CONFIG=$P_CONFIG"
    echo "SBP_SERVICE=$P_SERVICE"
    echo "SBP_GROUPS=$P_GROUPS"
    [ -n "$P_USERS" ] && echo "SBP_USERS=$P_USERS"
    [ -n "$P_TUN" ] && echo "SBP_TUN=$P_TUN"
  } > "$ENV_FILE"
  chmod 644 "$ENV_FILE"
else
  log "Оставляю существующие настройки $ENV_FILE"
fi

cat > /usr/local/bin/singbox-panel <<EOF
#!/bin/sh
[ \$# -gt 0 ] || { echo "singbox-panel lan on|off|status | gateway off | proxy remove"; exit 2; }
set -a; [ -r $ENV_FILE ] && . $ENV_FILE; set +a
exec /usr/bin/python3 -I $INSTALL_DIR/app.py "\$@"
EOF
chmod 755 /usr/local/bin/singbox-panel

step "PAM-служба для входа в панель"
if [ ! -f /etc/pam.d/singbox-panel ] && [ -f /etc/pam.d/common-auth ]; then
  printf '%s\n' '# PAM-служба singbox-panel (без pam_securetty из login)' '@include common-auth' '@include common-account' > /etc/pam.d/singbox-panel
fi

step "Устанавливаю systemd-юнит"
cat > "$UNIT" <<EOF
[Unit]
Description=sing-box web panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=-$ENV_FILE
ExecStart=/usr/bin/python3 -I $INSTALL_DIR/app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

step "Запускаю панель"
if [ "$START" -eq 1 ]; then
  systemctl enable singbox-panel >/dev/null 2>&1
  systemctl restart singbox-panel
  sleep 1.5
  systemctl is-active --quiet singbox-panel || { journalctl -u singbox-panel -n 20 --no-pager; die "панель не запустилась"; }
fi

# ------------------------------------------------------------------ проверки
set -a; . "$ENV_FILE"; set +a
command -v sing-box >/dev/null || log "sing-box пока не установлен: при первом входе в панель мастер предложит его поставить"
[ -f "${SBP_CONFIG:-$P_CONFIG}" ] || warn "конфиг ${SBP_CONFIG:-$P_CONFIG} не найден. Проверьте SBP_CONFIG в $ENV_FILE"
[ -f /etc/pam.d/login ] || [ -f /etc/pam.d/singbox-panel ] || warn "нет /etc/pam.d/login. Задайте SBP_PAM_SERVICE в $ENV_FILE"

log "Готово. Панель доступна по адресам:"
for ip in $(hostname -I 2>/dev/null); do echo "    http://$ip:${SBP_PORT:-8088}"; done
echo
echo "Вход: системный логин и пароль (группы: ${SBP_GROUPS:-sudo}${SBP_USERS:+, пользователи: $SBP_USERS})."
echo "Настройки: $ENV_FILE (после правки: systemctl restart singbox-panel)"
echo "Логи:      journalctl -u singbox-panel -f"
