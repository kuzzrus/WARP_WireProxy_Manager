#!/usr/bin/env bash
# install-warp-check.sh
# Устанавливает локальную копию warp-wireproxy-native.sh и добавляет cron-задачу
# для проверки WARP и автоматической замены endpoint при поломке.
#
# NOTE: основной способ установки — warpwp --install. Этот файл оставлен
# как отдельный минимальный установщик cron-проверки.

set -Eeuo pipefail

RELEASE_TAG="${WARPWP_RELEASE_TAG:-v1.3.4}"
RELEASE_BASE="https://github.com/kuzzrus/WARP_WireProxy_Manager/releases/download/$RELEASE_TAG"
SCRIPT_URL="$RELEASE_BASE/warp-wireproxy-native.sh"
SELF_URL="$RELEASE_BASE/install-warp-check.sh"
LOCAL_SCRIPT="/usr/local/bin/warp-wireproxy-native.sh"
CRON_FILE="/etc/cron.d/warp-wireproxy-check"
LOG_FILE="/var/log/warp-check.log"
SCAN_COUNT="25"
CRON_SCHEDULE="*/10 * * * *"
LOCK_FILE="/var/lock/warpwp-check.lock"
TIMER_SERVICE_FILE="/etc/systemd/system/warp-wireproxy-check.service"
TIMER_FILE="/etc/systemd/system/warp-wireproxy-check.timer"
TIMER_ENV_FILE="/etc/default/warp-wireproxy-check"

TMP_SCRIPT=""
BACKUP_SCRIPT=""
NATIVE_REPLACED="0"
INSTALL_COMMITTED="0"

log()  { printf '\033[1;36m[ИНФО]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[ОК]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[ВНИМАНИЕ]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[ОШИБКА]\033[0m %s\n' "$*" >&2; }

cleanup() {
  [[ -n "$TMP_SCRIPT" ]] && rm -f -- "$TMP_SCRIPT" 2>/dev/null || true
  [[ -n "$BACKUP_SCRIPT" ]] && rm -f -- "$BACKUP_SCRIPT" 2>/dev/null || true
}

on_exit() {
  local rc=$?

  if [[ "$rc" -ne 0 && "$NATIVE_REPLACED" == "1" && "$INSTALL_COMMITTED" != "1" ]]; then
    if [[ -n "$BACKUP_SCRIPT" && -f "$BACKUP_SCRIPT" ]]; then
      mv -f -- "$BACKUP_SCRIPT" "$LOCAL_SCRIPT" 2>/dev/null || true
      BACKUP_SCRIPT=""
      warn "Ошибка установки: восстановлена предыдущая версия native-скрипта."
    else
      rm -f -- "$LOCAL_SCRIPT" 2>/dev/null || true
    fi
  fi

  cleanup
  exit "$rc"
}
trap on_exit EXIT

validate_scan_count() {
  if ! [[ "$SCAN_COUNT" =~ ^[1-9][0-9]*$ ]]; then
    err "--scan-count должен быть целым числом больше нуля."
    return 1
  fi
}

validate_cron_schedule() {
  local field
  local -a fields=()

  if [[ -z "$CRON_SCHEDULE" || "$CRON_SCHEDULE" == *$'\n'* || "$CRON_SCHEDULE" == *$'\r'* ]]; then
    err "--schedule должен содержать одну строку cron-расписания."
    return 1
  fi

  read -r -a fields <<< "$CRON_SCHEDULE"
  if [[ "${#fields[@]}" -ne 5 ]]; then
    err "--schedule должен содержать ровно 5 cron-полей."
    return 1
  fi

  for field in "${fields[@]}"; do
    if ! [[ "$field" =~ ^[-A-Za-z0-9*/,]+$ ]]; then
      err "Небезопасное cron-поле: $field"
      return 1
    fi
  done

  CRON_SCHEDULE="${fields[*]}"
}

ensure_cron_installed() {
  if command -v cron >/dev/null 2>&1 || command -v crond >/dev/null 2>&1; then
    return 0
  fi

  log "cron/crond не найден, устанавливаю..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y cron
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y cronie
  elif command -v yum >/dev/null 2>&1; then
    yum install -y cronie
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache cronie
  else
    err "cron/crond не найден и пакетный менеджер неизвестен."
    return 1
  fi

  if ! command -v cron >/dev/null 2>&1 && ! command -v crond >/dev/null 2>&1; then
    err "cron/crond не появился после установки пакета."
    return 1
  fi
}

cron_service_name() {
  if command -v cron >/dev/null 2>&1; then
    printf '%s\n' "cron"
  else
    printf '%s\n' "crond"
  fi
}

start_and_verify_cron() {
  local service_name
  service_name="$(cron_service_name)"

  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl enable --now "$service_name.service"
    if ! systemctl is-active --quiet "$service_name.service"; then
      err "$service_name.service не запустился."
      return 1
    fi
  elif command -v rc-service >/dev/null 2>&1; then
    command -v rc-update >/dev/null 2>&1 && rc-update add "$service_name" default >/dev/null 2>&1 || true
    rc-service "$service_name" restart
    rc-service "$service_name" status >/dev/null 2>&1 || {
      err "$service_name не запустился."
      return 1
    }
  elif command -v service >/dev/null 2>&1; then
    command -v update-rc.d >/dev/null 2>&1 && update-rc.d "$service_name" defaults >/dev/null 2>&1 || true
    command -v chkconfig >/dev/null 2>&1 && chkconfig "$service_name" on >/dev/null 2>&1 || true
    service "$service_name" restart
    service "$service_name" status >/dev/null 2>&1 || {
      err "$service_name не запустился."
      return 1
    }
  else
    err "Не найден менеджер служб для запуска cron/crond."
    return 1
  fi
}

remove_project_timer() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl disable --now warp-wireproxy-check.timer >/dev/null 2>&1 || true
    systemctl stop warp-wireproxy-check.service >/dev/null 2>&1 || true
  fi

  rm -f -- "$TIMER_SERVICE_FILE" "$TIMER_FILE" "$TIMER_ENV_FILE"

  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    systemctl reset-failed warp-wireproxy-check.service warp-wireproxy-check.timer >/dev/null 2>&1 || true
    if systemctl is-active --quiet warp-wireproxy-check.timer || systemctl is-active --quiet warp-wireproxy-check.service; then
      err "Не удалось остановить project systemd scheduler."
      return 1
    fi
  fi
}

install_native_script() {
  local target_dir
  target_dir="$(dirname "$LOCAL_SCRIPT")"
  mkdir -p "$target_dir"

  TMP_SCRIPT="$(mktemp "$target_dir/.warp-wireproxy-native.XXXXXX")"
  curl -fsSL "$SCRIPT_URL" -o "$TMP_SCRIPT"
  bash -n "$TMP_SCRIPT"
  chmod 0755 "$TMP_SCRIPT"

  if [[ -e "$LOCAL_SCRIPT" || -L "$LOCAL_SCRIPT" ]]; then
    BACKUP_SCRIPT="$(mktemp "$target_dir/.warp-wireproxy-native.backup.XXXXXX")"
    cp -p -- "$LOCAL_SCRIPT" "$BACKUP_SCRIPT"
  fi

  mv -f -- "$TMP_SCRIPT" "$LOCAL_SCRIPT"
  TMP_SCRIPT=""
  NATIVE_REPLACED="1"
}

usage() {
  cat <<EOF_USAGE
Использование:
  bash $0 [опции]

Опции:
  --scan-count <число>      Сколько endpoint'ов проверять при поломке. По умолчанию: 25
  --schedule "cron"         Расписание cron. По умолчанию: */10 * * * *
  --remove                  Удалить cron-задачу, локальный скрипт не удалять
  -h, --help                Показать справку

Примеры:
  bash $0
  bash $0 --scan-count 40
  bash $0 --schedule "*/5 * * * *"
  bash $0 --remove
EOF_USAGE
}

REMOVE="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan-count)
      [[ $# -ge 2 && -n "$2" ]] || { err "Для --scan-count нужно указать значение."; exit 2; }
      SCAN_COUNT="$2"
      shift 2
      ;;
    --schedule)
      [[ $# -ge 2 && -n "$2" ]] || { err "Для --schedule нужно указать значение."; exit 2; }
      CRON_SCHEDULE="$2"
      shift 2
      ;;
    --remove) REMOVE="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Неизвестная опция: $1"; usage; exit 1 ;;
  esac
done

validate_scan_count
validate_cron_schedule

if [[ "${EUID}" -ne 0 ]]; then
  err "Запусти от root."
  exit 1
fi

if [[ "$REMOVE" == "1" ]]; then
  rm -f "$CRON_FILE"
  systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null || true
  ok "Cron-задача удалена: $CRON_FILE"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y || true
    apt-get install -y curl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl
  else
    err "curl не найден и пакетный менеджер неизвестен."
    exit 1
  fi
fi

ensure_cron_installed

if command -v flock >/dev/null 2>&1; then
  CHECK_CMD="flock -n $LOCK_FILE $LOCAL_SCRIPT --check --scan-count $SCAN_COUNT --enough-good 1"
else
  warn "flock не найден. Cron будет без lock-защиты."
  CHECK_CMD="$LOCAL_SCRIPT --check --scan-count $SCAN_COUNT --enough-good 1"
fi

log "Скачиваю локальную копию warp-wireproxy-native.sh..."
install_native_script
ok "Скрипт установлен: $LOCAL_SCRIPT"

log "Создаю cron-задачу: $CRON_FILE"
cat > "$CRON_FILE" <<EOF_CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

$CRON_SCHEDULE root $CHECK_CMD >> $LOG_FILE 2>&1
EOF_CRON
chmod 0644 "$CRON_FILE"

start_and_verify_cron
remove_project_timer
INSTALL_COMMITTED="1"

ok "Автопроверка WARP установлена."
echo
echo "Локальный скрипт:"
echo "  $LOCAL_SCRIPT"
echo
echo "Cron-файл:"
echo "  $CRON_FILE"
echo
echo "Расписание:"
echo "  $CRON_SCHEDULE"
echo
echo "Лог:"
echo "  $LOG_FILE"
echo
echo "Проверить вручную:"
echo "  $LOCAL_SCRIPT --check --scan-count $SCAN_COUNT"
echo
echo "Посмотреть последние логи:"
echo "  tail -n 80 $LOG_FILE"
echo
echo "Удалить cron-задачу:"
echo "  WARPWP_RELEASE_TAG=$RELEASE_TAG bash <(curl -fsSL $SELF_URL) --remove"
