#!/usr/bin/env bash
# install-warp-check.sh
# Устанавливает локальную копию warp-wireproxy-native.sh и добавляет cron-задачу
# для проверки WARP и автоматической замены endpoint при поломке.
#
# NOTE: основной способ установки — warpwp --install. Этот файл оставлен
# как отдельный минимальный установщик cron-проверки.

set -Eeuo pipefail

RELEASE_TAG="${WARPWP_RELEASE_TAG:-v1.3.9}"
RELEASE_BASE="https://github.com/kuzzrus/WARP_WireProxy_Manager/releases/download/$RELEASE_TAG"
SCRIPT_URL="$RELEASE_BASE/warp-wireproxy-native.sh"
SELF_URL="$RELEASE_BASE/install-warp-check.sh"
MANIFEST_URL="$RELEASE_BASE/SHA256SUMS"
SIGNATURE_URL="$RELEASE_BASE/SHA256SUMS.sig"
RELEASE_SIGNING_ID="warpwp-release"
RELEASE_SIGNING_NAMESPACE="warpwp-release"
RELEASE_SIGNING_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEa+mDJ1BJ6w2YdAogupkcdL8MJLo2XjMJlPT9WyQyA3"
LOCAL_SCRIPT="${WARPWP_LOCAL_SCRIPT:-/usr/local/bin/warp-wireproxy-native.sh}"
CRON_FILE="${WARPWP_CRON_FILE:-/etc/cron.d/warp-wireproxy-check}"
LOG_FILE="${WARPWP_LOG_FILE:-/var/log/warp-check.log}"
SCAN_COUNT="25"
CRON_SCHEDULE="*/10 * * * *"
LOCK_FILE="${WARPWP_CHECK_LOCK_FILE:-/var/lock/warpwp-check.lock}"
ADMIN_LOCK_FILE="${WARPWP_ADMIN_LOCK_FILE:-/var/lock/warpwp-admin.lock}"
ADMIN_LOCK_TIMEOUT="${WARPWP_ADMIN_LOCK_TIMEOUT:-30}"
TIMER_SERVICE_FILE="${WARPWP_TIMER_SERVICE_FILE:-/etc/systemd/system/warp-wireproxy-check.service}"
TIMER_FILE="${WARPWP_TIMER_FILE:-/etc/systemd/system/warp-wireproxy-check.timer}"
TIMER_ENV_FILE="${WARPWP_TIMER_ENV_FILE:-/etc/default/warp-wireproxy-check}"

TMP_SCRIPT=""
BACKUP_SCRIPT=""
NATIVE_REPLACED="0"
INSTALL_COMMITTED="0"
VERIFY_DIR=""
SCHEDULER_BACKUP_DIR=""
SCHEDULER_TRANSACTION_ACTIVE="0"
SCHEDULER_CRON_SERVICE=""
SCHEDULER_CRON_ACTIVE="0"
SCHEDULER_CRON_ENABLED="0"
SCHEDULER_TIMER_ACTIVE="0"
SCHEDULER_TIMER_ENABLED="0"
SCHEDULER_TIMER_SERVICE_ACTIVE="0"
ADMIN_LOCK_HELD="0"
ROLLBACK_FAILED="0"

log()  { printf '\033[1;36m[ИНФО]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[ОК]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[ВНИМАНИЕ]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[ОШИБКА]\033[0m %s\n' "$*" >&2; }

cleanup() {
  [[ -n "$TMP_SCRIPT" ]] && rm -f -- "$TMP_SCRIPT" 2>/dev/null || true
  if [[ "$ROLLBACK_FAILED" != "1" ]]; then
    [[ -n "$BACKUP_SCRIPT" ]] && rm -f -- "$BACKUP_SCRIPT" 2>/dev/null || true
    [[ -n "$SCHEDULER_BACKUP_DIR" ]] && rm -rf -- "$SCHEDULER_BACKUP_DIR" 2>/dev/null || true
  fi
  [[ -n "$VERIFY_DIR" ]] && rm -rf -- "$VERIFY_DIR" 2>/dev/null || true
  if [[ "$ADMIN_LOCK_HELD" == "1" ]]; then
    flock -u 9 2>/dev/null || true
    exec 9>&-
    ADMIN_LOCK_HELD="0"
  fi
}

on_exit() {
  local rc=$?
  local rollback_rc=0
  trap - EXIT

  if [[ "$rc" -ne 0 && "$SCHEDULER_TRANSACTION_ACTIVE" == "1" ]]; then
    if ! rollback_scheduler_transaction; then
      rollback_rc=1
      ROLLBACK_FAILED="1"
      err "Не удалось полностью восстановить scheduler; резервная копия оставлена: $SCHEDULER_BACKUP_DIR"
    else
      warn "Ошибка установки: прежняя конфигурация cron/systemd восстановлена."
    fi
  fi

  if [[ "$rc" -ne 0 && "$NATIVE_REPLACED" == "1" && "$INSTALL_COMMITTED" != "1" ]]; then
    if [[ -n "$BACKUP_SCRIPT" && -f "$BACKUP_SCRIPT" ]]; then
      if mv -f -- "$BACKUP_SCRIPT" "$LOCAL_SCRIPT" 2>/dev/null; then
        BACKUP_SCRIPT=""
        NATIVE_REPLACED="0"
        warn "Ошибка установки: восстановлена предыдущая версия native-скрипта."
      else
        rollback_rc=1
        ROLLBACK_FAILED="1"
        err "Не удалось восстановить native-скрипт; резервная копия оставлена: $BACKUP_SCRIPT"
      fi
    else
      if rm -f -- "$LOCAL_SCRIPT" 2>/dev/null; then
        NATIVE_REPLACED="0"
      else
        rollback_rc=1
        ROLLBACK_FAILED="1"
      fi
    fi
  fi

  cleanup
  [[ "$rollback_rc" -eq 0 ]] || rc=1
  exit "$rc"
}

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

has_systemd() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

ensure_flock_installed() {
  command -v flock >/dev/null 2>&1 && return 0

  log "flock не найден, устанавливаю util-linux для административной блокировки..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y util-linux
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y util-linux
  elif command -v yum >/dev/null 2>&1; then
    yum install -y util-linux
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache util-linux
  else
    err "flock не найден и пакетный менеджер неизвестен."
    return 1
  fi
  command -v flock >/dev/null 2>&1 || { err "flock не появился после установки util-linux."; return 1; }
}

acquire_admin_lock() {
  if ! [[ "$ADMIN_LOCK_TIMEOUT" =~ ^[0-9]+$ ]]; then
    err "WARPWP_ADMIN_LOCK_TIMEOUT должен быть целым числом секунд."
    return 2
  fi
  mkdir -p -- "$(dirname "$ADMIN_LOCK_FILE")" || return 1
  exec 9>"$ADMIN_LOCK_FILE" || return 1
  if ! flock -w "$ADMIN_LOCK_TIMEOUT" 9; then
    err "Другой процесс warpwp изменяет конфигурацию (lock: $ADMIN_LOCK_FILE)."
    exec 9>&-
    return 75
  fi
  ADMIN_LOCK_HELD="1"
}

snapshot_scheduler_file() {
  local target="$1" name="$2"
  if [[ -e "$target" || -L "$target" ]]; then
    : > "$SCHEDULER_BACKUP_DIR/$name.existed" || return 1
    cp -a -- "$target" "$SCHEDULER_BACKUP_DIR/$name.backup" || return 1
  fi
}

restore_scheduler_file() {
  local target="$1" name="$2"
  if [[ -f "$SCHEDULER_BACKUP_DIR/$name.existed" ]]; then
    mkdir -p -- "$(dirname "$target")" || return 1
    rm -f -- "$target" || return 1
    cp -a -- "$SCHEDULER_BACKUP_DIR/$name.backup" "$target" || return 1
  else
    rm -f -- "$target" || return 1
  fi
}

begin_scheduler_transaction() {
  SCHEDULER_BACKUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/warpwp-scheduler.XXXXXX")" || return 1
  snapshot_scheduler_file "$CRON_FILE" cron || return 1
  snapshot_scheduler_file "$TIMER_SERVICE_FILE" timer-service || return 1
  snapshot_scheduler_file "$TIMER_FILE" timer || return 1
  snapshot_scheduler_file "$TIMER_ENV_FILE" timer-env || return 1

  SCHEDULER_CRON_SERVICE="$(cron_service_name)"
  if has_systemd; then
    systemctl is-active --quiet "$SCHEDULER_CRON_SERVICE.service" && SCHEDULER_CRON_ACTIVE="1" || true
    systemctl is-enabled --quiet "$SCHEDULER_CRON_SERVICE.service" && SCHEDULER_CRON_ENABLED="1" || true
    systemctl is-active --quiet warp-wireproxy-check.timer && SCHEDULER_TIMER_ACTIVE="1" || true
    systemctl is-enabled --quiet warp-wireproxy-check.timer && SCHEDULER_TIMER_ENABLED="1" || true
    systemctl is-active --quiet warp-wireproxy-check.service && SCHEDULER_TIMER_SERVICE_ACTIVE="1" || true
  fi
  SCHEDULER_TRANSACTION_ACTIVE="1"
}

restore_systemd_unit_state() {
  local unit="$1" enabled="$2" active="$3" rc=0
  if [[ "$enabled" == "1" ]]; then systemctl enable "$unit" >/dev/null 2>&1 || rc=1
  else systemctl disable "$unit" >/dev/null 2>&1 || true
  fi
  if [[ "$active" == "1" ]]; then systemctl start "$unit" >/dev/null 2>&1 || rc=1
  else systemctl stop "$unit" >/dev/null 2>&1 || true
  fi
  return "$rc"
}

rollback_scheduler_transaction() {
  local rc=0
  [[ "$SCHEDULER_TRANSACTION_ACTIVE" == "1" ]] || return 0
  restore_scheduler_file "$CRON_FILE" cron || rc=1
  restore_scheduler_file "$TIMER_SERVICE_FILE" timer-service || rc=1
  restore_scheduler_file "$TIMER_FILE" timer || rc=1
  restore_scheduler_file "$TIMER_ENV_FILE" timer-env || rc=1

  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || rc=1
    restore_systemd_unit_state "$SCHEDULER_CRON_SERVICE.service" "$SCHEDULER_CRON_ENABLED" "$SCHEDULER_CRON_ACTIVE" || rc=1
    restore_systemd_unit_state warp-wireproxy-check.timer "$SCHEDULER_TIMER_ENABLED" "$SCHEDULER_TIMER_ACTIVE" || rc=1
    if [[ "$SCHEDULER_TIMER_SERVICE_ACTIVE" == "1" ]]; then
      systemctl start warp-wireproxy-check.service >/dev/null 2>&1 || rc=1
    else
      systemctl stop warp-wireproxy-check.service >/dev/null 2>&1 || true
    fi
  fi
  [[ "$rc" -eq 0 ]] && SCHEDULER_TRANSACTION_ACTIVE="0"
  return "$rc"
}

commit_scheduler_transaction() {
  [[ -z "$SCHEDULER_BACKUP_DIR" ]] || rm -rf -- "$SCHEDULER_BACKUP_DIR" || return 1
  SCHEDULER_BACKUP_DIR=""
  SCHEDULER_TRANSACTION_ACTIVE="0"
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

  if has_systemd; then
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
  if has_systemd; then
    systemctl disable --now warp-wireproxy-check.timer >/dev/null 2>&1 || true
    systemctl stop warp-wireproxy-check.service >/dev/null 2>&1 || true
  fi

  rm -f -- "$TIMER_SERVICE_FILE" "$TIMER_FILE" "$TIMER_ENV_FILE"

  if has_systemd; then
    systemctl daemon-reload
    systemctl reset-failed warp-wireproxy-check.service warp-wireproxy-check.timer >/dev/null 2>&1 || true
    if systemctl is-active --quiet warp-wireproxy-check.timer || systemctl is-active --quiet warp-wireproxy-check.service; then
      err "Не удалось остановить project systemd scheduler."
      return 1
    fi
  fi
}

install_cron_file() {
  local target_dir tmp_cron
  target_dir="$(dirname "$CRON_FILE")"
  mkdir -p -- "$target_dir" || return 1
  tmp_cron="$(mktemp "$target_dir/.warp-wireproxy-check.XXXXXX")" || return 1
  if ! {
    cat > "$tmp_cron" <<EOF_CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

$CRON_SCHEDULE root $CHECK_CMD >> $LOG_FILE 2>&1
EOF_CRON
    chmod 0644 "$tmp_cron"
    mv -f -- "$tmp_cron" "$CRON_FILE"
  }; then
    rm -f -- "$tmp_cron"
    return 1
  fi
}

install_native_script() {
  local target_dir
  target_dir="$(dirname "$LOCAL_SCRIPT")"
  mkdir -p "$target_dir" || return 1
  download_verified_native || return 1
  TMP_SCRIPT="$(mktemp "$target_dir/.warp-wireproxy-native.XXXXXX")" || return 1
  install -m 0755 "$VERIFY_DIR/warp-wireproxy-native.sh" "$TMP_SCRIPT" || return 1

  if [[ -e "$LOCAL_SCRIPT" || -L "$LOCAL_SCRIPT" ]]; then
    BACKUP_SCRIPT="$(mktemp "$target_dir/.warp-wireproxy-native.backup.XXXXXX")"
    cp -p -- "$LOCAL_SCRIPT" "$BACKUP_SCRIPT"
  fi

  mv -f -- "$TMP_SCRIPT" "$LOCAL_SCRIPT"
  TMP_SCRIPT=""
  NATIVE_REPLACED="1"
}

verify_manifest() {
  local manifest="$1" signature="$2" allowed="$3"
  printf '%s\n' "$RELEASE_SIGNING_ID $RELEASE_SIGNING_PUBLIC_KEY" > "$allowed" || return 1
  ssh-keygen -Y verify -f "$allowed" -I "$RELEASE_SIGNING_ID" -n "$RELEASE_SIGNING_NAMESPACE" -s "$signature" < "$manifest"
}

verify_asset() {
  local manifest="$1" asset="$2" file="$3" expected
  expected="$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { if (seen++) duplicate=1; hash=$1 } END { if (seen != 1 || duplicate) exit 1; print hash }' "$manifest")" || return 1
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c --status -
}

download_verified_native() {
  local manifest signature allowed
  command -v ssh-keygen >/dev/null 2>&1 || { err "Для проверки подписанного release нужен ssh-keygen (openssh-client)."; return 1; }
  command -v sha256sum >/dev/null 2>&1 || { err "Для проверки release нужен sha256sum."; return 1; }
  VERIFY_DIR="$(mktemp -d)" || return 1
  manifest="$VERIFY_DIR/SHA256SUMS"
  signature="$VERIFY_DIR/SHA256SUMS.sig"
  allowed="$VERIFY_DIR/allowed_signers"
  curl -fsSL "$MANIFEST_URL" -o "$manifest" || return 1
  curl -fsSL "$SIGNATURE_URL" -o "$signature" || return 1
  verify_manifest "$manifest" "$signature" "$allowed" || { err "Подпись SHA256SUMS не прошла проверку; установка отменена."; return 1; }
  curl -fsSL "$SCRIPT_URL" -o "$VERIFY_DIR/warp-wireproxy-native.sh" || return 1
  verify_asset "$manifest" warp-wireproxy-native.sh "$VERIFY_DIR/warp-wireproxy-native.sh" || { err "Хеш native-скрипта не совпал с подписанным manifest; установка отменена."; return 1; }
  bash -n "$VERIFY_DIR/warp-wireproxy-native.sh" || { err "Скачанный native-скрипт имеет ошибку синтаксиса; установка отменена."; return 1; }
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

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --scan-count)
        [[ $# -ge 2 && -n "$2" ]] || { err "Для --scan-count нужно указать значение."; return 2; }
        SCAN_COUNT="$2"
        shift 2
        ;;
      --schedule)
        [[ $# -ge 2 && -n "$2" ]] || { err "Для --schedule нужно указать значение."; return 2; }
        CRON_SCHEDULE="$2"
        shift 2
        ;;
      --remove) REMOVE="1"; shift ;;
      -h|--help) usage; return 64 ;;
      *) err "Неизвестная опция: $1"; usage; return 2 ;;
    esac
  done
}

ensure_curl_installed() {
  command -v curl >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl
  else
    err "curl не найден и пакетный менеджер неизвестен."
    return 1
  fi
  command -v curl >/dev/null 2>&1 || { err "curl не появился после установки."; return 1; }
}

main() {
  local parse_rc
  parse_args "$@" || {
    parse_rc=$?
    [[ "$parse_rc" -eq 64 ]] && return 0
    return "$parse_rc"
  }
  validate_scan_count
  validate_cron_schedule

  if [[ "${EUID}" -ne 0 ]]; then
    err "Запусти от root."
    return 1
  fi

  ensure_flock_installed
  acquire_admin_lock

  if [[ "$REMOVE" == "1" ]]; then
    begin_scheduler_transaction
    rm -f -- "$CRON_FILE"
    commit_scheduler_transaction
    INSTALL_COMMITTED="1"
    ok "Cron-задача удалена: $CRON_FILE"
    return 0
  fi

  ensure_curl_installed
  ensure_cron_installed
  begin_scheduler_transaction

  CHECK_CMD="flock -n $LOCK_FILE $LOCAL_SCRIPT --check --scan-count $SCAN_COUNT --enough-good 1"

  log "Скачиваю локальную копию warp-wireproxy-native.sh..."
  install_native_script
  ok "Скрипт установлен: $LOCAL_SCRIPT"

  log "Создаю cron-задачу: $CRON_FILE"
  install_cron_file
  start_and_verify_cron
  remove_project_timer
  commit_scheduler_transaction
  INSTALL_COMMITTED="1"
  [[ -z "$BACKUP_SCRIPT" ]] || rm -f -- "$BACKUP_SCRIPT" || warn "Не удалось удалить временную резервную копию: $BACKUP_SCRIPT"
  BACKUP_SCRIPT=""

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
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap on_exit EXIT
  main "$@"
fi
