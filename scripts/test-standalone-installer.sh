#!/usr/bin/env bash
# Transaction and lock tests for the standalone cron installer.  Everything
# runs under a temporary directory; root, systemd and the network are mocked.
# shellcheck disable=SC2034

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../install-warp-check.sh
source "$ROOT_DIR/install-warp-check.sh"

fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
export TMPDIR="$tmp_dir"

CRON_FILE="$tmp_dir/etc/cron.d/warp-wireproxy-check"
TIMER_SERVICE_FILE="$tmp_dir/etc/systemd/system/warp-wireproxy-check.service"
TIMER_FILE="$tmp_dir/etc/systemd/system/warp-wireproxy-check.timer"
TIMER_ENV_FILE="$tmp_dir/etc/default/warp-wireproxy-check"
mkdir -p "$(dirname "$CRON_FILE")" "$(dirname "$TIMER_FILE")" "$(dirname "$TIMER_ENV_FILE")"
printf 'old cron\n' > "$CRON_FILE"
printf 'old service\n' > "$TIMER_SERVICE_FILE"
printf 'old timer\n' > "$TIMER_FILE"

systemctl_log="$tmp_dir/systemctl.log"
cron_service_name() { printf '%s\n' cron; }
has_systemd() { return 0; }
systemctl() {
  if [[ "$1" == "is-active" && "$2" == "--quiet" ]]; then
    [[ "$3" == "cron.service" || "$3" == "warp-wireproxy-check.timer" ]]
    return
  fi
  if [[ "$1" == "is-enabled" && "$2" == "--quiet" ]]; then
    [[ "$3" == "cron.service" || "$3" == "warp-wireproxy-check.timer" ]]
    return
  fi
  printf '%s\n' "$*" >> "$systemctl_log"
}

begin_scheduler_transaction
printf 'new cron\n' > "$CRON_FILE"
rm -f -- "$TIMER_SERVICE_FILE" "$TIMER_FILE"
printf 'new env\n' > "$TIMER_ENV_FILE"
rollback_scheduler_transaction

[[ "$(cat "$CRON_FILE")" == "old cron" ]] || fail "cron file was not restored"
[[ "$(cat "$TIMER_SERVICE_FILE")" == "old service" ]] || fail "timer service was not restored"
[[ "$(cat "$TIMER_FILE")" == "old timer" ]] || fail "timer unit was not restored"
[[ ! -e "$TIMER_ENV_FILE" ]] || fail "new timer env must be removed on rollback"
grep -qx 'daemon-reload' "$systemctl_log" || fail "systemd daemon-reload was not requested"
grep -qx 'enable cron.service' "$systemctl_log" || fail "cron enabled state was not restored"
grep -qx 'start cron.service' "$systemctl_log" || fail "cron active state was not restored"
grep -qx 'enable warp-wireproxy-check.timer' "$systemctl_log" || fail "timer enabled state was not restored"
grep -qx 'start warp-wireproxy-check.timer' "$systemctl_log" || fail "timer active state was not restored"
grep -qx 'stop warp-wireproxy-check.service' "$systemctl_log" || fail "timer service active state was not restored"

CRON_SCHEDULE='*/5 * * * *'
CHECK_CMD='flock -n /tmp/check.lock /usr/local/bin/native --check'
LOG_FILE='/var/log/check.log'
install_cron_file
grep -Fqx '*/5 * * * * root flock -n /tmp/check.lock /usr/local/bin/native --check >> /var/log/check.log 2>&1' "$CRON_FILE" || fail "atomic cron writer produced wrong command"

ADMIN_LOCK_FILE="$tmp_dir/warpwp-admin.lock"
ADMIN_LOCK_TIMEOUT=0
flock() { return 1; }
set +e
( acquire_admin_lock >/dev/null 2>&1 )
lock_rc=$?
set -e
[[ "$lock_rc" -eq 75 ]] || fail "busy administrative lock must return 75, got $lock_rc"

printf '[OK] standalone installer tests passed\n'
