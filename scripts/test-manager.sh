#!/usr/bin/env bash
# Unit tests for manager helpers. They run without root, systemd, or network.
# shellcheck disable=SC2034

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../warpwp.sh
source "$ROOT_DIR/warpwp.sh"

fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

CRON_FILE="$tmp_dir/warp-wireproxy-check"
TIMER_FILE="$tmp_dir/warp-wireproxy-check.timer"
TIMER_SERVICE_FILE="$tmp_dir/warp-wireproxy-check.service"
TIMER_ENV_FILE="$tmp_dir/warp-wireproxy-check.env"
printf '%s\n' \
  'SHELL=/bin/bash' \
  '*/7 * * * * root flock -n /var/lock/warpwp-check.lock /usr/local/bin/warp-wireproxy-native.sh --check' > "$CRON_FILE"

systemctl() {
  case "${1:-}:${2:-}:${3:-}" in
    cat:cron.service:*) return 0 ;;
    cat:crond.service:*) return 1 ;;
    is-active:--quiet:cron.service) return 0 ;;
    *) return 1 ;;
  esac
}

[[ "$(scheduler_name)" == "cron" ]] || fail "cron-only scheduler must be recognized"
schedule_output="$(scheduler_status)"
[[ "$schedule_output" == *'scheduler: cron'* && "$schedule_output" == *'cron schedule: */7 * * * *'* ]] || fail "scheduler status must succeed in cron-only mode"

WG_DIR="$tmp_dir/wireguard"
mkdir -p "$WG_DIR"
printf '%s\n' '[Socks5]' 'BindAddress = 127.0.0.1:40123' > "$WG_DIR/proxy.conf"
[[ "$(current_socks_host):$(current_socks_port)" == "127.0.0.1:40123" ]] || fail "custom BindAddress must be read from proxy.conf"

curl() { printf '%s\n' 'ip=198.51.100.10' 'colo=HEL' 'loc=FI' 'warp=on'; }
routing_danger_bool() { return 1; }
status_json_file="$tmp_dir/status.json"
status_json > "$status_json_file"
json_parser="${WARPWP_TEST_PYTHON_BIN:-python3}"
"$json_parser" -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); assert data["socks5"]["port"] == 40123; assert data["cron"]["schedule"] == "*/7 * * * *"' "$status_json_file" || fail "status JSON must be valid and use live config"

bad_mtu="$tmp_dir/bad-mtu.conf"
printf '%s\n' '[Interface]' 'PrivateKey = private' 'Address = 10.0.0.2/32' 'MTU = nope' '[Peer]' 'PublicKey = public' 'Endpoint = 162.159.192.1:2408' > "$bad_mtu"
if wg_emit_json "$bad_mtu" >/dev/null 2>&1; then fail "non-numeric MTU must be rejected"; fi

two_peers="$tmp_dir/two-peers.conf"
printf '%s\n' '[Interface]' 'PrivateKey = private' 'Address = 10.0.0.2/32' '[Peer]' 'PublicKey = public-one' 'Endpoint = 162.159.192.1:2408' '[Peer]' 'PublicKey = public-two' 'Endpoint = 162.159.192.2:2408' > "$two_peers"
if wg_emit_json "$two_peers" >/dev/null 2>&1; then fail "multiple peers must be rejected"; fi

[[ "$(ask_timer_minutes 08)" == "8" ]] || fail "timer interval with a leading zero must normalize"

NATIVE_BIN="/bin/false"
LOCK_FILE="$tmp_dir/scan.lock"
acquire_admin_lock() { :; }
ensure_flock() { :; }
fix_routing() { :; }
flock() { return 0; }
if run_scan 1 test >/dev/null 2>&1; then fail "native scan failure must reach manager caller"; fi

flock() { [[ "${1:-}" == "-n" ]] && return 75; return 0; }
if run_scan 1 test >/dev/null 2>&1; then fail "busy scan lock must fail"; else rc=$?; fi
[[ "$rc" == "75" ]] || fail "busy scan lock must return code 75"

# Removal must stop before any destructive action when either maintenance lock
# is busy; `if ! flock; rc=$?` used to turn the 75 into a false success.
NATIVE_LOCK_FILE="$tmp_dir/native.lock"
ensure_flock() { :; }
flock() { [[ "${1:-}" == "-w" ]] && return 75; return 0; }
if acquire_maintenance_locks >/dev/null 2>&1; then fail "busy maintenance lock must fail"; else rc=$?; fi
[[ "$rc" == "75" ]] || fail "busy maintenance lock must return code 75"

# Even explicitly cleaning legacy system WARP must never flush numeric table
# 51820: wg-quick may have assigned it to an unrelated wg0 tunnel.
acquire_admin_lock() { :; }
TABLE_51820_FLUSHED=0
systemctl() { return 1; }
ip() {
  if [[ "$*" == *'route flush table 51820'* ]]; then TABLE_51820_FLUSHED=1; fi
  if [[ "${2:-}" == "link" ]]; then return 1; fi
  return 0
}
fix_routing --force >/dev/null 2>&1 || fail "explicit routing cleanup mock"
[[ "$TABLE_51820_FLUSHED" == "0" ]] || fail "routing cleanup must not flush foreign table 51820"

printf '[OK] manager scheduler/config/lock tests completed\n'
