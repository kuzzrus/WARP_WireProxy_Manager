#!/usr/bin/env bash
# Небольшие unit-тесты чистой логики native scanner без root/systemd/network.
# shellcheck disable=SC2034

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../warp-wireproxy-native.sh
source "$ROOT_DIR/warp-wireproxy-native.sh"

fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }
expect_true() { local label="$1"; shift; "$@" || fail "$label"; }
expect_false() { local label="$1"; shift; if "$@"; then fail "$label"; fi; }

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

[[ "$(normalize_code_list 'hel, arn HEL')" == "HEL,ARN" ]] || fail "normalize_code_list"
parse_args --scanner auto --node 'hel,arn' --avoid-country ru --policy-mode strict --stability-probes 7
[[ "$SCANNER:$NODE_ALLOW:$COUNTRY_DENY:$POLICY_MODE:$STABILITY_PROBES" == "auto:HEL,ARN:RU:strict:7" ]] || fail "parse_args scanner/policy"
if (parse_args --ports '' >/dev/null 2>&1); then fail "empty --ports must be rejected"; fi

USE_CUSTOM_ENDPOINTS="1"
CUSTOM_ENDPOINTS=("162.159.192.1:2408" "[2606:4700:103::1]:443")
CANDIDATES_FILE="$tmp_dir/custom-candidates.txt"
generate_endpoint_candidates >/dev/null
[[ "$(paste -sd, "$CANDIDATES_FILE")" == "162.159.192.1:2408,[2606:4700:103::1]:443" ]] || fail "custom endpoints must be exclusive"
USE_CUSTOM_ENDPOINTS="0"; CUSTOM_ENDPOINTS=()

# Эти globals читает endpoint_matches_policy из sourced native-скрипта.
NODE_ALLOW="HEL,ARN"; NODE_DENY=""; COUNTRY_ALLOW="DE,NL"; COUNTRY_DENY="RU"
expect_true "matching endpoint policy" endpoint_matches_policy HEL DE
expect_false "node allowlist" endpoint_matches_policy DME DE
expect_false "country denylist" endpoint_matches_policy HEL RU
expect_false "unknown node under policy" endpoint_matches_policy '' DE
NODE_ALLOW=""; NODE_DENY="DME"; COUNTRY_ALLOW=""; COUNTRY_DENY=""
expect_false "node denylist" endpoint_matches_policy DME DE
expect_true "node denylist fallback" endpoint_matches_policy HEL RU

# The scheduler must not disconnect active SOCKS clients on each health check.
FAKE_WIREPROXY_ACTIVE="1"
FAKE_SOCKS_LISTENING="1"
FAKE_RESTARTS="0"
systemctl() {
  [[ "$1" == "is-active" && "$2" == "--quiet" && "$3" == "wireproxy" ]] || return 1
  [[ "$FAKE_WIREPROXY_ACTIVE" == "1" ]]
}
socks_port_listening() { [[ "$FAKE_SOCKS_LISTENING" == "1" ]]; }
restart_wireproxy() { FAKE_RESTARTS=$((FAKE_RESTARTS + 1)); }
expect_true "healthy wireproxy needs no restart" ensure_wireproxy_ready_for_check
[[ "$FAKE_RESTARTS" == "0" ]] || fail "health check restarted an active wireproxy"
FAKE_SOCKS_LISTENING="0"
expect_true "missing SOCKS listener restarts wireproxy" ensure_wireproxy_ready_for_check
[[ "$FAKE_RESTARTS" == "1" ]] || fail "missing SOCKS listener did not restart wireproxy"
FAKE_SOCKS_LISTENING="1"; FAKE_WIREPROXY_ACTIVE="0"
expect_true "inactive wireproxy restarts" ensure_wireproxy_ready_for_check
[[ "$FAKE_RESTARTS" == "2" ]] || fail "inactive wireproxy did not restart"

RESULT_FILE="$tmp_dir/results.tsv"
printf '%s\n' \
  $'fast-fallback:2408\tOK\t0.050000\t1.1.1.1\tDME\tRU\ton\t0\t1\tMISMATCH\tnative' \
  $'stable-match:2408\tOK\t0.200000\t1.1.1.1\tHEL\tDE\ton\t20\t1\tMATCH\tnative' \
  $'best-match:2408\tOK\t0.300000\t1.1.1.1\tARN\tSE\ton\t0\t1\tMATCH\tnative' > "$RESULT_FILE"
POLICY_MODE="strict"
[[ "$(pick_best_line "$RESULT_FILE" | cut -f1)" == "best-match:2408" ]] || fail "policy match is selected before fallback"
grep 'MISMATCH' "$RESULT_FILE" > "$tmp_dir/fallback-only.tsv"
[[ -z "$(pick_best_line "$tmp_dir/fallback-only.tsv")" ]] || fail "strict policy rejects fallback"
POLICY_MODE="prefer"
[[ "$(pick_best_line "$tmp_dir/fallback-only.tsv" | cut -f1)" == "fast-fallback:2408" ]] || fail "prefer policy fallback"

FAKE_CURL_STATE_FILE="$tmp_dir/curl-state"
FAKE_CURL_MODE="stable"
curl() {
  local n=0
  [[ -f "$FAKE_CURL_STATE_FILE" ]] && n="$(cat "$FAKE_CURL_STATE_FILE")"
  n=$((n + 1)); printf '%s' "$n" > "$FAKE_CURL_STATE_FILE"
  if [[ "$FAKE_CURL_MODE" == "torn" && "$n" -ge 3 ]]; then
    printf '__TIME_TOTAL__=8.000000\n__HTTP_CODE__=000\n'
  else
    printf 'warp=on\n__TIME_TOTAL__=0.100000\n__HTTP_CODE__=200\n'
  fi
}
STABILITY_PROBES="5"
expect_true "stable probe series" stability_check 0.100000
[[ "$LAST_STABILITY_LOSS:$LAST_STABILITY_TORN" == "0:0" ]] || fail "stable probe metrics"
: > "$FAKE_CURL_STATE_FILE"; FAKE_CURL_MODE="torn"
expect_false "trailing teardown" stability_check 0.100000
[[ "$LAST_STABILITY_LOSS:$LAST_STABILITY_TORN" == "40:1" ]] || fail "teardown metrics"

QUICK_CHECK_RETRY_DELAY="0"
curl() {
  printf 'warp=on\n__TIME_TOTAL__=0.100000\n__HTTP_CODE__=200\n'
  return 56
}
expect_false "partial curl output must not pass WARP check" quick_warp_check

# A single transient failure must not be treated as a dead tunnel: the
# scheduler used to skip straight to a full endpoint rescan (and several
# forced wireproxy restarts) on one bad probe.
FAKE_QUICK_RETRY_STATE="$tmp_dir/quick-retry-state"
curl() {
  local n=0
  [[ -f "$FAKE_QUICK_RETRY_STATE" ]] && n="$(cat "$FAKE_QUICK_RETRY_STATE")"
  n=$((n + 1)); printf '%s' "$n" > "$FAKE_QUICK_RETRY_STATE"
  if [[ "$n" -eq 1 ]]; then
    return 28
  fi
  printf 'ip=1.1.1.1\ncolo=HEL\nloc=DE\nwarp=on\n__TIME_TOTAL__=0.100000\n__HTTP_CODE__=200\n'
}
get_current_endpoint() { printf '%s' ''; }
expect_true "quick check recovers after one transient failure" quick_warp_check
[[ "$(cat "$FAKE_QUICK_RETRY_STATE")" == "2" ]] || fail "quick check must retry before giving up"

WG_DIR="$tmp_dir/wireguard"
GOOD_ENDPOINTS_FILE="$WG_DIR/warp-endpoints.good"
BAD_ENDPOINTS_FILE="$WG_DIR/warp-endpoints.bad"
remember_good_endpoint "162.159.192.1:2408" "0.123000" "HEL" "DE" "20" "1" "warpscout"
cache_line="$(cat "$GOOD_ENDPOINTS_FILE")"
[[ "$(awk -F'\t' '{print NF}' <<< "$cache_line")" == "8" ]] || fail "extended good-cache columns"
[[ "$(awk -F'\t' '{print $6":"$7":"$8}' <<< "$cache_line")" == "20:1:warpscout" ]] || fail "extended good-cache metrics"

if [[ -n "${WARPWP_TEST_PYTHON_BIN:-}" ]]; then
  python3() {
    local arg; local -a converted=()
    for arg in "$@"; do
      if [[ "$arg" == /* ]] && command -v cygpath >/dev/null 2>&1; then converted+=("$(cygpath -w "$arg")")
      else converted+=("$arg"); fi
    done
    "$WARPWP_TEST_PYTHON_BIN" "${converted[@]}"
  }
fi

if [[ "${WARPWP_SKIP_PYTHON_TEST:-0}" != "1" ]]; then
  ACCOUNT_JSON="$tmp_dir/raw-account.json"
  PRIVATE_KEY_FILE="$tmp_dir/private.key"
  WARPSCOUT_ACCOUNT_FILE="$tmp_dir/warpscout-account.json"
  printf '%s\n' 'private-key-value' > "$PRIVATE_KEY_FILE"
  cat > "$ACCOUNT_JSON" <<'JSON'
{"id":"device-id","token":"device-token","config":{"peers":[{"public_key":"peer-key-value"}]}}
JSON
  prepare_warpscout_account
  python3 - "$WARPSCOUT_ACCOUNT_FILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as fh:
    data = json.load(fh)
assert data == {
    'private_key': 'private-key-value',
    'peer_public_key': 'peer-key-value',
}
PY

  printf '%s\n' '{}' > "$ACCOUNT_JSON"
  WARPSCOUT_ACCOUNT_FILE="$tmp_dir/invalid-warpscout-account.json"
  if prepare_warpscout_account 2>/dev/null; then fail "invalid account adapter must fail"; fi
  [[ -z "$WARPSCOUT_ACCOUNT_FILE" && ! -e "$tmp_dir/invalid-warpscout-account.json" ]] || fail "failed account adapter cleanup"

  printf '%s\n' '{"config":{"peers":[{"public_key":"peer-key-value"}]}}' > "$ACCOUNT_JSON"
  WARPSCOUT_ACCOUNT_FILE="$tmp_dir/integration-account.json"
  WARPSCOUT_BIN="$tmp_dir/warpscout"
  export WARPWP_FAKE_ARGS="$tmp_dir/warpscout-args"
  cat > "$WARPSCOUT_BIN" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$WARPWP_FAKE_ARGS"
printf '%s\n' '162.159.192.9:2408'
SH
  chmod +x "$WARPSCOUT_BIN"
  get_current_endpoint() { printf '%s' '162.159.192.1:2408'; }
  test_endpoint() {
    LAST_POLICY_MATCH="1"
    printf '%s\tOK\t0.123000\t1.1.1.1\tHEL\tDE\ton\t0\t1\tMATCH\twarpscout\n' "$1" >> "$RESULT_FILE"
  }
  APPLIED_LINE=""; APPLIED_ACTIVE=""
  apply_best_line() { APPLIED_LINE="$1"; APPLIED_ACTIVE="${2:-0}"; }
  SCAN_COUNT="25"; WARPSCOUT_JOBS="4"; STABILITY_PROBES="7"
  NODE_ALLOW="HEL,ARN"; NODE_DENY=""; COUNTRY_ALLOW=""; COUNTRY_DENY=""
  USE_CUSTOM_ENDPOINTS="0"; POLICY_MODE="strict"; SCANNER="warpscout"
  select_best_endpoint_warpscout >/dev/null 2>&1 || fail "WARPSCOUT integration"
  arg_value() { awk -v key="$1" '$0==key {getline; print; exit}' "$WARPWP_FAKE_ARGS"; }
  [[ "$(arg_value -n):$(arg_value -jt):$(arg_value -tun-ping-count):$(arg_value -node)" == "2:4:7:HEL,ARN" ]] || fail "WARPSCOUT arguments"
  [[ "$(cut -f1 <<< "$APPLIED_LINE"):$APPLIED_ACTIVE" == "162.159.192.9:2408:1" ]] || fail "WARPSCOUT selected endpoint"
fi

expect_true "valid IPv4 endpoint" valid_scanned_endpoint 162.159.192.1:2408
expect_true "valid IPv6 endpoint" valid_scanned_endpoint '[2606:4700:103::1]:443'
expect_false "invalid scanned endpoint" valid_scanned_endpoint 'bad;endpoint:2408'
expect_false "invalid IPv4 endpoint" valid_scanned_endpoint '999.159.192.1:2408'
expect_false "invalid IPv6 endpoint" valid_scanned_endpoint '[1:]:443'
SOCKS_HOST="0.0.0.0"; SOCKS_PORT="40123"
[[ "$(socks_proxy_url)" == "socks5h://127.0.0.1:40123" ]] || fail "wildcard IPv4 bind must use loopback for checks"
SOCKS_HOST="[::1]"
[[ "$(socks_proxy_url)" == "socks5h://[::1]:40123" ]] || fail "IPv6 proxy URL must be bracketed"

printf '[OK] native policy/stability/cache tests completed\n'
