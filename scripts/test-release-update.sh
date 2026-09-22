#!/usr/bin/env bash
# Tests the signed release manifest used by warpwp --update.
# shellcheck disable=SC2034

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../warpwp.sh
source "$ROOT_DIR/warpwp.sh"

fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }
expect_true() { local label="$1"; shift; "$@" || fail "$label"; }
expect_false() { local label="$1"; shift; if "$@"; then fail "$label"; fi; }

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

expect_true "valid release tag" valid_release_tag v1.3.4
expect_false "invalid release tag" valid_release_tag main
[[ "$(release_asset_url v1.3.4 warpwp.sh)" == "https://github.com/kuzzrus/WARP_WireProxy_Manager/releases/download/v1.3.4/warpwp.sh" ]] || fail "release asset URL"
[[ "$RELEASE_SIGNING_PUBLIC_KEY" == "$(awk '{print $1 " " $2}' "$ROOT_DIR/release-signing.pub")" ]] || fail "embedded release public key"

key_file="$tmp_dir/signing-key"
ssh-keygen -q -t ed25519 -N "" -C "warpwp-release" -f "$key_file"
RELEASE_SIGNING_PUBLIC_KEY="$(awk '{print $1 " " $2}' "$key_file.pub")"

asset_dir="$tmp_dir/assets"
mkdir -p "$asset_dir"
cp "$ROOT_DIR/warpwp.sh" "$asset_dir/warpwp.sh"
cp "$ROOT_DIR/warp-wireproxy-native.sh" "$asset_dir/warp-wireproxy-native.sh"
(cd "$asset_dir" && sha256sum warpwp.sh warp-wireproxy-native.sh > SHA256SUMS)
rm -f -- "$asset_dir/SHA256SUMS.sig"
ssh-keygen -Y sign -f "$key_file" -n "$RELEASE_SIGNING_NAMESPACE" "$asset_dir/SHA256SUMS" >/dev/null 2>&1

allowed_signers="$tmp_dir/allowed-signers"
expect_true "valid signed manifest" verify_release_manifest "$asset_dir/SHA256SUMS" "$asset_dir/SHA256SUMS.sig" "$allowed_signers"
printf 'tamper\n' >> "$asset_dir/SHA256SUMS"
if verify_release_manifest "$asset_dir/SHA256SUMS" "$asset_dir/SHA256SUMS.sig" "$allowed_signers" >/dev/null 2>&1; then fail "tampered manifest"; fi
(cd "$asset_dir" && sha256sum warpwp.sh warp-wireproxy-native.sh > SHA256SUMS)
rm -f -- "$asset_dir/SHA256SUMS.sig"
ssh-keygen -Y sign -f "$key_file" -n "$RELEASE_SIGNING_NAMESPACE" "$asset_dir/SHA256SUMS" >/dev/null 2>&1

curl() {
  local output="" url=""
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -o) output="$2"; shift 2 ;;
      http://*|https://*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  [[ -n "$output" && -n "$url" ]] || return 1
  cp "$asset_dir/${url##*/}" "$output"
}

staged_native="$tmp_dir/staged-native.sh"
expect_true "asset hash and syntax verification" stage_release_asset v1.3.4 warp-wireproxy-native.sh "$asset_dir/SHA256SUMS" "$staged_native"
cmp -s "$asset_dir/warp-wireproxy-native.sh" "$staged_native" || fail "staged asset content"

NATIVE_BIN="$tmp_dir/installed/native.sh"
MANAGER_BIN="$tmp_dir/installed/warpwp"
acquire_admin_lock() { :; }
need_curl() { :; }
expect_true "pair update from signed release" update_local_scripts v1.3.4
cmp -s "$asset_dir/warp-wireproxy-native.sh" "$NATIVE_BIN" || fail "installed native asset"
cmp -s "$asset_dir/warpwp.sh" "$MANAGER_BIN" || fail "installed manager asset"

# update_local_scripts is also called in an `if`/`||` context by the manager.
# A failed signature must still return non-zero and leave both installed files
# byte-for-byte unchanged in that Bash corner case.
cp "$NATIVE_BIN" "$tmp_dir/native.before-invalid-signature"
cp "$MANAGER_BIN" "$tmp_dir/manager.before-invalid-signature"
printf '%s\n' 'invalid signature' > "$asset_dir/SHA256SUMS.sig"
if update_local_scripts v1.3.4; then fail "invalid signature must reject the full update"; fi
cmp -s "$NATIVE_BIN" "$tmp_dir/native.before-invalid-signature" || fail "invalid signature changed native script"
cmp -s "$MANAGER_BIN" "$tmp_dir/manager.before-invalid-signature" || fail "invalid signature changed manager script"

printf '[OK] signed release manifest tests completed\n'
