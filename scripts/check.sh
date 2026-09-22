#!/usr/bin/env bash
# scripts/check.sh
# Локальная проверка bash-скриптов проекта.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== Bash syntax check =="
while IFS= read -r -d '' file; do
  echo "bash -n $file"
  bash -n "$file"
done < <(find . -type f -name '*.sh' -not -path './.git/*' -print0)

PINNED_VERSION="$(tr -d '[:space:]' < .shellcheck-version 2>/dev/null || true)"

echo
echo "== ShellCheck =="
if command -v shellcheck >/dev/null 2>&1; then
  # Набор правил заметно меняется между версиями: на 0.11.0 проходило то,
  # что apt-версия в CI отвергала. Поэтому версия закреплена, а расхождение
  # с локальной явно проговаривается, чтобы «локально зелено» не вводило в
  # заблуждение.
  LOCAL_VERSION="$(shellcheck --version 2>/dev/null | awk '/^version:/{print $2}')"
  echo "shellcheck: ${LOCAL_VERSION:-unknown} (в CI закреплена ${PINNED_VERSION:-?})"
  if [[ -n "$PINNED_VERSION" && -n "$LOCAL_VERSION" && "$LOCAL_VERSION" != "$PINNED_VERSION" ]]; then
    echo "ВНИМАНИЕ: версия отличается от CI. Результат может не совпасть."
    echo "Скачать нужную: https://github.com/koalaman/shellcheck/releases/tag/v${PINNED_VERSION}"
  fi
  find . -type f -name '*.sh' -not -path './.git/*' -print0 | \
    xargs -0 shellcheck --severity=warning --external-sources
else
  echo "shellcheck не установлен, пропускаю."
  echo "Нужна версия ${PINNED_VERSION:-из .shellcheck-version}:"
  echo "  https://github.com/koalaman/shellcheck/releases/tag/v${PINNED_VERSION}"
fi

echo
echo "== Unit tests =="
bash scripts/test-native.sh
bash scripts/test-manager.sh
bash scripts/test-release-update.sh
bash scripts/test-standalone-installer.sh

echo
printf '[OK] checks completed\n'
