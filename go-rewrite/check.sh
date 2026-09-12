#!/usr/bin/env bash
# go-rewrite/check.sh — аналог scripts/check.sh из bash-проекта.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "== gofmt =="
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  echo "не отформатировано:"
  echo "$unformatted"
  exit 1
fi

echo "== go vet =="
go vet ./...

echo "== go build =="
go build -o /dev/null .

echo "== go test =="
go test ./... -timeout 60s

echo
echo "[OK] проверки пройдены"
