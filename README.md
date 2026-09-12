# WARP WireProxy Manager

![WARP WireProxy Manager](assets/warp-wireproxy-manager-logo.png)

`WARP WireProxy Manager` — неинтерактивный установщик и менеджер для схемы:

```text
3x-ui / Xray → socks5://127.0.0.1:40000 (по умолчанию) → wireproxy → Cloudflare WARP → internet
```

Проект рассчитан на VPS с Linux + systemd. Цель — быстро поднять Cloudflare WARP как **локальный SOCKS5 outbound** для 3x-ui/Xray, автоматически подобрать рабочий WARP endpoint и поддерживать его живым через один scheduler: cron или systemd timer.

> Alpine/OpenRC как отдельный init-режим не поддерживается: для автозапуска нужен `systemctl`.

## Важно про маршрутизацию

Этот проект **не должен** превращать весь VPS в WARP-VPN клиент. WARP используется только через `wireproxy` и локальный SOCKS5 `127.0.0.1:40000` по умолчанию.

Не запускай WARP-конфиг через `wg-quick`:

```bash
wg-quick up warp
systemctl enable --now wg-quick@warp
```

Если системный `wg-quick@warp` поднимет full-tunnel WARP, входящие подключения могут сломаться: SSH/443 приходят на обычный интерфейс VPS, а ответы уходят через WARP. Это выглядит как «сервер в интернете не отвечает», хотя пакеты до него доходят.

Начиная с `warpwp v1.2.1` и `warp-wireproxy-native.sh v1.1.4` добавлена защита:

- `warpwp --fix-routing` отключает опасный системный WARP full-tunnel и не трогает `wireproxy` SOCKS5;
- `warpwp --doctor` показывает routing guard: `ip rule`, `table 51820`, `interface warp`, `wg-quick@warp`;
- `warpwp --install`, `--check`, `--quick-scan`, `--deep-scan` перед работой очищают конфликтующий system-WARP routing;
- `/etc/wireguard/warp.conf` создаётся как guard-файл: случайный `wg-quick up warp` завершится ошибкой до добавления full-tunnel маршрутов;
- рабочий конфиг для `wireproxy` остаётся `/etc/wireguard/proxy.conf`.

Аварийное восстановление после сломанного WARP routing:

```bash
warpwp --fix-routing
ip route get 1.1.1.1
ip route get <твой-admin-ip>
```

Нормально, когда ответы идут через основной интерфейс VPS, например `ens3`, а не через `warp` / `table 51820`.

---

Репозиторий:

```text
https://github.com/kuzzrus/WARP_WireProxy_Manager
```

Текущая версия:

```text
warpwp v1.3.5
warp-wireproxy-native.sh v1.2.2
```

---

## Быстрый старт

Установить менеджер из подписанного release (замени `TAG` на нужную версию):

```bash
TAG=v1.3.5
BASE="https://github.com/kuzzrus/WARP_WireProxy_Manager/releases/download/$TAG"
TMP_DIR="$(mktemp -d)" && trap 'rm -rf "$TMP_DIR"' EXIT
for FILE in warpwp.sh warp-wireproxy-native.sh install-warp-check.sh warp-wireproxy-auto.sh release-signing.pub SHA256SUMS SHA256SUMS.sig; do
  curl -fsSLo "$TMP_DIR/$FILE" "$BASE/$FILE"
done
printf '%s\n' 'warpwp-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEa+mDJ1BJ6w2YdAogupkcdL8MJLo2XjMJlPT9WyQyA3' > "$TMP_DIR/allowed_signers"
ssh-keygen -Y verify -f "$TMP_DIR/allowed_signers" -I warpwp-release -n warpwp-release -s "$TMP_DIR/SHA256SUMS.sig" < "$TMP_DIR/SHA256SUMS"
(cd "$TMP_DIR" && sha256sum -c --strict SHA256SUMS)
install -m 0755 "$TMP_DIR/warpwp.sh" /usr/local/bin/warpwp
```

Установить/обновить WARP + wireproxy + cron:

```bash
warpwp --install
```

Проверить состояние:

```bash
warpwp --doctor
warpwp --status-json
```

Починить опасную системную WARP-маршрутизацию:

```bash
warpwp --fix-routing
```

---

## Основные команды

| Команда | Что делает |
|---|---|
| `warpwp` | Открыть меню |
| `warpwp --install` | Установить/обновить WARP + wireproxy + cron |
| `warpwp --install-cron` | Включить cron и отключить timer |
| `warpwp --install-timer [минуты]` | Включить timer и отключить cron |
| `warpwp --timer-status` | Показать статус systemd timer |
| `warpwp --scheduler-status` | Показать активный scheduler |
| `warpwp --status` | Показать состояние |
| `warpwp --status-json` | Показать JSON-статус |
| `warpwp --doctor` | Расширенная диагностика + routing guard |
| `warpwp --fix-routing` | Убрать системный WARP full-tunnel, не трогая `wireproxy` SOCKS5 |
| `warpwp --check` | Обычный ремонт endpoint, `scan-count=25` |
| `warpwp --quick-scan` | Быстрый ремонт endpoint, `scan-count=15` |
| `warpwp --deep-scan` | Глубокий ремонт endpoint, `scan-count=150` |
| `warpwp --warpscout-scan` | Независимый deep scan через установленный WARPSCOUT |
| `warpwp --check --scanner auto` | Сначала WARPSCOUT, при неудаче встроенный scanner |
| `warpwp --check --node HEL,ARN` | Выбирать только указанные Cloudflare colo |
| `warpwp --check --avoid-node DME` | Исключить указанные Cloudflare colo |
| `warpwp --check --country DE,NL` | Выбирать указанные выходные страны (`loc`) |
| `warpwp --check --avoid-country RU` | Исключить указанные выходные страны (`loc`) |
| `warpwp --xray` | Показать блоки для 3x-ui/Xray |
| `warpwp --zapret` | Показать строки для zapret4rocket |
| `warpwp --wg-paste` | Вставить WireGuard `.conf` в терминал и получить JSON |
| `warpwp --wg-json FILE` | Конвертировать WireGuard `.conf` в JSON для 3x-ui/Xray |
| `warpwp --wg-convert FILE` | Алиас для `--wg-json` |
| `warpwp --logs` | Показать логи |
| `warpwp --memo` | Показать полную памятку |
| `warpwp --update` | Обновить локальные скрипты |
| `warpwp --update vX.Y.Z` | Поставить конкретный подписанный release |
| `warpwp --version` | Показать версию менеджера |
| `warpwp --remove` | Безопасно удалить компоненты менеджера |
| `warpwp --purge` | Жёстко удалить WARP/wireproxy/wgcf/warp-cli/fscarmen-следы |

И `--remove`, и `--purge` удаляют из `/etc/wireguard` только файлы этого проекта
(`warp.conf`, `warp.wireproxy.conf`, `proxy.conf`, `warp-account.json`,
`warp-private.key`, кэши endpoint'ов). Посторонние конфиги вроде `wg0.conf`
остаются на месте, сам каталог удаляется только если стал пустым.

---

## Меню

```text
============================================================
 WARP + wireproxy manager v1.3.4
============================================================
 1) Установить / обновить WARP + wireproxy + cron
 2) Проверить состояние
 3) Проверить и починить endpoint
 4) Обновить локальные скрипты
 5) Безопасно удалить WARP Manager
 6) Показать логи
 7) Показать команды
 8) Показать полную памятку
 9) Doctor / расширенная диагностика
10) PURGE / жёсткая очистка WARP-следов
11) Включить cron/check и отключить timer
12) Показать блоки для 3x-ui / Xray
13) Quick scan endpoint
14) Deep scan endpoint
15) Показать JSON-статус
16) Включить systemd timer и отключить cron
17) Статус systemd timer
18) Удалить systemd timer
19) Scheduler status
20) Fix routing / убрать системный WARP full-tunnel
 0) Выход
============================================================
```

---

## Автопроверка без лишнего apt update

Cron и systemd timer вызывают native-скрипт в режиме `--check`:

```bash
warp-wireproxy-native.sh --check --scan-count 25
```

Режим `--check` делает лёгкую проверку уже установленных команд и не запускает `apt update` / `apt install`. Если `wireproxy` активен и SOCKS5-порт слушает, он также не перезапускается: текущие соединения через SOCKS5 не обрываются. Перезапуск выполняется только если сервис или порт действительно недоступен. Это важно для cron/timer, чтобы каждые 10 минут не дёргать пакетный менеджер и не рвать пользовательский трафик.

---

## Как работает перебор endpoint'ов

Пересканирование запускается только когда быстрая проверка не увидела `warp=on`, то есть когда туннель уже лежит. Поэтому здесь важно время восстановления.

Перебор останавливается, как только набрано 3 стабильных endpoint'а, соответствующих policy. Новый endpoint проверяется серией из 5 запросов: допускается одна случайная потеря, но две финальные ошибки подряд считаются teardown. Лучший выбирается по доле неудачных HTTP-проб, затем по среднему времени ответа. Это не ICMP packet loss: метрика показывает стабильность реального трафика через `wireproxy`. Раньше проверялись все кандидаты подряд, и `--deep-scan` прогонял 150 полных проверок даже если рабочий нашёлся на первой.

Сколько рабочих набирать, можно задать:

```bash
warp-wireproxy-native.sh --check --scan-count 150 --enough-good 1
```

Первыми всегда проверяются текущий endpoint и кэш `warp-endpoints.good`, отсортированный по времени ответа, поэтому обычное восстановление укладывается в несколько попыток. Полный проход всех кандидатов остаётся только для случая, когда не работает вообще ничего.

Если рабочий endpoint не нашёлся, в `proxy.conf` возвращается тот, что стоял до сканирования. Раньше там оставался последний проверенный случайный адрес.

### Policy по Cloudflare node и выходной стране

`colo` из Cloudflare trace — код edge-узла, а `loc` — страна, которую видят внешние сайты. Это разные параметры:

```bash
# Разрешить HEL или ARN, но исключить российский выходной регион
warpwp --check --node HEL,ARN --avoid-country RU

# Исключить DME и предпочитать выход через DE/NL
warpwp --deep-scan --avoid-node DME --country DE,NL
```

По умолчанию используется `--policy-mode prefer`: если подходящий endpoint не найден, Manager может взять любой стабильный рабочий. Для жёсткого запрета:

```bash
warpwp --check --avoid-node DME --policy-mode strict
```

Доступные параметры native-скрипта: `--node`, `--avoid-node`, `--country`, `--avoid-country`, `--policy-mode prefer|strict` и `--stability-probes N`.

### WARPSCOUT как независимый scanner

Если бинарник `warpscout` уже установлен, Manager может искать endpoint в отдельных userspace-туннелях, не переписывая боевой `proxy.conf` на каждом кандидате:

```bash
warpwp --warpscout-scan
warpwp --deep-scan --scanner auto --avoid-node DME
```

- `--scanner warpscout` требует WARPSCOUT и завершится ошибкой, если тот не нашёл endpoint.
- `--scanner auto` сначала пробует WARPSCOUT, затем возвращается к встроенному scanner.
- Временный WARPSCOUT account собирается из существующих `warp-account.json` и `warp-private.key`, содержит только tunnel keys без API token/id, имеет права `0600` и удаляется после запуска.
- Найденный endpoint всё равно проверяется через реальный `wireproxy` перед сохранением.
- Manager передаёт WARPSCOUT только положительный `--node`: параметр `-country` у WARPSCOUT означает страну расположения узла, а у Manager `--country` — выходной `loc`. Country/deny-policy проверяется финальным trace; в `--scanner auto` несовпадение передаётся native scanner.
- Сейчас интеграция использует только `-p wg`: AmneziaWG и MASQUE требуют другого SOCKS backend и в `wireproxy` не подставляются.

Путь и параллелизм можно переопределить:

```bash
warpwp --deep-scan --scanner warpscout \
  --warpscout-bin /usr/local/bin/warpscout \
  --warpscout-jobs 6
```

---

## WireGuard `.conf` → JSON для 3x-ui/Xray

Из файла:

```bash
warpwp --wg-json /root/wg0.conf
```

Вставкой прямо в терминал:

```bash
warpwp --wg-paste
```

Обычный WireGuard config:

```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/32
Address = fd00::2/128
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Будет преобразован в формат:

```json
{
  "protocol": "wireguard",
  "settings": {
    "mtu": 1280,
    "secretKey": "CLIENT_PRIVATE_KEY",
    "address": [
      "10.0.0.2/32",
      "fd00::2/128"
    ],
    "workers": 2,
    "peers": [
      {
        "publicKey": "SERVER_PUBLIC_KEY",
        "allowedIPs": [
          "0.0.0.0/0",
          "::/0"
        ],
        "endpoint": "1.2.3.4:51820",
        "keepAlive": 25
      }
    ],
    "noKernelTun": false
  }
}
```

Конвертер поддерживает несколько строк `Address`, поэтому IPv4 и IPv6 не теряются.

После создания outbound задай tag, например:

```text
WG
```

И используй routing на:

```json
{
  "type": "field",
  "domain": [
    "domain:openai.com",
    "domain:chatgpt.com"
  ],
  "outboundTag": "WG"
}
```

---

## Scheduler modes

Cron и systemd timer взаимоисключающие.

Включить cron-режим:

```bash
warpwp --install-cron
```

Включить timer-режим:

```bash
warpwp --install-timer
```

Передать интервал сразу без вопроса:

```bash
warpwp --install-timer 15
```

Проверить активный scheduler:

```bash
warpwp --scheduler-status
```

---

## JSON-статус

```bash
warpwp --status-json
```

JSON включает:

```text
manager_version
native_version
healthy
scheduler
service
socks5
warp
selection (time_total, probe_loss_percent, stable, scanner, checked_at)
routing_guard
cron
timer
logs
cache
```

---

## 3x-ui / Xray

```bash
warpwp --xray
```

Routing вести на:

```json
"outboundTag": "WARP"
```

Не направляй routing напрямую на `WARP-socks5`; этот outbound используется как промежуточный.

---

## zapret4rocket

```bash
warpwp --zapret
```

Рекомендуемая строка:

```bash
NFQWS_PORTS_UDP=443,2408,1843,1010,500,1701,4500,4443,8443,8095
```

Локальный порт `40000` — это SOCKS5 wireproxy. Его в zapret добавлять не нужно.

---

## Проверки

```bash
warpwp --doctor
warpwp --status-json
curl -m 10 -s -x socks5h://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace | grep -E 'ip=|colo=|loc=|warp='
```

Хороший результат:

```text
warp=on
```

Для маршрутизации должно быть чисто:

```bash
ip rule
ip route show table 51820
ip link show warp
```

Хорошее состояние:

```text
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
```

---

## Обновление

```bash
warpwp --update
```

`--update` получает GitHub Release, проверяет подпись `SHA256SUMS.sig` встроенным публичным ключом и только затем сверяет SHA-256 скриптов. Он никогда не скачивает исполняемый код из ветки `main`.

Чтобы установить строго определённую версию:

```bash
warpwp --update v1.3.5
```

---

## Удаление

```bash
warpwp --remove
warpwp --purge
```

---

## CI

Workflow:

```text
.github/workflows/shellcheck.yml
```

Проверяет:

```text
bash -n
shellcheck --severity=warning
scripts/test-native.sh
```

Версия shellcheck закреплена в `.shellcheck-version` и ставится из релизов koalaman: набор правил заметно меняется между версиями, и версия из apt дрейфовала вместе с образом раннера.

Тот же набор проверок локально:

```bash
scripts/check.sh
```

Скрипт печатает свою версию shellcheck рядом с закреплённой и предупреждает при расхождении. Если версии разные, «локально зелено» ещё не значит «в CI зелено».

---

## Экспериментальный Go-прототип (go-rewrite/)

`go-rewrite/` — отдельный необязательный прототип: переписывание `wireproxy` +
`warp-wireproxy-native.sh` в один Go-бинарь (`warpwp-go`). Это **не замена**
основному проекту и не ставится вместе с ним по умолчанию — самостоятельный
демон на своих портах, для тех, кто хочет попробовать альтернативную
архитектуру.

Чем отличается от bash-версии:

- WireGuard поднимается в userspace прямо в процессе (`wireguard-go` +
  `netstack`), без TUN-интерфейса и без root на биндинг.
- Кандидатов пробует параллельно (горутина на кандидата), а не по одному —
  без систематических `systemctl restart` на каждую проверку.
- Постоянный демон с фоновым health-check и атомарной горячей заменой
  endpoint'а вместо cron/timer.
- Интерактивная TUI-панель (`warpwp-go menu`) и loopback control API
  (`/status`, `/rescan`).
- Опциональная обфускация через `nfqws` (проект zapret) на WARP-портах,
  со своей подкомандой установки.

### Установка на сервер

Два канала релизов:

- `dev-latest` — rolling pre-release, всегда пересобирается на актуальный
  `main` при каждом релевантном коммите;
- `go-vX.Y.Z` — версии для конкретных вех.

Оба публикуются **без криптографической подписи** (в отличие от релизов
`warpwp.sh`) — проверяется только `SHA256SUMS`.

```bash
TAG=dev-latest   # или конкретный go-vX.Y.Z
ARCH=amd64       # или arm64
BASE="https://github.com/kuzzrus/WARP_WireProxy_Manager/releases/download/$TAG"

curl -fsSL "$BASE/warpwp-go-linux-$ARCH" -o /usr/local/bin/warpwp-go.new
curl -fsSL "$BASE/SHA256SUMS" -o /tmp/SHA256SUMS
grep "warpwp-go-linux-$ARCH" /tmp/SHA256SUMS \
  | sed "s#warpwp-go-linux-$ARCH#/usr/local/bin/warpwp-go.new#" \
  | sha256sum -c -
chmod +x /usr/local/bin/warpwp-go.new
mv /usr/local/bin/warpwp-go.new /usr/local/bin/warpwp-go

curl -fsSL https://raw.githubusercontent.com/kuzzrus/WARP_WireProxy_Manager/main/go-rewrite/warpwp-go.service \
  -o /etc/systemd/system/warpwp-go.service
systemctl daemon-reload
systemctl enable --now warpwp-go
```

Если `sha256sum -c` не напечатал `OK` — не продолжай, файл побился при
загрузке. Скачивание через промежуточный `.new` + `mv` вместо перезаписи
`/usr/local/bin/warpwp-go` напрямую важно при обновлении уже запущенного
демона: перезапись исполняемого файла, который в этот момент выполняется,
может упасть с `ETXTBSY`.

По умолчанию демон слушает `127.0.0.1:41080` (SOCKS5) и `127.0.0.1:41081`
(control API) — это **не** порт `wireproxy` (`40000` по умолчанию), оба
могут работать одновременно на одном сервере, не мешая друг другу.

### Команды

| Команда | Что делает |
|---|---|
| `warpwp-go menu` | Интерактивная TUI-панель (живой статус, `r` — rescan, `q` — выход) |
| `warpwp-go status` | JSON-статус текущего endpoint'а |
| `warpwp-go rescan` | Форсировать пересканирование через control API |
| `warpwp-go install-nfqws` | Собрать и поставить `nfqws` (zapret) из исходников |
| `warpwp-go version` | Показать версию сборки |
| `warpwp-go serve [флаги]` | Запустить демон напрямую — обычно не нужно, за это отвечает systemd-юнит |

Основные флаги `serve`: `-listen`, `-control`, `-account`, `-force-register`,
`-check-interval`, `-random`, `-obfuscate`, `-nfqws-bin`, `-nfqws-queue`,
`-nfqws-args`.

Управление сервисом — обычный systemd: `systemctl status|restart|stop warpwp-go`,
логи — `journalctl -u warpwp-go -f`. Полное удаление:

```bash
systemctl disable --now warpwp-go
rm -f /usr/local/bin/warpwp-go /etc/systemd/system/warpwp-go.service
```

`wireproxy`/`warp-wireproxy-native.sh` это не затрагивает никак — они
полностью независимы друг от друга.

### CI/релизы go-rewrite

```text
.github/workflows/go-check.yml       gofmt/vet/build/test на каждый push, трогающий go-rewrite/**
.github/workflows/go-release.yml     сборка linux/amd64+arm64 + pre-release на тег go-v*.*.*
.github/workflows/go-dev-latest.yml  пересборка и republish dev-latest на каждый push в main
```

Тот же набор проверок локально:

```bash
go-rewrite/check.sh
```

---

## Файлы в репозитории

```text
warpwp.sh                  единый менеджер с меню
warp-wireproxy-native.sh   нативный установщик WARP + wireproxy
install-warp-check.sh      отдельный минимальный установщик cron-проверки
warp-wireproxy-auto.sh     deprecated-wrapper для обратной совместимости
TODO.md                    список дальнейших улучшений
CHANGELOG.md               что менялось от версии к версии
LICENSE                    MIT
scripts/check.sh           локальный прогон тех же проверок, что в CI
.shellcheck-version        версия shellcheck, закреплённая для CI и локали
.github/workflows/         CI-проверки bash-скриптов и go-rewrite
go-rewrite/                экспериментальный Go-прототип (warpwp-go), см. раздел выше
```
