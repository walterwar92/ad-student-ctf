# Устройство стенда

```
                         ┌──────────────────────────────────────────┐
                         │              checksystem                   │
                         │  (infra/checksystem; в контейнере :8080,    │
                         │   наружу http://127.0.0.1:8090)            │
   каждые TICK_SECONDS:  │                                            │
   ┌──────────────────── │  фоновый цикл: для каждой команды и        │
   │  put(flag) / check  │  сервиса → check(), put(flag), get(old)    │
   │  get(flag)          │  пишет флаги и статусы в SQLite             │
   │                     │                                            │
   │                     │  HTTP:  /                 скорборд          │
   │                     │         /api/flag_ids     публичные id целей│
   │                     │         POST /flags       приём флагов      │
   │                     └───────────────┬────────────────────────────┘
   │                                     │ submit (X-Team-Token)
   ▼                                     ▲
┌───────┐  ┌───────┐        ┌───────┐    │        ты (team1):
│ team1 │  │ team2 │  ...   │team10 │    │        attacker/attack.py
│web/cr-│  │web/cr-│        │web/cr-│    └────────  ворует у team2..10,
│ypto/  │  │ypto/  │        │ypto/  │              сдаёт сюда
│depot  │  │depot  │        │depot  │
└───────┘  └───────┘        └───────┘
  одинаковые уязвимые боксы (infra/vulnbox), по 3 сервиса в каждом
```

## Жизненный цикл флага

1. Каждый **тик** (`TICK_SECONDS`, по умолчанию 30 с) checksystem для каждой команды и
   каждого сервиса:
   - `check(host, port)` — сервис жив и корректен?
   - `put(host, port, flag)` → `(status, flag_id, private)` — кладёт свежий флаг.
     `flag_id` — **публичный** идентификатор места флага (его отдают атакующим),
     `private` — секрет чекера (пароль/токен), наружу не уходит.
   - `get(...)` старого флага — проверка, что флаг ещё достаётся легально.
2. Флаг «живёт» `FLAG_LIFETIME_TICKS` тиков (по умолчанию 5). Его `flag_id` всё это время
   виден на `/api/flag_ids`. После — флаг просрочен (`TOO_OLD` при сдаче).
3. Формат флага: `[A-Z0-9]{31}=` (32 символа).

## Статусы сервиса (SLA)

`OK/UP=101`, `CORRUPT=102` (жив, но флаг не достаётся), `MUMBLE=103` (отвечает не по
протоколу), `DOWN=104` (не отвечает). Статус тика = худший из `check/put/get`.
`SLA% = доля тиков со статусом UP`.

## Подсчёт очков

- **attack** — число принятых украденных флагов (уникальных на команду).
- **lost** — сколько твоих флагов украли.
- **sla** — процент аптайма.
- **total** = `attack × 10 + round(sla%)`. Логика в `infra/checksystem/db.py:scoreboard`.
  Правило простое и его легко поменять под свой вкус.

## Протокол сдачи флагов

```
POST /flags
X-Team-Token: <токен команды>
<тело: по одному флагу на строку>
```
Ответ — по строке на флаг: `<flag> <VERDICT>`, где `VERDICT` ∈
`ACCEPTED, INVALID (не формат), NO_SUCH_FLAG, TOO_OLD, OWN_FLAG (свой), DUPLICATE`.

Токен команды детерминированный: `HMAC_SHA256(GAME_SECRET, team_name)[:16]` — поэтому
атакующий считает свой токен сам (см. `attacker/attack.py`), ничего скрейпить не надо.
Свой токен: `./run.ps1 token`.

## Контракт чекера и эксплойта

`services/<svc>/checker.py` — чёрный ящик, импортируется checksystem'ой:
```python
SERVICE = "web"; DEFAULT_PORT = 5001
def check(host, port) -> int
def put(host, port, flag) -> (status, flag_id, private)
def get(host, port, flag_id, flag, private) -> int
```
`services/<svc>/sploit.py` — эталонный эксплойт:
```python
def exploit(host, port, flag_id) -> list[str]   # украденные флаги
# CLI: python sploit.py <host> <port> <flag_id>
```
Значение `flag_id` по сервисам: `web` → имя пользователя-жертвы; `crypto` → id записи в
хранилище; `depot` → `"<user>/<key>"`.

## Запуск без Docker (отладка одного сервиса)

Docker ближе к реальному A&D, но всю логику можно гонять на чистом Python — удобно, когда
пишешь свой эксплойт или патч. Пример для `web`:

```bash
pip install flask requests          # crypto-сервис без внешних зависимостей (встроенный AES)

# 1) поднять сам сервис на 5001
PORT=5001 python services/web/app.py &

# 2) проверить эксплойт против него напрямую:
#    (сначала узнай flag_id — положи флаг чекером или зарегай юзера руками)
python services/web/sploit.py 127.0.0.1 5001 <flag_id>
```

Поднять checksystem против одной локальной «команды» (один бокс на 127.0.0.1):

```bash
cd infra/checksystem
set TEAMS_JSON=[{"name":"team1","host":"127.0.0.1"}]   # PowerShell: $env:TEAMS_JSON='...'
set SERVICES_DIR=../../services
set SCOREBOARD_PORT=8090
python app.py          # скорборд на http://127.0.0.1:8090
```
(в этом режиме все сервисы берутся с портов по умолчанию 5001/5002/5003 на localhost.)

## Добавить свой сервис

1. Заведи `services/<name>/` с `app.py`, `checker.py` (контракт выше), `sploit.py`,
   `requirements.txt`.
2. Добавь `(name, port)` в `SERVICES` в `infra/checksystem/config.py`,
   в `SERVICES` в `infra/vulnbox/supervisor.py` и порт-схему в `gen_compose.py` +
   `attacker/attack.py`.
3. `./run.ps1 rebuild`.
