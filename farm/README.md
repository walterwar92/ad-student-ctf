# farm/ — боевая ферма атак v2 (config-driven, stdlib-only, с GUI)

Обобщённая ферма, которую наводишь на **тестовую площадку организаторов** в день Х. Без
внешних зависимостей (чистый Python, GUI на `http.server` — поднимется на любом боксе без
интернета), настраивается одним файлом `config.py`, эксплойты подключаются как плагины.

Полная архитектура и обоснование — в [FARM_V2_SPEC.md](FARM_V2_SPEC.md).

## Что умеет (v2)

- **Развязанные циклы:** воровство, сдача флагов и опрос attack-data работают независимо.
  Сдача идёт по своему расписанию, а не «в конце раунда» — свежие флаги уходят сразу.
- **Безотказность:** конечный автомат флага `QUEUED→INFLIGHT→ACCEPTED/REJECTED/EXPIRED`
  с **TTL** и **ретраями с бэкоффом**; кеш last-good для attack-data (упал фетч — атакуем
  по последнему снимку); SQLite **WAL** + resume после падения/Ctrl+C.
- **Ум:** **AIMD-автотюнинг** темпа сдачи (сам находит лимит жюри); **карантин** сломанных
  эксплойтов; **cooldown** мёртвых целей; **hot-reload** эксплойтов по mtime; точный разбор
  ForcAD-вердикта по полю `status`.
- **GUI** — живой дашборд на `http://127.0.0.1:8070`: KPI, график accepted, вердикты, здоровье
  эксплойтов и целей, лента событий, таблица флагов. **Контролы на лету:** пауза/резюм,
  вкл-выкл сервиса/эксплойта/цели, смена темпа, reload и «прогнать сейчас».
- **Команда (клиент-сервер):** тиммейты запускают `client.py`, который льёт украденные флаги
  в твою ферму (`POST /push`). Один токен, один лимит, общий дедуп на сервере.
- **Совместимость:** интерфейс эксплойта `exploit(host, port, flag_id) -> list[str]` и форма
  конфига заморожены — старые эксплойты и `config.forcad.py` работают как есть.

## Запуск (сервер)

```bash
python farm/farm.py --loop                      # воровать+сдавать, с GUI на :8070
python farm/farm.py --once                       # один раунд, слить очередь, выйти
python farm/farm.py --once --dry-run             # украсть+очередь, НЕ сдавать (безопасно)
python farm/farm.py --loop --service web         # только один сервис
python farm/farm.py --once --team team3          # только одна цель
python farm/farm.py --loop --no-gui              # headless
python farm/farm.py --config farm/config.forcad.py --loop
```

Сейчас `config.py` настроен на **локальный стенд** (`run_local.py`) — ферму можно гонять
прямо сейчас: `python run_local.py`, затем `python farm/farm.py --loop` и открой
`http://127.0.0.1:8070`.

Для боевой площадки — пресет `config.forcad.py` (ForcAD). В день Х заполнить только свой IP,
токен и порты сервисов, затем `python farm/farm.py --config farm/config.forcad.py --loop`.

## Команда (клиент на боксе тиммейта)

На сервере (у тебя) в `config*.py → gui` поставь `host` = твой VPN-IP и `token` = общий
секрет. Тиммейт запускает:

```bash
python farm/client.py --config farm/config.forcad.py --server http://10.60.<твой>.2:8070 --token <секрет>
```

Клиент гоняет те же эксплойты локально и пушит флаги на сервер — сервер дедупит и сдаёт.
Чистый stdlib, без GUI и БД. (Нужен только общий `config`: `sploit_paths`, `services`,
`targets`, `attackdata`, `flag_regex`.)

## Что менять в день теста (в `config.py`)

1. **`flag_regex`** — формат флага организаторов.
2. **`targets`** — `template` + `resolve_address()`, или `list`, или `from_attackdata`.
3. **`services`** — реальные порты сервисов.
4. **`attackdata`** — URL и формат эндпоинта с flag_id (`teamservice`/`forcad`/`custom`).
5. **`submitter`** — `http`/`tcp`, адрес, **твой токен**, `verdicts` под ответы жюри.
6. **`sploit_paths`** — свои эксплойты в `farm/sploits/<service>.py`.
7. (опц.) **`flag_lifetime_seconds`** = `FLAG_LIFETIME_TICKS × round` — для TTL;
   **`collectors.subprocess_services`** — имена pwn-сервисов (запуск киллабельным процессом);
   **`gui`** — host/port/token.

> Токен и прод-конфиг не коммить: `config.local.py`/`config.prod.py` и `farm.log` — в `.gitignore`.

## Эксплойты (плагины)

Один файл на сервис: `farm/sploits/<service>.py`, с **замороженным** интерфейсом
```python
def exploit(host: str, port: int, flag_id) -> list[str]   # вернуть украденные флаги
```
Шаблон и правила — в [`sploits/_template.py`](sploits/_template.py). Ферма валидирует флаги
по `flag_regex`, кладёт в очередь и сдаёт. Для `subprocess_services` ферма запускает файл как
скрипт (`python <svc>.py <host> <port> <flag_id>`) — поэтому **держи эксплойт запускаемым
отдельно** (это и так требование шаблона). Промпт на написание — `EXPLOIT_PROMPT_TEMPLATE.md`.

## Самопроверка пайплайна (self-test)

Сервисы в репозитории **запатчены** (защитная половина упражнения), поэтому
эталонные эксплойты из `sploits/` с них **ничего не воруют** — и прогон фермы по
дереву репозитория не отличить от сломанного (и там, и там «0 флагов»).
`selftest_capture.py` закрывает это: поднимает **уязвимый baseline** трёх сервисов
из истории git во временную папку, запускает ферму `--once` и проверяет весь цикл
**украли → сдали → ACCEPTED** (+ что скорборд засчитал атаку).

```bash
python farm/selftest_capture.py            # 4 команды (3 жертвы), быстрый тик
python farm/selftest_capture.py --teams 3
```

Коды выхода: `0` — пайплайн рабочий, `1` — провал, `77` — пропуск (нет
flask/requests или в истории нет уязвимого baseline → безопасно для CI). Ничего в
репозитории не меняет, временную папку убирает за собой. Нужны свободные порты
сервисов (web `9300+i`, crypto `9400+i`, depot `9500+i`) и один порт скорборда.

## Модули

| Файл | Что делает |
|------|-----------|
| `farm.py` | точка входа + CLI, поднимает engine |
| `engine.py` | оркестратор: супервизит потоки (collectors/submitter/attack-data/GUI) |
| `collectors.py` | пул эксплойтов: жёсткий таймаут, subprocess-изоляция, hot-reload, карантин |
| `submitter.py` | цикл сдачи: token-bucket, AIMD, бэкофф, конечный автомат флага |
| `verdicts.py` | классификация ответа жюри (ForcAD `status`-bool + regex) |
| `attackdata.py` | фетч + кеш last-good |
| `store.py` | SQLite (WAL): флаги, события, цели, здоровье эксплойтов, meta |
| `runtime.py` | живое состояние (пауза/темп/вкл-выкл) — пишет GUI, читают циклы |
| `webgui/` | дашборд + control-API на `http.server` (офлайн, без CDN) |
| `client.py` | тонкий командный клиент: воровать локально → `POST /push` на сервер |
| `targets.py`, `util.py` | резолв целей, логирование |
| `selftest_capture.py` | self-test: уязвимый baseline из git → прогон цикла steal→submit→ACCEPTED |
