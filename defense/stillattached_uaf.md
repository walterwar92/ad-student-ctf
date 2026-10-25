# StillAttached — кража флагов: IDOR в list_targets + UAF движка (через `note`)

> Сервис реального бокса (не из тренировочного `services/`). Исходник живёт на боксе в
> `/opt/services/StillAttached/` (FastAPI `web/` + готовый ELF-движок `bin/stillattached`,
> свой `docker compose`). Этот файл — разбор дыр и **SLA-безопасные** патчи, применённые на
> team7 (10.60.7.2). Точные имена/смещения подставляй из `web/main.py` на боксе.

## Архитектура

```
клиент → web (FastAPI, :18080→:8080)  → engine (ELF, TCP :31337, внутренняя сеть backend, наружу НЕ проброшен)
         только валидация/прокси         хранит targets/notes в /data/targets.sqlite3, тема — «отладчик»
```

Команды движка (строки бинаря): `new_session / close_session / new_target / attach / threads /
threads_next / read_reg / note / detach / list_targets`. Схема:

```sql
targets(id INTEGER PRIMARY KEY AUTOINCREMENT, owner INTEGER NOT NULL, name TEXT, created_at INTEGER);
notes(target INTEGER REFERENCES targets(id), tid INTEGER, data BLOB, PRIMARY KEY(target,tid));
```

**Флаг чекер кладёт в `notes.data`** (команда `note` с `data` = set, без `data` = read). Размер
легитимной заметки ≤ 32 байт (флаг = `[A-Z0-9]{31}=` = 32 байта).

## Что воровали (из pcap, `defense/trafmon.py`)

Украдено за один дамп (флаги в ответах нашего :18080):

| IP | флагов | метод |
|---|---|---|
| 10.61.2.5 | 736 | `new_target`→`attach`→`threads`→`read_reg`, ключи JSON экранированы `\uXXXX` (обход строкового WAF) |
| 10.61.1.5 | 346 | спрей `note` с крафт-бинарём (`data="0800000000000000"+адрес кучи…`, ~256 Б) — **UAF** |
| 10.60.0.1 | 278 | `GET /api/targets?after=N` (разведка) → `attach` соседних id |
| 10.61.6.3 | 43 | UA `sti-uaf/1.0`, `attach`→`threads`→`read_reg(rsi/rdi)` |

## Две дыры

### A. IDOR в `list_targets` (чинится в вебе)

`GET /api/targets` → `rpc("list_targets", user["id"])`. Движок возвращает **все** таргеты, помечая
чужие `"mine":false`, вместе с `id/owner/name`:

```json
{"targets":[{"created_at":…,"id":99,"mine":false,"name":"…","owner":3708}, …]}
```

Это даёт атакующему **id/owner свежих таргетов жертвы** — разведка для всех воровских цепочек
(а если чекер кладёт флаг в `name` — то и прямая кража; в дампе такой был 1).

### B. UAF движка через большой `note` (бинарь; нейтрализуем из веба клэмпом)

Штатно всё скоупится по владельцу: `attach` чужого таргета режется движком (`"Target belongs to
another user"`, 136× в дампе), а `note`-read на своём свежем таргете возвращает пусто (проверено
curl'ом). То есть обычного IDOR на чтение заметок нет.

Кражу заметок делает **use-after-free в движке**: атакующий пишет `note` с крафт-payload'ом
(поддельный заголовок chunk'а + адрес кучи), грувит кучу и читает чужую заметку/память. Это
подтверждают UA `sti-uaf/1.0`, утечка указателей кучи через `read_reg` (`0x5649…`) и
распределение размеров `note.data` в дампе:

```
  ≤64 hex (≤32 Б): 177 запросов   — легитим (чекер; флаг = 64 hex)
  512 / 600 hex   : 7283 запроса  — UAF-грув (воры)
  между 64 и 512  : ПУСТО
```

Чистый разрыв ⇒ грув требует большой заметки, а чекеру хватает ≤32 Б.

## Патчи (применены на team7, оба SLA-safe)

Файл: `/opt/services/StillAttached/web/main.py`.

### Патч №1 — owner-фильтр в `GET /api/targets`

```python
# было:
@app.get("/api/targets")
async def targets(user: User, after: Annotated[int, Query(ge=0, le=65535)] = 0):
    return await rpc("list_targets", user["id"], after=after)

# стало:
@app.get("/api/targets")
async def targets(user: User, after: Annotated[int, Query(ge=0, le=65535)] = 0):
    data = await rpc("list_targets", user["id"], after=after)
    if isinstance(data, dict) and isinstance(data.get("targets"), list):
        data["targets"] = [t for t in data["targets"] if t.get("mine")]
    return data
```

Чекер видит только свои таргеты (`mine:true`) → SLA цел; чужие (`mine:false`) не отдаются →
разведка и утечка имён закрыты.

### Патч №2 — клэмп размера `note.data`

```python
# класс Command, поле data — было:
data: str | None = Field(default=None, max_length=8192, pattern=r"^(?:[0-9a-fA-F]{2})*$")
# стало (8192 → 256 hex = 128 байт):
data: str | None = Field(default=None, max_length=256,  pattern=r"^(?:[0-9a-fA-F]{2})*$")
```

256 hex = 128 Б — 4× запас над максимумом чекера (64 hex / 32 Б), но режет все грув-payload'ы
(512/600 hex) ⇒ UAF-грув через `note` не собирается. Легитимные заметки проходят.

## Деплой (только web, engine не трогаем — флаги в volume целы)

```bash
cd /opt/services/StillAttached
sudo cp web/main.py web/main.py.bak_$(date +%H%M%S)          # бэкап перед каждой правкой
# ... применить правки (напр. python3 -c '... .replace(...)') ...
python3 -c "import ast; ast.parse(open('web/main.py').read()); print('SYNTAX OK')"   # обязательно до сборки
sudo docker compose -f compose.yml build web
sudo docker compose -f compose.yml up -d --no-deps web       # --no-deps: engine не рестартит
```

## Верификация (на боксе, curl — читаемый ASCII, транспорт не бьёт)

```bash
H=http://10.60.7.2:18080
# SLA: register→login→new_session→new_target→attach→note(set 64hex)→note(get) должно вернуть те же байты
# IDOR: GET /api/targets у нового юзера — без чужих mine:false
# клэмп: note.data 64 hex → 200 ; note.data 512 hex → 422
```

Результаты на team7: `note set/get` 32 Б → 200 и возврат тех же байт (SLA ок); `GET /api/targets`
→ только `mine:true`; грув 256 Б → `422`.

## Остаточный риск и дальнейшее

- **Канал `read_reg`.** Ферма 10.61.2.5 (736) активно читала регистры. Грув у неё тоже через
  большой `note` (режется №2), но проверить, не утекает ли флаг и через `read_reg` без большого
  `note`. Если да — ограничить/занулить `read_reg` в вебе (чекер его, вероятно, не использует для
  `get` — убедиться по чекеру) или байт-патч.
- **UAF-варианты ≤128 Б.** Клэмп рубит наблюдаемые 256/300-байтные грувы; теоретически возможен
  грув меньшего размера. Если скорборд покажет остаточную утечку — ужать клэмп к 128 hex (64 Б,
  всё ещё 2× над чекером) или перейти к полному фиксу.
- **Полный фикс (фаза 3), если нужно:**
  - *веб-«сейф» заметок*: хранить `note.data` на стороне web (ключ `user_id+target+tid`) и
    отдавать чтение из него — тогда конфиденциальность заметок не зависит от памяти движка
    (UAF ничего не выдаёт). SLA-safe, если чекер читает флаг тем же аккаунтом, что писал.
  - *байт-патч движка* `bin/stillattached` (stripped PIE) — последнее средство, рискованно для SLA.

## Правила-26 (почему так)

Отдельных очков за защиту нет; рейтинг сервиса × SLA. Поэтому патчи **обязаны** сохранять
`put/get/check` чекера — оба патча это соблюдают (меняют только то, что не нужно легитимному
трафику). Любой фикс проверять обеими половинами (SLA + эксплойт) до и после.
