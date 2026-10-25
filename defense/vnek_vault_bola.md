# vnek — предсказуемый UUIDv1 → BOLA в `/api/vault` (кража чужого флага)

> Сервис реального бокса (не из тренировочного `services/`). Исходник на боксе в
> `/opt/services/vnek/` (Go + Postgres, свой `docker compose`, порт 28080→8080). Этот файл —
> разбор дыры и **SLA-безопасный** патч. На нашем боксе патч **уже стоит и проверен вживую**
> (см. «Проверка»); документ — для записи, для тиммейтов и для сверки у соседей.

## Суть (в двух словах)

Флаг хранится как `users.secret` («сейф»/vault). В версии, которую раздали организаторы,
`GET /api/vault?uuid=<id>` отдавал секрет **любого** пользователя — без авторизации и без
проверки владения (BOLA / object-level authz). Пример уязвимого кода (`handlers_vault.go.orig_preAD`):

```go
func (a *API) vault(w http.ResponseWriter, r *http.Request) {
    if !requireMethod(w, r, http.MethodGet) { return }
    u, err := a.service.Vault(r.Context(), r.URL.Query().Get("uuid")) // любой uuid, без requireUser
    if err != nil { problem(w, 404, "Unknown UUID"); return }
    respond(w, 200, map[string]string{"uuid": u.ID, "secret": u.Secret}) // отдаёт чужой секрет
}
```

Мало того, что читать можно по `uuid` — **сам `uuid` жертвы вычисляется из публичных данных**,
так что атакующему не нужен даже `flag_id`:

- `internal/identity` выдаёт **UUIDv1**. `node` (6 байт) и `clock_seq` берутся из 8-байтного
  сида, который лежит в БД (`app_meta.uuid_seed`), т.е. **фиксированы на весь бокс/процесс**.
  Свой `node`+`clock_seq` атакующий узнаёт из **собственного** UUID (его отдаёт `/api/register`
  и `/api/me`).
- `GET /api/users` и `GET /api/profile` публично отдают поле `created` = `CreatedAt(u.ID)` —
  это **timestamp, раскодированный из UUIDv1 самой жертвы**, с точностью до 100 нс (RFC3339Nano).
- → `uuid_жертвы = собрать(created, общий node, общий clock_seq)` — **точно, без перебора**
  (проверено 25000/25000 офлайн и на живом боксе: реконструкция совпала с реальным UUID).

## Цепочка атаки (для понимания; боевой эксплойт — `farm/sploits/vnek.py`)

```
POST /api/register                      # своя сессия; в ответе свой uuid → node+clock_seq бокса
GET  /api/users | /api/profile?username # публичный `created` жертвы (= timestamp её UUIDv1)
собрать UUID жертвы из created+node+cs  # точная реконструкция
GET  /api/vault?uuid=<uuid_жертвы>      # БЕЗ авторизации отдаёт {"secret": "<ФЛАГ>"}
```

Корень: **авторизация на доступ к объекту не проверяется**, а публичные эндпоинты **утекают
точный timestamp UUIDv1**, что превращает «угадай uuid» в «вычисли uuid».

---

## Патч (главный, SLA-безопасный): vault только свой и только после входа

В `GET /api/vault` закрыть доступ так, чтобы вернуть можно было **только секрет вызывающего**.
Именно это у нас и сделано (`handlers_vault.go`, строки с пометкой `SECURITY FIX (pre-game audit)`):

```go
func (a *API) vault(w http.ResponseWriter, r *http.Request) {
    if !requireMethod(w, r, http.MethodGet) { return }
    u := a.requireUser(w, r)                 // 1) обязателен вход
    if u == nil { return }
    requested := r.URL.Query().Get("uuid")
    if requested != "" && requested != u.ID { // 2) можно спрашивать только про себя
        problem(w, 403, "Можно смотреть только свой секрет"); return
    }
    self, err := a.service.Vault(r.Context(), u.ID) // 3) читаем ВСЕГДА только u.ID
    if err != nil { reportError(w, err); return }
    respond(w, 200, map[string]string{"uuid": self.ID, "secret": self.Secret})
}
```

**Почему это не ломает SLA.** Чекер кладёт флаг в `secret` от имени пользователя, которого сам
создал, и забирает его **своей же сессией** через `/api/me` (возвращает `"vault": u.Secret`) или
`/api/vault` без `uuid` (или с `uuid` == своего). Все три легальных пути остаются рабочими — патч
режет только чтение **чужого** секрета.

## Belt-and-suspenders (необязательно; только если есть время и не жаль SLA-риска)

Патч выше полностью закрывает кражу (прочитать чужой vault уже нельзя, даже зная uuid). Доп. слой
защиты — **перестать утекать точный timestamp UUIDv1**, чтобы uuid вообще нельзя было
реконструировать из публичных данных:

- отдавать в `created` только **грубую** дату (например, усечение до минуты/дня), ЛИБО
- перейти на **UUIDv4** (случайные) для `users.id`.

⚠️ Трогать генерацию id и формат `created` рискованно для SLA (чекер может сверять формат/значение
`created` или парсить `uuid`). **Без необходимости не трогаем** — основной патч самодостаточен.

---

## Проверка (`defense/verify.py` + ручная)

- Боевой валидатор: `python defense/verify.py vnek 10.60.7.2 28080` — цель: `SLA OK + VULN blocked`.
- Ручная проверка, подтверждённая вживую на нашем боксе: зарегистрировать A и B, B кладёт
  `secret=MARKER…`, A запрашивает `GET /api/vault?uuid=<uuid B>` → наш (пропатченный) бокс
  возвращает `{"error":"Можно смотреть только свой секрет"}` (а не MARKER). На уязвимом боксе
  вернулся бы секрет B.

## Как это выглядит со стороны атаки (для фермы)

Эксплойт: [farm/sploits/vnek.py](../farm/sploits/vnek.py). Интерфейс `exploit(host, port, flag_id)`;
`flag_id` может быть uuid (прямое чтение), username (profile→created→reconstruct→read) или `None`
(dump-all по `/api/users`). Подключён в `farm/config.forcad.py → sploit_paths`.
