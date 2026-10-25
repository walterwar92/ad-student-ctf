# attacker/ — ферма атак

`attack.py` — эталонная «ферма», которую в A&D каждая команда автоматизирует:

1. забирает публичные `flag_id` целей с `http://127.0.0.1:8090/api/flag_ids`;
2. для каждой **вражеской** команды (все, кроме `MY_TEAM`) запускает
   `services/<svc>/sploit.py:exploit(host, port, flag_id)`;
3. собирает украденные флаги и шлёт их на `POST /flags` со своим токеном;
4. печатает вердикты (`ACCEPTED`, `TOO_OLD`, `DUPLICATE`, …).

```bash
pip install requests          # нужно один раз

python attacker/attack.py                      # один проход
python attacker/attack.py --loop               # крутить каждый тик
python attacker/attack.py --service depot      # только один сервис
python attacker/attack.py --team team5         # только одна цель
```

Порт-схема целей (совпадает с `gen_compose.py`): `teamN` → web `9300+N`, crypto `9400+N`,
depot `9500+N`. Адрес скорборда и свой токен берёт из `.env`
(`SCOREBOARD_PORT`, `GAME_SECRET`, `MY_TEAM`).

**Как учиться:** сначала запусти как есть и посмотри на полный цикл steal→submit. Потом
открой `services/<svc>/sploit.py` и разберись, *как* именно воруется флаг. Дальше —
замени эталонный эксплойт своим: правь `sploit.py` (контракт — функция
`exploit(host, port, flag_id) -> list[str]`), и ферма подхватит его автоматически.
