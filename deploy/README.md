# Деплой на боевой сервер + мульти-VPN + ярлык

Комплект «под ключ»: развернуть ферму на сервере команды, поднять несколько
WireGuard-тоннелей так, чтобы они **не конфликтовали** с основным VPN сервера, и
атаковать соперников через **все** тоннели сразу. Управление — ярлыком с рабочего
стола этого ПК.

> Предпосылки: сервер команды — **Linux с systemd** (стандарт для ForcAD; если нет
> systemd — см. «Без systemd» ниже). На этом ПК — **Windows** + официальный
> WireGuard и OpenSSH-клиент (`ssh` уже есть в Windows 10/11). Токены и `.conf`
> **не коммитятся** (см. `.gitignore`).

## Что где лежит

| Файл | Для чего |
|------|----------|
| `deploy.env` (из `deploy.env.example`) | адрес/доступ к серверу, порт дашборда — **gitignored** |
| `deploy.sh` | с ПК: заливка кода, установка, systemd, старт/стоп/логи, заливка VPN |
| `farm.service` | systemd-юнит фермы (ставится как `ad-ctf-farm`) |
| `config.prod.example.py` → `farm/config.prod.py` | боевой конфиг (IP, токен, порты) — **gitignored** |
| `wg-multi/wg-multi.sh` | Linux: несколько WireGuard рядом, policy-routing, без конфликта |
| `wg-multi/conf/` | сюда кладёшь `.conf` от организаторов — **gitignored** |
| `../farm/vpn_balance.py` | ферма раскидывает атаки по всем тоннелям (SO_MARK) |
| `windows/wg-multi.ps1` | те же тоннели на этом ПК (запасной путь/идентичность) |
| `windows/farm-dashboard.ps1` | цель ярлыка: дашборд + подключение к серверу |
| `windows/install-shortcut.ps1` | создать ярлык «A&D Farm» на рабочем столе |

## Один раз (сейчас, без боевых данных)

1. Ярлык уже создан на рабочем столе (или: `powershell -File deploy\windows\install-shortcut.ps1`).
   Пока сервер не настроен — ярлык поднимает ферму локально и открывает дашборд.
2. (Опц.) Установи WireGuard для Windows и OpenSSH-клиент, если их нет.

## В день игры (как придут архив + реквизиты)

```bash
# на этом ПК, Git Bash, из корня репо:
cp deploy/deploy.env.example deploy/deploy.env      # впиши адрес/юзера/ключ сервера
cp deploy/config.prod.example.py farm/config.prod.py # впиши свой IP, токен, порты сервисов

./deploy/deploy.sh all          # залить код + поставить зависимости + systemd
# положи *.conf от организаторов в deploy/wg-multi/conf/ , затем:
./deploy/deploy.sh wg-push      # залить конфиги на сервер (в /etc/ad-ctf/wg)
./deploy/deploy.sh wg up        # поднять ВСЕ тоннели (каждый в своей таблице, без конфликта)
./deploy/deploy.sh wg test      # проверить, что 10.10.10.10 виден через каждый тоннель
./deploy/deploy.sh start        # запустить ферму (она подхватит FARM_VPN_MARKS и бьёт через все VPN)
./deploy/deploy.sh status       # ферма + тоннели + правила
./deploy/deploy.sh logs         # живой лог фермы
```

Дашборд: двойной клик по ярлыку **A&D Farm** → откроется SSH-тоннель на сервер и
браузер на `http://127.0.0.1:<DASHBOARD_PORT>`. Контрол-API остаётся на сервере
на `127.0.0.1` (наружу в игровую сеть не торчит).

## Проверка до старта (13:00 — открытие межкомандной сети)

```bash
./deploy/deploy.sh wg up
./deploy/deploy.sh wg test                 # все тоннели видят 10.10.10.10
# «холостой» прогон фермы: цели парсятся, но флаги не сдаются
./deploy/deploy.sh ssh                      # зайти на сервер, затем:
cd /opt/ad-ctf && python3 farm/farm.py --config farm/config.prod.py --once --dry-run --no-gui
```

## Как это не конфликтует с VPN сервера

Основной игровой VPN сервера остаётся в **главной** таблице маршрутов — его никто не
трогает. Каждый дополнительный тоннель `wg-multi` кладёт свои маршруты в **свою**
таблицу (`Table=10i` в его конфиге) и ловит трафик по `fwmark` через `ip rule`.
Ферма помечает исходящие сокеты (SO_MARK) по кругу — каждая атака уходит своим
тоннелем. Непомеченный трафик идёт как раньше, через основной VPN. Подробно —
[`wg-multi/README.md`](wg-multi/README.md).

## Без systemd

Если на сервере нет systemd — запускай ферму вручную в `tmux`/`screen` из корня репо:
```bash
cd /opt/ad-ctf && . /etc/ad-ctf/vpn.env 2>/dev/null; \
FARM_VPN_MARKS="$FARM_VPN_MARKS" python3 farm/farm.py --config farm/config.prod.py --loop --no-open
```
`wg-multi.sh up/down/status` от systemd не зависят.
