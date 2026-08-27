#!/usr/bin/env python3
"""gateway-acl — who routes through this Linux gateway, and how much they used.

devices.json is the source of truth. Any change to the list, or to a device's
"on" flag, regenerates the whole nftables table in a single atomic transaction.
Nothing else on the system is touched.

Traffic is counted by named nftables counters, two per device (up/down). They
are zeroed when the table is rebuilt and on reboot, so the poller accumulates
bytes per day, detecting resets (see accrue). The day in progress lives in
today.json and the days already closed in traffic.json — see flush() for why
the two are not one file.

Whoever knocks without being allowed is recorded by the kernel itself into the
dynamic `blocked` set with a timeout — that is the unknown-devices list.

The only request this program ever makes to the internet is a check of the
latest release tag on GitHub — once a day, once more whenever the settings are
saved, and whenever the check button is pressed. `"update_check": false` turns
the daily one off; the button asks anyway, but no oftener than once a minute.
`"update_notify"` decides whether the page that finds a release also raises a
browser notification about it.

Run as root: nft is required.
  --selftest        checks, never touches the network
  --dump            print the ruleset, handy to pipe into `nft -c -f -`
  --set-password    read a password from stdin and store only its hash
  --version         print the version and exit
"""
import base64
import contextlib
import getpass
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
import re
import secrets
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import zlib
import singbox_sub
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Must equal the release tag this code is published under: the panel compares
# it against the newest tag on GitHub, so a forgotten bump makes every install
# claim to be older than it is and show a banner that never goes away. CI
# refuses a tag push where the two disagree.
VERSION = "1.6.0"
RELEASES_URL = "https://api.github.com/repos/ChasoniCK/gateway-acl/releases/latest"
RELEASES_PAGE = "https://github.com/ChasoniCK/gateway-acl/releases/latest"
# The one address the update button may ever download from. The repository is
# part of the constant on purpose: only the tag comes off the network.
TARBALL = "https://codeload.github.com/ChasoniCK/gateway-acl/tar.gz/refs/tags/"
UPDATE_EVERY = 86400
# The floor between two hand-made checks. GitHub allows sixty unauthenticated
# requests an hour from an address, and spending them on a button held down is
# how the daily check starts failing too.
MANUAL_EVERY = 60
TAR_MAX = 20 << 20

ETC = os.environ.get("GWACL_DIR", "/etc/gateway-acl")
CONFIG = f"{ETC}/config.json"
DEVICES = f"{ETC}/devices.json"
TRAFFIC = f"{ETC}/traffic.json"
TODAY = f"{ETC}/today.json"
SESSIONS = f"{ETC}/sessions.json"
UPDATE_LOG = f"{ETC}/update.log"
TUNNELS = f"{ETC}/tunnels.json"
TUNNEL_DIR = f"{ETC}/tunnels"
LEGACY_SUB_URL = f"{ETC}/sub.url"
LEGACY_SUB_EXCLUDE = f"{ETC}/sub.exclude"
SINGBOX_CONFIG = os.environ.get("GWACL_SINGBOX_CONFIG", "/etc/sing-box/config.json")

DEFAULTS = {"iface": "eno1", "lan": "192.168.1.0/24", "self_ip": "192.168.1.10",
            "port": 8080, "poll_sec": 60, "pw": None, "lang": "ru",
            "update_check": True, "update_notify": True, "keep_months": 3,
            "reboot": False, "reboot_at": "05:30",
            # Not a setting and not on the form: the moment the gateway stops
            # letting everyone through again. It lives in the config because it
            # has to survive a restart — the table is rebuilt from disk on every
            # start, and a bypass that evaporated there would lock out a room
            # full of guests the moment the service is updated.
            "bypass": 0,
            # The fwmark a device sent past the tunnel is stamped with. Not on
            # the form either: it belongs to the tunnel, not to this program,
            # and whoever has to change it is already editing that tunnel's
            # config. 0 turns the whole feature off.
            #
            # 0x2024 is sing-box's AutoRedirectOutputMark — what it puts on its
            # own packets so they are not swallowed again, and therefore the one
            # thing its rules step aside for. Its neighbour 0x2023 is the
            # *input* mark and does the exact opposite: `ip rule ... fwmark
            # 0x2023 lookup 2022` sends the packet into the tun. Reading it off
            # the host beats trusting either number — see docs/singbox.md.
            # wg-quick's is its own port, 51820.
            "vpn_mark": 0x2024}
SESSION_TTL = 7 * 86400
FAIL_LIMIT = 5          # misses in a row from one address
FAIL_BLOCK = 60         # and that is how long it then sits out
BLOCK_TTL = 6 * 3600    # how long the kernel remembers whom it dropped
TIMER_MAX = 7 * 86400   # the longest a device may be switched off "for a while"
# ...and the longest the whole gateway may stand open. Shorter than a device's
# timer on purpose: this one suspends the entire point of the program, and
# "until tomorrow" is not a thing anybody means by "let the guests in".
BYPASS_MAX = 6 * 3600
# How long /api reuses its own last answer. Every open tab asks every five
# seconds, and on a phone plus a laptop that is two full readings — the day
# buckets copied, the ARP table and the lease file read, /proc walked — for a
# number that cannot have changed in between. Below POLL_MIN on purpose: the
# counters are behind that window anyway, so this only removes work nothing
# was waiting for.
STATE_CACHE = 1.0
# How long today.json is allowed to lag behind memory. This is the seconds of
# accounting a power cut costs — a clean stop or a crash costs nothing, see
# flush() — and it is what keeps a page refreshing every five seconds from
# rewriting the file every five seconds. Five minutes of a gateway's traffic is
# worth less than the flash this saves: the file is rewritten whole, so this
# number divides the bytes written per day straight down.
FLUSH_EVERY = 300
# A rate is measured over a window; below this one there is nothing new to
# divide, so a poll inside it would spend an nft call to learn nothing.
POLL_MIN = 2
# Months kept day by day, from "keep_months". Older ones are folded into a
# single figure per month: monthly totals stay exact to the byte, what is given
# up is the per-day chart of a month that far back. Set by reload_conf.
KEEP_MONTHS = DEFAULTS["keep_months"]

_lock = threading.Lock()
_statelock = threading.Lock()
_conf_lock = threading.RLock()
_vpn_lock = threading.RLock()
_vpn_closed = False
_state = {"at": 0.0, "month": None, "val": None}   # the last answer /api gave
_sessions = {}          # digest of the token -> when it expires
_csrf_secret = secrets.token_bytes(32)
_fails = {}             # address -> (misses, blocked until)
_upd = {"at": 0, "new": None, "manual": 0}  # last check, the tag worth showing,
                                            # and when a hand last asked


def conf():
    try:
        with open(CONFIG) as f:
            return dict(DEFAULTS, **json.load(f))
    except FileNotFoundError:
        return dict(DEFAULTS)
    except PermissionError:
        # config.json is 0600 — it holds the password hash. A plain user (say,
        # running --selftest by hand) gets the defaults, but is told so out
        # loud: a silently wrong iface and network would look like healthy work.
        lang = "en" if os.environ.get("GWACL_LANG") == "en" else "ru"
        print(STRINGS[lang]["cfgUnreadable"].replace("{cfg}", CONFIG), file=sys.stderr)
        return dict(DEFAULTS)


def _write_private_bytes(path, data):
    """Atomically replace one owner-only file and make the rename durable."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        dfd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def write_private(path, obj):
    """Write JSON so a cut leaves an old or new owner-only file, never half."""
    _write_private_bytes(path, json.dumps(obj, indent=1).encode())


def write_private_text(path, text):
    _write_private_bytes(path, text.encode())


def write_atomic(path, obj):
    """Write json so that a power cut leaves either the old file or the new one.

    `open(path, "w")` truncates first: cut the power in that window and what
    comes back up is half a file, which is not json and takes the panel with it
    on the next start. The rename is the atomic step, and the fsync is what
    makes it mean anything — without it the rename can reach the disk before
    the bytes do. Compact separators because nobody reads these two files by
    hand and every comma is written FLUSH_EVERY seconds apart, for ever.
    """
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def save_conf(c):
    with _conf_lock:
        write_private(CONFIG, c)
        _state["val"] = None   # the page asks again in a moment; it must see this


def update_conf(change):
    """Serialize a config read-modify-write and return the committed value."""
    with _conf_lock:
        c = conf()
        changed = change(c)
        c = changed if changed is not None else c
        save_conf(c)
        return c


STRINGS = {
    "ru": {
        "title": "Шлюз",
        "h1": "Устройства через шлюз",
        "logout": "выйти",
        "close": "Закрыть",
        "total": "всего",
        "inbound": "входящий",
        "outbound": "исходящий",
        "perDay": "в среднем в день",
        "devicesTitle": "Устройства",
        "colAddr": "адрес",
        "colName": "имя",
        "colTraffic": "трафик",
        "colSeen": "активность",
        "sortBy": "Сортировка",
        "sortAsc": "Сортировка: по возрастанию",
        "sortDesc": "Сортировка: по убыванию",
        "addDevice": "Добавить устройство",
        "phName": "название устройства",
        "add": "добавить",
        "hint": "На устройстве прописать вручную: шлюз <b>{{GW}}</b>, маска "
                "<b>{{MASK}}</b> (Android спрашивает длину префикса — "
                "<b>{{PFX}}</b>), DNS <b>1.1.1.1</b>. Кого нет в списке — тот через "
                "шлюз не ходит вообще. «Выключить» оставляет устройство в списке "
                "вместе с историей и именем, но закрывает ему выход. Устройство "
                "запоминается по MAC: если DHCP выдаст ему другой адрес, запись "
                "переедет туда вместе со всей своей историей.",
        "blockedTitle": "Стучались, но не пущены",
        "blockedHint": "Ядро запомнило адреса, чьи пакеты дропнуты за последние 6 часов.",
        "noData": "за этот месяц данных ещё нет",
        "youAre": "Вы",
        "turnOff": "выключить",
        "turnOn": "включить",
        "vpnOff": "мимо VPN",
        "vpnOn": "через VPN",
        "vpnWhat": "Выпустить устройство мимо туннеля: интернет у него остаётся, "
                   "но идёт напрямую через шлюз, а не через VPN. Пакеты "
                   "помечаются fwmark, по которой туннель их не забирает — "
                   "метка задаётся в config.json как \"vpn_mark\".",
        "del": "удалить",
        "tmFor": "на время",
        "tmWhat": "Выключить или включить на время: когда срок выйдет, устройство "
                  "само вернётся к тому состоянию, в котором стоит сейчас. "
                  "Точность — период опроса счётчиков.",
        "tm15": "15 минут",
        "tm1h": "1 час",
        "tm3h": "3 часа",
        "tm8h": "8 часов",
        "tmMorning": "до 07:00",
        "tmLeftM": "ещё {n} мин",
        "tmLeftH": "ещё {n} ч",
        "tmCancel": "снять таймер и оставить как есть",
        "badTimer": "таймер — от минуты до недели",
        "badBypass": "открытым шлюз можно держать не дольше {n} ч",
        "tm5": "5 минут",
        "byp": "пустить всех",
        "bypOn": "открыто для всех",
        "bypWhat": "На это время шлюз пропускает всех подряд, включая тех, кого "
                   "нет в списке. Учёт трафика не прерывается, и ядро всё так же "
                   "запоминает, кто приходил, — когда время выйдет, они окажутся "
                   "в списке внизу, и любого можно будет добавить в один клик.",
        "confirmByp": "Пустить через шлюз всех подряд? На это время список не "
                      "действует — выход получит любое устройство в сети.",
        "allOff": "выключить всех",
        "allOn": "включить всех",
        "allWhat": "Кроме вашего собственного адреса",
        "confirmAllOff": "Закрыть выход всем устройствам? Ваш адрес останется "
                         "включённым, вернуть остальных можно той же кнопкой.",
        "useHost": "назвать так, как устройство представляется сети: {n}",
        "clashTitle": "На адресе не то устройство",
        "clashLine": "в списке {a}, отвечает {b}",
        "clashHint": "Правило разрешает адрес, а отвечает с него сейчас другое "
                     "железо — значит, через шлюз ходит не то, что вы разрешали. "
                     "Обычно это статический адрес, который DHCP успел выдать "
                     "кому-то ещё. Проще всего сменить адрес одному из двоих.",
        "macRandom": "случайный адрес",
        "empty": "пусто — сейчас через шлюз не ходит никто",
        "confirmDel": "Удалить {ip}? История трафика останется.",
        "confirmDelMe": "Удалить {ip}? Это ваш собственный адрес — интернет через шлюз "
                        "пропадёт, но панель останется доступна, и себя можно будет вернуть.",
        "b": " Б", "kb": " КБ", "mb": " МБ", "gb": " ГБ",
        "now": "сейчас",
        "minAgo": "{n} мин назад",
        "hAgo": "{n} ч назад",
        "dAgo": "{n} дн назад",
        "loginTitle": "Шлюз — вход",
        "panelTitle": "Панель шлюза",
        "password": "пароль",
        "signIn": "войти",
        "wrongPw": "Неверный пароль.",
        "loggedOut": "Вы вышли.",
        "tooMany": "Слишком много попыток. Подождите минуту.",
        "noPw": "Пароль не задан. На шлюзе: panel.py --set-password",
        "needLogin": "нужен вход",
        "badIp": "{ip}: нужен адрес клиента из {lan}, но не сам шлюз",
        "pwSaved": "пароль записан",
        "noIface": "интерфейса {iface} нет — поправьте iface в {cfg}",
        "noPwWarn": "ВНИМАНИЕ: пароль не задан, панель никого не пустит. "
                    "Задайте: {cmd} --set-password",
        "cfgUnreadable": "{cfg} читается только root — беру значения по умолчанию",
        "pwShort": "пароль короче 8 символов",
        "updateTitle": "Есть обновление",
        "updateNew": "Вышла версия {v}, установлена {{VERSION}}.",
        "updateHint": "Кнопка скачивает релиз с GitHub и запускает тот же "
                      "<code>install.sh</code>, отвечая за вас теми значениями, "
                      "что уже настроены. Список устройств и статистика не "
                      "тронутся. Руками: <code>git pull</code> и "
                      "<code>sudo ./install.sh</code>. Проверку можно выключить "
                      "в настройках.",
        "updateNow": "Установить сейчас",
        "updateConfirm": "Скачать {v} и установить? Панель перезапустится сама.",
        "updating": "Обновление пошло. Панель перезапустится — обновите страницу "
                    "через минуту-другую.",
        "updateNone": "Обновления нет.",
        "updateFound": "Вышла версия {v}.",
        "updateFail": "GitHub не ответил. Проверьте связь и попробуйте позже.",
        "updateLog": "Как всё прошло: {{UPDLOG}}",
        "settingsTitle": "Настройки",
        "groupGeneral": "Основное",
        "groupNet": "Сеть",
        "groupVpn": "Туннели",
        "vpnSubscription": "Подписка",
        "vpnWireGuard": "WireGuard",
        "vpnAmneziaWG": "AmneziaWG",
        "vpnName": "название",
        "vpnNamePh": "например, Франкфурт",
        "vpnUrl": "ссылка HTTPS",
        "vpnExclude": "исключить узлы",
        "vpnExcludePh": "необязательное регулярное выражение",
        "vpnConfig": "конфиг",
        "vpnConfigPh": "вставьте весь файл .conf",
        "vpnAdd": "добавить туннель",
        "vpnEmpty": "туннелей ещё нет",
        "vpnLoading": "загрузка…",
        "vpnDirect": "Сейчас трафик идёт напрямую",
        "vpnClosed": "Транзит закрыт: активный туннель не работает",
        "vpnRunning": "Активен: {kind}",
        "vpnStopped": "туннель остановлен",
        "vpnEnabled": "включён",
        "vpnDisabled": "выключен",
        "vpnNodes": "узлов: {n}",
        "vpnEnable": "включить",
        "vpnDisable": "выключить",
        "vpnRefresh": "обновить",
        "vpnDelete": "удалить",
        "vpnConfirmDisable": "Выключить последний активный туннель? Трафик пойдёт напрямую.",
        "vpnConfirmDelete": "Удалить этот туннель и его сохранённые данные? Если он активен, подключение будет переключено.",
        "vpnIpv6": "В конфиге нет полного маршрута IPv6",
        "vpnHint": "Новый туннель сначала сохраняется выключенным. Подписки можно "
                   "включать вместе; WireGuard или AmneziaWG заменяет их как "
                   "единственный активный backend. Команды из хуков конфигов запрещены.",
        "vpnBusy": "Применяю…",
        "vpnSaved": "Готово",
        "vpnBadForm": "Заполните название и данные выбранного типа.",
        "vpnErrMissing": "файл профиля отсутствует",
        "vpnErrTool": "нужная программа не установлена",
        "vpnErrStopped": "туннель остановлен",
        "vpnErrStart": "не удалось запустить туннель",
        "vpnErrValidation": "конфиг или подписка не прошли проверку",
        "vpnErrRollback": "откат не завершён; транзит оставлен закрытым",
        "vpnErrConflict": "найден другой активный туннель; операция отменена",
        "vpnErrInvalid": "состояние туннелей повреждено",
        "vpnErrLegacy": "старая подписка работает, но ещё не обновлена панелью",
        "groupMaint": "Обслуживание",
        "groupPw": "Пароль",
        "theme": "Тема",
        "themeAuto": "Авто",
        "themeLight": "Светлая",
        "themeDark": "Тёмная",
        "sLang": "язык панели",
        "sUpdate": "сообщать о новых версиях",
        "sNotify": "уведомлять о них в браузере",
        "sNotifyHint": "Пока вкладка открыта, о новой версии скажет уведомление "
                       "браузера — если он их разрешил и страница открыта по "
                       "https или с localhost; по http на адрес в сети браузер "
                       "уведомления не даёт вовсе. Там, где не даёт, точка "
                       "появится в заголовке вкладки. Про версию говорится один "
                       "раз, а не при каждом опросе.",
        "notifyBody": "Вышла версия {v}. Откройте панель, чтобы поставить.",
        "sCheck": "проверить обновление",
        "sCheckHint": "Панель и так спрашивает GitHub раз в сутки. Вручную — "
                      "не чаще раза в минуту и всё равно редко: GitHub считает "
                      "запросы с адреса (60 в час), и если их выбрать, "
                      "перестанет отвечать и суточной проверке.",
        "sPoll": "опрос счётчиков, с",
        "sKeep": "хранить по дням, мес.",
        "sKeepWhat": "Сколько месяцев держать разбивку по дням. Что старше — "
                     "сворачивается в одну цифру за месяц: итоги месяцев и "
                     "устройств остаются точными до байта, пропадает только "
                     "график по дням. Уменьшение сворачивает лишнее сразу.",
        "sIface": "интерфейс",
        "sLan": "локальная сеть",
        "sSelfIp": "адрес шлюза в ней",
        "sPort": "порт панели",
        "sPw": "новый пароль",
        "sPwKeep": "оставить прежний",
        "sSave": "сохранить",
        "sRebootAt": "ребут каждый день в",
        "sRebootAtWhat": "Перезагружать шлюз каждую ночь в это время. Точность "
                         "— период опроса: ребут случится в первый опрос после "
                         "указанного времени.",
        "sReboot": "перезагрузить шлюз",
        "confirmReboot": "Перезагрузить шлюз? Пока он загружается, интернета не "
                         "будет ни у одного устройства.",
        "rebooting": "Шлюз перезагружается. Панель вернётся через минуту-другую.",
        "sNetHint": "Первые три поля — то же, что нашёл установщик. Меняйте их, только "
                    "если сеть действительно переехала: правила nftables пересобираются "
                    "сразу, а устройства вне новой сети добавить будет уже нельзя. "
                    "Смена порта перезапускает панель. Всё лежит в {{CFG}}.",
        "sRestart": "Порт изменён. Панель перезапускается — откройте {url}",
        "badLang": "языка {lang} нет",
        "badNumber": "здесь нужно число",
        "badPoll": "опрос — от 5 до 3600 секунд",
        "badKeep": "хранить по дням — от 1 до 24 месяцев",
        "badTime": "время ребута — чч:мм",
        "badPort": "порт — от 1 до 65535",
        "badIface": "интерфейса {iface} в системе нет",
        "selfOutside": "{ip} не входит в сеть {lan}",
        "portBusy": "порт {port} уже занят — панель не поднимется на нём",
        "colNow": "сейчас",
        "byDay": "по дням",
        "byHour": "за сутки",
        "byMonth": "по месяцам",
        "locale": "ru-RU",
        "cumul": "накопительно",
        "vsPrev": "к прошлому месяцу",
        "noHours": "часы копятся с запуска панели — подождите немного",
        "showAll": "показать все",
        "showInChart": "Показать в графике",
        "sysTitle": "Машина",
        "sCpu": "процессор",
        "sMem": "память",
        "sSwap": "подкачка",
        "sDisk": "диск",
        "sNetIf": "интерфейс {iface}",
        "sLoad": "нагрузка",
        "sTemp": "температура",
        "sUptime": "аптайм",
        "cores": "ядер {n}",
        "sysNone": "эта система не отдаёт метрики",
        "tempWhat": "Датчик {n} — самый горячий из тех, что ядро показывает "
                    "в /sys/class/thermal. Их несколько, и меряют они разное: "
                    "пакет процессора, чипсет, диск.",
        "perSec": "/с",
        "dShort": "д",
        "hShort": "ч",
        "other": "прочее",
        "otherWhat": "Трафик адресов, которых в списке уже нет. История привязана "
                     "к адресу и переживает удаление устройства, поэтому байты "
                     "остаются в итогах месяца — но приписать их больше некому. "
                     "Сюда же попадает всё, что было учтено до того, как адрес "
                     "добавили заново.",
        "filter": "фильтр",
        "noMatch": "под фильтр ничего не подошло",
        "csvWhat": "скачать таблицу за выбранный месяц",
        "offline": "нет связи, данные от {t}",
        "updateWhat": "что изменилось",
        "dotLive": "трафик идёт",
        "dotQuiet": "тихо",
        "rolled": "подробности по дням за этот месяц свёрнуты — остался только итог",
    },
    "en": {
        "title": "Gateway",
        "h1": "Devices through the gateway",
        "logout": "log out",
        "close": "Close",
        "total": "total",
        "inbound": "inbound",
        "outbound": "outbound",
        "perDay": "daily average",
        "devicesTitle": "Devices",
        "colAddr": "address",
        "colName": "name",
        "colTraffic": "traffic",
        "colSeen": "activity",
        "sortBy": "Sort",
        "sortAsc": "Sort: ascending",
        "sortDesc": "Sort: descending",
        "addDevice": "Add device",
        "phName": "name device",
        "add": "add",
        "hint": "Set manually on the device: gateway <b>{{GW}}</b>, netmask "
                "<b>{{MASK}}</b> (Android and Quest ask for prefix length — "
                "<b>{{PFX}}</b>), DNS <b>1.1.1.1</b>. Anything not on the list does not "
                "route through the gateway at all. &ldquo;Turn off&rdquo; keeps a device "
                "listed with its name and history, but closes its way out. A device is "
                "remembered by its hardware address: if DHCP moves it to another "
                "address, the entry follows it there with all of its history.",
        "blockedTitle": "Knocked, not allowed",
        "blockedHint": "The kernel recorded the addresses whose packets it dropped "
                       "in the last 6 hours.",
        "noData": "no data for this month yet",
        "youAre": "You",
        "turnOff": "turn off",
        "turnOn": "turn on",
        "vpnOff": "no VPN",
        "vpnOn": "via VPN",
        "vpnWhat": "Let the device past the tunnel: it keeps its internet, but "
                   "goes straight out through the gateway instead of through "
                   "the VPN. Its packets are stamped with an fwmark the tunnel "
                   "leaves alone — the mark is \"vpn_mark\" in config.json.",
        "del": "delete",
        "tmFor": "for a while",
        "tmWhat": "Turn off or on for a while: when the time is up the device goes "
                  "back to the state it stands in now. It is as precise as the "
                  "counter poll interval.",
        "tm15": "15 minutes",
        "tm1h": "1 hour",
        "tm3h": "3 hours",
        "tm8h": "8 hours",
        "tmMorning": "until 07:00",
        "tmLeftM": "{n} min left",
        "tmLeftH": "{n} h left",
        "tmCancel": "drop the timer and leave it as it is",
        "badTimer": "a timer is a minute to a week",
        "badBypass": "the gateway may stand open for {n} h at most",
        "tm5": "5 minutes",
        "byp": "let everyone in",
        "bypOn": "open to everyone",
        "bypWhat": "For that long the gateway lets everything through, the "
                   "devices that are not on the list included. The accounting "
                   "carries on, and the kernel goes on recording who came — when "
                   "the time is up they are in the list at the bottom, and any of "
                   "them is one click from being allowed for good.",
        "confirmByp": "Let everything through the gateway? For that long the list "
                      "does not apply — any device on the network gets out.",
        "allOff": "turn everyone off",
        "allOn": "turn everyone on",
        "allWhat": "Except your own address",
        "confirmAllOff": "Close the way out for every device? Your own address "
                         "stays on, and the same button brings the rest back.",
        "useHost": "name it the way it introduces itself to the network: {n}",
        "clashTitle": "Another device is on that address",
        "clashLine": "listed as {a}, answers as {b}",
        "clashHint": "The rule allows an address, and different hardware is "
                     "answering from it — so what routes through the gateway is "
                     "not what you allowed. Usually a static address that DHCP "
                     "has handed out to somebody else as well. The simplest fix "
                     "is to move one of the two.",
        "macRandom": "randomised address",
        "empty": "empty — nobody routes through the gateway right now",
        "confirmDel": "Delete {ip}? Its traffic history stays.",
        "confirmDelMe": "Delete {ip}? That is your own address — you will lose internet "
                        "through the gateway, but the panel stays reachable and you can "
                        "add yourself back.",
        "b": " B", "kb": " KB", "mb": " MB", "gb": " GB",
        "now": "now",
        "minAgo": "{n} min ago",
        "hAgo": "{n} h ago",
        "dAgo": "{n} d ago",
        "loginTitle": "Gateway — sign in",
        "panelTitle": "Gateway panel",
        "password": "password",
        "signIn": "sign in",
        "wrongPw": "Wrong password.",
        "loggedOut": "Signed out.",
        "tooMany": "Too many attempts. Wait a minute.",
        "noPw": "No password set. On the gateway: panel.py --set-password",
        "needLogin": "sign in required",
        "badIp": "{ip}: expected a client address from {lan}, not the gateway itself",
        "pwSaved": "password saved",
        "noIface": "interface {iface} does not exist — fix iface in {cfg}",
        "noPwWarn": "WARNING: no password set, the panel will let nobody in. "
                    "Set one: {cmd} --set-password",
        "cfgUnreadable": "{cfg} is readable by root only — falling back to defaults",
        "pwShort": "password shorter than 8 characters",
        "updateTitle": "Update available",
        "updateNew": "Version {v} is out, you have {{VERSION}}.",
        "updateHint": "The button downloads the release from GitHub and runs the "
                      "same <code>install.sh</code>, answering it with the "
                      "settings you already have. Your device list and "
                      "statistics are left alone. By hand: <code>git pull</code> "
                      "then <code>sudo ./install.sh</code>. The check can be "
                      "turned off in the settings.",
        "updateNow": "Install now",
        "updateConfirm": "Download {v} and install it? The panel restarts itself.",
        "updating": "The update has started. The panel will restart — reload the "
                    "page in a minute or two.",
        "updateNone": "There is no update.",
        "updateFound": "Version {v} is out.",
        "updateFail": "GitHub did not answer. Check the link and try later.",
        "updateLog": "How it went: {{UPDLOG}}",
        "settingsTitle": "Settings",
        "groupGeneral": "General",
        "groupNet": "Network",
        "groupVpn": "Tunnels",
        "vpnSubscription": "Subscription",
        "vpnWireGuard": "WireGuard",
        "vpnAmneziaWG": "AmneziaWG",
        "vpnName": "name",
        "vpnNamePh": "for example, Frankfurt",
        "vpnUrl": "HTTPS link",
        "vpnExclude": "exclude nodes",
        "vpnExcludePh": "optional regular expression",
        "vpnConfig": "configuration",
        "vpnConfigPh": "paste the complete .conf file",
        "vpnAdd": "add tunnel",
        "vpnEmpty": "no tunnels yet",
        "vpnLoading": "loading…",
        "vpnDirect": "Traffic is currently going direct",
        "vpnClosed": "Forwarding is closed: the active tunnel is down",
        "vpnRunning": "Active: {kind}",
        "vpnStopped": "tunnel stopped",
        "vpnEnabled": "enabled",
        "vpnDisabled": "disabled",
        "vpnNodes": "nodes: {n}",
        "vpnEnable": "enable",
        "vpnDisable": "disable",
        "vpnRefresh": "refresh",
        "vpnDelete": "delete",
        "vpnConfirmDisable": "Disable the last active tunnel? Traffic will go direct.",
        "vpnConfirmDelete": "Delete this tunnel and its saved data? If it is active, the connection will switch.",
        "vpnIpv6": "The configuration has no full IPv6 route",
        "vpnHint": "A new tunnel is saved disabled first. Subscriptions may be "
                   "enabled together; WireGuard or AmneziaWG replaces them as "
                   "the only active backend. Configuration hooks are forbidden.",
        "vpnBusy": "Applying…",
        "vpnSaved": "Done",
        "vpnBadForm": "Fill in the name and the data required for this type.",
        "vpnErrMissing": "the profile file is missing",
        "vpnErrTool": "the required program is not installed",
        "vpnErrStopped": "the tunnel is stopped",
        "vpnErrStart": "the tunnel could not be started",
        "vpnErrValidation": "the configuration or subscription failed validation",
        "vpnErrRollback": "rollback did not finish; forwarding remains closed",
        "vpnErrConflict": "another tunnel is active; the operation was cancelled",
        "vpnErrInvalid": "the tunnel state is damaged",
        "vpnErrLegacy": "the old subscription works but has not been refreshed by the panel",
        "groupMaint": "Maintenance",
        "groupPw": "Password",
        "theme": "Theme",
        "themeAuto": "Auto",
        "themeLight": "Light",
        "themeDark": "Dark",
        "sLang": "panel language",
        "sUpdate": "tell me about new versions",
        "sNotify": "and pop up a browser notification",
        "sNotifyHint": "While a tab is open, a new version arrives as a browser "
                       "notification — if the browser allows them and the page "
                       "came over https or from localhost; over plain http on a "
                       "network address the browser withholds notifications "
                       "entirely. Where it does, a dot appears in the tab title "
                       "instead. A version is announced once, not on every poll.",
        "notifyBody": "Version {v} is out. Open the panel to install it.",
        "sCheck": "check for an update",
        "sCheckHint": "The panel already asks GitHub once a day. By hand: once a "
                      "minute at most, and sparingly even then — GitHub counts "
                      "requests per address (60 an hour), and spending them "
                      "stops the daily check from getting an answer too.",
        "sPoll": "counter poll, s",
        "sKeep": "keep day by day, months",
        "sKeepWhat": "How many months keep their day-by-day breakdown. Older "
                     "ones are folded into one figure per month: monthly and "
                     "per-device totals stay exact to the byte, only the daily "
                     "chart goes. Lowering this folds what is over the line at once.",
        "sIface": "interface",
        "sLan": "local network",
        "sSelfIp": "this gateway in it",
        "sPort": "panel port",
        "sPw": "new password",
        "sPwKeep": "leave the current one",
        "sSave": "save",
        "sRebootAt": "reboot every day at",
        "sRebootAtWhat": "Reboot the gateway every night at this time. It is as "
                         "precise as the poll interval: the reboot happens on "
                         "the first poll past that time.",
        "sReboot": "reboot the gateway",
        "confirmReboot": "Reboot the gateway? Every device is without internet "
                         "until it comes back up.",
        "rebooting": "The gateway is rebooting. The panel is back in a minute or two.",
        "sNetHint": "The first three are what the installer found. Change them only if "
                    "the network really moved: the nftables rules are rebuilt at once, "
                    "and devices outside the new network can no longer be added. "
                    "Changing the port restarts the panel. All of it lives in {{CFG}}.",
        "sRestart": "The port changed. The panel is restarting — open {url}",
        "badLang": "there is no {lang} language",
        "badNumber": "a number is expected here",
        "badPoll": "the poll interval is 5 to 3600 seconds",
        "badKeep": "days are kept for 1 to 24 months",
        "badTime": "the reboot time is hh:mm",
        "badPort": "the port is 1 to 65535",
        "badIface": "there is no {iface} interface on this system",
        "selfOutside": "{ip} is outside the {lan} network",
        "portBusy": "port {port} is taken — the panel would not come back up on it",
        "colNow": "now",
        "byDay": "by day",
        "byHour": "last 24 h",
        "byMonth": "by month",
        "locale": "en-GB",
        "cumul": "cumulative",
        "vsPrev": "against the previous month",
        "noHours": "hours accrue from the panel's start — give it a moment",
        "showAll": "show all",
        "showInChart": "Show in chart",
        "sysTitle": "Machine",
        "sCpu": "cpu",
        "sMem": "memory",
        "sSwap": "swap",
        "sDisk": "disk",
        "sNetIf": "interface {iface}",
        "sLoad": "load",
        "sTemp": "temperature",
        "sUptime": "uptime",
        "cores": "{n} cores",
        "sysNone": "this system exposes no metrics",
        "tempWhat": "Sensor {n} — the warmest of the ones the kernel exposes in "
                    "/sys/class/thermal. There are several, and they measure "
                    "different things: the processor package, the chipset, a disk.",
        "perSec": "/s",
        "dShort": "d",
        "hShort": "h",
        "other": "other",
        "otherWhat": "Traffic of addresses that are no longer on the list. History "
                     "is kept per address and outlives the device, so its bytes "
                     "stay in the month's totals — but there is nobody left to "
                     "attribute them to. Anything counted before an address was "
                     "added back lands here too.",
        "filter": "filter",
        "noMatch": "nothing matches the filter",
        "csvWhat": "download the selected month as a table",
        "offline": "no connection, data from {t}",
        "updateWhat": "what changed",
        "dotLive": "traffic is flowing",
        "dotQuiet": "quiet",
        "rolled": "the day-by-day detail for this month has been folded away — "
                  "only the total is left",
    },
}


def reload_conf():
    """Re-read config.json into the globals and rebuild the page.

    Called once at import and again whenever the settings form saves, so a
    changed language or network takes effect without a restart. Only the port
    cannot be picked up this way — the socket is already bound (see restart).
    """
    global CFG, LANG, T, IFACE, PORT, POLL_SEC, KEEP_MONTHS, LAN, SELF_IP, PAGE
    CFG = conf()
    LANG = CFG.get("lang") if CFG.get("lang") in STRINGS else "ru"
    T = STRINGS[LANG]
    IFACE = CFG["iface"]
    PORT = int(CFG["port"])
    POLL_SEC = int(CFG["poll_sec"])
    KEEP_MONTHS = int(CFG["keep_months"])
    LAN = ipaddress.ip_network(CFG["lan"])
    SELF_IP = ipaddress.ip_address(CFG["self_ip"])
    PAGE = render(PAGE_T)


def check_settings(body, base):
    """Validate the whole settings form and return the config to write.

    Nothing is saved unless every field passes: a half-applied network change
    is exactly how one locks oneself out of the panel. Only fields that
    actually changed are checked against the system, so a save does not fail
    because the configured interface happens to be down.
    """
    c = dict(base)
    lang = str(body.get("lang", c["lang"]))
    if lang not in STRINGS:
        raise ValueError(T["badLang"].replace("{lang}", lang))
    c["lang"] = lang
    c["update_check"] = bool(body.get("update_check", c["update_check"]))
    c["update_notify"] = bool(body.get("update_notify", c["update_notify"]))

    try:
        poll_sec = int(body.get("poll_sec", c["poll_sec"]))
        port = int(body.get("port", c["port"]))
        keep = int(body.get("keep_months", c["keep_months"]))
    except (TypeError, ValueError):
        raise ValueError(T["badNumber"])
    if not 5 <= poll_sec <= 3600:
        raise ValueError(T["badPoll"])
    if not 1 <= port <= 65535:
        raise ValueError(T["badPort"])
    if not 1 <= keep <= 24:
        raise ValueError(T["badKeep"])
    c["poll_sec"], c["port"], c["keep_months"] = poll_sec, port, keep

    # The hour is kept whether the reboot is on or off — turning the switch back
    # on should find the time that was there before, not an empty field. Stored
    # normalised, because <input type=time> will not show "5:30".
    try:
        at = time.strftime("%H:%M", time.strptime(
            str(body.get("reboot_at", c["reboot_at"])).strip(), "%H:%M"))
    except ValueError:
        raise ValueError(T["badTime"])
    c["reboot"], c["reboot_at"] = bool(body.get("reboot", c["reboot"])), at

    iface = str(body.get("iface", c["iface"])).strip()
    if iface != base["iface"] and not os.path.isdir(f"/sys/class/net/{iface}"):
        raise ValueError(T["badIface"].replace("{iface}", iface))
    c["iface"] = iface

    # ip_network is strict: 192.168.1.5/24 is rejected, and that is the point —
    # a network with host bits set would quietly drop devices out of validate().
    lan = ipaddress.ip_network(str(body.get("lan", c["lan"])).strip())
    self_ip = ipaddress.ip_address(str(body.get("self_ip", c["self_ip"])).strip())
    if self_ip not in lan:
        raise ValueError(T["selfOutside"].replace("{ip}", str(self_ip))
                                         .replace("{lan}", str(lan)))
    c["lan"], c["self_ip"] = str(lan), str(self_ip)

    if port != base["port"]:
        # A port already taken would crash the restarted process, and systemd
        # would keep restarting it — the panel would be gone for good.
        with socket.socket() as s:
            try:
                s.bind(("", port))
            except OSError:
                raise ValueError(T["portBusy"].replace("{port}", str(port)))
    return c


def stop(*_):
    """Everything that must reach the disk before this process goes away."""
    with _lock:
        flush(force=True)


def restart():
    """Replace this process, the only way to bind a changed port."""
    # ponytail: a fixed delay instead of a shutdown handshake — long enough for
    # the reply to leave, and the browser is told to reconnect by hand anyway.
    def go():
        stop()
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Timer(0.7, go).start()


def reboot_host():
    """Reboot the machine the panel runs on.

    The same delay as restart(), for the same reason. Nothing is flushed here:
    systemd stops the service on the way down and the SIGTERM handler does it,
    exactly as it would for a `systemctl reboot` typed at the shell.
    """
    threading.Timer(0.7, lambda: subprocess.run(["systemctl", "reboot"])).start()


def uptime():
    """Seconds since this machine booted, 0 where that cannot be answered."""
    # ponytail: /proc, not a boot-time constant — on anything that is not Linux
    # (a Mac running --selftest) 0 means the scheduled reboot never fires, which
    # is the right answer there anyway.
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return 0.0


def reboot_due(at, now, up, window):
    """Whether the daily reboot time fell inside the window just polled.

    `at` is the hour to go down at, or anything falsy for a switch that is off.

    No cron, no timer unit: the poller is already awake every POLL_SEC, and a
    scheduler that lives in config.json is one the settings form can change
    without touching the host. The window has to be a poll long — the tick
    lands where it lands, not on the minute — so what stops the machine from
    going down again the moment it comes back up is `up`: nothing here fires in
    the first two hours of a boot, and a window is at most one hour and a bit.
    """
    if not at:
        return False
    try:
        h, m = str(at).split(":")
        target = int(h) * 3600 + int(m) * 60
    except ValueError:
        # The form cannot write anything but hh:mm, a text editor can. Junk here
        # means "never" — an exception would take the poller thread with it.
        return False
    since_midnight = now.tm_hour * 3600 + now.tm_min * 60 + now.tm_sec
    return up > 2 * 3600 and 0 <= since_midnight - target < window


_devs = {"mtime": None, "val": []}


def _devs_stamp():
    """When the device list on disk was last written, or None if there is none.

    The poller reads the list, spends a moment deciding what to do with it and
    writes the whole of it back; a button pressed in that moment lands in the
    file and is then overwritten by a list that predates it. Compared before
    the write, this says the poller lost the race and should let go.
    """
    try:
        return os.stat(DEVICES).st_mtime_ns
    except OSError:
        return None


def load():
    """The device list, re-read only when the file has changed underneath us.

    It is asked for on every poll, on every page refresh and on every button —
    the same few hundred bytes, parsed again each time. What is handed back is a
    copy of each row: callers mutate what they get and then call save(), so
    lending out the cached list itself would let a change that was never written
    take effect anyway, and a failed request would leave it behind.
    """
    try:
        m = os.stat(DEVICES).st_mtime_ns
    except OSError:
        return []
    if m != _devs["mtime"]:
        with open(DEVICES) as f:
            _devs["val"] = json.load(f)
        _devs["mtime"] = m
    return [dict(d) for d in _devs["val"]]


def save(devs):
    with open(DEVICES, "w") as f:
        json.dump(devs, f, indent=1, ensure_ascii=False)
    # Not "store what we just wrote": mtime_ns is the cheap check, and a write
    # from anywhere else has to invalidate it just the same.
    _devs["mtime"] = None
    # Every change to a device passes through here, and the answer the page is
    # about to ask for must show it — a button that takes a second to look like
    # it was pressed reads as a button that did not work.
    _state["val"] = None


def validate(ip):
    a = ipaddress.ip_address(ip.strip())  # raises ValueError on junk
    if a not in LAN or a == SELF_IP:
        raise ValueError(T["badIp"].replace("{ip}", str(a)).replace("{lan}", str(LAN)))
    return str(a)


def check_minutes(v, cap=None, bad=None):
    """The timer off the button, in minutes. 0 means "no timer".

    Minutes and not a moment: the browser knows what "until 07:00" means in the
    timezone the person is standing in, the gateway knows what time it is. Only
    one of those two is worth trusting over the wire, and it is the duration.
    """
    cap = TIMER_MAX // 60 if cap is None else cap
    bad = bad or T["badTimer"]
    try:
        m = int(v)
    except (TypeError, ValueError):
        raise ValueError(bad)
    if m and not 1 <= m <= cap:
        raise ValueError(bad)
    return m


def lan_client(ip):
    """The same question validate() answers, without raising: an address on
    this network that is not the gateway. The lease file is written by another
    program and may hold anything, IPv6 entries included — a junk line there
    must not take the whole page down."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a in LAN and a != SELF_IP


def is_mac(s):
    """A hardware address fit to be written into a rule.

    Everywhere else a MAC is a label on a page; in the ruleset it is syntax.
    Both places one comes from — the ARP cache and dnsmasq's lease file — are
    written by other programs, and a single junk field would make `nft -f`
    reject the table. Atomically, which is the bad part: the old rules stay,
    the panel goes on answering, and nothing anyone does to a device takes
    effect again.
    """
    p = str(s).split(":")
    return len(p) == 6 and all(
        len(x) == 2 and all(c in "0123456789abcdefABCDEF" for c in x) for x in p)


def cname(direction, ip):
    return f"{direction}_{ip.replace('.', '_')}"


# --- password ---------------------------------------------------------------

def pw_hash(password, salt):
    """scrypt from the standard library, parameters as recommended for logins."""
    return hashlib.scrypt(password.encode(), salt=salt,
                          n=16384, r=8, p=1, dklen=32).hex()


def set_password(password):
    if len(password) < 8:
        raise ValueError(T["pwShort"])
    salt = secrets.token_bytes(16)

    def change(c):
        c["pw"] = {"salt": salt.hex(), "hash": pw_hash(password, salt)}

    update_conf(change)


def check_password(password):
    pw = conf()["pw"]
    if not pw:
        return False
    return hmac.compare_digest(pw_hash(password, bytes.fromhex(pw["salt"])), pw["hash"])


def _tok(token):
    """What is kept on disk instead of the cookie itself: a leaked
    sessions.json then hands over nothing that can be presented as a session."""
    return hashlib.sha256((token or "").encode()).hexdigest()


def _save_sessions():
    try:
        write_private(SESSIONS, _sessions)
    except OSError:
        # A read-only /etc is not a reason to refuse a login — the session
        # simply goes back to living only in memory.
        pass


def new_session():
    t = secrets.token_urlsafe(32)
    _sessions[_tok(t)] = time.time() + SESSION_TTL
    _save_sessions()
    return t


def drop_session(token):
    if _sessions.pop(_tok(token), None) is not None:
        _save_sessions()


def session_ok(token):
    exp = _sessions.get(_tok(token))
    if exp and exp > time.time():
        return True
    drop_session(token)
    return False


def csrf_for(token):
    return hmac.new(_csrf_secret, str(token or "").encode(),
                    hashlib.sha256).hexdigest()


def _load_sessions():
    """Sessions outlive the process: an update runs install.sh, which restarts
    the service, and being thrown out of the panel by its own upgrade is the
    one moment it stings most. Expired ones are dropped on the way in."""
    try:
        with open(SESSIONS) as f:
            return {k: v for k, v in json.load(f).items() if v > time.time()}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}   # missing, or a file this program did not write


_sessions.update(_load_sessions())


def note_fail(ip):
    n, until = _fails.get(ip, (0, 0))
    n = 1 if 0 < until < time.time() else n + 1
    _fails[ip] = (n, time.time() + FAIL_BLOCK if n >= FAIL_LIMIT else until)


def fail_blocked(ip):
    return time.time() < _fails.get(ip, (0, 0))[1]


# --- nftables ---------------------------------------------------------------

def ruleset(devs, bypass=None, vpn_closed=None):
    """The whole table as one string. `bypass` is the moment the gateway stops
    letting everyone through — resolved from the config when it is not given,
    because a reload_conf()-managed value must never be frozen into a default.
    """
    # While that moment is in the future the chain keeps everything it does
    # except the verdict: the counters still run, and `update @blocked` still
    # records every address that came in past the list — so when the window
    # shuts, who used it is on the page rather than lost.
    open_now = (CFG["bypass"] if bypass is None else bypass) > time.time()
    closed = _vpn_closed if vpn_closed is None else bool(vpn_closed)
    verdict = "" if open_now else "\n    drop"
    guard = f'''\n  chain vpn_guard {{
    type filter hook forward priority raw; policy accept;
    iifname "{IFACE}" drop
  }}''' if closed else ""
    on = [d for d in devs if d.get("on", True)]
    ips = ", ".join(d["ip"] for d in on)
    elems = f"\n    elements = {{ {ips} }}" if ips else ""
    ctrs = "\n".join(f"  counter {cname(w, d['ip'])} {{ }}"
                     for d in devs for w in ("up", "down"))
    up = "\n".join(f"    ip saddr {d['ip']} counter name {cname('up', d['ip'])}"
                   for d in devs)
    down = "\n".join(f"    ip daddr {d['ip']} counter name {cname('down', d['ip'])}"
                     for d in devs)
    # "vpn": false — allowed through the gateway, but not through the tunnel.
    # A mark is the only handle this program has on something it does not own:
    # every one of them keeps a mark for its own packets, so that what it sends
    # is not swallowed by itself again — and that mark is the one thing its
    # rules step aside for. sing-box: `ip rule fwmark 0x2024 goto` past the tun
    # lookup, and `meta mark 0x2024 ... return` above its queue. wg-quick: `ip
    # rule not fwmark 51820`. Both then route the packet by the main table and
    # out of the uplink. Which is why this is set at raw — before the routing
    # decision and before any redirect chain, the two places that read it.
    # Getting the number wrong is not a no-op: sing-box's neighbouring 0x2023
    # forces the packet *into* the tun instead. Read it off the host.
    #
    # By the hardware address wherever one is known, because a device's IPv6 is
    # not in devices.json and cannot be — it is handed out by the network, there
    # are several of them and they rotate. The frame carries the same MAC either
    # way, so one rule covers both protocols. Marking only the v4 address is how
    # this first shipped, and it left every such device still leaving by the
    # tunnel over v6 while the panel said it was out.
    mark = int(CFG.get("vpn_mark") or 0)
    novpn = "".join(
        f"\n    ether saddr {d['mac']} meta mark set 0x{mark:x}"
        if is_mac(d.get("mac")) else
        f"\n    ip saddr {d['ip']} meta mark set 0x{mark:x}"
        for d in devs if not d.get("vpn", True)) if mark else ""
    # `table` before `delete` — so delete never fails on a first run.
    # priority raw (-300) — ahead of any redirect chains (auto_redirect, in the
    # case of sing-box), otherwise the verdict comes after the interception.
    # fib daddr type != unicast lets through everything addressed to the host
    # itself: SSH and the panel stay reachable even to a blocked device.
    # Counting happens before the verdict: upload on the way in, download on
    # the way out (replies go through forward, NAT does not rewrite them).
    # ponytail: a switched-off device still accrues its own doomed retries as
    # upload. A few kilobytes, and it makes the knocking visible.
    # The mark is the one thing above `meta nfproto != ipv4 accept`, because it
    # is the one thing that has to happen to an IPv6 packet too; everything
    # below that line is v4 by construction.
    return f"""\
table inet gwacl
delete table inet gwacl
table inet gwacl {{
{ctrs}
  set allowed {{
    type ipv4_addr{elems}
  }}
  set blocked {{
    type ipv4_addr
    flags dynamic,timeout
    timeout {BLOCK_TTL}s
  }}{guard}
  chain prerouting {{
    type filter hook prerouting priority raw; policy accept;
    iifname != "{IFACE}" accept{novpn}
    meta nfproto != ipv4 accept
{up}
    ip saddr @allowed accept
    fib daddr type != unicast accept
    update @blocked {{ ip saddr }}{verdict}
  }}
  chain postrouting {{
    type filter hook postrouting priority 0; policy accept;
    oifname != "{IFACE}" accept
{down}
  }}
}}
"""
# ponytail: IPv6 is neither counted nor filtered — a typical gateway has v6
# forwarding off. When it is needed: a second set and rules on ip6 saddr/daddr.
# It is *marked*, though, and that is not symmetry for its own sake: a device
# let past the tunnel over v4 while its v6 still went through it read, to every
# site that asked, as a device still sitting in the tunnel.


def nft_json(*args):
    out = subprocess.run(["nft", "-j", "list", *args],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)["nftables"]


def nft_table():
    """Everything this panel keeps in the kernel, in one call.

    The counters are wanted on every poll and the blocked set on every page
    refresh; asking for the two separately meant two `nft` processes to read one
    table. The rules come along with them — parsing a few kilobytes more of json
    is cheaper than spawning a second process.
    """
    return nft_json("table", "inet", "gwacl")


def counters(objs):
    return {o["counter"]["name"]: o["counter"]["bytes"]
            for o in objs if "counter" in o}


def _secs(v):
    """A duration out of nft's json. Some builds write 21599, others "21599s"."""
    try:
        return int(str(v).rstrip("s"))
    except (TypeError, ValueError):
        return None


def parse_blocked(objs):
    """{address: seconds since it last knocked}. Without a timeout an element
    is a string, with one it is a dict.

    The kernel re-arms the timeout on every packet it drops, so what is left of
    it says when the address last tried — the difference between somebody
    hammering the gateway right now and somebody who gave up hours ago. None
    when this build tells us nothing.
    """
    out = {}
    for o in objs:
        # By name: the table carries `allowed` as well, and its elements are
        # bare strings that would read as a list of addresses nobody let in.
        if "set" not in o or o["set"].get("name") != "blocked":
            continue
        for e in o["set"].get("elem", []):
            if not isinstance(e, dict):
                out[e] = None
                continue
            left = _secs(e["elem"].get("expires"))
            ttl = _secs(e["elem"].get("timeout")) or BLOCK_TTL
            out[e["elem"]["val"]] = None if left is None else max(0, ttl - left)
        break
    return out


_blk = {"set": {}}


def note_blocked(objs):
    """Keep what the poll just read of the dynamic set."""
    _blk["set"] = parse_blocked(objs)


def blocked():
    """The dynamic set as of the last poll.

    Nothing is read here: every page refresh polls first, and that reading
    already carried the set with it. A set with a six-hour timeout has nothing
    new to say in the two seconds the poll window holds anyway.
    """
    return _blk["set"]


def apply(devs):
    poll(force=True)  # sample the counters before the rebuild zeroes them
    with _lock:
        # ...and get that reading onto the disk. The rebuild zeroes the
        # counters, so a baseline older than this sampling would read the drop
        # as a reset and lose whatever stood between the two.
        flush(force=True)
    subprocess.run(["nft", "-f", "-"], input=ruleset(devs), text=True, check=True)
    _blk["set"] = {}  # the rebuild emptied the set; the next poll refills it
    # The baseline is deliberately left alone: after the rebuild a counter is
    # below it, and accrue reads that as a reset and returns zero.


def bypass_until(when):
    """Hold the gateway open until then, or shut it again with 0.

    CFG itself, not a copy: it is what ruleset() reads, and the two must not be
    able to disagree. The caller rebuilds the table.
    """
    when = int(when)
    update_conf(lambda c: c.__setitem__("bypass", when))
    CFG["bypass"] = when


def flip_all(devs, on, mine=""):
    """Switch every device at once, except the address that asked.

    The panel offers this as one button, and a button that can take the
    internet away from the person pressing it, on a page that then has to be
    used to give it back, is a button that will be pressed exactly once.
    """
    for d in devs:
        if d["ip"] != mine:
            d["on"], d["until"] = on, 0
    return devs


def expire(now=None):
    """Flip back whatever a timer was set on. True if the ruleset changed.

    One field per device carries it: `until` is the moment the state it stands
    in now runs out. Which way it flips is not stored, because it is not needed
    — a timer always undoes what set it, so "off until seven" and "on for an
    hour" are the same field and the same line of code.

    Called from the poller, so it is as precise as poll_sec — same as the
    nightly reboot, and for the same reason: a thread that wakes on a schedule
    is the whole mechanism, and a second one would not be worth its own bugs.
    """
    now = int(time.time() if now is None else now)
    stamp = _devs_stamp()
    devs = load()
    due = [d for d in devs if 0 < d.get("until", 0) <= now]
    over = 0 < CFG["bypass"] <= now      # the open gateway, shutting again
    if not due and not over:
        return False
    if due and _devs_stamp() != stamp:
        return False     # written from under us; the next tick reads it again
    for d in due:
        d["on"], d["until"] = not d.get("on", True), 0
    if due:
        save(devs)
    if over:
        bypass_until(0)
    apply(devs)
    return True


# --- traffic accounting -----------------------------------------------------

def accrue(prev, cur):
    """Counter increment. A drop means a table rebuild or a reboot."""
    return cur if cur < prev else cur - prev


def _load_json(path, empty):
    """One of our two data files, or `empty` when there is nothing to read.

    A file that is not json used to take the panel down on every start, and
    systemd would restart it into the same crash for ever. It is written
    atomically now, so this can only be damage done by a version that did not,
    or by something outside this program — either way, saying so once and
    carrying on beats a boot loop nobody can see the reason for.
    """
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return empty
    except (ValueError, OSError) as e:
        print(f"gateway-acl: {path}: {e}", file=sys.stderr)
        return empty


def _read_history():
    """Both files, joined back into the one dict the rest of this program reads.

    The day in progress is whatever today.json says: it is the file that is
    kept up to date, and traffic.json holds a copy of that day only until the
    rollover rewrites it. Upgrading from a single-file version lands here with
    no today.json at all — traffic.json still has today, `seen` and `last` in
    it, and the first flush moves them across.
    """
    h = _load_json(TRAFFIC, {"days": {}})
    if "days" not in h:  # old format: month keys straight in the root
        h = {"days": h}
    h.setdefault("seen", {})
    h.setdefault("last", {})
    hot = _load_json(TODAY, {})
    if hot.get("date"):
        h["days"][hot["date"]] = hot.get("day", {})
        h["seen"], h["last"] = hot.get("seen", {}), hot.get("last", {})
    return h


_hist = None            # the history itself; the files are a copy taken now and then
_flushed = 0.0          # when that copy was last brought up to date
_dirty = False          # whether it is behind
_cold = False           # ...and whether the closed days behind it moved too
_hot_date = None        # the day the hot file is holding


def history():
    """The traffic history, read from disk once and then kept in memory.

    Both halves of it have to move together: the day buckets and `last`, the
    baseline the increments are measured from. Re-reading the file after a poll
    that was not written would hand back a stale baseline, and the same bytes
    would be counted a second time into the hourly chart and the rate.

    Callers must hold _lock. Readers that do not want to hold it use snapshot().
    """
    global _hist
    if _hist is None:
        _hist = _read_history()
    return _hist


def snapshot():
    """A private copy for a reader outside the lock.

    poll() mutates the live history in place — a new day, a device seen for the
    first time — and iterating it from an HTTP thread at that moment is how a
    page refresh crashes on "dictionary changed size during iteration". One
    level deep is all state() reads.
    """
    with _lock:
        h = history()
        return {"days": {k: dict(v) for k, v in h["days"].items()},
                "seen": dict(h["seen"])}


def flush(force=False):
    """Write the history out, at most every FLUSH_EVERY seconds. Holds _lock.

    Buffering costs nothing on a clean stop — SIGTERM flushes — and nothing
    even on a kill: the baseline on disk is exactly as old as the totals beside
    it, so the next poll measures the increment from there and lands on the
    same figure. Only losing the kernel's counters at the same moment, which
    means a reboot or a power cut, costs the last FLUSH_EVERY seconds.

    Two files, because only one of them changes. Today's bucket, `seen` and the
    baseline are a kilobyte or so and have to be written every FLUSH_EVERY
    seconds; the months behind them are a hundred times that and cannot change
    until midnight. Writing them together meant rewriting a year of history to
    record the last five minutes — hundreds of megabytes a day onto the flash
    of a machine that is never turned off. So traffic.json is written when a
    day closes or a month is folded, and today.json on the clock.
    """
    global _flushed, _dirty, _cold
    if not _dirty or (not force and time.time() - _flushed < FLUSH_EVERY):
        return False
    if _cold:
        write_atomic(TRAFFIC, {"days": {k: v for k, v in _hist["days"].items()
                                        if k != _hot_date}})
        _cold = False
    write_atomic(TODAY, {"date": _hot_date, "day": _hist["days"].get(_hot_date, {}),
                         "seen": _hist["seen"], "last": _hist["last"]})
    _flushed, _dirty = time.time(), False
    return True


def apply_deltas(cur, last, day, devs):
    """Add the counters' increment into the day's bucket.

    `last` is the baseline of readings, updated in place. It has to survive a
    restart of the process, or the entire content of the counters gets counted
    a second time. Returns {address: [up, down]} for whatever moved.
    """
    moved = {}
    for d in devs:
        ip = d["ip"]
        row = day.setdefault(ip, [0, 0])
        got = [0, 0]
        for i, w in enumerate(("up", "down")):
            key = cname(w, ip)
            n = cur.get(key)
            if n is None:
                continue
            delta = accrue(last.get(key, 0), n)
            row[i] += delta
            got[i] = delta
            last[key] = n
        if got[0] or got[1]:
            moved[ip] = got
    return moved


_rate = {}              # ip -> [up B/s, down B/s], what the panel calls "now"
_pend = {}              # bytes seen since the window the rates were last cut on
_rate_at = time.time()
_hours = {}             # "YYYY-MM-DD HH" -> {ip: [up, down]}, memory only


def rates(moved, devs, now):
    """Turn the increment into bytes per second.

    poll() runs both on the poller's tick and on every page refresh, so the
    gap between two calls is anything from a second to a minute. Increments
    are therefore held in `_pend` until the window is wide enough to divide by
    — otherwise two refreshes in a row would report a wild number, or drop the
    bytes that fell between them on the floor.
    """
    global _rate_at
    for ip, (u, d) in moved.items():
        p = _pend.setdefault(ip, [0, 0])
        p[0] += u
        p[1] += d
    dt = now - _rate_at
    if dt < POLL_MIN:
        return
    _rate_at = now
    _rate.clear()
    for d in devs:
        u, dn = _pend.get(d["ip"], (0, 0))
        # Whole bytes: a rate is a measurement over a ragged window, and the
        # fraction is noise the page would faithfully print to ten decimals.
        _rate[d["ip"]] = [round(u / dt), round(dn / dt)]
    _pend.clear()


def note_hour(moved, key=None):
    """Keep the last 24 hourly buckets, per device.

    ponytail: memory only, so a restart of the service starts the day over.
    Storing them would multiply today.json by twenty-four, and that is the file
    written every FLUSH_EVERY seconds, for a chart whose whole point is the
    last day — the month is already on disk.
    """
    bucket = _hours.setdefault(key or time.strftime("%Y-%m-%d %H"), {})
    for ip, (u, d) in moved.items():
        row = bucket.setdefault(ip, [0, 0])
        row[0] += u
        row[1] += d
    for old in sorted(_hours)[:-24]:
        del _hours[old]
    return bucket


def rekey(old, new):
    """Carry one address's traffic history over to another. Holds _lock.

    Everything the history knows is filed under an address: the day buckets, the
    hour buckets, when it was last seen. A device that DHCP has moved keeps none
    of that unless it is carried across — its month would start again from zero
    and its past would surface as "other", which is exactly the pair of symptoms
    that reads as the panel having lost the data.

    The baseline is dropped rather than moved: the new address gets new counters
    and they start at zero.
    """
    global _dirty, _cold
    with _lock:
        h = history()
        for bucket in list(h["days"].values()) + list(_hours.values()):
            row = bucket.pop(old, None)
            if row:
                into = bucket.setdefault(new, [0, 0])
                into[0] += row[0]
                into[1] += row[1]
        if old in h["seen"]:
            h["seen"][new] = max(h["seen"].pop(old), h["seen"].get(new, 0))
        for w in ("up", "down"):
            h["last"].pop(cname(w, old), None)
        _rate.pop(old, None)
        _pend.pop(old, None)
        # A closed day may have just changed hands, so the cold file moves too.
        _dirty = _cold = True


def roll_up(days, month, keep=None):
    """Fold the day buckets of long-past months into one figure per month.

    A month key is a shape this program already reads: month_totals counts it,
    and the per-day chart skips it on key length. So the monthly totals and the
    strip below the chart stay exact to the byte; what is given up is the
    day-by-day chart of a month older than `keep`.

    Without this, days accumulate for ever in a file every start has to read.
    Returns how many day buckets were folded. `keep` defaults to the setting at
    call time, not at import time: it is a number the user can lower, and a
    default argument would have frozen the one that was there at startup.
    """
    cut = month
    keep = KEEP_MONTHS if keep is None else keep
    for _ in range(keep):
        cut = prev_month(cut)
    old = [k for k in days if len(k) == 10 and k[:7] <= cut]
    for k in old:
        into = days.setdefault(k[:7], {})
        for ip, (u, d) in days.pop(k).items():
            row = into.setdefault(ip, [0, 0])
            row[0] += u
            row[1] += d
    return len(old)


_polled = 0.0


def poll(force=False):
    """Sample the nftables counters and add the increment to today.

    Called on the poller's tick and by every page refresh — every open tab, four
    times a minute. Two of them a second apart would run nft twice to learn the
    same thing, so anything inside POLL_MIN is dropped. apply() forces its way
    through: that call exists to read the counters before the rebuild zeroes
    them, and skipping it would lose whatever they hold.
    """
    global _polled, _dirty, _cold, _hot_date
    with _lock:
        now = time.time()
        if not force and now - _polled < POLL_MIN:
            return
        _polled = now
        try:
            objs = nft_table()
        except (OSError, subprocess.CalledProcessError, ValueError, KeyError):
            return  # no table yet — first run
        cur = counters(objs)
        note_blocked(objs)   # the same reading carries the dynamic set
        h = history()
        today = time.strftime("%Y-%m-%d")
        if _hot_date != today:
            # Midnight, or the first poll of this process. Yesterday is a closed
            # day now and closed days live in the cold file — which is also the
            # only moment a month can have aged past keep_months, so this is
            # where the fold belongs rather than on every poll of the day.
            _hot_date, _cold = today, True
            _dirty = True   # even an idle rollover has to reach the disk
            roll_up(h["days"], time.strftime("%Y-%m"))
        was = dict(h["last"])
        day = h["days"].setdefault(today, {})
        devs = load()
        moved = apply_deltas(cur, h["last"], day, devs)
        for ip in moved:
            h["seen"][ip] = int(now)
        note_hour(moved)
        rates(moved, devs, now)
        # Counters of removed devices are not kept in the baseline.
        h["last"] = {k: v for k, v in h["last"].items() if k in cur}
        # Nothing moved means nothing to record: a delta of zero leaves the day,
        # `seen` and the baseline exactly as they were. What did change waits in
        # memory until flush() decides the file has lagged long enough.
        if moved or h["last"] != was:
            _dirty = True
        flush()


def refold():
    """Apply a lowered keep_months now instead of at the next rollover.

    The fold itself belongs at midnight — nothing can age past the line inside a
    day. But someone who has just cut the retention did it to get the space
    back, and telling them to wait until tomorrow for a number they typed
    themselves is the kind of thing that reads as broken.
    """
    global _dirty, _cold
    with _lock:
        if roll_up(history()["days"], time.strftime("%Y-%m")):
            _dirty = _cold = True
            flush(force=True)


def _ver(s):
    """A release tag as a comparable tuple: v1.2 -> (1, 2, 0, 0).

    None when the tag is not a plain numeric version. The padding is what makes
    1.2 and 1.2.0 the same release instead of the former looking older forever.
    """
    try:
        return (tuple(int(p) for p in s.strip().lstrip("vV").split(".")) + (0, 0, 0))[:4]
    except ValueError:
        return None


def newer(tag, cur=VERSION):
    """The tag worth announcing, or None. Equal, older and odd tags are silence."""
    new, old = _ver(tag), _ver(cur)
    return tag.strip() if new and old and new > old else None


def check_update(force=False):
    """Ask GitHub, at most once a day, whether a newer release is tagged.

    `force` is the button: it asks regardless of the day gate and regardless of
    "update_check", because somebody who clicked wants an answer now. It returns
    True when GitHub answered, False when it did not and None when the check was
    skipped — the button has to say which of the three happened, the poller
    ignores all of it.

    Every failure is silence: a gateway that cannot reach the internet is a
    supported setup, not a fault to report on the panel. The timestamp is
    written before the request, so an unreachable GitHub is tried once a day
    too, not once a minute. The whole body is inside the try — this runs in the
    poller thread, and an answer of an unexpected shape must not take the
    traffic counters down with it.
    """
    if not force and (not CFG.get("update_check", True)
                      or time.time() - _upd["at"] < UPDATE_EVERY):
        return None
    _upd["at"] = time.time()
    try:
        req = urllib.request.Request(RELEASES_URL, headers={
            "Accept": "application/vnd.github+json",
            # GitHub answers 403 to a request without a User-Agent.
            "User-Agent": f"gateway-acl/{VERSION}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            _upd["new"] = newer(json.loads(r.read(1 << 20)).get("tag_name") or "")
        return True
    except Exception:
        return False


# --- installing an update ---------------------------------------------------

# One at a time: a second click while the first download runs is not a second
# install. Held for the whole of install_update(), released when the installer
# has been handed off — by which point this process is about to be replaced.
_updating = threading.Lock()


def tar_url(tag):
    """The address of a release tarball, or ValueError.

    Everything but the tag is a constant, and the tag has to look like a version
    and nothing else. This is the whole of what keeps GitHub's answer from
    choosing what a root process downloads and runs: a path, a query or another
    host arriving in `tag_name` must not survive this function.
    """
    if not re.fullmatch(r"v?[0-9]+(\.[0-9]+){0,3}", str(tag or "")):
        raise ValueError(f"tag {tag!r} is not a version")
    return TARBALL + tag


def _safe_members(tf):
    """The regular files of an archive, with nothing that writes outside it.

    Not tarfile's `filter=`: that arrived in 3.12 and the gateway runs whatever
    python it has. Absolute paths, paths climbing out with `..`, symlinks and
    devices are dropped rather than repaired — a release tarball has no business
    containing any of them.
    """
    for m in tf.getmembers():
        if not m.isfile():
            continue
        name = os.path.normpath(m.name)
        if os.path.isabs(name) or name.startswith(".."):
            continue
        yield m


def fetch_release(tag, dest):
    """Download and unpack a release into `dest`, returning its directory."""
    req = urllib.request.Request(tar_url(tag), headers={
        "User-Agent": f"gateway-acl/{VERSION}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        # urllib follows redirects on its own; the answer must still come from
        # the host asked for, or the constant above guarantees nothing.
        if urlparse(r.url).hostname != urlparse(TARBALL).hostname:
            raise ValueError(f"redirected to {urlparse(r.url).hostname}")
        data = r.read(TAR_MAX + 1)
    if len(data) > TAR_MAX:
        raise ValueError("the tarball is larger than a release has any right to be")
    path = os.path.join(dest, "release.tar.gz")
    with open(path, "wb") as f:
        f.write(data)
    with tarfile.open(path) as tf:
        tf.extractall(dest, list(_safe_members(tf)))
    os.remove(path)
    roots = [d for d in os.listdir(dest) if os.path.isdir(os.path.join(dest, d))]
    if len(roots) != 1:
        raise ValueError(f"expected one directory in the archive, got {len(roots)}")
    return os.path.join(dest, roots[0])


def install_update(tag):
    """Fetch the announced release and hand it to install.sh.

    Two checks stand between the download and root running it: the code has to
    say it is the version that was announced, and its own selftest has to pass.
    Neither is a signature — what they buy is that a truncated or mislabelled
    tarball is refused before anything on the host is replaced.

    The installer is started detached and outlives this process on purpose: its
    last steps restart the service, which kills the panel that asked for it.
    Progress and failure go to UPDATE_LOG, because after the restart there is
    nobody left to tell.
    """
    if not _updating.acquire(blocking=False):
        return
    tmp = tempfile.mkdtemp(prefix="gwacl-update-")
    try:
        with open(UPDATE_LOG, "a") as log:
            log.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} "
                      f"{VERSION} -> {tag}\n")
            log.flush()
            try:
                src = fetch_release(tag, tmp)
                said = subprocess.run(
                    [sys.executable, os.path.join(src, "panel.py"), "--version"],
                    capture_output=True, text=True, timeout=30).stdout.strip()
                if _ver(said) != _ver(tag):
                    raise ValueError(f"the archive is {said!r}, the tag is {tag!r}")
                subprocess.run(
                    [sys.executable, os.path.join(src, "panel.py"), "--selftest"],
                    check=True, stdout=log, stderr=log, timeout=300)
                log.write("selftest ok, running install.sh\n")
                log.flush()
                # Not removed on success: the installer is still reading it.
                # /tmp, so a reboot clears what a failed run left behind.
                subprocess.Popen(
                    ["bash", os.path.join(src, "install.sh"), "--yes",
                     "--lang", LANG],
                    cwd=src, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    start_new_session=True)
                tmp = None
            except Exception as e:
                log.write(f"не установлено / not installed: {e}\n")
    except OSError:
        pass                                  # a log that cannot be written is
    finally:                                  # not a reason to keep the lock
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        _updating.release()


# --- tunnels ----------------------------------------------------------------

VPN_MAX = 128 << 10
SUB_URL_MAX = 4096
TUNNEL_ID_RE = re.compile(r"t[0-9a-f]{12}\Z")
TUNNEL_KINDS = ("subscription", "wireguard", "amneziawg")
TUNNEL_SUFFIXES = (".json", ".conf")
QUICK_TOOLS = {"wireguard": "wg-quick", "amneziawg": "awg-quick"}
AWG_KEYS = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
            "h1", "h2", "h3", "h4"}
FORBIDDEN_QUICK = {"preup", "postup", "predown", "postdown", "saveconfig"}
SAFE_VPN_ERRORS = {
    "", "legacy/no-cache", "missing-secret", "tool-missing", "stopped",
    "start-failed", "validation-failed", "rollback-failed", "conflict",
    "invalid-state",
}
VPN_COMMANDS = {"sing-box", "systemctl", "wg", "awg", "wg-quick",
                "awg-quick", "ip", "nft"}


class VpnError(ValueError):
    """A browser-safe tunnel failure code, never external stdout or a secret."""


def check_tunnel_id(value):
    value = str(value or "")
    if not TUNNEL_ID_RE.fullmatch(value):
        raise ValueError("invalid tunnel id")
    return value


def tunnel_path(tid, suffix):
    tid = check_tunnel_id(tid)
    if suffix not in TUNNEL_SUFFIXES:
        raise ValueError("invalid tunnel file type")
    return os.path.join(TUNNEL_DIR, tid + suffix)


def _tunnel_row(row):
    if not isinstance(row, dict):
        raise ValueError("invalid tunnel record")
    tid = check_tunnel_id(row.get("id"))
    kind = str(row.get("kind") or "")
    if kind not in TUNNEL_KINDS:
        raise ValueError("invalid tunnel type")
    name = " ".join(str(row.get("name") or "").split())[:40]
    if not name:
        raise ValueError("empty tunnel name")
    error = str(row.get("error") or "")
    if error not in SAFE_VPN_ERRORS:
        error = "invalid-state"
    try:
        nodes = max(0, int(row.get("nodes") or 0))
    except (TypeError, ValueError):
        nodes = 0
    clean = {"id": tid, "name": name, "kind": kind,
             "enabled": bool(row.get("enabled")), "error": error,
             "nodes": nodes}
    for key in ("verified", "ipv6"):
        if key in row:
            clean[key] = bool(row[key])
    return clean


def load_tunnels():
    rows = _load_json(TUNNELS, [])
    if not isinstance(rows, list):
        return []
    clean, used = [], set()
    for row in rows:
        try:
            row = _tunnel_row(row)
        except ValueError:
            continue
        if row["id"] in used:
            continue
        used.add(row["id"])
        clean.append(row)
    return clean


def save_tunnels(rows):
    clean = [_tunnel_row(row) for row in rows]
    if len({row["id"] for row in clean}) != len(clean):
        raise ValueError("duplicate tunnel id")
    write_private(TUNNELS, clean)


def new_tunnel_id(rows):
    used = {row.get("id") for row in rows if isinstance(row, dict)}
    while True:
        tid = "t" + secrets.token_hex(6)
        if tid not in used:
            return tid


def public_tunnels(rows=None, runner=None):
    """Browser-safe metadata only; `runner` is used by runtime status later."""
    del runner
    return [_tunnel_row(row) for row in (load_tunnels() if rows is None else rows)]


def vpn_public(runner=None):
    """The settings page may see status and metadata, never profile secrets."""
    rows = public_tunnels()
    try:
        backend = backend_state(rows, runner)
        backend["error"] = "" if backend["active"] or backend["kind"] == "none" \
            else "stopped"
    except VpnError as e:
        code = str(e)
        backend = {"kind": "unknown", "active": False,
                   "error": code if code in SAFE_VPN_ERRORS else "invalid-state"}
    return {"profiles": rows, "backend": backend, "closed": _vpn_closed,
            "tools": {"singbox": bool(shutil.which("sing-box")),
                      "wireguard": bool(shutil.which("wg-quick")),
                      "amneziawg": bool(shutil.which("awg-quick"))}}


def _ensure_tunnel_dir():
    os.makedirs(TUNNEL_DIR, mode=0o700, exist_ok=True)
    os.chmod(TUNNEL_DIR, 0o700)


def check_subscription(url, exclude):
    url = str(url or "").strip()
    p = urlparse(url)
    if (len(url) > SUB_URL_MAX or any(ord(c) < 32 or ord(c) == 127 for c in url)
            or p.scheme != "https" or not p.hostname):
        raise ValueError("subscription URL must use HTTPS")
    exclude = str(exclude or "")
    if len(exclude) > 128:
        raise ValueError("subscription exclusion is too long")
    try:
        re.compile(exclude, re.I)
    except re.error:
        raise ValueError("invalid subscription exclusion") from None
    return url, exclude


def load_subscription_secret(tid):
    try:
        with open(tunnel_path(tid, ".json")) as f:
            secret = json.load(f)
    except (OSError, ValueError):
        raise VpnError("missing-secret") from None
    if not isinstance(secret, dict) or not isinstance(secret.get("body"), str):
        raise VpnError("missing-secret")
    return secret


def build_singbox(rows, base=None, secrets_map=None):
    taken, outs, counts = set(), [], {}
    getter = (load_subscription_secret if secrets_map is None else
              (secrets_map if callable(secrets_map) else secrets_map.__getitem__))
    for row in rows:
        if row.get("kind") != "subscription" or not row.get("enabled"):
            continue
        tid = check_tunnel_id(row.get("id"))
        try:
            secret = getter(tid)
            one = singbox_sub.convert(
                secret["body"], exclude=secret.get("exclude"),
                prefix=f"sub-{tid}-", taken=taken)
        except VpnError:
            raise
        except Exception:
            raise VpnError("validation-failed") from None
        if not one:
            raise VpnError("validation-failed")
        counts[tid] = len(one)
        outs.extend(one)
    if not outs:
        raise VpnError("validation-failed")
    try:
        if base is None:
            try:
                with open(SINGBOX_CONFIG) as f:
                    base = json.load(f)
            except FileNotFoundError:
                return singbox_sub.fresh(outs, IFACE), counts
        return singbox_sub.merge(base, outs), counts
    except (OSError, ValueError, TypeError):
        raise VpnError("validation-failed") from None


def active_backend(rows):
    enabled = [row for row in rows if row.get("enabled")]
    subscriptions = [row for row in enabled if row.get("kind") == "subscription"]
    quick = [row for row in enabled if row.get("kind") in QUICK_TOOLS]
    if (subscriptions and quick) or len(quick) > 1:
        raise VpnError("invalid-state")
    if quick:
        return _tunnel_row(quick[0])
    if subscriptions:
        return {"kind": "singbox",
                "ids": [check_tunnel_id(row.get("id")) for row in subscriptions]}
    return None


def vpn_exec(argv, input_text=None, timeout=30, runner=None):
    if (not isinstance(argv, (list, tuple)) or not argv
            or argv[0] not in VPN_COMMANDS
            or any(not isinstance(part, str) or "\x00" in part for part in argv)):
        raise VpnError("invalid-state")
    try:
        return (runner or subprocess.run)(
            list(argv), input=input_text, capture_output=True, text=True,
            timeout=timeout, shell=False)
    except FileNotFoundError:
        raise VpnError("tool-missing") from None
    except (OSError, subprocess.TimeoutExpired):
        raise VpnError("start-failed") from None


def parse_singbox_mark(text):
    marks = set()
    for line in str(text or "").splitlines():
        if "return" not in line:
            continue
        match = re.search(
            r"\bmeta\s+mark(?:\s+&\s+(?:0x[0-9a-f]+|[0-9]+))?"
            r"\s+(?:==\s+)?(0x[0-9a-f]+|[0-9]+)\b", line, re.I)
        if match:
            marks.add(int(match.group(1), 0))
    return marks.pop() if len(marks) == 1 else 0


def backend_mark(backend, runner=None):
    if not backend:
        return 0
    kind = backend.get("kind")
    if kind == "singbox":
        result = vpn_exec(["nft", "list", "table", "inet", "sing-box"],
                          runner=runner)
        return parse_singbox_mark(result.stdout) if not result.returncode else 0
    if kind in QUICK_TOOLS:
        tool = "wg" if kind == "wireguard" else "awg"
        result = vpn_exec([tool, "show", check_tunnel_id(backend.get("id")),
                           "fwmark"], runner=runner)
        values = str(result.stdout or "").strip().splitlines()
        if result.returncode or len(values) != 1 or values[0].lower() == "off":
            return 0
        try:
            mark = int(values[0], 0)
            return mark if 0 <= mark <= 0xffffffff else 0
        except ValueError:
            return 0
    return 0


def backend_state(rows, runner=None):
    backend = active_backend(rows)
    if backend is None:
        return {"kind": "none", "active": False}
    if backend["kind"] == "singbox":
        result = vpn_exec(["systemctl", "is-active", "sing-box"], runner=runner)
    else:
        result = vpn_exec(["ip", "link", "show", "dev", backend["id"]],
                          runner=runner)
    return {"kind": backend["kind"], "active": result.returncode == 0}


def set_transit_closed(closed, applier=None):
    global _vpn_closed
    closed = bool(closed)
    if closed == _vpn_closed:
        return
    before, _vpn_closed = _vpn_closed, closed
    try:
        (applier or apply)(load())
    except Exception:
        _vpn_closed = before
        raise


def _profile_name(value):
    name = " ".join(str(value or "").split())[:40]
    if not name:
        raise VpnError("validation-failed")
    return name


def vpn_add(body, runner=None, fetcher=None):
    with _vpn_lock:
        rows = load_tunnels()
        kind = str(body.get("kind") or "")
        if kind not in TUNNEL_KINDS:
            raise VpnError("validation-failed")
        tid = new_tunnel_id(rows)
        row = {"id": tid, "name": _profile_name(body.get("name")),
               "kind": kind, "enabled": False, "error": "", "nodes": 0}
        _ensure_tunnel_dir()
        if kind == "subscription":
            try:
                url, exclude = check_subscription(body.get("url"),
                                                  body.get("exclude"))
                content = (fetcher or singbox_sub.fetch)(url)
                if (not isinstance(content, str)
                        or len(content.encode("utf-8")) > singbox_sub.SUB_BODY_MAX):
                    raise ValueError
                outs = singbox_sub.convert(content, exclude=exclude,
                                            prefix=f"sub-{tid}-")
            except Exception:
                raise VpnError("validation-failed") from None
            if not outs:
                raise VpnError("validation-failed")
            row["nodes"] = len(outs)
            write_private(tunnel_path(tid, ".json"),
                          {"url": url, "exclude": exclude, "body": content})
        else:
            config = body.get("config")
            try:
                checked = check_quick_config(kind, config, runner, tid)
            except ValueError:
                raise VpnError("validation-failed") from None
            row.update(checked)
            if not checked["verified"]:
                row["error"] = "tool-missing"
            write_private_text(tunnel_path(tid, ".conf"), _quick_text(config))
        save_tunnels(rows + [row])
        return _tunnel_row(row)


def _find_tunnel(rows, tid):
    tid = check_tunnel_id(tid)
    row = next((row for row in rows if row["id"] == tid), None)
    if row is None:
        raise VpnError("validation-failed")
    return row


def _read_quick_config(row):
    try:
        with open(tunnel_path(row["id"], ".conf"), "rb") as f:
            data = f.read(VPN_MAX + 1)
    except OSError:
        raise VpnError("missing-secret") from None
    if len(data) > VPN_MAX:
        raise VpnError("validation-failed")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise VpnError("validation-failed") from None


def _check_singbox_candidate(config, runner=None):
    try:
        text = json.dumps(config, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        raise VpnError("validation-failed") from None
    _ensure_tunnel_dir()
    with tempfile.TemporaryDirectory(prefix=".singbox-", dir=TUNNEL_DIR) as td:
        os.chmod(td, 0o700)
        path = os.path.join(td, "candidate.json")
        write_private_text(path, text)
        result = vpn_exec(["sing-box", "check", "-c", path], runner=runner)
    if result.returncode:
        raise VpnError("validation-failed")
    return text


def _prepare_backend(rows, runner=None, secrets_map=None):
    backend = active_backend(rows)
    if backend is None:
        return None
    if backend["kind"] == "singbox":
        config, counts = build_singbox(rows, secrets_map=secrets_map)
        for row in rows:
            if row["id"] in counts:
                row["nodes"], row["error"] = counts[row["id"]], ""
        return dict(backend, config_text=_check_singbox_candidate(config, runner))
    row = _find_tunnel(rows, backend["id"])
    config = _read_quick_config(row)
    try:
        checked = check_quick_config(row["kind"], config, runner, row["id"])
    except ValueError:
        raise VpnError("validation-failed") from None
    if not checked["verified"]:
        raise VpnError("tool-missing")
    row.update(checked)
    row["error"] = ""
    return dict(row, path=tunnel_path(row["id"], ".conf"))


def _default_route_devs(runner=None):
    main = vpn_exec(["ip", "-j", "route", "show", "default"], runner=runner)
    all_routes = vpn_exec(
        ["ip", "-j", "route", "show", "table", "all", "default"], runner=runner)
    if main.returncode or all_routes.returncode:
        raise VpnError("conflict")
    try:
        main_routes = json.loads(main.stdout or "[]")
        routes = json.loads(all_routes.stdout or "[]")
    except (TypeError, ValueError):
        raise VpnError("conflict") from None

    def devices(items):
        return {dev for route in items
                for dev in ([route.get("dev")] +
                            [hop.get("dev") for hop in route.get("nexthops", [])])
                if dev}

    main_devs = devices(main_routes)
    return main_devs, devices(routes) - main_devs


def _unmanaged_tunnel(current, runner=None):
    """Conservative default-route conflict check before touching a backend."""
    _, extras = _default_route_devs(runner)
    if current and current.get("id"):
        extras.discard(current["id"])
    # A managed sing-box contributes one policy-table default whose interface
    # name is owned by sing-box, not by this panel. A second extra is foreign.
    if current and current.get("kind") == "singbox":
        return len(extras) > 1
    return bool(extras)


def _file_snapshot(path):
    try:
        with open(path, "rb") as f:
            return f.read(), os.stat(path).st_mode & 0o777
    except FileNotFoundError:
        return None


def _restore_file(path, snapshot):
    if snapshot is None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        return
    data, mode = snapshot
    _write_private_bytes(path, data)
    os.chmod(path, mode)


def _stop_backend(backend, runner=None, quiet=False):
    if not backend:
        return
    if backend["kind"] == "singbox":
        argv = ["systemctl", "stop", "sing-box"]
    else:
        argv = [QUICK_TOOLS[backend["kind"]], "down",
                tunnel_path(backend["id"], ".conf")]
    result = vpn_exec(argv, runner=runner)
    if result.returncode and not quiet:
        raise VpnError("start-failed")


def _start_backend(backend, runner=None):
    if not backend:
        return
    if backend["kind"] == "singbox":
        if "config_text" in backend:
            write_private_text(SINGBOX_CONFIG, backend["config_text"])
        argv = ["systemctl", "restart", "sing-box"]
    else:
        argv = [QUICK_TOOLS[backend["kind"]], "up",
                tunnel_path(backend["id"], ".conf")]
    if vpn_exec(argv, runner=runner).returncode:
        raise VpnError("start-failed")


def _check_backend(backend, runner=None):
    if not backend:
        return
    if backend["kind"] == "singbox":
        result = vpn_exec(["systemctl", "is-active", "sing-box"], runner=runner)
        try:
            _, policy_devs = _default_route_devs(runner)
        except VpnError:
            policy_devs = set()
        if result.returncode or not policy_devs:
            raise VpnError("start-failed")
        return
    tid = check_tunnel_id(backend["id"])
    if vpn_exec(["ip", "link", "show", "dev", tid], runner=runner).returncode:
        raise VpnError("start-failed")
    routes = vpn_exec(
        ["ip", "-j", "route", "show", "table", "all", "dev", tid],
        runner=runner)
    try:
        has_default = any(route.get("dst") in ("default", "0.0.0.0/0")
                          for route in json.loads(routes.stdout or "[]"))
    except (TypeError, ValueError):
        has_default = False
    if routes.returncode or not has_default:
        raise VpnError("start-failed")


def _set_vpn_mark(mark):
    mark = int(mark or 0)
    if not 0 <= mark <= 0xffffffff:
        mark = 0
    with _conf_lock:
        current = conf()
        if int(current.get("vpn_mark") or 0) != mark:
            current["vpn_mark"] = mark
            save_conf(current)
    CFG["vpn_mark"] = mark


def switch_backend(old_rows, new_rows, runner=None, applier=None,
                   secrets_map=None, before_commit=None, on_rollback=None):
    old_rows = [dict(row) for row in old_rows]
    new_rows = [dict(row) for row in new_rows]
    old_backend = active_backend(old_rows)
    new_backend = _prepare_backend(new_rows, runner, secrets_map)
    if _unmanaged_tunnel(old_backend, runner):
        raise VpnError("conflict")
    same_backend = bool(old_backend and new_backend
        and old_backend["kind"] == new_backend["kind"]
        and (old_backend.get("id") == new_backend.get("id")
             if old_backend["kind"] != "singbox"
             else old_backend.get("ids") == new_backend.get("ids")))
    old_mark = int(conf().get("vpn_mark") or 0)
    old_singbox = _file_snapshot(SINGBOX_CONFIG)
    set_transit_closed(True, applier)
    attempted = False
    try:
        _stop_backend(old_backend, runner, quiet=same_backend)
        if new_backend:
            attempted = True
            _start_backend(new_backend, runner)
            _check_backend(new_backend, runner)
        mark = backend_mark(new_backend, runner)
        if before_commit:
            before_commit()
        _set_vpn_mark(mark)
        save_tunnels(new_rows)
        set_transit_closed(False, applier)
        return new_rows
    except Exception as original:
        try:
            if attempted:
                _stop_backend(new_backend, runner, quiet=True)
            _restore_file(SINGBOX_CONFIG, old_singbox)
            if on_rollback:
                on_rollback()
            if old_backend:
                _start_backend(old_backend, runner)
                _check_backend(old_backend, runner)
            _set_vpn_mark(old_mark)
            save_tunnels(old_rows)
            set_transit_closed(False, applier)
        except Exception:
            for row in old_rows:
                if row.get("enabled"):
                    row["error"] = "rollback-failed"
            with contextlib.suppress(Exception):
                save_tunnels(old_rows)
            raise VpnError("rollback-failed") from None
        if isinstance(original, VpnError):
            raise VpnError(str(original)) from None
        raise VpnError("start-failed") from None


def vpn_enable(tid, runner=None, applier=None):
    with _vpn_lock:
        rows = load_tunnels()
        target = _find_tunnel(rows, tid)
        if target["kind"] == "subscription":
            for row in rows:
                if row["kind"] in QUICK_TOOLS:
                    row["enabled"] = False
            target["enabled"] = True
        else:
            for row in rows:
                row["enabled"] = row["id"] == target["id"]
        target["error"] = ""
        committed = switch_backend(load_tunnels(), rows, runner, applier)
        return _find_tunnel(committed, tid)


def vpn_disable(tid, runner=None, applier=None):
    with _vpn_lock:
        old_rows = load_tunnels()
        rows = [dict(row) for row in old_rows]
        target = _find_tunnel(rows, tid)
        if not target["enabled"]:
            return target
        target["enabled"], target["error"] = False, ""
        committed = switch_backend(old_rows, rows, runner, applier)
        return _find_tunnel(committed, tid)


def _unlink_tunnel_secret(row):
    suffix = ".json" if row["kind"] == "subscription" else ".conf"
    # A failed unlink leaves a 0600 orphan for startup reconciliation; the
    # committed catalog no longer names it, which is safer than undoing runtime.
    with contextlib.suppress(OSError):
        os.unlink(tunnel_path(row["id"], suffix))


def vpn_delete(tid, runner=None, applier=None):
    with _vpn_lock:
        old_rows = load_tunnels()
        target = _find_tunnel(old_rows, tid)
        rows = [dict(row) for row in old_rows if row["id"] != target["id"]]
        if target["enabled"]:
            switch_backend(old_rows, rows, runner, applier)
        else:
            save_tunnels(rows)
        _unlink_tunnel_secret(target)
        return True


def vpn_refresh(tid, runner=None, applier=None, fetcher=None):
    with _vpn_lock:
        old_rows = load_tunnels()
        rows = [dict(row) for row in old_rows]
        target = _find_tunnel(rows, tid)
        if target["kind"] != "subscription":
            raise VpnError("validation-failed")
        path = tunnel_path(target["id"], ".json")
        snapshot = _file_snapshot(path)
        if snapshot is None:
            raise VpnError("missing-secret")
        try:
            old_secret = json.loads(snapshot[0])
            url, exclude = check_subscription(old_secret.get("url"),
                                              old_secret.get("exclude"))
            content = (fetcher or singbox_sub.fetch)(url)
            if (not isinstance(content, str)
                    or len(content.encode("utf-8")) > singbox_sub.SUB_BODY_MAX):
                raise ValueError
            outs = singbox_sub.convert(content, exclude=exclude,
                                        prefix=f"sub-{target['id']}-")
        except Exception:
            raise VpnError("validation-failed") from None
        if not outs:
            raise VpnError("validation-failed")
        secret = {"url": url, "exclude": exclude, "body": content}
        target["nodes"], target["error"] = len(outs), ""
        if not target["enabled"]:
            try:
                write_private(path, secret)
                save_tunnels(rows)
            except Exception:
                _restore_file(path, snapshot)
                raise VpnError("start-failed") from None
            return target

        def secrets_for(profile_id):
            return secret if profile_id == target["id"] else \
                load_subscription_secret(profile_id)

        committed = switch_backend(
            old_rows, rows, runner, applier, secrets_for,
            before_commit=lambda: write_private(path, secret),
            on_rollback=lambda: _restore_file(path, snapshot))
        return _find_tunnel(committed, tid)


def vpn_action(action, body, runner=None, applier=None, fetcher=None):
    actions = {"add": lambda: vpn_add(body, runner, fetcher),
               "enable": lambda: vpn_enable(body.get("id"), runner, applier),
               "disable": lambda: vpn_disable(body.get("id"), runner, applier),
               "refresh": lambda: vpn_refresh(body.get("id"), runner, applier,
                                                fetcher)}
    try:
        call = actions[action]
    except (KeyError, TypeError):
        raise VpnError("validation-failed") from None
    try:
        return call()
    except VpnError:
        raise
    except (ValueError, TypeError, AttributeError):
        raise VpnError("validation-failed") from None


def _clean_tunnel_orphans(rows):
    if not os.path.isdir(TUNNEL_DIR):
        return
    expected = {row["id"] + (".json" if row["kind"] == "subscription" else ".conf")
                for row in rows}
    for name in os.listdir(TUNNEL_DIR):
        path = os.path.join(TUNNEL_DIR, name)
        if re.fullmatch(r"t[0-9a-f]{12}\.(?:json|conf)", name):
            if name not in expected:
                with contextlib.suppress(OSError):
                    os.unlink(path)
        elif re.fullmatch(r"\.t[0-9a-f]{12}\.(?:json|conf)\..+", name):
            with contextlib.suppress(OSError):
                os.unlink(path)
        elif name.startswith(".singbox-") and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)


def _has_tunnel_secret(row):
    suffix = ".json" if row["kind"] == "subscription" else ".conf"
    return os.path.isfile(tunnel_path(row["id"], suffix))


def reconcile_tunnels(runner=None, applier=None):
    """Reconcile disk and managed runtime without making HTTP depend on it."""
    with _vpn_lock:
        migrate_legacy_subscription()
        rows = load_tunnels()
        _clean_tunnel_orphans(rows)
        broken = False
        for row in rows:
            if not _has_tunnel_secret(row):
                broken |= row["enabled"]
                row["enabled"], row["error"] = False, "missing-secret"
        try:
            backend = active_backend(rows)
        except VpnError:
            for row in rows:
                if row["enabled"]:
                    row["error"] = "invalid-state"
            save_tunnels(rows)
            _set_vpn_mark(0)
            set_transit_closed(True, applier)
            return False
        if backend is None:
            save_tunnels(rows)
            _set_vpn_mark(0)
            set_transit_closed(broken, applier)
            return not broken

        legacy = (backend["kind"] == "singbox" and any(
            row["enabled"] and row["error"] == "legacy/no-cache" for row in rows))
        try:
            try:
                _check_backend(backend, runner)
            except VpnError:
                if legacy:
                    raise
                if _unmanaged_tunnel(None, runner):
                    raise VpnError("conflict")
                prepared = _prepare_backend(rows, runner)
                _start_backend(prepared, runner)
                _check_backend(prepared, runner)
                backend = prepared
            _set_vpn_mark(backend_mark(backend, runner))
            if not legacy:
                for row in rows:
                    if row["enabled"]:
                        row["error"] = ""
            save_tunnels(rows)
            set_transit_closed(False, applier)
            return True
        except VpnError as e:
            code = str(e) if str(e) in SAFE_VPN_ERRORS else "start-failed"
            for row in rows:
                if row["enabled"]:
                    row["error"] = code
            with contextlib.suppress(Exception):
                _set_vpn_mark(0)
                save_tunnels(rows)
            set_transit_closed(True, applier)
            return False


def vpn_poll(runner=None, applier=None):
    with _vpn_lock:
        rows = load_tunnels()
        try:
            backend = active_backend(rows)
            if backend is None:
                failed_managed = any(
                    row.get("error") == "missing-secret"
                    or (row.get("enabled") and row.get("error")) for row in rows)
                set_transit_closed(failed_managed, applier)
                return
            _check_backend(backend, runner)
            _set_vpn_mark(backend_mark(backend, runner))
            dirty = False
            for row in rows:
                if (row["enabled"] and row["error"]
                        and row["error"] != "legacy/no-cache"):
                    row["error"] = ""
                    dirty = True
            if dirty:
                save_tunnels(rows)
            set_transit_closed(False, applier)
        except Exception:
            dirty = False
            for row in rows:
                if row.get("enabled") and row.get("error") != "stopped":
                    row["error"] = "stopped"
                    dirty = True
            with contextlib.suppress(Exception):
                if dirty:
                    save_tunnels(rows)
                set_transit_closed(True, applier)


def _quick_text(value):
    try:
        text = value.decode("utf-8") if isinstance(value, bytes) else str(value)
        raw = text.encode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        raise ValueError("tunnel config must be UTF-8") from None
    if len(raw) > VPN_MAX:
        raise ValueError("tunnel config is too large")
    if "\x00" in text:
        raise ValueError("tunnel config contains NUL")
    return text


def _quick_sections(text):
    sections, current = [], None
    for source in text.splitlines():
        line = source.strip()
        if not line or line.startswith(("#", ";")):
            continue
        match = re.fullmatch(r"\[\s*(Interface|Peer)\s*\]", line, re.I)
        if match:
            current = {"section": match.group(1).lower(), "values": {}}
            sections.append(current)
            continue
        if current is None or "=" not in line:
            raise ValueError("invalid tunnel config structure")
        key, value = (part.strip() for part in line.split("=", 1))
        key = key.lower()
        if not key or not value or key in current["values"]:
            raise ValueError("invalid tunnel config field")
        if key in FORBIDDEN_QUICK:
            raise ValueError("tunnel config hooks are not allowed")
        current["values"][key] = value
    return sections


def _valid_wg_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def _strip_quick(kind, text, runner, tid):
    tool = QUICK_TOOLS[kind]
    if runner is None:
        if shutil.which(tool) is None:
            return False
        runner = subprocess.run
    tid = check_tunnel_id(tid or "t000000000000")
    try:
        with tempfile.TemporaryDirectory(prefix="gwacl-quick-") as td:
            os.chmod(td, 0o700)
            path = os.path.join(td, tid + ".conf")
            write_private_text(path, text)
            result = runner([tool, "strip", path], capture_output=True,
                            text=True, timeout=10, shell=False)
    except FileNotFoundError:
        return False
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("quick tool could not validate tunnel config") from None
    if result.returncode:
        raise ValueError("quick tool rejected tunnel config")
    return True


def check_quick_config(kind, value, runner=None, tid=None):
    if kind not in QUICK_TOOLS:
        raise ValueError("invalid tunnel type")
    text = _quick_text(value)
    sections = _quick_sections(text)
    interfaces = [s["values"] for s in sections if s["section"] == "interface"]
    peers = [s["values"] for s in sections if s["section"] == "peer"]
    if len(interfaces) != 1 or not peers:
        raise ValueError("tunnel config needs one interface and a peer")
    interface = interfaces[0]
    if not _valid_wg_key(interface.get("privatekey")) or not interface.get("address"):
        raise ValueError("tunnel interface is incomplete")
    try:
        for address in interface["address"].split(","):
            ipaddress.ip_interface(address.strip())
    except ValueError:
        raise ValueError("invalid tunnel address") from None
    table = interface.get("table", "auto").lower()
    if table != "auto":
        raise ValueError("only automatic tunnel routing is supported")
    if "mtu" in interface:
        try:
            mtu = int(interface["mtu"])
        except ValueError:
            raise ValueError("invalid tunnel MTU") from None
        if not 576 <= mtu <= 65535:
            raise ValueError("invalid tunnel MTU")

    awg = AWG_KEYS.intersection(interface)
    if kind == "wireguard" and awg:
        raise ValueError("AmneziaWG parameters in WireGuard config")
    if kind == "amneziawg" and not awg:
        raise ValueError("AmneziaWG parameters are missing")
    try:
        for key in awg:
            int(interface[key])
    except ValueError:
        raise ValueError("invalid AmneziaWG parameter") from None

    has_v4 = has_v6 = False
    for peer in peers:
        if (not _valid_wg_key(peer.get("publickey"))
                or not peer.get("allowedips") or not peer.get("endpoint")):
            raise ValueError("tunnel peer is incomplete")
        if "presharedkey" in peer and not _valid_wg_key(peer["presharedkey"]):
            raise ValueError("invalid tunnel peer key")
        endpoint = peer["endpoint"]
        match = re.fullmatch(r"(?:\[[^]]+\]|[^:]+):([0-9]+)", endpoint)
        if not match or not 1 <= int(match.group(1)) <= 65535:
            raise ValueError("invalid tunnel endpoint")
        for value in peer["allowedips"].split(","):
            try:
                network = ipaddress.ip_network(value.strip(), strict=False)
            except ValueError:
                raise ValueError("invalid tunnel routes") from None
            has_v4 |= network.version == 4 and network.prefixlen == 0
            has_v6 |= network.version == 6 and network.prefixlen == 0
    if not has_v4:
        raise ValueError("tunnel must carry the IPv4 default route")

    return {"ipv6": has_v6,
            "verified": _strip_quick(kind, text, runner, tid)}


def migrate_legacy_subscription():
    """Move the old secret once without rebuilding or restarting sing-box."""
    if os.path.exists(TUNNELS) or not os.path.isfile(LEGACY_SUB_URL):
        return False
    try:
        with open(LEGACY_SUB_URL) as f:
            url = f.read(VPN_MAX + 1).strip()
        if not url or len(url.encode()) > VPN_MAX:
            return False
        try:
            with open(LEGACY_SUB_EXCLUDE) as f:
                exclude = f.read(129).strip()
        except FileNotFoundError:
            exclude = ""
        if len(exclude) > 128:
            exclude = ""
    except OSError:
        return False

    rows = []
    tid = new_tunnel_id(rows)
    _ensure_tunnel_dir()
    write_private(tunnel_path(tid, ".json"),
                  {"url": url, "exclude": exclude})
    save_tunnels([{"id": tid, "name": "Подписка", "kind": "subscription",
                   "enabled": True, "error": "legacy/no-cache", "nodes": 0}])
    for path in (LEGACY_SUB_URL, LEGACY_SUB_EXCLUDE):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
    dfd = os.open(os.path.dirname(TUNNELS) or ".", os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return True


# --- the machine itself -----------------------------------------------------

LEASES = ("/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases")
_syslock = threading.Lock()
_sys = {"at": 0.0, "cpu": None, "net": None, "pct": None, "bps": [0, 0], "out": None}


def _read(path):
    """A whole small /proc or /sys file, or "" when this kernel has no such
    thing. Every metric below is optional — the panel leaves out what it did
    not get rather than refusing to draw."""
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _num(s):
    try:
        return float(s.split()[0])
    except (ValueError, IndexError):
        return None


def cpu_jiffies(text):
    """(idle, total) off the first line of /proc/stat, None if it is not one.

    Idle counts iowait as well: a gateway waiting on its disk is not busy, and
    calling it busy would light the meter up for no reason.
    """
    f = text.split("\n", 1)[0].split()
    if len(f) < 5 or f[0] != "cpu":
        return None
    try:
        n = [int(x) for x in f[1:]]
    except ValueError:
        return None
    return n[3] + n[4], sum(n)


def cpu_pct(prev, cur):
    """Busy share between two /proc/stat readings, or None if it cannot tell."""
    if not prev or not cur:
        return None
    idle, total = cur[0] - prev[0], cur[1] - prev[1]
    if total <= 0:
        return None
    return round(max(0.0, min(100.0, 100 * (1 - idle / total))), 1)


def parse_meminfo(text):
    """/proc/meminfo as bytes. It speaks kB, everything else here speaks bytes."""
    m = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        try:
            m[k] = int(v.split()[0]) * 1024
        except (ValueError, IndexError):
            continue
    return m


def temp_c(root="/sys/class/thermal"):
    """The warmest sensor the kernel exposes: (°C, what it calls itself).

    Zones are milli-degrees and a machine has several, measuring different
    things — the processor package, the chipset, an NVMe drive. The hottest is
    the one worth showing, but on its own it is an anonymous number, so the
    zone's `type` goes with it and the panel names the sensor it picked.
    Absurd readings are dropped: an empty or disabled zone happily reports 0
    or −273.
    """
    best = None
    try:
        zones = sorted(os.listdir(root))
    except OSError:
        return None
    for z in zones:
        t = _num(_read(f"{root}/{z}/temp"))
        if t is None or not 0 < t / 1000 < 150:
            continue
        if best is None or t / 1000 > best[0]:
            # A zone without a type file is named after its directory.
            best = (round(t / 1000, 1), _read(f"{root}/{z}/type").strip() or z)
    return best


def sysinfo():
    """CPU, memory, disk and interface throughput, straight out of /proc and /sys.

    Two of those are rates and need two readings, so the first call after a
    start reports zero and each later one covers the time since the previous
    one. The readings are kept apart from the traffic counters on purpose: a
    machine that stops answering about itself must not stop the accounting.

    The whole answer is held for that same window rather than only the two
    rates: inside it there is nothing new to say, and re-reading /proc, statvfs
    and every thermal zone once per open tab was work whose result was already
    on the screen.
    """
    with _syslock:
        now = time.time()
        dt = now - _sys["at"]
        if dt < 2 and _sys["out"]:
            return _sys["out"]
        cpu = cpu_jiffies(_read("/proc/stat"))
        net = [_num(_read(f"/sys/class/net/{IFACE}/statistics/{w}_bytes"))
               for w in ("rx", "tx")]
        pct = cpu_pct(_sys["cpu"], cpu)
        if pct is not None:
            _sys["pct"] = pct
        if None not in net and _sys["net"] and None not in _sys["net"]:
            _sys["bps"] = [round(max(0.0, (b - a) / dt))
                           for a, b in zip(_sys["net"], net)]
        _sys["at"], _sys["cpu"], _sys["net"] = now, cpu, net
        mem = parse_meminfo(_read("/proc/meminfo"))
        try:
            v = os.statvfs("/")
            disk = [(v.f_blocks - v.f_bavail) * v.f_frsize, v.f_blocks * v.f_frsize]
        except OSError:
            disk = None
        try:
            load = list(os.getloadavg())
        except (OSError, AttributeError):
            load = None
        _sys["out"] = {
            "cpu": _sys["pct"],
            "cores": os.cpu_count(),
            "load": load,
            "mem": ([mem["MemTotal"] - mem["MemAvailable"], mem["MemTotal"]]
                    if mem.get("MemTotal") and "MemAvailable" in mem else None),
            "swap": ([mem["SwapTotal"] - mem["SwapFree"], mem["SwapTotal"]]
                     if mem.get("SwapTotal") else None),
            "disk": disk,
            "temp": temp_c(),
            "up": _num(_read("/proc/uptime")),
            "iface": IFACE,
            "bps": _sys["bps"],
        }
        return _sys["out"]


def parse_arp(text):
    """{address: hardware address} out of /proc/net/arp, skipping empty entries."""
    out = {}
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 4 and f[3] != "00:00:00:00:00:00":
            out[f[0]] = f[3]
    return out


def parse_leases(text):
    """{address: hostname} out of a dnsmasq lease file.

    A line is `expiry mac address name clientid`, and a client that gave no
    name leaves a bare `*` there — that is not a name, it is a placeholder.
    """
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and f[3] != "*":
            out[f[2]] = f[3]
    return out


def parse_lease_macs(text, now=None):
    """{hardware address: address} out of a dnsmasq lease file, expired lines out.

    The one place that says where a device is *now*. The kernel's ARP cache does
    not: it keeps the entry for an address a device has left, and on a home LAN
    it keeps it for ever — the collector only starts above `gc_thresh1`, which a
    few dozen devices never reach. A device that has ever had two addresses is
    therefore at both of them as far as the cache is concerned. dnsmasq instead
    rewrites the line when the client takes another address, so this is the
    tie-breaker; `0` in the expiry field means the lease never runs out.
    """
    now = time.time() if now is None else now
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 3 or not is_mac(f[1]):
            continue
        try:
            exp = int(f[0])
        except ValueError:
            continue
        if exp and exp < now:
            continue
        out[f[1].lower()] = f[2]
    return out


def _lease_text():
    """The lease file, from whichever of the usual places holds one."""
    for path in LEASES:
        text = _read(path)
        if text:
            return text
    return ""


def lease_macs():
    return parse_lease_macs(_lease_text())


def lan_names():
    """{address: [hostname, mac]} — whatever the system already knows.

    Hardware addresses come from the kernel's ARP cache, names from dnsmasq if
    it happens to run on this gateway. Both are a courtesy: without them the
    unknown-devices list is a column of bare numbers, and with them it says
    which box in the flat is knocking.
    """
    out = {ip: ["", mac] for ip, mac in parse_arp(_read("/proc/net/arp")).items()}
    for ip, host in parse_leases(_lease_text()).items():
        out.setdefault(ip, ["", ""])[0] = host
    return out


# Where a distribution keeps the IEEE list, if it has it at all. A gateway
# installed from a minimal image usually does not, hence the short table below:
# what actually turns up on a home network, and nothing at all for the rest —
# a wrong manufacturer is worse than none.
OUI_FILES = ("/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt",
             "/usr/share/hwdata/oui.txt", "/usr/share/misc/oui.txt",
             "/usr/share/wireshark/manuf")
OUI = {
    "525400": "QEMU/KVM", "080027": "VirtualBox", "000c29": "VMware",
    "005056": "VMware", "000569": "VMware", "00155d": "Hyper-V", "00163e": "Xen",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "240ac4": "Espressif", "a4cf12": "Espressif", "30aea4": "Espressif",
    "84f3eb": "Espressif", "00e04c": "Realtek", "001b63": "Apple",
    "a483e7": "Apple", "f01898": "Apple", "d89695": "Apple", "3c0754": "Apple",
    "001632": "Samsung", "781fdb": "Samsung", "ac5f3e": "Samsung",
    "640980": "Xiaomi", "f8a45f": "Xiaomi", "7811dc": "Xiaomi",
    "001b21": "Intel", "3c970e": "Intel", "a4c3f0": "Intel", "94659c": "Intel",
    "50c7bf": "TP-Link", "a42bb0": "TP-Link", "ec086b": "TP-Link",
    "4c5e0c": "MikroTik", "488f5a": "MikroTik", "e48d8c": "MikroTik",
    "24a43c": "Ubiquiti", "788a20": "Ubiquiti", "fcecda": "Ubiquiti",
    "f4f5d8": "Google", "44650d": "Amazon", "f0272d": "Amazon",
}
_oui = {}   # prefix -> who makes it, "" for one nobody here can name


def _oui_key(mac):
    return mac[:8].replace(":", "").replace("-", "").lower()


def scan_oui(path, want, into):
    """One pass of an IEEE list for a set of prefixes.

    Both formats a distribution ships look the same at the front — three bytes,
    a separator, then the name. `oui.txt` puts "(hex)" in between and gives the
    long name; wireshark's `manuf` gives a short name first, which is the one
    worth showing in a table cell. Lines carrying a "/" are the 28- and 36-bit
    assignments: their prefix is longer than three bytes, and taking one would
    name a whole block after one small company inside it.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                p = _oui_key(line)
                if p not in want or "/" in line[:24]:
                    continue
                rest = line[8:].replace("(hex)", "")
                name = next((s.strip() for s in rest.split("\t") if s.strip()), "")
                if name:
                    into[p] = name[:24]
    except OSError:
        pass
    return into


def vendors(macs):
    """{hardware address: who made it}, for whatever can be answered.

    The IEEE list is thirty thousand lines, so it is read once for every prefix
    asked about at once, and the answers — the empty ones too — are kept. After
    the first page there is nothing left to look up until something with a
    prefix nobody has seen before turns up.

    An address with the locally-administered bit set was made up by the device
    itself. Modern phones do that per network, which is why a perfectly ordinary
    handset has no manufacturer — saying so is more useful than a blank.
    """
    want = {_oui_key(m) for m in macs if len(m) >= 8}
    miss = want - set(_oui)
    if miss:
        for p in miss:
            _oui[p] = OUI.get(p, "")
        path = next((p for p in OUI_FILES if os.path.exists(p)), None)
        if path:
            scan_oui(path, miss, _oui)   # the system's list outranks the table
    out = {}
    for m in macs:
        p = _oui_key(m)
        name = _oui.get(p, "")
        if not name:
            try:
                name = T["macRandom"] if int(p[:2], 16) & 2 else ""
            except ValueError:
                name = ""
        out[m] = name
    return out


def clashes(devs, names):
    """Listed addresses that are answering with different hardware.

    The entry says one address, the wire says another device is on it — so the
    rule that was written for the tablet is now the rule for whatever took its
    address, and nothing on the page would otherwise say so. track_macs() moves
    an entry whose device merely went somewhere else; what is left here is the
    case where its address was taken and there is nowhere to move it to.
    """
    out = []
    for d in devs:
        mac = d.get("mac")
        now = names.get(d["ip"], ["", ""])[1]
        if mac and now and now != mac:
            out.append([d["ip"], mac, now])
    return out


def track_macs():
    """Follow a device that DHCP has moved to another address.

    Everything here hangs off the address: the rule, the two counters, the day
    buckets. A new lease therefore turns an entry into a rule for nobody — the
    device is silently outside the gateway, or silently through it, and the
    panel goes on reporting the old address as quiet. The hardware address is
    the thing that did not change, and the kernel's own ARP table says where it
    is now.

    A device that has never been seen has no hardware address to be followed by,
    so the first sighting records one. Returns True if the ruleset changed.

    The cache alone is not enough to say where a device is: it holds every
    address the device has ever answered from, and reading it into
    {mac: address} kept whichever line came last. Two addresses for one device
    is the normal state of affairs after somebody edits the address on the
    phone, and the entry then followed the file's own order — onto the address
    the device had left, back again on the next poll, dragging its history with
    it each time and putting an address the owner had deleted back on the page.
    So: one address answering, follow it; several, and only the lease file may
    break the tie, because it is the one that is rewritten when the address
    actually changes. Neither, and the entry stays where its owner put it.
    """
    names = lan_names()
    at = {}
    for ip, (_, mac) in names.items():
        if mac and lan_client(ip):
            at.setdefault(mac, []).append(ip)
    lease = lease_macs()
    devs = load()
    stamp = _devs_stamp()
    taken = {d["ip"] for d in devs}
    moves, learned = [], False
    for d in devs:
        mac = d.get("mac") or names.get(d["ip"], ["", ""])[1]
        if not mac:
            continue
        learned = learned or mac != d.get("mac")
        d["mac"] = mac
        here = at.get(mac, [])
        new = here[0] if len(here) == 1 else (
            lease.get(mac) if lease.get(mac) in here else None)
        # `taken`: two entries must never end up on one address, and an entry
        # whose new address is already somebody else's is left where it is.
        if not new or new == d["ip"] or new in taken:
            continue
        moves.append((d["ip"], new))
        taken.discard(d["ip"])
        taken.add(new)
        d["ip"] = new
    if not moves and not learned:
        return False
    if _devs_stamp() != stamp:
        # Somebody pressed a button while this was being worked out, and what is
        # in hand is now the list as it was before they did. Writing it would
        # undo them — a deleted device would come back by itself a poll later.
        # ponytail: the next tick works it out again from the file they wrote.
        return False
    if moves:
        # Bank what the old address moved before the list stops mentioning it:
        # poll() reads the counters against whatever load() says, and the next
        # one will be reading them against the new address.
        poll(force=True)
        for old, new in moves:
            rekey(old, new)
    devs.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    save(devs)
    if moves:
        apply(devs)
    return bool(moves)


def prev_month(m):
    """The month before "YYYY-MM"."""
    y, mo = int(m[:4]), int(m[5:7])
    return f"{y - 1:04d}-12" if mo == 1 else f"{y:04d}-{mo - 1:02d}"


def month_totals(days, month):
    tot = {}
    for k, devs in days.items():
        if not k.startswith(month):
            continue
        for ip, (u, d) in devs.items():
            t = tot.setdefault(ip, [0, 0])
            t[0] += u
            t[1] += d
    return tot


def month_sums(days):
    """One total per month, in a single pass over the day buckets.

    Asking month_totals for each month in turn walked the whole history once per
    month — a year of days re-summed thirteen times over, on every request of
    every open tab, for the strip under the chart.
    """
    out = {}
    for k, devs in days.items():
        out[k[:7]] = out.get(k[:7], 0) + sum(sum(v) for v in devs.values())
    return out


def build_state(month=None):
    poll()
    h = snapshot()
    sums = month_sums(h["days"])
    months = sorted(set(sums) | {time.strftime("%Y-%m")})
    if month not in months:
        month = time.strftime("%Y-%m")
    tot = month_totals(h["days"], month)
    devs = load()
    known = {d["ip"] for d in devs}
    # len == 10 filters out old-format keys ("2026-07"): they still count
    # towards the month total, but never into the per-day chart.
    day_keys = sorted(k for k in h["days"] if k.startswith(month) and len(k) == 10)
    hour_keys = sorted(_hours)
    names = lan_names()
    clash = clashes(devs, names)
    blk = [[ip] + names.get(ip, ["", ""]) + [ago]
           for ip, ago in sorted(blocked().items()) if ip not in known]
    # One lookup for the whole page: both lists ask about hardware nobody on
    # this network has named.
    ven = vendors([r[2] for r in blk] + [c[2] for c in clash])

    return {
        "month": month,
        # Every month is offered in the picker; the strip below the chart draws
        # the last twelve of them.
        "months": [[m, sums.get(m, 0)] for m in months],
        "prev": sums.get(prev_month(month), 0),
        "now": int(time.time()),
        "poll": POLL_SEC,
        "devices": [dict(d, on=d.get("on", True),
                         vpn=d.get("vpn", True),
                         until=int(d.get("until") or 0),
                         up=tot.get(d["ip"], [0, 0])[0],
                         down=tot.get(d["ip"], [0, 0])[1],
                         seen=h["seen"].get(d["ip"], 0),
                         rate=_rate.get(d["ip"], [0, 0]),
                         host=names.get(d["ip"], ["", ""])[0],
                         # What ARP says now, or what the entry was bound to.
                         mac=names.get(d["ip"], ["", ""])[1] or d.get("mac", ""),
                         series=[h["days"][k].get(d["ip"], [0, 0]) for k in day_keys],
                         # .get: the poller may drop the oldest hour between
                         # the snapshot of the keys and the read.
                         hseries=[_hours.get(k, {}).get(d["ip"], [0, 0])
                                  for k in hour_keys])
                    for d in devs],
        "days": [[k, sum(v[0] for v in h["days"][k].values()),
                  sum(v[1] for v in h["days"][k].values())] for k in day_keys],
        "hours": [[k[-2:], sum(v[0] for v in _hours.get(k, {}).values()),
                   sum(v[1] for v in _hours.get(k, {}).values())] for k in hour_keys],
        # Address, whatever the network calls it, how long ago it knocked, and
        # who made the thing.
        "blocked": [r + [ven.get(r[2], "")] for r in blk],
        # A listed address that is answering as somebody else.
        "clash": [c + [ven.get(c[2], "")] for c in clash],
        # While this is in the future the list is suspended and everyone is let
        # through; the page says so rather than looking merely broken.
        "bypass": int(CFG["bypass"]),
        # No mark, no way to send anyone past the tunnel — then the button that
        # offers it is a button that does nothing, so it is not drawn at all.
        "vpnable": bool(int(CFG.get("vpn_mark") or 0)),
        # Everything the system knows of on this network and the list does not:
        # the add form offers them rather than asking anyone to remember one.
        "lan": [[ip, names[ip][0]] for ip in sorted(names)
                if ip not in known and lan_client(ip)],
        "sys": sysinfo(),
        "update": _upd["new"],
    }


def state(month=None):
    """What the page draws, reused for STATE_CACHE seconds.

    A phone and a laptop left open ask five seconds apart each, and every ask
    copied the whole history, read the ARP table and the lease file and walked
    /proc for an answer that cannot have moved since the last one — the counters
    themselves are behind a wider window than this. The answer is shared, so the
    caller must not write into it; the handler copies before it adds `you`.
    """
    expire()
    with _statelock:
        now = time.time()
        if _state["val"] is None or _state["month"] != month \
                or now - _state["at"] >= STATE_CACHE:
            _state.update(val=build_state(month), month=month, at=now)
        return _state["val"]


# --- pages ------------------------------------------------------------------

# Светлая — значения по умолчанию: панель равняется на Настройки macOS, а те
# светлые. Тёмная описана один раз и подставляется в два селектора — в
# media-запрос для тех, кто ничего не выбирал, и в атрибут для ручного выбора.
LIGHT = """--bg:#F2F2F7;--panel:#FFFFFF;--line:rgba(60,60,67,.29);
  --fill:rgba(120,120,128,.12);--fg:#000000;--dim:rgba(60,60,67,.6);
  --dim2:rgba(60,60,67,.3);--blue:#007AFF;--green:#34C759;--red:#FF3B30;
  --orange:#FF9500;--mut:rgba(120,120,128,.35);--track:rgba(120,120,128,.16);
  --redbg:rgba(255,59,48,.12);--bluebg:rgba(0,122,255,.12);
  --sh:0 8px 30px rgba(0,0,0,.14)"""

DARK = """--bg:#1C1C1E;--panel:#2C2C2E;--line:rgba(84,84,88,.6);
  --fill:rgba(120,120,128,.24);--fg:#FFFFFF;--dim:rgba(235,235,245,.6);
  --dim2:rgba(235,235,245,.3);--blue:#0A84FF;--green:#30D158;--red:#FF453A;
  --orange:#FF9F0A;--mut:rgba(120,120,128,.45);--track:rgba(120,120,128,.24);
  --redbg:rgba(255,69,58,.18);--bluebg:rgba(10,132,255,.18);
  --sh:0 8px 30px rgba(0,0,0,.5)"""

# Форма и кегль от темы не зависят, поэтому объявлены один раз. --on здесь же:
# кнопка переключателя и текст на синей кнопке белые в обеих темах.
SHAPE = """--on:#FFFFFF;--r-panel:10px;--r-ctl:6px;--r-pill:999px;
  --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;
  --f-h1:20px;--f-group:13px;--f-row:14px;--f-sec:12px;--f-hero:28px;
  --down:var(--blue);--up:var(--orange);
  --sh-knob:0 1px 3px rgba(0,0,0,.3);--sh-seg:0 1px 3px rgba(0,0,0,.18);
  --scrim:rgba(0,0,0,.35)"""

TOKENS = (" :root{%s;%s}\n"
          " @media (prefers-color-scheme:dark){:root:not([data-theme=light]){%s}}\n"
          " :root[data-theme=dark]{%s}\n" % (LIGHT, SHAPE, DARK, DARK))

CSS = TOKENS + """
 *{box-sizing:border-box}
 body{font:var(--f-row)/1.45 system-ui,sans-serif;margin:0;
      padding:var(--s5) var(--s5) var(--s6);background:var(--bg);color:var(--fg);
      -webkit-font-smoothing:antialiased}
 h1{font-size:var(--f-h1);font-weight:600;margin:0;letter-spacing:-.01em}
 h2{font-size:var(--f-group);font-weight:600;margin:0;letter-spacing:0}
 .num{font-variant-numeric:tabular-nums;white-space:nowrap}
 .mono{font-family:ui-monospace,SFMono-Regular,monospace;
       font-variant-numeric:tabular-nums}
 .dim{color:var(--dim)}
 .sec{font-size:var(--f-sec);color:var(--dim)}
 .hint{color:var(--dim);font-size:var(--f-sec);margin:var(--s2) 0 0;
       overflow-wrap:anywhere}

 /* Панель: белое на сером отделяется само, поэтому рамки нет. В тёмной теме
    серое на сером не отделяется — там она волосяная. */
 .panel{background:var(--panel);border-radius:var(--r-panel);
        padding:var(--s4);margin-bottom:var(--s4)}
 @media (prefers-color-scheme:dark){:root:not([data-theme=light]) .panel{
   box-shadow:0 0 0 .5px var(--line)}}
 :root[data-theme=dark] .panel{box-shadow:0 0 0 .5px var(--line)}

 /* Строка списка. Разделитель отступлен слева под контент — маковский приём:
    он показывает, где начинается смысл строки. */
 .list{display:flex;flex-direction:column}
 .row{display:flex;align-items:center;gap:var(--s3);min-height:44px;
      padding:var(--s2) 0;border-bottom:.5px solid var(--line)}
 .row:last-child{border-bottom:0}
 .list.inset .row{margin-left:var(--s6)}
 .list.inset .row>:first-child{margin-left:calc(-1 * var(--s6))}
 .row .sp{flex:1}

 button,select,input,textarea{font:inherit;color:inherit}
 .btn{background:none;border:0;border-radius:var(--r-ctl);cursor:pointer;
      padding:var(--s1) var(--s2);color:var(--blue)}
 .btn:hover{background:var(--fill)}
 .btn.plain{color:var(--fg)}
 .btn.bad{color:var(--red)}
 .btn:disabled{color:var(--dim2);cursor:default;background:none}
 .btn.tinted{background:var(--blue);color:var(--on)}
 .field{background:var(--fill);border:0;border-radius:var(--r-ctl);
        padding:var(--s1) var(--s2);min-width:0}
 .field:focus,.btn:focus-visible,.sw:focus-visible,.seg button:focus-visible{
   outline:2px solid var(--blue);outline-offset:1px}

 /* Переключатель — сам чекбокс без нативного вида, кнопка это его ::before. */
 .sw{appearance:none;-webkit-appearance:none;flex:none;position:relative;
     width:38px;height:22px;padding:0;margin:0;border-radius:var(--r-pill);
     background:var(--track);cursor:pointer;transition:background .15s}
 .sw::before{content:"";position:absolute;top:2px;left:2px;width:18px;height:18px;
     border-radius:50%;background:var(--on);box-shadow:var(--sh-knob);
     transition:transform .15s}
 .sw:checked{background:var(--blue)}
 .sw:checked::before{transform:translateX(16px)}

 .seg{display:inline-flex;background:var(--track);border-radius:var(--r-pill);
      padding:2px}
 .seg button{background:none;border:0;border-radius:var(--r-pill);cursor:pointer;
      padding:var(--s1) var(--s3);font-size:var(--f-sec);color:var(--dim)}
 .seg button.on{background:var(--panel);color:var(--fg);
      box-shadow:var(--sh-seg)}

 .sheet{position:fixed;inset:0;z-index:20;background:var(--scrim);
        display:flex;align-items:center;justify-content:center;padding:var(--s4)}
 /* [hidden] and .sheet share specificity, so without this the display:flex
    above wins over the UA rule and the hidden attribute stops hiding anything. */
 .sheet[hidden]{display:none}
 .sheet>div{background:var(--panel);border-radius:14px;box-shadow:var(--sh);
        width:min(30rem,100%);max-height:86vh;overflow:auto;padding:var(--s5)}

 /* 11: above the sticky header (10) so a hover card near the top of a
    scrolled chart is not drawn under it, below the settings sheet (20) so
    it never floats over a modal. */
 .pop{position:absolute;z-index:11;padding:var(--s2) var(--s3);
      background:var(--panel);border-radius:var(--r-ctl);box-shadow:var(--sh);
      font-size:var(--f-sec);pointer-events:none;white-space:nowrap}
 a{color:var(--blue)}
 @media (max-width:620px){body{padding:var(--s3) var(--s3) var(--s5)}
  .panel{padding:var(--s3)}}
"""

# ponytail: one inline glyph instead of a file to serve — it also stops the
# browser asking for /favicon.ico on every page.
ICON = ("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>"
        "<rect width='16' height='16' rx='3' fill='%232C2C2E'/>"
        "<circle cx='8' cy='8' r='3.4' fill='%230A84FF'/></svg>")


def png_icon(size=180, bg=(44, 44, 46), fg=(10, 132, 255)):
    """The same mark as a PNG, for "add to home screen".

    Safari ignores an SVG in an apple-touch-icon and falls back to a screenshot
    of the page, which is what a panel on somebody's home screen looks like
    without this. iOS masks the corners itself, so the image is a flat square
    with a dot in it — and a PNG of two colours is a header, one zlib stream of
    rows and a checksum, which is less code than carrying a base64 blob around
    and no dependency at all.
    """
    r = size * .21
    rows = b""
    for y in range(size):
        dy = y - size / 2 + .5
        half = int((r * r - dy * dy) ** .5) if abs(dy) < r else 0
        left = size // 2 - half
        rows += (b"\0" + bytes(bg) * left + bytes(fg) * (half * 2)
                 + bytes(bg) * (size - left - half * 2))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data)))

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(rows, 9))
           + chunk(b"IEND", b""))
    return "data:image/png;base64," + base64.b64encode(png).decode()


ICON_PNG = png_icon()

# The head both pages share. theme-color paints the browser's own chrome around
# the panel — the address bar on Android, the status bar of a page kept on a
# home screen — and it cannot read a CSS variable, so the two backgrounds are
# repeated here by hand.
HEAD = """<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=theme-color content="#1C1C1E" media="(prefers-color-scheme: dark)">
<meta name=theme-color content="#F2F2F7" media="(prefers-color-scheme: light)">
<link rel=icon href="{{ICON}}">
<link rel=apple-touch-icon href="{{ICONPNG}}">
<script>/* до первой отрисовки, иначе тёмная панель моргнёт светлой */
try{var t=localStorage.gwacl_theme;
if(t=="dark"||t=="light")document.documentElement.dataset.theme=t}catch(e){}</script>"""

LOGIN_T = """<!doctype html><meta charset=utf-8>
{{HEAD}}
<title>{{t.loginTitle}}</title>
<style>{{CSS}}
 body{max-width:20rem;margin:0 auto;padding-top:22vh}
 /* Колонкой, а не в строку: на входе одно поле и одно действие, и кнопка во
    всю ширину — это и есть «войти», а не приписка сбоку от поля. */
 form{display:flex;flex-direction:column;gap:var(--s2);margin-top:var(--s3)}
 form input{width:100%}
 .err{color:var(--red);font-size:var(--f-sec);margin-top:var(--s2)}
</style>
<div class=panel>
 <h1>{{t.panelTitle}}</h1>
 <form method=post action=/login>
  <input class=field name=password type=password autocomplete=current-password
    placeholder="{{t.password}}" autofocus>
  <button class="btn tinted">{{t.signIn}}</button>
 </form>
 {{MSG}}
</div>
"""


def render(tpl, t=None):
    """Substitute the styling, the language strings and the network settings.

    Order matters: {{GW}} and its neighbours live inside the translated hint,
    so the network is substituted after the strings, not before.
    """
    t = t or T
    out = tpl.replace("{{CSS}}", CSS)
    out = out.replace("{{T_JSON}}", json.dumps(t, ensure_ascii=False))
    for k, v in t.items():
        out = out.replace("{{t.%s}}" % k, v)
    # HEAD before ICON: the head is where the two icons are asked for.
    return (out.replace("{{HEAD}}", HEAD)
               .replace("{{GW}}", str(SELF_IP))
               .replace("{{MASK}}", str(LAN.netmask))
               .replace("{{PFX}}", str(LAN.prefixlen))
               .replace("{{VERSION}}", VERSION)
               .replace("{{CFG}}", CONFIG)
               .replace("{{ICON}}", ICON)
               .replace("{{ICONPNG}}", ICON_PNG)
               .replace("{{RELEASES}}", RELEASES_PAGE)
               .replace("{{UPDLOG}}", UPDATE_LOG)
               # The settings form is filled in from the running config.
               .replace("{{IFACE}}", html.escape(IFACE, quote=True))
               .replace("{{LANCIDR}}", str(LAN))
               .replace("{{PORT}}", str(PORT))
               .replace("{{POLL}}", str(POLL_SEC))
               .replace("{{KEEP}}", str(KEEP_MONTHS))
               .replace("{{REBOOT_AT}}", html.escape(CFG["reboot_at"], quote=True))
               .replace("{{RB}}", " checked" if CFG["reboot"] else "")
               .replace("{{RB_OFF}}", "" if CFG["reboot"] else " disabled")
               .replace("{{SEL_RU}}", " selected" if LANG == "ru" else "")
               .replace("{{SEL_EN}}", " selected" if LANG == "en" else "")
               .replace("{{UPD}}", " checked" if CFG["update_check"] else "")
               .replace("{{NTF}}", " checked" if CFG["update_notify"] else "")
               .replace("{{NTF_OFF}}", "" if CFG["update_check"] else " disabled")
               .replace("{{EXAMPLE}}",
                        str(LAN.network_address + min(56, LAN.num_addresses - 2))))


def login_page(msg="", t=None):
    return render(LOGIN_T, t).replace("{{MSG}}", msg)


PAGE_T = """<!doctype html><meta charset=utf-8>
{{HEAD}}
<title>{{t.title}}</title>
<style>{{CSS}}
 #hdr{display:flex;align-items:center;gap:var(--s2);position:sticky;top:0;
      z-index:10;background:var(--bg);padding:var(--s3) 0;margin-bottom:var(--s3)}
 #hdr.stuck{box-shadow:0 .5px 0 var(--line)}
 #hdr .sp{flex:1}
 .ban{display:flex;align-items:center;gap:var(--s3);border-radius:var(--r-panel);
      padding:var(--s2) var(--s3);margin-bottom:var(--s2);font-size:var(--f-row)}
 .ban .sp{flex:1}
 .ban.red{background:var(--redbg);color:var(--red)}
 .ban.blue{background:var(--bluebg)}
 .ban.grey{background:var(--fill);color:var(--dim)}
 /* The chart earns the width, the machine's numbers do not. */
 .row2{display:grid;gap:var(--s4);grid-template-columns:minmax(0,2fr) minmax(0,22rem);
      align-items:start}
 .ch{display:flex;align-items:baseline;gap:.6rem;margin-bottom:.9rem}
 .ch h2{margin:0}
 .ch .sp{flex:1}
 .chead{display:flex;align-items:center;flex-wrap:wrap;gap:var(--s3);margin-bottom:var(--s3)}
 .chead .sp{flex:1}
 .sortgrp{display:flex;align-items:center;gap:2px}
 .hero{display:flex;align-items:baseline;gap:var(--s2)}
 .hero b{font-size:var(--f-hero);font-weight:600;letter-spacing:-.02em}
 .hero em{font-style:normal;font-size:var(--f-sec);color:var(--dim)}
 #chartbox{position:relative;margin-top:var(--s4)}
 #chartbox svg{display:block;width:100%;height:auto}
 svg.dim g{opacity:.4}
 svg.dim g.hi{opacity:1}
 /* One bar per month, click to go there. The height is the month's total, so
    a glance says whether this one is out of the ordinary. */
 .months{display:flex;gap:var(--s1);align-items:flex-end}
 .mo{flex:1;min-width:0;background:none;border:0;padding:var(--s1) 0 14px;
     cursor:pointer;position:relative;
     display:flex;flex-direction:column;justify-content:flex-end;align-items:center;
     gap:var(--s1)}
 /* Narrow: at full page width a bar as wide as its cell reads as a tile, and
    the differences in height stop being the thing you notice. */
 .mo i{display:block;width:100%;max-width:1.4rem;background:var(--mut);
       border-radius:3px 3px 0 0}
 .mo:hover i{background:var(--dim2)}
 .mo.cur i{background:var(--blue)}
 .mo span{font-size:var(--f-sec);color:var(--dim);font-variant-numeric:tabular-nums}
 /* Из потока: иначе лишняя строка делает кнопку выше, а flex-end прижимает по
    низу кнопку целиком — и бар января оказывается выше баров соседей. */
 .mo u{position:absolute;bottom:0;left:0;right:0;text-align:center;
       font-size:10px;color:var(--dim2);text-decoration:none}
 .mo.cur span{color:var(--fg);font-weight:600}
 .meter{height:3px;border-radius:var(--r-pill);background:var(--track);
        margin:0 0 var(--s2) var(--s6)}
 .meter i{display:block;height:100%;border-radius:var(--r-pill);background:var(--blue)}
 /* Not a title attribute: this card is rebuilt on every poll, and the browser
    drops a pending native tooltip whenever the node under the cursor is
    replaced. A CSS one survives that, opens on focus as well as on hover — so
    a tap works too — and shows up in a screenshot. */
 .q{position:relative;margin-left:var(--s1);color:var(--dim);font-style:normal;
    font-size:var(--f-sec);cursor:help}
 .q:hover,.q:focus{color:var(--fg);outline:none}
 /* 11: above the sticky header (10) — the machine card scrolls under #hdr and
    the tooltip must stay readable there — below the settings sheet (20), same
    reasoning as .pop. */
 .q>span{display:none;position:absolute;z-index:11;left:0;top:calc(100% + var(--s1));
    width:min(15rem,62vw);padding:var(--s2) var(--s3);background:var(--panel);
    border-radius:var(--r-ctl);box-shadow:var(--sh);color:var(--fg);
    font-size:var(--f-sec);line-height:1.4;white-space:normal}
 .q:hover>span,.q:focus>span{display:block}
 #flt{max-width:9rem}
 #addrow>summary{list-style:none;display:inline-block;margin-top:var(--s3)}
 #addrow>summary::-webkit-details-marker{display:none}
 #addrow form{display:flex;gap:var(--s2);flex-wrap:wrap;margin-top:var(--s2)}
 #addrow form input{flex:1;min-width:8rem}
 .bad{color:var(--red)}
 .drow{border-bottom:.5px solid var(--line)}
 .drow:last-child{border-bottom:0}
 .dmain{display:flex;align-items:center;gap:var(--s3);min-height:48px;
        padding:var(--s2) 0;cursor:pointer}
 .dmain .sp{flex:1}
 .dname{min-width:0;flex:0 1 14rem}
 .nm{background:none;border:0;border-radius:var(--r-ctl);padding:2px var(--s1);
     width:100%;font-size:var(--f-row)}
 .nm:hover{background:var(--fill)}
 .nm:focus{background:var(--fill);outline:2px solid var(--blue);outline-offset:0}
 .dnum{text-align:right}
 .dot{flex:none;width:7px;height:7px;border-radius:50%;background:transparent}
 .dot.live{background:var(--green)}
 .chev{color:var(--dim);transition:transform .15s,color .15s;display:inline-block}
 .drow.open .chev{transform:rotate(90deg)}
 @media (hover:hover){
  .dmain:hover{background:var(--fill)}
  .dmain:hover .chev{color:var(--fg)}
 }
 .drow.off .nm,.drow.off .dnum{color:var(--dim)}
 .ddet{padding:0 0 var(--s3) var(--s5);display:flex;flex-direction:column;
       gap:var(--s2)}
 .spark{display:block;width:100%;height:28px}
 .dacts{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap}
 .dacts .sp{flex:1}
 .vpn{display:flex;align-items:center;gap:var(--s2);font-size:var(--f-sec);
      color:var(--dim)}
 .dname{position:relative}
 .ghost{position:absolute;right:2px;top:2px;padding:0 var(--s1);font-size:var(--f-sec);
        color:var(--dim);background:var(--fill);border:0;border-radius:var(--r-ctl);
        cursor:pointer}
 .ghost:hover{color:var(--fg)}
 @media (hover:hover){.ghost{opacity:0;transition:opacity .1s}
  .drow:hover .ghost,.ghost:focus{opacity:1}}
 .shead{display:flex;align-items:center;gap:var(--s2);margin-bottom:var(--s4)}
 .shead .sp{flex:1}
 .grp{margin:var(--s4) 0 var(--s2);color:var(--dim)}
 .srow2{display:flex;align-items:center;gap:var(--s2);margin-top:var(--s4)}
 .srow2 .sp{flex:1}
 .sheet .field{max-width:11rem}
 .vpnform{display:flex;flex-direction:column;gap:var(--s2);margin-top:var(--s3)}
 .vpnform .field{width:100%;max-width:none}
 .vpnform textarea{min-height:9rem;resize:vertical}
 .vpnlist .row{align-items:flex-start;flex-wrap:wrap}
 .vpnmeta{min-width:12rem;flex:1}
 .vpnacts{display:flex;gap:var(--s1);flex-wrap:wrap;justify-content:flex-end}
 .sheet input:disabled{opacity:1;color:var(--dim);-webkit-text-fill-color:var(--dim);
   cursor:not-allowed}
 a{color:var(--blue)}
 form{display:flex;gap:.5rem;flex-wrap:wrap}
 form input{flex:1;min-width:8rem}
 @media (max-width:900px){.row2{grid-template-columns:1fr}}
 @media (max-width:620px){
  body{padding:1rem .7rem 3rem}
 }
</style>
<header id=hdr>
 <h1>{{t.h1}}</h1><span class=sp></span>
 <button class="btn plain" onclick=openSheet()>{{t.settingsTitle}}</button>
 <button class="btn plain" onclick=logout()>{{t.logout}}</button>
</header>
<div id=banners></div>
<div class=sheet id=sheet hidden onclick="if(event.target===this)closeSheet()">
 <div>
  <div class=shead><h1>{{t.settingsTitle}}</h1><span class=sp></span>
   <button class=btn onclick=closeSheet()>{{t.close}}</button></div>

  <h2 class=grp>{{t.groupGeneral}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sLang}}</span><select id=s_lang class=field>
    <option value=ru{{SEL_RU}}>Русский<option value=en{{SEL_EN}}>English</select></div>
   <div class=row><span class=sp>{{t.theme}}</span><select id=s_theme class=field
     onchange="setTheme(this.value)"><option value=auto>{{t.themeAuto}}
     <option value=light>{{t.themeLight}}<option value=dark>{{t.themeDark}}</select></div>
   <div class=row><span class=sp>{{t.sPoll}}</span>
    <input id=s_poll class=field type=number min=5 max=3600 value="{{POLL}}"></div>
   <div class=row><span class=sp>{{t.sKeep}}</span>
    <input id=s_keep class=field type=number min=1 max=24 value="{{KEEP}}"></div>
   <p class=hint>{{t.sKeepWhat}}</p>
  </div>

  <h2 class=grp>{{t.groupNet}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sPort}}</span>
    <input id=s_port class=field type=number min=1 max=65535 value="{{PORT}}"></div>
   <div class=row><span class=sp>{{t.sIface}}</span>
    <input id=s_iface class=field value="{{IFACE}}"></div>
   <div class=row><span class=sp>{{t.sLan}}</span>
    <input id=s_lan class=field value="{{LANCIDR}}"></div>
   <div class=row><span class=sp>{{t.sSelfIp}}</span>
    <input id=s_self class=field value="{{GW}}"></div>
   <p class=hint>{{t.sNetHint}}</p>
  </div>

  <h2 class=grp>{{t.groupVpn}}</h2>
  <div class="list inset panel">
   <div class=row><span id="vpnSummary" class=sp>{{t.vpnLoading}}</span></div>
   <div id="vpnList" class=vpnlist></div>
   <div class=vpnform>
    <div class=row><label for=vpnKind>{{t.groupVpn}}</label><span class=sp></span>
     <select id="vpnKind" class=field onchange=vpnFields()>
      <option value=subscription>{{t.vpnSubscription}}</option>
      <option value=wireguard>{{t.vpnWireGuard}}</option>
      <option value=amneziawg>{{t.vpnAmneziaWG}}</option></select></div>
    <div class=row><label for=vpnName>{{t.vpnName}}</label><span class=sp></span>
     <input id="vpnName" class=field maxlength=40 autocomplete="off"
       placeholder="{{t.vpnNamePh}}"></div>
    <div id="vpnSubFields">
     <div class=row><label for=vpnUrl>{{t.vpnUrl}}</label><span class=sp></span>
      <input id="vpnUrl" class=field type=url autocomplete="off"
        placeholder=https:// required></div>
     <div class=row><label for=vpnExclude>{{t.vpnExclude}}</label><span class=sp></span>
      <input id="vpnExclude" class=field maxlength=128 autocomplete="off"
        placeholder="{{t.vpnExcludePh}}"></div>
    </div>
    <div id="vpnQuickFields" hidden>
     <label for=vpnSecret>{{t.vpnConfig}}</label>
     <textarea id="vpnSecret" class=field autocomplete="off" spellcheck=false
       placeholder="{{t.vpnConfigPh}}"></textarea>
    </div>
    <div class=srow2><span id="vpnStatus" class="hint sp" role="status"
      aria-live="polite"></span>
     <button id="vpnAdd" class="btn tinted" onclick=vpnAddProfile()>{{t.vpnAdd}}</button></div>
   </div>
   <p class=hint>{{t.vpnHint}}</p>
  </div>

  <h2 class=grp>{{t.groupMaint}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sRebootAt}}</span>
    <input id=s_reboot_at class=field type=time lang=en-GB value="{{REBOOT_AT}}"{{RB_OFF}}>
    <input id=s_rb class=sw type=checkbox{{RB}} aria-label="{{t.sRebootAt}}"
      onchange="s_reboot_at.disabled=!this.checked"></div>
   <div class=row><span class=sp>{{t.sUpdate}}</span><input id=s_upd class=sw
     type=checkbox{{UPD}} aria-label="{{t.sUpdate}}" onchange="s_ntf.disabled=!this.checked"></div>
   <div class=row><span class=sp>{{t.sNotify}}</span><input id=s_ntf class=sw
     type=checkbox{{NTF}}{{NTF_OFF}} aria-label="{{t.sNotify}}" onchange=askNotify()></div>
   <p class=hint>{{t.sNotifyHint}}</p>
   <div class=row><span class=sp>{{t.byp}}</span><span id=bypbox></span></div>
   <div class=row><span class=sp></span>
    <button class=btn id=s_check onclick=checkUpd()>{{t.sCheck}}</button>
    <button class="btn bad" id=s_reboot onclick=rebootHost()>{{t.sReboot}}</button></div>
   <p class=hint>{{t.sCheckHint}}</p>
  </div>

  <h2 class=grp>{{t.groupPw}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sPw}}</span><input id=s_pw class=field
     type=password autocomplete=new-password placeholder="{{t.sPwKeep}}"></div>
  </div>

  <div class=srow2><span class="sec mono sp">gateway-acl {{VERSION}}</span>
   <button class="btn tinted" onclick=saveCfg()>{{t.sSave}}</button></div>
 </div>
</div>

<div class=row2>
 <div class=panel>
  <div class=chead><h2 id=mtitle></h2><span class=sp></span>
   <div class=seg id=seg>
    <button onclick="setMode('day')">{{t.byDay}}</button>
    <button onclick="setMode('hour')">{{t.byHour}}</button></div>
   <button class=btn onclick=csv() title="{{t.csvWhat}}">CSV</button>
  </div>
  <div class=hero><b class="num" id=kt></b><em id=kdelta></em></div>
  <div class="sec num" id=ksum></div>
  <div id=chartbox></div>
  <h3 class=grp>{{t.byMonth}}</h3>
  <div id=mstrip></div>
 </div>
 <div class=panel>
  <h2>{{t.sysTitle}}</h2>
  <div class="list inset" id=sysbox></div>
 </div>
</div>

<div class=panel>
 <div class=chead><h2>{{t.devicesTitle}}</h2><span class=sp></span>
  <input id=flt class=field placeholder="{{t.filter}}" aria-label="{{t.filter}}"
    oninput=draw()>
  <span class=sortgrp><select id=srt class=field title="{{t.sortBy}}" onchange=setSort(this.value)></select>
  <button class=btn id=srtd onclick=flipSort()></button></span>
  <button class=btn id=allsw onclick=toggleAll() title="{{t.allWhat}}"></button>
 </div>
 <div class="list inset" id=tb></div>
 <details id=addrow>
  <summary class=btn>+ {{t.addDevice}}</summary>
  <form id=f>
   <!-- The list is what ARP and the DHCP leases already know and this table
        does not: a native datalist, so the browser does the completing. -->
   <input name=ip class=field placeholder="{{EXAMPLE}}" list=lanips required>
   <datalist id=lanips></datalist>
   <input name=nm class=field placeholder="{{t.phName}}">
   <button class="btn tinted">{{t.add}}</button>
  </form>
 </details>
 <p class=hint>{{t.hint}}</p>
</div>

<div class=panel id=clash hidden>
 <h2>{{t.clashTitle}}</h2>
 <div class="list inset" id=clashb></div>
</div>

<div class=panel id=unk hidden>
 <h2>{{t.blockedTitle}}</h2>
 <div class="list inset" id=ub></div>
 <p class=hint>{{t.blockedHint}}</p>
</div>

<script>
const T = {{T_JSON}};
let csrf = '';
const esc = s => (s||'').replace(/[<&">]/g, c => ({'<':'&lt;','&':'&amp;','"':'&quot;','>':'&gt;'}[c]));
// Строки подсказок писались для HTML и несут <code> вокруг имён команд.
// В нативном атрибуте разметка не парсится — там нужен голый текст.
const plain = s => (s || '').replace(/<[^>]+>/g, '');
// Math.round on the first branch: the others end in toFixed, but a rate is a
// float and bare bytes would print as 957.4611172333846.
const fmt = b => b < 1024 ? Math.round(b) + T.b
  : b < 1048576 ? (b/1024).toFixed(0) + T.kb
  : b < 1073741824 ? (b/1048576).toFixed(1) + T.mb
  : (b/1073741824).toFixed(2) + T.gb;
// For the axis — no decimals, or the label will not fit the left gutter.
const fmtAx = b => b < 1048576 ? Math.round(b/1024) + T.kb
  : b < 1073741824 ? Math.round(b/1048576) + T.mb
  : (b < 10737418240 ? (b/1073741824).toFixed(1) : Math.round(b/1073741824)) + T.gb;
const n = (tpl, v) => tpl.replace('{n}', v);
const ago = s => s < 90 ? T.now : s < 3600 ? n(T.minAgo, Math.round(s/60))
  : s < 86400 ? n(T.hAgo, Math.round(s/3600)) : n(T.dAgo, Math.round(s/86400));

// A timer is one field: when the state a device stands in now runs out. Which
// way it flips then is nowhere, because it is not needed — a timer always undoes
// whatever set it, so "off until seven" and "on for an hour" are the same thing.
const left = s => s < 5400 ? n(T.tmLeftM, Math.max(1, Math.round(s/60)))
                           : n(T.tmLeftH, Math.round(s/3600));
const banner = (kind, text, act) =>
  `<div class="ban ${kind}"><span class=sp>${text}</span>${act || ''}</div>`;
const TIMES = [[15, 'tm15'], [60, 'tm1h'], [180, 'tm3h'], [480, 'tm8h'],
               ['am', 'tmMorning']];
// Minutes and not a moment: the browser is the one that knows what "until
// 07:00" means where the person reading it is standing, and the gateway is the
// one that knows what time it is. Only the duration survives both.
const tillMorning = () => {
  const d = new Date();
  d.setHours(7, 0, 0, 0);
  if (d <= Date.now()) d.setDate(d.getDate() + 1);
  return Math.round((d - Date.now()) / 60000);
};
const timer = (ip, on, el) => {
  const v = el.value;
  el.value = '';   // a menu of actions, not a state to sit in
  if (v) post({ip, on, for: v === 'am' ? tillMorning() : +v});
};

// The same idea one level up: the list itself, suspended for a while. Shorter
// options than a device's, because this one lets in everything on the network.
const BYP = [[5, 'tm5'], [15, 'tm15'], [60, 'tm1h']];
const mutate = (url, method='POST', body) => fetch(url, {
  method,
  headers: {'Content-Type':'application/json',
            'X-CSRF-Token': csrf},
  body: body === undefined ? '' : JSON.stringify(body)
});
const bypass = (v, el) => {
  if (el) el.value = '';
  if (v === '') return;
  if (+v && !confirm(T.confirmByp)) return;
  mutate('/bypass', 'POST', {for: +v})
    .then(r => r.ok ? load() : r.text().then(alert));
};
// Everyone at once, except whoever is looking: the button offers whichever of
// the two states the others are not already in.
const toggleAll = () => {
  const on = !S.devices.filter(x => x.ip !== S.you).some(x => x.on);
  if (!on && !confirm(T.confirmAllOff)) return;
  post({all: on, except: S.you});
};

const upfmt = s => {
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600);
  return (d ? d + T.dShort + ' ' : '') + h + T.hShort;
};

// S is the last answer from the server, kept so that sorting, the day/hour
// switch and picking a device redraw from memory instead of asking again.
// Раскрытие держится в переменной, а не в разметке: draw() перерисовывает
// список каждые пять секунд и стёр бы состояние, живущее только в DOM.
// open — имя функции окна; своя переменная с тем же именем перекрыла бы её
// на весь скрипт, поэтому openIp.
let S = null, month = null, sel = null, mode = 'day', sortk = 'ip', sortd = 1,
    oth = 0, mtot = 0, openIp = null;
let VPN = null, vpnBusy = false;

// [short label, up, down, full label, other] — the chart draws whatever this
// returns, so the month, the last 24 hours and one device's slice are the same
// code. "other" is what the bucket holds and nobody on the list accounts for:
// history is kept per address and outlives the device it belonged to. With one
// device picked there is nothing to attribute, so it stays out.
const rows = () => {
  const src = mode === 'hour' ? S.hours : S.days;
  const key = mode === 'hour' ? 'hseries' : 'series';
  const d = sel && S.devices.find(x => x.ip === sel);
  const ser = d && d[key];
  const sum = (i, j) => S.devices.reduce((a, x) => a + x[key][i][j], 0);
  return src.map((r, i) => [mode === 'hour' ? r[0] : String(+r[0].slice(8)),
                            ser ? ser[i][0] : r[1], ser ? ser[i][1] : r[2], r[0],
                            ser ? 0 : Math.max(0, r[1] + r[2] - sum(i, 0) - sum(i, 1))]);
};

const chart = (rs, cum) => {
  if (!rs.length) return `<p class=hint>${mode === 'hour' ? T.noHours
    : mtot ? T.rolled : T.noData}</p>`;
  const W = Math.max(chartbox.clientWidth || 720, 280), H = 180, B = 18, top = 16;
  const max = Math.max(...rs.map(d => d[1] + d[2] + d[4]), 1024);
  const bw = W / rs.length, plot = H - B - top;
  const y = v => top + plot - (v / max) * plot;
  // Единственная линия: потолок. Ось слева не нужна — цифры даёт карточка.
  let g = `<line x1=0 x2=${W} y1=${y(max)} y2=${y(max)} stroke="var(--line)"/>`
    + `<text x=0 y=${y(max) - 5} fill="var(--dim)" font-size=10>${fmtAx(max)}</text>`;
  const bars = rs.map((d, i) => {
    const x = i * bw + bw * .24, w = Math.max(1, bw * .52), o = d[4];
    const r = Math.min(3, w / 2);
    const lbl = rs.length > 20 ? (i % 5 === 0) : true;
    // Скругление только сверху: rect с rx скруглил бы и основание, поэтому
    // верхний сегмент рисуется путём, а нижние — обычными прямоугольниками.
    const cap = (yy, hh, fill, op) => hh < .5 ? '' :
      `<path d="M${x} ${yy + hh}V${yy + r}q0 -${r} ${r} -${r}h${w - 2 * r}`
      + `q${r} 0 ${r} ${r}V${yy + hh}z" fill="${fill}"${op ? ` opacity="${op}"` : ''}/>`;
    const box = (yy, hh, fill, op) => hh < .5 ? '' :
      `<rect x=${x} y=${yy} width=${w} height=${hh} fill="${fill}"${op ? ` opacity="${op}"` : ''}/>`;
    const hu = (d[1] / max) * plot, hd = (d[2] / max) * plot, ho = (o / max) * plot;
    // Скругление достаётся самому верхнему видимому сегменту, а не тому, что
    // сверху по замыслу: «прочее» высотой в полпикселя не рисуется вовсе, и
    // столбец остался бы с плоским верхом среди скруглённых соседей. Тише не
    // цветом, а прозрачностью: входящий — главный — остаётся в полную силу.
    const segs = [[ho, 'var(--mut)', y(d[1] + d[2] + o), .6],
                  [hu, 'var(--up)', y(d[1] + d[2]), .9],
                  [hd, 'var(--down)', y(d[2]), null]];
    const first = segs.findIndex(s => s[0] >= .5);
    const body = segs.map(([h, f, yy, op], k) =>
        h < .5 ? '' : k === first ? cap(yy, h, f, op) : box(yy, h, f, op)).join('');
    return `<g data-i=${i} onmouseenter="hover(${i})" onmouseleave="hover(-1)">`
      + `<title>${d[3]}  ↓ ${fmt(d[2])}  ↑ ${fmt(d[1])}`
      + `${o ? `  ${T.other} ${fmt(o)}` : ''}</title>`
      + body
      + `<rect x=${i * bw} y=${top} width=${bw} height=${plot} fill="none" `
      + `pointer-events="all"/></g>`
      + (lbl ? `<text x=${x + w / 2} y=${H - 4} text-anchor=middle `
             + `fill="var(--dim)" font-size=10>${d[0]}</text>` : '');
  }).join('');
  let line = '';
  const tot = rs.reduce((a, d) => a + d[1] + d[2] + d[4], 0);
  if (cum && rs.length > 1 && tot) {
    let run = 0;
    const pts = rs.map((d, i) => { run += d[1] + d[2] + d[4];
      return `${(i * bw + bw / 2).toFixed(1)},${(top + plot - run / tot * plot).toFixed(1)}`;
    }).join(' ');
    line = `<polyline fill=none stroke="var(--dim2)" stroke-width=1 `
      + `stroke-dasharray="2 3" points="${pts}"><title>${T.cumul}  `
      + `${fmt(tot)}</title></polyline>`;
  }
  return `<svg viewBox="0 0 ${W} ${H}">${g}${bars}${line}</svg>`
    + `<div class=pop hidden></div>`;
};

// Наведение не перерисовывает график: столбцы гасятся классом, карточка —
// один div, который переезжает. Иначе каждое движение мыши стоило бы SVG.
const hover = i => {
  const svg = chartbox.querySelector('svg'), pop = chartbox.querySelector('.pop');
  if (!svg || !pop) return;
  svg.classList.toggle('dim', i >= 0);
  for (const g of svg.querySelectorAll('g')) g.classList.toggle('hi', +g.dataset.i === i);
  if (i < 0) { pop.hidden = true; return; }
  const d = rows()[i];
  pop.innerHTML = `<b>${d[3]}</b><br>`
    + `<span style="color:var(--down)">↓</span> ${fmt(d[2])} · `
    + `<span style="color:var(--up)">↑</span> ${fmt(d[1])}`
    + (d[4] ? ` · ${T.other} ${fmt(d[4])}` : '');
  pop.hidden = false;
  const box = svg.getBoundingClientRect(), bw = box.width / rows().length;
  const x = (i + .5) * bw - pop.offsetWidth / 2;
  pop.style.left = Math.max(0, Math.min(box.width - pop.offsetWidth, x)) + 'px';
  // Не выше окна: график можно прокрутить так, что его верх уйдёт за верхнюю
  // границу, а столбцы ещё останутся видны — карточка, приколотая к верху
  // графика, уехала бы вместе с ним.
  pop.style.top = Math.max(0, -box.top + 4) + 'px';
};

const spark = (ser, max, on) => {
  if (!ser || ser.length < 2) return '';
  const w = 240, h = 28, bw = w / ser.length;
  return `<svg class=spark viewBox="0 0 ${w} ${h}" preserveAspectRatio=none `
    + `fill="var(--down)"${on ? '' : ' opacity=.35'}>`
    + ser.map((v, i) => { const t = (v[0] + v[1]) / max * h;
        return t < .4 ? '' : `<rect x="${(i * bw).toFixed(2)}" y="${(h - t).toFixed(2)}" `
          + `width="${Math.max(.7, bw * .72).toFixed(2)}" height="${t.toFixed(2)}"/>`;
      }).join('') + `</svg>`;
};

const devDetail = (x, peak) => `<div class=ddet>`
  + spark(x.series, peak, x.on)
  + `<div class=dacts>`
  + (x.until > S.now
      ? `<button class=btn title="${esc(T.tmCancel)}" `
        + `onclick="post({ip:'${esc(x.ip)}',for:0})">${left(x.until - S.now)} ×</button>`
      : `<select class=field title="${esc(T.tmWhat)}" `
        + `onchange="timer('${esc(x.ip)}',${!x.on},this)">`
        + `<option value="">${T.tmFor}</option>`
        + TIMES.map(([v, k]) => `<option value="${v}">${T[k]}</option>`).join('')
        + `</select>`)
  // vpnOff — это «мимо VPN»: у переключателя подпись называет состояние, в
  // которое он включён, а не действие, как называла его кнопка.
  + (S.vpnable ? `<label class=vpn title="${esc(T.vpnWhat)}">${T.vpnOff}`
      + `<input class=sw type=checkbox${x.vpn ? '' : ' checked'} `
      + `onchange="post({ip:'${esc(x.ip)}',vpn:!this.checked})"></label>` : '')
  + `<button class=btn onclick="pickDev('${esc(x.ip)}')">${T.showInChart}</button>`
  + `<span class=sp></span>`
  + `<button class="btn bad" onclick="del('${esc(x.ip)}',${x.ip === S.you})">`
  + `${T.del}</button></div>`
  + `<div class="sec mono">${esc(x.mac)}</div></div>`;

const toggleRow = ip => { openIp = openIp === ip ? null : ip; draw(); };

const strip = () => {
  const ms = S.months.slice(-12), max = Math.max(...ms.map(m => m[1]), 1);
  return `<div class=months>` + ms.map((m, i) => {
    const [yy, mm] = m[0].split('-');
    // Год только там, где он меняется: двенадцать одинаковых подписей ничего
    // не сообщают, а «12» слева и «08» справа — это разные годы.
    const yr = (i === 0 || mm === '01') ? `<u>${yy.slice(2)}</u>` : '';
    return `<button class="mo${m[0] === S.month ? ' cur' : ''}" `
      + `onclick="load('${m[0]}')" title="${esc(m[0] + '  ' + fmt(m[1]))}">`
      + `<i style="height:${Math.max(2, m[1] / max * 46).toFixed(0)}px"></i>`
      + `<span>${mm}</span>${yr}</button>`;
  }).join('') + `</div>`;
};

// ⓘ, а не кружок с вопросом: тот же CSS-механизм — нативный title не годится,
// карточка перерисовывается на каждом опросе и снимает незакрытую подсказку.
const q = text => `<i class=q tabindex=0>ⓘ<span>${esc(text)}</span></i>`;
const meter = (pct, warn) => `<div class=meter><i style="width:`
  + `${Math.min(100, Math.max(0, pct)).toFixed(0)}%`
  + `${pct >= warn ? ';background:var(--red)' : ''}"></i></div>`;
const srow = (label, val, pct, warn) =>
  `<div class=row><span class=sp>${label}</span><b class=num>${val}</b></div>`
  + (pct === null ? '' : meter(pct, warn));

const machine = s => {
  let h = '';
  if (s.cpu !== null) h += srow(T.sCpu, s.cpu.toFixed(0) + '%', s.cpu, 85);
  if (s.mem) h += srow(T.sMem, `${fmt(s.mem[0])} / ${fmt(s.mem[1])}`,
                       s.mem[0]/s.mem[1]*100, 88);
  if (s.swap) h += srow(T.sSwap, `${fmt(s.swap[0])} / ${fmt(s.swap[1])}`,
                        s.swap[0]/s.swap[1]*100, 50);
  if (s.disk) h += srow(T.sDisk, `${fmt(s.disk[0])} / ${fmt(s.disk[1])}`,
                        s.disk[0]/s.disk[1]*100, 90);
  h += srow(T.sNetIf.replace('{iface}', esc(s.iface)),
            `↓ ${fmt(s.bps[0])}${T.perSec}  ↑ ${fmt(s.bps[1])}${T.perSec}`, null);
  if (s.load) h += srow(T.sLoad, s.load.map(x => x.toFixed(2)).join('  ')
      + (s.cores ? '  · ' + n(T.cores, s.cores) : ''), null);
  if (s.temp) h += srow(T.sTemp + q(n(T.tempWhat, s.temp[1])),
                        s.temp[0].toFixed(0) + ' °C', null);
  if (s.up) h += srow(T.sUptime, upfmt(s.up), null);
  return h || `<p class=hint>${T.sysNone}</p>`;
};

const CMP = {
  // Octets padded, or 192.168.1.9 would sort after 192.168.1.10.
  ip: x => x.ip.split('.').map(o => o.padStart(3, '0')).join('.'),
  name: x => (x.name || '￿').toLowerCase(),
  traf: x => x.up + x.down,
  now: x => x.rate[0] + x.rate[1],
  seen: x => x.seen,
};
// Тема — вкус того, кто смотрит, а не настройка шлюза: в config.json её нет,
// значит и saveCfg() о ней не знает.
const setTheme = v => {
  const r = document.documentElement;
  if (v === 'auto') { delete r.dataset.theme; } else { r.dataset.theme = v; }
  try { v === 'auto' ? localStorage.removeItem('gwacl_theme')
                     : localStorage.setItem('gwacl_theme', v); } catch (e) {}
};
try { s_theme.value = localStorage.gwacl_theme || 'auto'; } catch (e) {}

const VPN_TYPES = {subscription:T.vpnSubscription, wireguard:T.vpnWireGuard,
                   amneziawg:T.vpnAmneziaWG, singbox:T.vpnSubscription,
                   none:T.vpnDirect};
const VPN_ERRORS = {'legacy/no-cache':T.vpnErrLegacy,
  'missing-secret':T.vpnErrMissing, 'tool-missing':T.vpnErrTool,
  stopped:T.vpnErrStopped, 'start-failed':T.vpnErrStart,
  'validation-failed':T.vpnErrValidation, 'rollback-failed':T.vpnErrRollback,
  conflict:T.vpnErrConflict, 'invalid-state':T.vpnErrInvalid};
const vpnError = code => VPN_ERRORS[code] || T.vpnErrInvalid;
const vpnNode = (tag, cls, text) => {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
};
const vpnButton = (text, action, bad=false) => {
  const b = vpnNode('button', 'btn' + (bad ? ' bad' : ''), text);
  b.type = 'button'; b.disabled = vpnBusy; b.onclick = action;
  return b;
};
const vpnFields = () => {
  const sub = vpnKind.value === 'subscription';
  vpnSubFields.hidden = !sub; vpnQuickFields.hidden = sub;
};
const renderVpn = () => {
  vpnList.replaceChildren();
  if (!VPN) { vpnSummary.textContent = T.vpnLoading; return; }
  const backend = VPN.backend || {kind:'none', active:false};
  vpnSummary.textContent = VPN.closed ? T.vpnClosed
    : backend.kind === 'none' ? T.vpnDirect
    : backend.active ? T.vpnRunning.replace('{kind}', VPN_TYPES[backend.kind] || backend.kind)
    : vpnError(backend.error || 'stopped');
  if (!VPN.profiles.length) vpnList.append(vpnNode('p', 'hint', T.vpnEmpty));
  VPN.profiles.forEach(p => {
    const row = vpnNode('div', 'row');
    const dot = vpnNode('i', 'dot' + (p.enabled ? ' live' : ''));
    dot.setAttribute('aria-hidden', 'true'); row.append(dot);
    const meta = vpnNode('div', 'vpnmeta');
    meta.append(vpnNode('b', '', p.name));
    const details = [VPN_TYPES[p.kind] || p.kind,
      p.enabled ? T.vpnEnabled : T.vpnDisabled];
    if (p.kind === 'subscription') details.push(T.vpnNodes.replace('{n}', p.nodes));
    meta.append(vpnNode('div', 'sec', details.join(' · ')));
    if (p.ipv6 === false) meta.append(vpnNode('div', 'sec', T.vpnIpv6));
    if (p.error) meta.append(vpnNode('div', 'bad sec', vpnError(p.error)));
    row.append(meta);
    const acts = vpnNode('div', 'vpnacts');
    if (p.enabled) acts.append(vpnButton(T.vpnDisable, () => {
      const subs = VPN.profiles.filter(x => x.enabled && x.kind === 'subscription');
      if ((p.kind !== 'subscription' || subs.length === 1)
          && !confirm(T.vpnConfirmDisable)) return;
      vpnCall('disable', {id:p.id});
    }));
    else acts.append(vpnButton(T.vpnEnable, () => vpnCall('enable', {id:p.id})));
    if (p.kind === 'subscription')
      acts.append(vpnButton(T.vpnRefresh, () => vpnCall('refresh', {id:p.id})));
    acts.append(vpnButton(T.vpnDelete, () => vpnDeleteProfile(p), true));
    row.append(acts); vpnList.append(row);
  });
  vpnAdd.disabled = vpnBusy;
  vpnFields();
};
const loadVpn = async () => {
  vpnStatus.textContent = T.vpnLoading;
  try {
    const r = await fetch('/vpn');
    if (r.status === 401) { location.reload(); return; }
    if (!r.ok) throw new Error(T.vpnErrStart);
    VPN = await r.json(); csrf = VPN.csrf || csrf; renderVpn();
    vpnStatus.textContent = '';
  } catch (e) { vpnStatus.textContent = e.message || T.vpnErrStart; }
};
const vpnRequest = async (method, url, body) => {
  vpnBusy = true; renderVpn(); vpnStatus.textContent = T.vpnBusy;
  let ok = false;
  try {
    const r = await mutate(url, method, body);
    const data = await r.json();
    if (!r.ok) throw new Error(vpnError(data.error));
    VPN = data; csrf = data.csrf || csrf; renderVpn();
    vpnStatus.textContent = T.vpnSaved; ok = true;
  } catch (e) { vpnStatus.textContent = e.message || T.vpnErrStart; }
  finally {
    vpnUrl.value = ''; vpnSecret.value = '';
    vpnBusy = false; renderVpn();
  }
  return ok;
};
const vpnCall = (action, body={}) => vpnRequest('POST', '/vpn', {action, ...body});
const vpnAddProfile = () => {
  const kind = vpnKind.value, name = vpnName.value.trim();
  const body = {kind, name, exclude:vpnExclude.value};
  if (kind === 'subscription') body.url = vpnUrl.value.trim();
  else body.config = vpnSecret.value;
  if (!name || (kind === 'subscription' ? !body.url : !body.config)) {
    vpnStatus.textContent = T.vpnBadForm; return;
  }
  vpnCall('add', body).then(ok => { if (ok) vpnName.value = ''; });
};
const vpnDeleteProfile = p => {
  if (!confirm(T.vpnConfirmDelete)) return;
  vpnRequest('DELETE', '/vpn?id=' + encodeURIComponent(p.id));
};

// details закрывался сам; шит — нет, поэтому Esc и клик мимо пишутся руками.
const openSheet = () => { sheet.hidden = false; s_lang.focus(); loadVpn(); };
const closeSheet = () => {
  sheet.hidden = true; vpnUrl.value = ''; vpnSecret.value = '';
};
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !sheet.hidden) closeSheet();
});

// The view someone left behind, so a reload does not throw them back to the
// default sort. In a private window localStorage throws — then it is simply
// not remembered. The picked device is not here: it lives in the address bar.
const keep = () => { try {
  localStorage.gwacl = JSON.stringify({mode, sortk, sortd});
} catch (e) {} };
// Ключ и направление разведены: раньше повторный клик по колонке переворачивал
// порядок, а у селекта повторный выбор того же пункта события не даёт.
const DIRDEF = {ip: 1, name: 1, traf: -1, now: -1, seen: -1};
const setSort = k => { sortk = k; sortd = DIRDEF[k]; keep(); draw(); };
const flipSort = () => { sortd = -sortd; keep(); draw(); };
const setMode = m => { mode = m; keep(); draw(); };
// The picked device goes in the fragment and nowhere else: that makes it a
// link one can send, and gives the back button something to undo. Picking only
// moves the address on — onhashchange is what redraws, once.
const pickDev = ip => { location.hash = (!ip || sel === ip) ? '' : ip; };
onhashchange = () => { sel = location.hash.slice(1) || null; draw(); };
const addKnown = b => post({ip: b.dataset.ip, name: b.dataset.nm});

// The table as the panel shows it, for a spreadsheet. Built here rather than
// on the gateway: everything it needs is already in the browser.
const csv = () => {
  if (!S) return;
  const cell = v => typeof v === 'number' ? v
    : '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const B = T.b.trim();
  const out = [[T.colAddr, T.colName, `${T.inbound}, ${B}`, `${T.outbound}, ${B}`,
                `${T.total}, ${B}`, T.colSeen]];
  for (const x of S.devices)
    out.push([x.ip, x.name || x.host || '', x.down, x.up, x.up + x.down,
              x.seen ? new Date(x.seen*1000).toISOString() : '']);
  if (oth) out.push([T.other, '', 0, 0, oth, '']);
  // A BOM, or a spreadsheet opens Cyrillic names as mojibake.
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(
    ['\\ufeff' + out.map(r => r.map(cell).join(';')).join('\\r\\n')],
    {type: 'text/csv;charset=utf-8'}));
  a.download = `gateway-${S.month}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
};

// Баннеры рисуются отдельно от остальной страницы: связь может пропасть до
// того, как приедет первое состояние, и сказать об этом надо всё равно.
const renderBanners = () => {
  banners.innerHTML =
      (S && S.bypass > S.now
        ? banner('red', `${T.bypOn} ${left(S.bypass - S.now)}`,
                 `<button class="btn bad" onclick="bypass(0)">${T.close}</button>`)
        : '')
    + (S && S.update
        ? banner('blue', esc(T.updateNew.replace('{v}', S.update)),
                 `<a class=btn href="{{RELEASES}}" target=_blank `
                 + `rel="noopener noreferrer">${T.updateWhat}</a>`
                 + `<button class=btn title="${esc(plain(T.updateHint) + ' ' + plain(T.updateLog))}" `
                 + `onclick=doUpdate()>${T.updateNow}</button>`)
        : '')
    + offban;
};

const draw = () => {
  if (!S) return;
  if (sel && !S.devices.some(x => x.ip === sel)) sel = null;
  const one = sel && S.devices.find(x => x.ip === sel);
  // The menu that opens it — while it is already open there is nothing left
  // to pick, so the row shows the remaining time instead; the warning and the
  // way to close it live in the red banner above.
  bypbox.innerHTML = S.bypass > S.now
    ? `<span class="sec num">${left(S.bypass - S.now)}</span>`
    : `<select class=field title="${esc(T.bypWhat)}" onchange="bypass(this.value,this)">`
      + `<option value="">${T.byp}</option>`
      + BYP.map(([v, k]) => `<option value="${v}">${T[k]}</option>`).join('')
      + `</select>`;
  const others = S.devices.filter(x => x.ip !== S.you);
  allsw.hidden = !others.length;
  allsw.textContent = others.some(x => x.on) ? T.allOff : T.allOn;
  srt.innerHTML = Object.entries({ip: 'colAddr', name: 'colName', traf: 'colTraffic',
                                  now: 'colNow', seen: 'colSeen'})
    .map(([k, s]) => `<option value=${k}${k === sortk ? ' selected' : ''}>`
                     + `${T[s]}</option>`).join('');
  srtd.textContent = sortd > 0 ? '↑' : '↓';
  srtd.title = T.sortBy;
  srtd.setAttribute('aria-label', sortd > 0 ? T.sortAsc : T.sortDesc);
  const dv = one ? [one] : S.devices;
  const U = dv.reduce((a,x) => a+x.up, 0), D = dv.reduce((a,x) => a+x.down, 0);
  // The month's total counts every address the history knows of, the devices
  // only those still on the list. What is left over is "other" — hence a total
  // that is more than inbound plus outbound, and a tile that says why.
  mtot = (S.months.find(m => m[0] === S.month) || [0, 0])[1];
  oth = one ? 0 : Math.max(0, mtot - S.devices.reduce((a,x) => a+x.up+x.down, 0));

  // Только имя месяца: с year:'numeric' русская локаль добавляет «г.», и
  // заголовок карточки начинает читаться как строка из бухгалтерского отчёта.
  const [my, mm] = S.month.split('-');
  const mname = new Date(+my, +mm - 1).toLocaleDateString(T.locale, {month: 'long'});
  mtitle.innerHTML = mname[0].toUpperCase() + mname.slice(1) + ' ' + my
    + (one ? ` · <button class=btn onclick="pickDev(null)" title="${esc(T.showAll)}">`
             + `${esc(one.name || one.ip)} ×</button>` : '');

  kt.textContent = fmt(U + D + oth);
  // Only against the whole month: a single device against everything last
  // month would be a comparison of two different things.
  const pc = (!one && S.prev) ? Math.round((U + D + oth - S.prev) / S.prev * 100) : null;
  kdelta.textContent = pc === null ? '' : (pc > 0 ? '+' : '') + pc + '%';
  kdelta.title = pc === null ? '' : T.vsPrev;
  ksum.innerHTML = `↓ ${fmt(D)} · ↑ ${fmt(U)} · `
    + `${fmt(Math.round((U + D + oth) / Math.max(S.days.length, 1)))} ${T.perDay}`
    + (oth ? ` · ${T.other} ${fmt(oth)}${q(T.otherWhat)}` : '');

  for (const [i, b] of [...seg.children].entries())
    b.className = (i === 0) === (mode === 'day') ? 'on' : '';

  // Не под курсором: перерисовка снесла бы открытую карточку значений, а
  // держать цифры неподвижными — ровно то, чего хочет тот, кто на них смотрит.
  if (!chartbox.matches(':hover')) chartbox.innerHTML = chart(rows(), mode === 'day');
  mstrip.innerHTML = strip();
  // Not while the pointer is in there: rebuilding the card would close an open
  // tooltip, and holding the numbers still is exactly what someone reading
  // them wants anyway.
  if (!sysbox.matches(':hover'))
    sysbox.innerHTML = S.sys ? machine(S.sys) : `<p class=hint>${T.sysNone}</p>`;

  const peak = Math.max(1, ...S.devices.flatMap(x => x.series.map(v => v[0]+v[1])));
  const fresh = Math.max(120, S.poll * 2);
  // The peak stays the whole list's, so filtering does not silently rescale
  // every sparkline against whatever happens to be left on screen.
  const fq = flt.value.trim().toLowerCase();
  const list = S.devices.filter(x => !fq ||
      (x.ip + ' ' + x.name + ' ' + (x.host || '')).toLowerCase().includes(fq))
    .sort((a, b) => {
      const p = CMP[sortk](a), q = CMP[sortk](b);
      return (p < q ? -1 : p > q ? 1 : 0) * sortd;
    });
  tb.innerHTML = list.map(x => {
    const t = x.up + x.down, me = x.ip === S.you, r = x.rate[0] + x.rate[1];
    const live = r > 0 || (x.seen && S.now - x.seen < fresh);
    const op = openIp === x.ip;
    return `<div class="drow${x.on ? '' : ' off'}${op ? ' open' : ''}">`
     + `<div class=dmain onclick="toggleRow('${esc(x.ip)}')">`
     + `<i class="dot${live ? ' live' : ''}" `
     + `title="${esc(live ? T.dotLive : T.dotQuiet)}"></i>`
     + `<div class=dname>`
     // stopPropagation: клик по имени правит имя, а не раскрывает строку.
     + `<input class=nm value="${esc(x.name)}" placeholder="${esc(x.host || T.phName)}" `
     + `onclick="event.stopPropagation()" `
     + `onchange="setName('${esc(x.ip)}',this.value)">`
     // Имя, которым устройство представляется сети, предложено как имя, которое
     // можно оставить. Через data-, не в onclick: hostname из чужого файла аренд.
     + (!x.name && x.host ? `<button class=ghost data-ip="${esc(x.ip)}" `
        + `data-nm="${esc(x.host)}" onclick="event.stopPropagation();addKnown(this)" `
        + `title="${esc(n(T.useHost, x.host))}">+</button>` : '')
     + `<div class=sec><span class=mono>${esc(x.ip)}</span>`
     + `${me ? ' · ' + T.youAre : ''} · ${x.seen ? ago(S.now - x.seen) : '—'}</div>`
     + `</div><span class=sp></span>`
     + `<div class=dnum><b class=num>${fmt(t)}</b>`
     + `<div class="sec num">${r > 0 ? `↓ ${fmt(x.rate[1])}${T.perSec}`
        + `  ↑ ${fmt(x.rate[0])}${T.perSec}` : '—'}</div></div>`
     + `<span class=chev>›</span>`
     + `<input class=sw type=checkbox${x.on ? ' checked' : ''} `
     + `aria-label="${esc(x.name || x.ip)}" `
     + `onclick="event.stopPropagation()" `
     + `onchange="post({ip:'${esc(x.ip)}',on:this.checked})">`
     + `</div>${op ? devDetail(x, peak) : ''}</div>`;
  }).join('') || `<p class=hint>${fq ? T.noMatch : T.empty}</p>`;

  renderBanners();
  if (S.update) announce(S.update);
  // A listed address that answers as somebody else — the rule is now written
  // for whoever took it.
  clash.hidden = !S.clash.length;
  clashb.innerHTML = S.clash.map(([ip, was, now, ven]) =>
    `<div class=row><div class=dname><b class=mono>${esc(ip)}</b>`
    + `<div class=sec>${esc(T.clashLine.replace('{a}', was).replace('{b}', now))}`
    + `${ven ? ' · ' + esc(ven) : ''}</div></div><span class=sp></span>`
    + `<span class=bad>${q(T.clashHint)}</span></div>`).join('');

  unk.hidden = !S.blocked.length;
  // The name and the hardware address go through data-, not into the onclick:
  // both come out of a lease file this program does not own.
  ub.innerHTML = S.blocked.map(([ip, host, mac, knocked, ven]) =>
    `<div class=row><div class=dname><b class=mono>${esc(ip)}</b>`
    + `<div class=sec>${esc(host)}${host && mac ? ' · ' : ''}${esc(mac)}`
    + `${ven ? ' · ' + esc(ven) : ''}</div></div><span class=sp></span>`
    + `<span class=sec>${knocked === null ? '' : ago(knocked)}</span>`
    + `<button class=btn data-ip="${esc(ip)}" data-nm="${esc(host)}" `
    + `onclick="addKnown(this)">${T.add}</button></div>`).join('');

  lanips.innerHTML = S.lan.map(([ip, host]) =>
    `<option value="${esc(ip)}">${esc(host)}</option>`).join('');
};

// Without this the page keeps showing the last good numbers for as long as it
// is open: the service restarts, the gateway goes down, and nothing on screen
// changes. The header says so instead, and names the time it last heard back.
let okAt = null, offban = '';
const stale = bad => {
  offban = bad ? banner('grey', T.offline.replace('{t}', okAt
    ? okAt.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '—')) : '';
  renderBanners();            // связь может пропасть до первого S — баннер не ждёт draw()
  if (!bad) okAt = new Date();
};
const load = m => fetch('/api?month=' + (month = m || month || ''))
  .then(r => r.status === 401 ? location.reload()
    : r.json().then(s => { csrf = s.csrf || csrf; S = s; draw(); }))
  .then(() => stale(0), () => stale(1));
const post = body => mutate('/api', 'POST', body)
  .then(r => r.ok ? load() : r.text().then(alert));
const setName = (ip, name) => post({ip, name});
const del = (ip, me) => confirm((me ? T.confirmDelMe : T.confirmDel).replace('{ip}', ip))
  && mutate('/api?ip=' + encodeURIComponent(ip), 'DELETE')
     .then(r => r.ok ? load() : r.text().then(alert));
f.onsubmit = e => { e.preventDefault();
  post({ip: f.ip.value, name: f.nm.value}).then(() => f.reset()); };
// The answer is the new address when the port changed, and empty otherwise:
// everything else is already live, the reload is only to redraw the labels.
const saveCfg = () => mutate('/settings', 'POST', {
    lang: s_lang.value, update_check: s_upd.checked,
    update_notify: s_ntf.checked, poll_sec: +s_poll.value,
    keep_months: +s_keep.value, reboot: s_rb.checked, reboot_at: s_reboot_at.value,
    port: +s_port.value, iface: s_iface.value,
    lan: s_lan.value, self_ip: s_self.value, pw: s_pw.value})
  .then(r => r.text().then(x => !r.ok ? alert(x)
    : x ? alert(T.sRestart.replace('{url}', x)) : location.reload()));
// The one button here that cannot be taken back, so it asks first. Nothing is
// reloaded afterwards: the answer is the last thing that arrives before the
// machine goes down, and the page is expected to sit there stale until it is back.
const rebootHost = () => confirm(T.confirmReboot)
  && mutate('/reboot').then(r => r.text().then(alert));
const logout = () => S && mutate('/logout').then(r =>
  r.ok ? location.reload() : r.text().then(alert));

// A new version is worth one interruption, not one per poll: a panel tab sits
// open for days. The version told about is kept in localStorage and not in a
// variable, or a reload would announce the same release over again.
const TITLE = document.title;
const announce = v => {
  if (!s_ntf.checked || s_ntf.disabled
      || localStorage.getItem('gwacl_told') === v) return;
  localStorage.setItem('gwacl_told', v);
  // Notification exists in a secure context only: over plain http on a network
  // address the browser withholds it entirely, and the tab title is then the
  // one thing left that reaches somebody looking at another tab.
  if (window.Notification && Notification.permission === 'granted')
    new Notification(T.updateTitle, {body: T.notifyBody.replace('{v}', v)});
  document.title = '\u2022 ' + TITLE;
};
onfocus = () => { document.title = TITLE; };
// The permission may only be asked for out of a gesture, so the switch is where
// it is asked. A refusal is the browser's to keep: the switch stays on, and the
// dot in the title is what is left.
const askNotify = () => { if (s_ntf.checked && window.Notification
    && Notification.permission === 'default') Notification.requestPermission(); };

// Asks the gateway to ask GitHub now. The answer is a sentence either way, so
// it is shown as it arrives; a found release still has to reach the page through
// the ordinary state, hence the reload of it rather than a line written here.
const checkUpd = () => { s_check.disabled = true;
  mutate('/check')
    .then(r => r.text().then(x => { alert(x); if (r.ok) load(); }))
    .finally(() => { s_check.disabled = false; }); };

// The tag goes into the question through replace, not into any address: what
// gets downloaded is decided on the gateway, off a constant.
const doUpdate = () => confirm(T.updateConfirm.replace('{v}', S && S.update || ''))
  && mutate('/update').then(r => r.text().then(alert));
// Only the chart depends on the pixel width. Redrawing the table here would
// take the cursor out of a name someone is in the middle of typing.
onresize = () => { if (S) chartbox.innerHTML = chart(rows(), mode === 'day'); };
onscroll = () => hdr.classList.toggle('stuck', scrollY > 4);

// "/" is where one starts typing at a table, in every other program.
document.onkeydown = e => {
  if (!sheet.hidden) return;   // filter sits behind the sheet's scrim
  if (e.key === '/' && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) {
    e.preventDefault();
    flt.focus();
  }
};

// Whatever was left behind last time, checked before it is trusted: this comes
// out of storage the panel does not control, and an unknown sort key would
// take the table down with it.
try {
  const p = JSON.parse(localStorage.gwacl || '{}');
  if (CMP[p.sortk]) { sortk = p.sortk; sortd = p.sortd === -1 ? -1 : 1; }
  if (p.mode === 'day' || p.mode === 'hour') mode = p.mode;
} catch (e) {}
sel = location.hash.slice(1) || null;   // draw() drops it if it is gone

load();
// A hidden tab asks for nothing: every /api costs the gateway an nft call, and
// a page left open in a background tab would go on paying for it all week.
// Coming back is worth a fresh look, though.
document.onvisibilitychange = () => document.hidden || load();
// Five seconds, not fifteen: the "now" column is a rate measured over exactly
// this window, so the interval is how alive the page is allowed to look. What
// it costs the gateway is two comparisons and, on a quiet network, no write at
// all — the counters are behind the poll window and the blocked set is cached.
// SELECT as well as INPUT: redrawing the table under an open menu closes it,
// and the timer is chosen from one.
setInterval(() => document.hidden
  || /^(INPUT|SELECT)$/.test(document.activeElement.tagName) || load(), 5000);
</script>
"""

reload_conf()


class HttpError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class H(BaseHTTPRequestHandler):
    server_version = "gateway-acl"

    def _send(self, code, body, ctype="text/html; charset=utf-8", cookie=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        # Nothing here survives its own request: /api is a live reading and the
        # page itself carries the current settings. Without this the address is
        # the same on every refresh, the answer has no validator and no expiry,
        # and a browser is free to serve its own copy — a panel frozen on old
        # numbers with nothing in the console to say why.
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(b)

    def _session_token(self):
        try:
            morsel = SimpleCookie(self.headers.get("Cookie") or "").get("sess")
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def _authed(self):
        return session_ok(self._session_token())

    def _csrf_ok(self):
        token = self._session_token()
        got = self.headers.get("X-CSRF-Token") or ""
        return bool(token) and hmac.compare_digest(got, csrf_for(token))

    def _read_body(self, limit=VPN_MAX):
        if self.headers.get("Transfer-Encoding"):
            raise HttpError(400, "transfer encoding is not supported")
        value = self.headers.get("Content-Length")
        if value is None:
            raise HttpError(411, "content length required")
        value = str(value).strip()
        if not re.fullmatch(r"[0-9]+", value):
            raise HttpError(400, "invalid content length")
        length = int(value)
        if length > limit:
            raise HttpError(413, "request body too large")
        try:
            body = self.rfile.read(length)
        except OSError:
            raise HttpError(400, "incomplete request body") from None
        if len(body) != length:
            raise HttpError(400, "incomplete request body")
        return body

    @staticmethod
    def _json_body(raw):
        try:
            body = json.loads(raw or b"{}")
        except (ValueError, TypeError):
            raise HttpError(400, "invalid json") from None
        if not isinstance(body, dict):
            raise HttpError(400, "invalid json")
        return body

    def _deny(self):
        """A live page gets 401, an ordinary navigation gets the login form."""
        if urlparse(self.path).path in ("/api", "/vpn"):
            self._send(401, T["needLogin"], "text/plain")
        else:
            self._send(200, login_page())

    def do_GET(self):
        path = urlparse(self.path).path
        if path not in ("/", "/api", "/vpn"):
            self._send(404, "not found", "text/plain")
            return
        if not self._authed():
            self._deny()
            return
        if path == "/":
            self._send(200, PAGE)
        elif path == "/api":
            month = parse_qs(urlparse(self.path).query).get("month", [None])[0]
            s = dict(state(month))
            s["you"] = self.client_address[0]
            s["csrf"] = csrf_for(self._session_token())
            self._send(200, json.dumps(s), "application/json")
        else:
            s = vpn_public()
            s["csrf"] = csrf_for(self._session_token())
            self._send(200, json.dumps(s), "application/json")

    def do_POST(self):
        path = urlparse(self.path).path
        allowed = {"/login", "/logout", "/settings", "/reboot", "/check",
                   "/update", "/bypass", "/api", "/vpn"}
        if path not in allowed:
            self._send(404, "not found", "text/plain")
            return
        try:
            if path == "/login":
                self._login(self._read_body(4096))
                return
            if not self._authed():
                self._deny()
                return
            if not self._csrf_ok():
                self._send(403, "invalid csrf token", "text/plain")
                return
            raw = self._read_body()
            if path == "/logout":
                drop_session(self._session_token())
                self._send(200, login_page(f'<p class=hint>{T["loggedOut"]}</p>'),
                           cookie="sess=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
                return
            if path == "/settings":
                self._settings(raw)
                return
            if path == "/reboot":
                self._send(200, T["rebooting"], "text/plain")
                reboot_host()
                return
            if path == "/check":
                if time.time() - _upd["manual"] < MANUAL_EVERY:
                    self._send(429, T["sCheckHint"], "text/plain")
                    return
                _upd["manual"] = time.time()
                if not check_update(force=True):
                    self._send(502, T["updateFail"], "text/plain")
                elif _upd["new"]:
                    self._send(200, T["updateFound"].replace("{v}", _upd["new"]),
                               "text/plain")
                else:
                    self._send(200, T["updateNone"], "text/plain")
                return
            if path == "/update":
                tag = _upd["new"]
                try:
                    tar_url(tag)
                except ValueError:
                    tag = None
                if not tag:
                    self._send(409, T["updateNone"], "text/plain")
                    return
                self._send(200, T["updating"], "text/plain")
                threading.Timer(0.7, install_update, (tag,)).start()
                return
            if path == "/bypass":
                self._bypass(raw)
                return
            if path == "/api":
                self._api(raw)
                return
            body = self._json_body(raw)
            try:
                vpn_action(body.get("action"), body)
                answer = vpn_public()
                answer["csrf"] = csrf_for(self._session_token())
                self._send(200, json.dumps(answer), "application/json")
            except VpnError as e:
                code = str(e) if str(e) in SAFE_VPN_ERRORS else "invalid-state"
                self._send(409, json.dumps({"ok": False, "error": code}),
                           "application/json")
        except HttpError as e:
            self._send(e.status, str(e), "text/plain")

    def _api(self, raw):
        try:
            body = self._json_body(raw)
            devs = load()
            before = ruleset(devs)
            if "all" in body:
                flip_all(devs, bool(body["all"]), str(body.get("except") or ""))
                save(devs)
                if ruleset(devs) != before:
                    apply(devs)
                self._send(200, "ok", "text/plain")
                return
            ip = validate(body.get("ip", ""))
            cur = next((d for d in devs if d["ip"] == ip), None)
            if cur is None:
                cur = {"ip": ip, "name": "", "on": True}
                devs.append(cur)
                devs.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
            if "name" in body:
                cur["name"] = str(body.get("name") or "").strip()[:40]
            if "on" in body:
                cur["on"] = bool(body["on"])
            if "vpn" in body:
                cur["vpn"] = bool(body["vpn"])
            mins = check_minutes(body["for"]) if "for" in body else None
            if mins is not None:
                cur["until"] = int(time.time()) + mins * 60 if mins else 0
            elif "on" in body:
                cur["until"] = 0
            save(devs)
            if ruleset(devs) != before:
                apply(devs)
            self._send(200, "ok", "text/plain")
        except (ValueError, TypeError, AttributeError) as e:
            self._send(400, str(e), "text/plain")

    def _bypass(self, raw):
        """Hold the gateway open for a while, or shut it again now.

        The window is written to the config before the table is rebuilt: a
        crash between the two leaves a gateway that is merely still closed,
        where the other order would leave one that is open with nothing on disk
        saying until when.
        """
        try:
            mins = check_minutes(
                json.loads(raw or b"{}").get("for"), BYPASS_MAX // 60,
                T["badBypass"].replace("{n}", str(BYPASS_MAX // 3600)))
        except ValueError as e:
            self._send(400, str(e), "text/plain")
            return
        bypass_until(int(time.time()) + mins * 60 if mins else 0)
        apply(load())
        self._send(200, "ok", "text/plain")

    def _settings(self, raw):
        """Save the settings form. The answer is the new address, or empty.

        Everything but the port is picked up by reload_conf on the spot; a
        changed port needs the process replaced, and the browser is told where
        to look rather than sent to a socket that is not listening yet.
        """
        try:
            body = json.loads(raw or b"{}")
            pw = str(body.get("pw") or "")
            if pw and len(pw) < 8:
                raise ValueError(T["pwShort"])   # before anything is written
            with _conf_lock:
                base = conf()
                c = check_settings(body, base)
                if pw:
                    salt = secrets.token_bytes(16)
                    c["pw"] = {"salt": salt.hex(),
                               "hash": pw_hash(pw, salt)}
                save_conf(c)
            reload_conf()
            refold()   # keep_months may have just come down
            # Saving the form is the one moment the user is asking about this,
            # so drop the once-a-day timer and let the next tick go and look.
            # Without it a release cut this morning stays invisible until
            # tomorrow, and there would be no way to ask short of a restart.
            _upd["at"] = 0
            if (c["iface"], c["lan"], c["self_ip"]) != \
                    (base["iface"], base["lan"], base["self_ip"]):
                apply(load())      # the rules are written against the new network
        except ValueError as e:
            self._send(400, str(e), "text/plain")
            return
        if c["port"] == base["port"]:
            self._send(200, "", "text/plain")
            return
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        self._send(200, f'http://{host or SELF_IP}:{c["port"]}/', "text/plain")
        restart()

    def _login(self, raw):
        ip = self.client_address[0]
        if fail_blocked(ip):
            self._send(429, login_page(f'<p class=err>{T["tooMany"]}</p>'))
            return
        if not conf()["pw"]:
            self._send(200, login_page(f'<p class=err>{T["noPw"]}</p>'))
            return
        password = parse_qs(raw.decode("utf-8", "replace")).get("password", [""])[0]
        if not check_password(password):
            note_fail(ip)
            self._send(200, login_page(f'<p class=err>{T["wrongPw"]}</p>'))
            return
        _fails.pop(ip, None)
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"sess={new_session()}; Path=/; HttpOnly; "
                                       f"SameSite=Strict; Max-Age={SESSION_TTL}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path not in ("/api", "/vpn"):
            self._send(404, "not found", "text/plain")
            return
        if not self._authed():
            self._deny()
            return
        if not self._csrf_ok():
            self._send(403, "invalid csrf token", "text/plain")
            return
        if path == "/vpn":
            try:
                tid = parse_qs(urlparse(self.path).query).get("id", [""])[0]
                vpn_delete(check_tunnel_id(tid))
                answer = vpn_public()
                answer["csrf"] = csrf_for(self._session_token())
                self._send(200, json.dumps(answer), "application/json")
            except (ValueError, VpnError) as e:
                code = str(e) if str(e) in SAFE_VPN_ERRORS else "invalid-state"
                self._send(409, json.dumps({"ok": False, "error": code}),
                           "application/json")
            return
        try:
            ip = validate(parse_qs(urlparse(self.path).query).get("ip", [""])[0])
        except ValueError as e:
            self._send(400, str(e), "text/plain")
            return
        old = load()
        devs = [d for d in old if d["ip"] != ip]
        if len(devs) == len(old):
            self._send(404, "not found", "text/plain")
            return
        save(devs)
        apply(devs)
        self._send(200, "ok", "text/plain")

    def do_PUT(self):
        self._send(404, "not found", "text/plain")

    do_PATCH = do_PUT
    do_OPTIONS = do_PUT

    def log_message(self, *a):
        pass


def poller():
    while True:
        time.sleep(POLL_SEC)
        poll()
        expire()        # a timer that has run out
        track_macs()    # a device DHCP has moved to another address
        vpn_poll()      # a managed tunnel that vanished closes forwarded traffic
        check_update()
        # A minute of slack so two ticks cannot leave a gap between windows.
        if reboot_due(CFG["reboot"] and CFG["reboot_at"],
                      time.localtime(), uptime(), POLL_SEC + 60):
            reboot_host()


def selftest():
    global CONFIG, TUNNELS, TUNNEL_DIR, LEGACY_SUB_URL, LEGACY_SUB_EXCLUDE
    global SINGBOX_CONFIG
    global save_tunnels
    global _set_vpn_mark
    global _vpn_closed

    class BombReader:
        def read(self, *unused):
            raise AssertionError("request body was read before authentication")

    def request(path, headers=None, body=b""):
        h = object.__new__(H)
        h.path = path
        h.headers = headers or {}
        h.rfile = io.BytesIO(body)
        h.client_address = ("127.0.0.1", 1)
        h.replies = []
        h._send = lambda code, text, *a, **k: h.replies.append(
            (code, text, a, k))
        return h

    h = request("/api", {"Content-Length": "1"})
    h.rfile = BombReader()
    h.do_POST()
    assert h.replies[0][0] == 401

    token = "selftest-csrf-" + secrets.token_hex(8)
    _sessions[_tok(token)] = time.time() + 60
    cookie = {"Cookie": "sess=" + token, "Content-Length": "1"}
    h = request("/vpn", cookie)
    h.rfile = BombReader()
    h.do_POST()
    assert h.replies[0][0] == 403, "bad CSRF must fail before body read"
    assert csrf_for(token) != token and csrf_for(token) != csrf_for(token + "x")

    body_cases = [
        ({}, 411),
        ({"Content-Length": "wat"}, 400),
        ({"Content-Length": "-1"}, 400),
        ({"Content-Length": str(VPN_MAX + 1)}, 413),
        ({"Content-Length": "0", "Transfer-Encoding": "chunked"}, 400),
        ({"Content-Length": "2"}, 400),
    ]
    for headers, status in body_cases:
        h = request("/api", headers, b"x" if headers.get("Content-Length") == "2" else b"")
        try:
            h._read_body()
            raise AssertionError(f"bad request body accepted: {headers}")
        except HttpError as e:
            assert e.status == status, (headers, e.status)
    h = request("/api", {"Content-Length": "3"}, b"abc")
    assert h._read_body(3) == b"abc"

    for method, path in (("do_GET", "/apiX"), ("do_GET", "/vpnX"),
                         ("do_POST", "/apiX"), ("do_DELETE", "/vpnX")):
        h = request(path, {"Content-Length": "1"})
        h.rfile = BombReader()
        getattr(h, method)()
        assert h.replies[0][0] == 404, f"prefix route accepted: {path}"

    h = request("/logout", {"Cookie": "sess=" + token})
    h.do_GET()
    assert h.replies[0][0] == 404 and session_ok(token), \
        "GET logout must neither exist nor revoke the session"
    real_save_sessions = globals()["_save_sessions"]
    try:
        globals()["_save_sessions"] = lambda: None
        h = request("/logout", {"Cookie": "sess=" + token,
                                "X-CSRF-Token": csrf_for(token),
                                "Content-Length": "0"})
        h.do_POST()
        assert h.replies[0][0] == 200 and not session_ok(token), \
            "logout must be a CSRF-protected POST"
    finally:
        globals()["_save_sessions"] = real_save_sessions
        _sessions.pop(_tok(token), None)

    with tempfile.TemporaryDirectory() as td:
        secret = os.path.join(td, "secret.json")
        os.chmod(td, 0o755)
        write_private(secret, {"value": 1})
        assert os.stat(secret).st_mode & 0o777 == 0o600
        first_inode = os.stat(secret).st_ino
        write_private(secret, {"value": 2})
        with open(secret) as f:
            assert json.load(f) == {"value": 2}
        assert os.stat(secret).st_ino != first_inode, \
            "private files must be atomically replaced, not truncated"
        assert os.stat(td).st_mode & 0o777 == 0o755, \
            "a private file must not chmod its existing parent"
        text_secret = os.path.join(td, "profile.conf")
        write_private_text(text_secret, "PrivateKey = hidden\n")
        with open(text_secret) as f:
            assert f.read() == "PrivateKey = hidden\n"
        assert os.stat(text_secret).st_mode & 0o777 == 0o600
        real_replace = os.replace
        try:
            os.replace = lambda *unused: (_ for _ in ()).throw(OSError("cut"))
            try:
                write_private_text(os.path.join(td, "failed.conf"), "secret")
                raise AssertionError("replace failure must escape")
            except OSError:
                pass
        finally:
            os.replace = real_replace
        assert sorted(os.listdir(td)) == ["profile.conf", "secret.json"], \
            "private temp file leaked"

        old_config, CONFIG = CONFIG, os.path.join(td, "config.json")
        try:
            write_private(CONFIG, {"bypass": 123, "vpn_mark": 9})

            def set_mark(c):
                c["vpn_mark"] = 10

            changed = update_conf(set_mark)
            assert changed["bypass"] == 123 and changed["vpn_mark"] == 10, \
                "a config mutation must preserve the latest unrelated values"
        finally:
            CONFIG = old_config

    tid = new_tunnel_id([])
    assert re.fullmatch(r"t[0-9a-f]{12}", tid), tid
    for bad in ("", "../x", "t1/../x", "t" + "0" * 11, "t" + "0" * 13,
                "T" + "0" * 12):
        try:
            check_tunnel_id(bad)
            raise AssertionError(f"unsafe tunnel id accepted: {bad!r}")
        except ValueError:
            pass
    for bad_suffix in ("json", "/x", "../x", ".service"):
        try:
            tunnel_path(tid, bad_suffix)
            raise AssertionError(f"unsafe tunnel suffix accepted: {bad_suffix!r}")
        except ValueError:
            pass
    with tempfile.TemporaryDirectory() as td:
        old_paths = (TUNNELS, TUNNEL_DIR, LEGACY_SUB_URL,
                     LEGACY_SUB_EXCLUDE)
        TUNNELS = os.path.join(td, "tunnels.json")
        TUNNEL_DIR = os.path.join(td, "tunnels")
        LEGACY_SUB_URL = os.path.join(td, "sub.url")
        LEGACY_SUB_EXCLUDE = os.path.join(td, "sub.exclude")
        try:
            try:
                vpn_action("enable", {"id": "../x"})
                raise AssertionError("unsafe POST tunnel id accepted")
            except VpnError as e:
                assert str(e) == "validation-failed"
            rows = [{"id": tid, "name": "Secret profile",
                     "kind": "subscription", "enabled": False,
                     "error": "", "nodes": 0,
                     "url": "https://provider.example/private-token",
                     "body": "vless://private", "PrivateKey": "hidden",
                     "Endpoint": "198.51.100.1:51820"}]
            save_tunnels(rows)
            assert os.stat(TUNNELS).st_mode & 0o777 == 0o600
            loaded = load_tunnels()
            assert loaded[0]["id"] == tid
            stored = open(TUNNELS).read()
            assert "private-token" not in stored and "PrivateKey" not in stored
            public = json.dumps(public_tunnels(loaded), sort_keys=True)
            public += json.dumps(vpn_public(), sort_keys=True)
            for secret_value in ("private-token", "vless://", "hidden",
                                 "198.51.100.1"):
                assert secret_value not in public
            try:
                save_tunnels(loaded + loaded)
                raise AssertionError("duplicate tunnel ids must be rejected")
            except ValueError:
                pass

            with open(LEGACY_SUB_URL, "w") as f:
                f.write("https://legacy.example/private-token\n")
            with open(LEGACY_SUB_EXCLUDE, "w") as f:
                f.write("Russia\n")
            os.unlink(TUNNELS)  # migration is only for a host with no catalog
            real_run = subprocess.run
            subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("migration must not touch the running tunnel"))
            try:
                assert migrate_legacy_subscription()
            finally:
                subprocess.run = real_run
            migrated = load_tunnels()
            assert len(migrated) == 1 and migrated[0]["kind"] == "subscription"
            assert migrated[0]["enabled"] and migrated[0]["error"] == "legacy/no-cache"
            secret_path = tunnel_path(migrated[0]["id"], ".json")
            assert os.stat(TUNNEL_DIR).st_mode & 0o777 == 0o700
            assert os.stat(secret_path).st_mode & 0o777 == 0o600
            with open(secret_path) as f:
                migrated_secret = json.load(f)
            assert migrated_secret == {
                "url": "https://legacy.example/private-token",
                "exclude": "Russia"}
            assert not os.path.exists(LEGACY_SUB_URL)
            assert not os.path.exists(LEGACY_SUB_EXCLUDE)
            assert not migrate_legacy_subscription(), "legacy migration ran twice"
            assert len(load_tunnels()) == 1
            assert "private-token" not in open(TUNNELS).read()
        finally:
            (TUNNELS, TUNNEL_DIR, LEGACY_SUB_URL,
             LEGACY_SUB_EXCLUDE) = old_paths

    with tempfile.TemporaryDirectory() as td:
        old_paths = (TUNNELS, TUNNEL_DIR, LEGACY_SUB_URL,
                     LEGACY_SUB_EXCLUDE)
        TUNNELS = os.path.join(td, "tunnels.json")
        TUNNEL_DIR = os.path.join(td, "tunnels")
        LEGACY_SUB_URL = os.path.join(td, "sub.url")
        LEGACY_SUB_EXCLUDE = os.path.join(td, "sub.exclude")
        with open(LEGACY_SUB_URL, "w") as f:
            f.write("https://legacy.example/private-token\n")
        real_save_tunnels = save_tunnels
        try:
            save_tunnels = lambda rows: (_ for _ in ()).throw(OSError("cut"))
            try:
                migrate_legacy_subscription()
                raise AssertionError("catalog failure must escape migration")
            except OSError:
                pass
        finally:
            save_tunnels = real_save_tunnels
            (TUNNELS, TUNNEL_DIR, LEGACY_SUB_URL,
             LEGACY_SUB_EXCLUDE) = old_paths
        assert os.path.exists(os.path.join(td, "sub.url")), \
            "legacy secret was deleted before catalog commit"
        assert not os.path.exists(os.path.join(td, "tunnels.json"))

    for url, exclude in (("http://provider.example/sub", ""),
                         ("file:///etc/passwd", ""),
                         ("https:///missing-host", ""),
                         ("https://provider.example/sub\nX-Test: bad", ""),
                         ("https://provider.example/" + "x" * 4097, ""),
                         ("https://provider.example/sub", "["),
                         ("https://provider.example/sub", "x" * 129)):
        try:
            check_subscription(url, exclude)
            raise AssertionError("bad subscription input accepted")
        except ValueError:
            pass
    assert check_subscription(" https://provider.example/sub ", "Russia") == \
        ("https://provider.example/sub", "Russia")

    key = base64.b64encode(b"k" * 32).decode()
    wg = f"""# ordinary WireGuard client
[Interface]
PrivateKey = {key}
Address = 10.66.66.5/32, fd42:42:42::5/128
DNS = 1.1.1.1, 8.8.8.8
Table = auto

[Peer]
PublicKey = {key}
PresharedKey = {key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example:51820
PersistentKeepalive = 25
"""
    awg = wg.replace(
        f"PrivateKey = {key}\n",
        f"PrivateKey = {key}\nJc = 10\nJmin = 47\nJmax = 129\n"
        "S1 = 46\nS2 = 30\nS3 = 17\nS4 = 13\n"
        "H1 = 1035708199\nH2 = 256240833\nH3 = 197207975\nH4 = 556935419\n")
    quick_calls = []

    def quick_ok(argv, **kwargs):
        quick_calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")

    checked = check_quick_config("wireguard", wg, quick_ok, "t000000000001")
    assert checked == {"ipv6": True, "verified": True}
    assert quick_calls[-1][0][:2] == ["wg-quick", "strip"]
    assert quick_calls[-1][1]["shell"] is False
    assert "PrivateKey" not in " ".join(quick_calls[-1][0])
    assert not os.path.exists(quick_calls[-1][0][2]), "strip temp config leaked"
    checked = check_quick_config("amneziawg", awg, quick_ok, "t000000000002")
    assert checked["verified"] and quick_calls[-1][0][0] == "awg-quick"
    no_tool = lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    assert not check_quick_config("wireguard", wg, no_tool)["verified"]
    assert not check_quick_config(
        "wireguard", wg.replace(", ::/0", ""), no_tool)["ipv6"]

    bad_quick = {
        "nul": wg + "\x00",
        "too large": wg + "#" * VPN_MAX,
        "invalid utf8": b"[Interface]\nPrivateKey = \xff",
        "second interface": wg + f"\n[Interface]\nPrivateKey = {key}\n",
        "no private key": wg.replace(f"PrivateKey = {key}\n", "", 1),
        "no address": wg.replace(
            "Address = 10.66.66.5/32, fd42:42:42::5/128\n", ""),
        "no peer": wg.split("[Peer]", 1)[0],
        "no public key": wg.replace(f"PublicKey = {key}\n", ""),
        "no allowed ips": wg.replace("AllowedIPs = 0.0.0.0/0, ::/0\n", ""),
        "no endpoint": wg.replace("Endpoint = vpn.example:51820\n", ""),
        "split route": wg.replace("0.0.0.0/0, ::/0", "10.0.0.0/8"),
        "table off": wg.replace("Table = auto", "Table = off"),
        "custom table": wg.replace("Table = auto", "Table = 51820"),
        "mtu too small": wg.replace("Table = auto", "MTU = 575"),
        "mtu too large": wg.replace("Table = auto", "MTU = 999999"),
        "hook": wg.replace("DNS = 1.1.1.1, 8.8.8.8",
                           "pOsTuP = touch /tmp/x"),
        "save config": wg.replace("Table = auto", "SaveConfig = false"),
        "awg fields in wg": awg,
    }
    for why, config in bad_quick.items():
        try:
            check_quick_config("wireguard", config, no_tool)
            raise AssertionError(f"bad quick config accepted: {why}")
        except ValueError as e:
            assert key not in str(e), "a key escaped in a validation error"
    try:
        check_quick_config("amneziawg", wg, no_tool)
        raise AssertionError("plain WireGuard config accepted as AmneziaWG")
    except ValueError:
        pass

    with tempfile.TemporaryDirectory() as td:
        old_paths = TUNNELS, TUNNEL_DIR
        TUNNELS, TUNNEL_DIR = (os.path.join(td, "tunnels.json"),
                               os.path.join(td, "tunnels"))
        try:
            save_tunnels([])
            uid = "5eb99d66-0000-0000-0000-000000000000"
            subscription_body = f"vless://{uid}@a.example:443?security=tls#A"
            added_sub = vpn_add(
                {"kind": "subscription", "name": "Provider A",
                 "url": "https://provider.example/private-token",
                 "exclude": "Russia"}, fetcher=lambda url: subscription_body)
            assert not added_sub["enabled"] and added_sub["nodes"] == 1
            added_wg = vpn_add({"kind": "wireguard", "name": "Frankfurt",
                                "config": wg}, runner=quick_ok)
            assert not added_wg["enabled"] and added_wg["verified"]
            added_awg = vpn_add({"kind": "amneziawg", "name": "Amnezia",
                                 "config": awg}, runner=no_tool)
            assert added_awg["error"] == "tool-missing"
            catalog = load_tunnels()
            assert len(catalog) == 3 and not any(row["enabled"] for row in catalog)
            metadata = open(TUNNELS).read()
            for secret_value in ("private-token", "PrivateKey", key,
                                 "vpn.example:51820"):
                assert secret_value not in metadata
        finally:
            TUNNELS, TUNNEL_DIR = old_paths

    with tempfile.TemporaryDirectory() as td:
        old_tunnel_dir, TUNNEL_DIR = TUNNEL_DIR, os.path.join(td, "tunnels")
        old_singbox, SINGBOX_CONFIG = SINGBOX_CONFIG, os.path.join(td, "sing-box.json")
        try:
            _ensure_tunnel_dir()
            uid = "5eb99d66-0000-0000-0000-000000000000"
            body_a = f"vless://{uid}@a.example:443?security=tls#same"
            body_b = f"vless://{uid}@b.example:443?security=tls#same"
            rows = [
                {"id": "t000000000001", "name": "A", "kind": "subscription",
                 "enabled": True, "error": "", "nodes": 0},
                {"id": "t000000000002", "name": "B", "kind": "subscription",
                 "enabled": True, "error": "", "nodes": 0},
            ]
            write_private(tunnel_path(rows[0]["id"], ".json"),
                          {"url": "https://a.example/sub", "exclude": "",
                           "body": body_a})
            write_private(tunnel_path(rows[1]["id"], ".json"),
                          {"url": "https://b.example/sub", "exclude": "",
                           "body": body_b})
            base_cfg = {"route": {"final": "proxy"}, "outbounds": [
                {"type": "urltest", "tag": "proxy", "outbounds": [],
                 "tolerance": 42},
                {"type": "direct", "tag": "direct"},
                {"type": "vless", "tag": "hand", "server": "hand.example"},
            ]}
            combined, counts = build_singbox(rows, base_cfg)
            assert counts == {"t000000000001": 1, "t000000000002": 1}
            group = next(o for o in combined["outbounds"] if o["tag"] == "proxy")
            assert any(t.startswith("sub-t000000000001-") for t in group["outbounds"])
            assert any(t.startswith("sub-t000000000002-") for t in group["outbounds"])
            before_b = next(o for o in combined["outbounds"]
                            if o["tag"].startswith("sub-t000000000002-"))
            only_b, _ = build_singbox(rows[1:], combined)
            assert not any(o.get("tag", "").startswith("sub-t000000000001-")
                           for o in only_b["outbounds"])
            assert next(o for o in only_b["outbounds"]
                        if o["tag"].startswith("sub-t000000000002-")) == before_b
            write_private(tunnel_path(rows[0]["id"], ".json"),
                          {"url": "https://a.example/sub", "exclude": "",
                           "body": body_a.replace("a.example", "new.example")})
            refreshed, _ = build_singbox(rows, combined)
            assert next(o for o in refreshed["outbounds"]
                        if o["tag"].startswith("sub-t000000000002-")) == before_b

            assert active_backend(rows) == {
                "kind": "singbox", "ids": ["t000000000001", "t000000000002"]}
            quick_row = {"id": "t000000000003", "name": "$(touch /tmp/x)",
                         "kind": "wireguard", "enabled": True,
                         "error": "", "nodes": 0}
            for conflict in (rows + [quick_row], [quick_row, dict(
                    quick_row, id="t000000000004", kind="amneziawg")]):
                try:
                    active_backend(conflict)
                    raise AssertionError("more than one backend class accepted")
                except VpnError:
                    pass
        finally:
            TUNNEL_DIR, SINGBOX_CONFIG = old_tunnel_dir, old_singbox

    seen_commands = []

    def runtime(argv, **kwargs):
        seen_commands.append((argv, kwargs))
        output = {
            "wg": "0xca6c\n",
            "awg": "51820\n",
            "nft": "meta mark 0x2024 return\nmeta mark 0x2023 accept\n",
            "systemctl": "active\n",
            "ip": "7: t000000000003: <POINTOPOINT,UP>\n",
        }.get(argv[0], "")
        return subprocess.CompletedProcess(argv, 0, output, "")

    assert backend_mark(quick_row, runtime) == 0xca6c
    assert backend_mark(dict(quick_row, kind="amneziawg"), runtime) == 51820
    assert backend_mark({"kind": "singbox", "ids": []}, runtime) == 0x2024
    assert parse_singbox_mark("meta mark 0x2024 return\nmeta mark 0x2023 accept") == 0x2024
    assert parse_singbox_mark(
        "meta mark & 0x0000ffff == 0x00002024 return") == 0x2024
    assert parse_singbox_mark("meta mark 0x2024 return\nmeta mark 0x2025 return") == 0
    assert parse_singbox_mark("no mark here") == 0
    assert backend_state([quick_row], runtime) == {
        "kind": "wireguard", "active": True}
    assert all("$(touch" not in " ".join(argv) for argv, _ in seen_commands)
    assert all(kwargs["shell"] is False for _, kwargs in seen_commands)
    try:
        vpn_exec(["sh", "-c", "touch /tmp/x"], runner=runtime)
        raise AssertionError("arbitrary VPN command accepted")
    except VpnError:
        pass

    class FakeVpn:
        def __init__(self):
            self.active = None
            self.fail = set()
            self.commands = []
            self.unmanaged = False
            self.no_tunnel_route = False

        def __call__(self, argv, **kwargs):
            self.commands.append((list(argv), kwargs))
            label = tuple(argv[:2])
            if label in self.fail:
                self.fail.remove(label)
                return subprocess.CompletedProcess(argv, 1, "", "failed-secret")
            if label == ("sing-box", "check"):
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:3] == ["systemctl", "stop", "sing-box"]:
                self.active = None
            elif argv[:3] == ["systemctl", "restart", "sing-box"]:
                self.active = "singbox"
            elif argv[:3] == ["systemctl", "is-active", "sing-box"]:
                code = 0 if self.active == "singbox" else 3
                return subprocess.CompletedProcess(argv, code,
                                                   "active\n" if not code else "", "")
            elif len(argv) > 2 and argv[0] in ("wg-quick", "awg-quick"):
                if argv[1] == "strip":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                tid = os.path.basename(argv[2]).removesuffix(".conf")
                if argv[1] == "down" and self.active != tid:
                    return subprocess.CompletedProcess(argv, 1, "", "not running")
                self.active = tid if argv[1] == "up" else None
            elif argv[:5] == ["ip", "-j", "route", "show", "default"]:
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps([{"dst": "default", "dev": "eth0"}]), "")
            elif argv[:7] == ["ip", "-j", "route", "show", "table", "all", "default"]:
                routes = [{"dst": "default", "dev": "eth0"}]
                if self.active == "singbox" and not self.no_tunnel_route:
                    routes.append({"dst": "default", "dev": "tun0",
                                   "table": 2022})
                elif self.active and self.active != "singbox":
                    routes.append({"dst": "default", "dev": self.active,
                                   "table": 51820})
                if self.unmanaged:
                    routes.append({"dst": "default", "dev": "wg-unmanaged",
                                   "table": 1234})
                return subprocess.CompletedProcess(argv, 0, json.dumps(routes), "")
            elif argv[:6] == ["ip", "-j", "route", "show", "table", "all"]:
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps([{"dst": "default", "dev": argv[-1]}]), "")
            elif argv[:5] == ["ip", "link", "show", "dev"]:
                code = 0 if self.active == argv[4] else 1
                return subprocess.CompletedProcess(argv, code, "link\n" if not code else "", "")
            elif len(argv) == 4 and argv[0] in ("wg", "awg") and argv[3] == "fwmark":
                return subprocess.CompletedProcess(argv, 0, "0xca6c\n", "")
            elif argv[0] == "nft":
                return subprocess.CompletedProcess(argv, 0,
                                                   "meta mark 0x2024 return\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

    with tempfile.TemporaryDirectory() as td:
        old_paths = CONFIG, TUNNELS, TUNNEL_DIR, SINGBOX_CONFIG
        old_mark, old_closed = CFG.get("vpn_mark"), _vpn_closed
        CONFIG = os.path.join(td, "config.json")
        TUNNELS = os.path.join(td, "tunnels.json")
        TUNNEL_DIR = os.path.join(td, "tunnels")
        SINGBOX_CONFIG = os.path.join(td, "sing-box.json")
        fake, gate_states, fail_open = FakeVpn(), [], [False]

        def gate_apply(devs):
            gate_states.append(_vpn_closed)
            assert ("chain vpn_guard" in ruleset(devs)) == _vpn_closed
            if fail_open[0] and not _vpn_closed:
                fail_open[0] = False
                raise OSError("nft apply failed")

        try:
            write_private(CONFIG, dict(DEFAULTS, vpn_mark=0, bypass=0))
            CFG["vpn_mark"] = 0
            save_tunnels([])
            uid = "5eb99d66-0000-0000-0000-000000000000"
            body = f"vless://{uid}@a.example:443?security=tls#A"
            sub = vpn_add({"kind": "subscription", "name": "A",
                           "url": "https://provider.example/token"},
                          fetcher=lambda url: body)
            wire = vpn_add({"kind": "wireguard", "name": "WG",
                            "config": wg}, runner=fake)

            vpn_enable(sub["id"], runner=fake, applier=gate_apply)
            assert fake.active == "singbox" and not _vpn_closed
            assert gate_states[-2:] == [True, False]
            assert next(r for r in load_tunnels() if r["id"] == sub["id"])["enabled"]
            assert json.load(open(CONFIG))["vpn_mark"] == 0x2024
            assert os.path.exists(SINGBOX_CONFIG)
            fake.no_tunnel_route = True
            try:
                _check_backend({"kind": "singbox", "ids": [sub["id"]]}, fake)
                raise AssertionError("sing-box without policy route was healthy")
            except VpnError:
                pass
            fake.no_tunnel_route = False
            assert not _unmanaged_tunnel(
                {"kind": "singbox", "ids": [sub["id"]]}, fake)
            fake.unmanaged = True
            assert _unmanaged_tunnel(
                {"kind": "singbox", "ids": [sub["id"]]}, fake)
            fake.unmanaged = False

            vpn_enable(wire["id"], runner=fake, applier=gate_apply)
            assert fake.active == wire["id"] and not _vpn_closed
            enabled = [r for r in load_tunnels() if r["enabled"]]
            assert [r["id"] for r in enabled] == [wire["id"]]
            assert json.load(open(CONFIG))["vpn_mark"] == 0xca6c

            before_rows = load_tunnels()
            before_config = open(SINGBOX_CONFIG, "rb").read()
            fake.fail.add(("systemctl", "restart"))
            try:
                vpn_enable(sub["id"], runner=fake, applier=gate_apply)
                raise AssertionError("failed sing-box candidate was committed")
            except VpnError:
                pass
            assert fake.active == wire["id"] and not _vpn_closed
            assert load_tunnels() == before_rows
            assert open(SINGBOX_CONFIG, "rb").read() == before_config

            vpn_enable(sub["id"], runner=fake, applier=gate_apply)
            before_rows = load_tunnels()
            before_config = open(SINGBOX_CONFIG, "rb").read()
            before_mark = json.load(open(CONFIG))["vpn_mark"]
            fake.fail.add(("systemctl", "stop"))
            try:
                vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                raise AssertionError("failed old-backend stop was committed")
            except VpnError:
                pass
            assert fake.active == "singbox" and not _vpn_closed
            assert load_tunnels() == before_rows
            fake.fail.add(("ip", "link"))
            try:
                vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                raise AssertionError("unhealthy candidate was committed")
            except VpnError:
                pass
            assert fake.active == "singbox" and not _vpn_closed
            assert load_tunnels() == before_rows
            real_set_mark = _set_vpn_mark
            fail_mark_write = [True]

            def set_mark_once_then_work(mark):
                if fail_mark_write[0]:
                    fail_mark_write[0] = False
                    raise OSError("config write failed")
                return real_set_mark(mark)

            _set_vpn_mark = set_mark_once_then_work
            try:
                try:
                    vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                    raise AssertionError("failed mark write was committed")
                except VpnError:
                    pass
            finally:
                _set_vpn_mark = real_set_mark
            assert fake.active == "singbox" and not _vpn_closed
            assert load_tunnels() == before_rows
            real_save_tunnels = save_tunnels
            fail_catalog = [True]

            def save_once_then_work(rows):
                if fail_catalog[0]:
                    fail_catalog[0] = False
                    raise OSError("catalog write failed")
                return real_save_tunnels(rows)

            save_tunnels = save_once_then_work
            try:
                try:
                    vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                    raise AssertionError("failed catalog write was committed")
                except VpnError:
                    pass
            finally:
                save_tunnels = real_save_tunnels
            assert fake.active == "singbox" and not _vpn_closed
            assert load_tunnels() == before_rows
            fail_open[0] = True
            try:
                vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                raise AssertionError("failed final ruleset was committed")
            except VpnError:
                pass
            assert fake.active == "singbox" and not _vpn_closed
            assert load_tunnels() == before_rows
            fake.fail.add(("wg-quick", "up"))
            try:
                vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                raise AssertionError("failed candidate was committed")
            except VpnError:
                pass
            assert fake.active == "singbox" and not _vpn_closed
            assert load_tunnels() == before_rows
            assert open(SINGBOX_CONFIG, "rb").read() == before_config
            assert json.load(open(CONFIG))["vpn_mark"] == before_mark
            assert "failed-secret" not in json.dumps(public_tunnels())

            sub2 = vpn_add({"kind": "subscription", "name": "B",
                            "url": "https://provider.example/two"},
                           fetcher=lambda url: body.replace("#A", "#B"))
            vpn_enable(sub2["id"], runner=fake, applier=gate_apply)
            assert len([r for r in load_tunnels()
                        if r["kind"] == "subscription" and r["enabled"]]) == 2
            first_secret = tunnel_path(sub["id"], ".json")
            vpn_delete(sub["id"], runner=fake, applier=gate_apply)
            assert fake.active == "singbox" and not os.path.exists(first_secret)
            assert [r["id"] for r in load_tunnels()
                    if r["kind"] == "subscription"] == [sub2["id"]]

            second_secret = tunnel_path(sub2["id"], ".json")
            old_secret = open(second_secret, "rb").read()
            old_runtime = open(SINGBOX_CONFIG, "rb").read()
            fake.fail.add(("sing-box", "check"))
            try:
                vpn_refresh(sub2["id"], runner=fake, applier=gate_apply,
                            fetcher=lambda url: body.replace("a.example", "bad.example"))
                raise AssertionError("failed refresh replaced a working cache")
            except VpnError:
                pass
            assert open(second_secret, "rb").read() == old_secret
            assert open(SINGBOX_CONFIG, "rb").read() == old_runtime
            assert fake.active == "singbox" and not _vpn_closed

            vpn_refresh(sub2["id"], runner=fake, applier=gate_apply,
                        fetcher=lambda url: body.replace("a.example", "new.example"))
            assert b"new.example" in open(second_secret, "rb").read()
            vpn_disable(sub2["id"], runner=fake, applier=gate_apply)
            assert fake.active is None and not _vpn_closed
            assert json.load(open(CONFIG))["vpn_mark"] == 0

            amz = vpn_add({"kind": "amneziawg", "name": "AWG",
                           "config": awg}, runner=fake)
            vpn_enable(amz["id"], runner=fake, applier=gate_apply)
            assert fake.active == amz["id"]
            assert any(argv[:2] == ["awg-quick", "up"]
                       for argv, _ in fake.commands)
            assert any(argv[0] == "awg" and argv[-1] == "fwmark"
                       for argv, _ in fake.commands)
            assert key not in json.dumps(vpn_public(runner=fake)), \
                "the AmneziaWG secret reached the browser projection"
            vpn_disable(amz["id"], runner=fake, applier=gate_apply)
            assert fake.active is None and not _vpn_closed
            amz_secret = tunnel_path(amz["id"], ".conf")
            vpn_delete(amz["id"], runner=fake, applier=gate_apply)
            assert not os.path.exists(amz_secret), \
                "deleting an AmneziaWG profile left its config behind"

            fake.unmanaged = True
            gates_before = list(gate_states)
            try:
                vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                raise AssertionError("unmanaged default-route tunnel was stopped")
            except VpnError as e:
                assert str(e) == "conflict"
            assert gate_states == gates_before and fake.active is None
            fake.unmanaged = False

            vpn_delete(sub2["id"], runner=fake, applier=gate_apply)
            assert not os.path.exists(second_secret)
            assert not any(r["id"] == sub2["id"] for r in load_tunnels())

            last = vpn_add({"kind": "subscription", "name": "rollback",
                            "url": "https://provider.example/last"},
                           fetcher=lambda url: body)
            vpn_enable(last["id"], runner=fake, applier=gate_apply)
            fake.fail.update({("wg-quick", "up"),
                              ("systemctl", "restart")})
            try:
                vpn_enable(wire["id"], runner=fake, applier=gate_apply)
                raise AssertionError("failed rollback opened transit")
            except VpnError as e:
                assert str(e) == "rollback-failed"
            assert _vpn_closed, "rollback failure must keep transit closed"
            assert next(r for r in load_tunnels() if r["id"] == last["id"])[
                "error"] == "rollback-failed"
        finally:
            (CONFIG, TUNNELS, TUNNEL_DIR, SINGBOX_CONFIG) = old_paths
            CFG["vpn_mark"], _vpn_closed = old_mark, old_closed

    with tempfile.TemporaryDirectory() as td:
        old_paths = CONFIG, TUNNELS, TUNNEL_DIR, SINGBOX_CONFIG
        old_mark, old_closed = CFG.get("vpn_mark"), _vpn_closed
        CONFIG = os.path.join(td, "config.json")
        TUNNELS = os.path.join(td, "tunnels.json")
        TUNNEL_DIR = os.path.join(td, "tunnels")
        SINGBOX_CONFIG = os.path.join(td, "sing-box.json")
        fake, gates = FakeVpn(), []

        def startup_gate(devs):
            gates.append(_vpn_closed)

        try:
            write_private(CONFIG, dict(DEFAULTS, vpn_mark=0, bypass=0))
            CFG["vpn_mark"] = 0
            _ensure_tunnel_dir()
            missing = {"id": "t000000000011", "name": "missing",
                       "kind": "wireguard", "enabled": True,
                       "error": "", "nodes": 0}
            save_tunnels([missing])
            orphan = tunnel_path("t000000000012", ".conf")
            write_private_text(orphan, wg)
            keep = os.path.join(TUNNEL_DIR, "keep.txt")
            write_private_text(keep, "not owned by the catalog")
            reconcile_tunnels(runner=fake, applier=startup_gate)
            row = load_tunnels()[0]
            assert not row["enabled"] and row["error"] == "missing-secret"
            assert _vpn_closed and gates[-1]
            assert not os.path.exists(orphan) and os.path.exists(keep)
            vpn_poll(runner=fake, applier=startup_gate)
            assert _vpn_closed, "poll must not reopen a missing managed backend"

            set_transit_closed(False, startup_gate)
            save_tunnels([])
            uid = "5eb99d66-0000-0000-0000-000000000000"
            body = f"vless://{uid}@a.example:443?security=tls#startup"
            sub = vpn_add({"kind": "subscription", "name": "startup",
                           "url": "https://provider.example/startup"},
                          fetcher=lambda url: body)
            rows = load_tunnels()
            _find_tunnel(rows, sub["id"])["enabled"] = True
            save_tunnels(rows)
            reconcile_tunnels(runner=fake, applier=startup_gate)
            assert fake.active == "singbox" and not _vpn_closed
            assert json.load(open(CONFIG))["vpn_mark"] == 0x2024

            fake.active = None
            vpn_poll(runner=fake, applier=startup_gate)
            assert _vpn_closed
            assert _find_tunnel(load_tunnels(), sub["id"])["error"] == "stopped"
            fake.active = "singbox"
            vpn_poll(runner=fake, applier=startup_gate)
            assert not _vpn_closed
            assert _find_tunnel(load_tunnels(), sub["id"])["error"] == ""
            catalog_mtime = os.stat(TUNNELS).st_mtime_ns
            vpn_poll(runner=fake, applier=startup_gate)
            assert os.stat(TUNNELS).st_mtime_ns == catalog_mtime, \
                "a healthy poll must not rewrite flash"

            legacy = load_tunnels()
            legacy[0]["error"] = "legacy/no-cache"
            write_private(tunnel_path(sub["id"], ".json"),
                          {"url": "https://legacy.example/sub", "exclude": ""})
            save_tunnels(legacy)
            fake.commands.clear()
            reconcile_tunnels(runner=fake, applier=startup_gate)
            assert fake.active == "singbox" and not _vpn_closed
            assert not any(argv[:2] == ["sing-box", "check"]
                           or argv[:3] == ["systemctl", "restart", "sing-box"]
                           for argv, _ in fake.commands), \
                "legacy migration must not rebuild the working service"

            stopped_quick = {"id": "t000000000013", "name": "stopped quick",
                             "kind": "wireguard", "enabled": True,
                             "error": "", "nodes": 0}
            write_private_text(tunnel_path(stopped_quick["id"], ".conf"), wg)
            save_tunnels([stopped_quick])
            fake.active = None
            set_transit_closed(True, startup_gate)
            vpn_enable(stopped_quick["id"], runner=fake, applier=startup_gate)
            assert fake.active == stopped_quick["id"] and not _vpn_closed
            assert _find_tunnel(load_tunnels(), stopped_quick["id"])["error"] == "", \
                "an enabled quick profile must recover after an external stop"
        finally:
            (CONFIG, TUNNELS, TUNNEL_DIR, SINGBOX_CONFIG) = old_paths
            CFG["vpn_mark"], _vpn_closed = old_mark, old_closed

    assert accrue(0, 100) == 100
    assert accrue(100, 250) == 150
    assert accrue(500, 20) == 20, "a counter reset must be counted in full"
    assert accrue(500, 500) == 0

    # Addresses come from the configured network: the test has to pass on any
    # subnet, not only on the one it was written against.
    a, b = str(LAN.network_address + 51), str(LAN.network_address + 55)
    d = [{"ip": a, "name": "MacBook"}, {"ip": b, "name": "Quest", "on": False}]
    r = ruleset(d)
    assert f"elements = {{ {a} }}" in r, "a switched-off device must not reach the allowed set"
    assert f"counter {cname('up', b)} {{ }}" in r, "but it still needs its counters"
    assert f"ip daddr {a} counter name {cname('down', a)}" in r
    assert "update @blocked { ip saddr }" in r
    # The panel subtracts what is left of this to say when an address knocked.
    assert f"timeout {BLOCK_TTL}s" in r
    assert "dport" not in r, "the panel port is open to the whole LAN, the password guards it"
    assert "elements" not in ruleset([]), "an empty set breaks nft syntax"
    assert ruleset([]).count("drop") == 1
    # Renaming must not touch nftables.
    assert ruleset(d) == ruleset([dict(d[0], name="Mac"), d[1]])

    # The gateway held open: the verdict goes, nothing else does.
    soon = time.time() + 60
    assert "drop" not in ruleset(d, bypass=soon), "the list must be suspended"
    assert "update @blocked { ip saddr }" in ruleset(d, bypass=soon), \
        "but who came in past the list still has to be recorded"
    assert f"counter {cname('up', b)} {{ }}" in ruleset(d, bypass=soon), \
        "and the accounting does not pause with it"
    assert "drop" in ruleset(d, bypass=time.time() - 1), "a window that has closed"

    guarded = ruleset(d, vpn_closed=True)
    assert "chain vpn_guard" in guarded and "hook forward" in guarded
    assert f'iifname "{IFACE}" drop' in guarded
    assert "hook input" not in guarded, "the tunnel gate must not cut panel or SSH"
    assert "chain vpn_guard" not in ruleset(d, vpn_closed=False)
    gates = []
    set_transit_closed(True, lambda devs: gates.append(ruleset(devs)))
    set_transit_closed(False, lambda devs: gates.append(ruleset(devs)))
    assert "chain vpn_guard" in gates[0] and "chain vpn_guard" not in gates[1]

    # Past the tunnel is not off the network: the device keeps its place in the
    # allowed set, and the mark is stamped before the rule that accepts it away.
    old, CFG["vpn_mark"] = CFG.get("vpn_mark"), 0x2024
    v = ruleset([dict(d[0], vpn=False), d[1]])
    assert f"ip saddr {a} meta mark set 0x2024" in v, "no MAC known, the address it is"
    assert f"elements = {{ {a} }}" in v, "sent past the vpn, still allowed through"
    assert v.index("meta mark set") < v.index("ip saddr @allowed accept"), \
        "a mark stamped after the accept would never be read"
    assert ruleset(d) != v, "and unlike a rename, this one has to reach nftables"
    assert "meta mark" not in ruleset(d), "nobody sent past it, nothing stamped"

    # With a hardware address the rule is written against that instead, and it
    # has to stand above the line that lets IPv6 out of the chain — that line is
    # why the first release of this marked v4 and left v6 in the tunnel.
    m = ruleset([dict(d[0], vpn=False, mac="aa:bb:cc:dd:ee:ff"), d[1]])
    assert "ether saddr aa:bb:cc:dd:ee:ff meta mark set 0x2024" in m
    assert f"ip saddr {a} meta mark set" not in m, "one rule for the device, not two"
    assert m.index("meta mark set") < m.index("meta nfproto != ipv4 accept"), \
        "below that line an IPv6 packet has already left the chain"
    # /proc/net/arp and the lease file are written by other programs, and a
    # ruleset nft refuses is a panel whose every button silently stops working.
    for junk in ("", None, "nope", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:zz",
                 "aa:bb:cc:dd:ee:ff; drop"):
        assert not is_mac(junk), junk
        assert f"ip saddr {a} meta mark set" in ruleset(
            [dict(d[0], vpn=False, mac=junk), d[1]]), "junk falls back to the address"
    assert is_mac("AA:BB:CC:DD:EE:FF"), "the ARP cache is lowercase, a lease file need not be"

    CFG["vpn_mark"] = 0
    assert "meta mark" not in ruleset([dict(d[0], vpn=False), d[1]]), \
        "no mark configured is the feature switched off, not a mark of zero"
    CFG["vpn_mark"] = old

    devs = [{"ip": "10.0.0.1", "on": True, "until": 5}, {"ip": "10.0.0.2", "on": True}]
    flip_all(devs, False, "10.0.0.1")
    assert devs[0] == {"ip": "10.0.0.1", "on": True, "until": 5}, \
        "the address that pressed the button must be left alone"
    assert devs[1] == {"ip": "10.0.0.2", "on": False, "until": 0}
    flip_all(devs, True)
    assert [d["on"] for d in devs] == [True, True] and devs[0]["until"] == 0, \
        "with nobody excepted it switches everyone and spends their timers"

    d = [{"ip": a, "name": "MacBook"}, {"ip": b, "name": "Quest", "on": False}]

    assert validate(f" {a} ") == a
    # 203.0.113.0/24 is TEST-NET-3, never a home network.
    for bad in (str(SELF_IP), "203.0.113.7", "8.8.8.8", "nope", ""):
        try:
            validate(bad)
        except ValueError:
            continue
        raise AssertionError(f"junk accepted: {bad!r}")

    # The timer arrives as minutes, and only the gateway turns them into a
    # moment: a browser whose clock is wrong must not be able to name one.
    assert check_minutes(0) == 0 and check_minutes("15") == 15
    assert check_minutes(TIMER_MAX // 60) == TIMER_MAX // 60
    for bad in (-1, TIMER_MAX // 60 + 1, "soon", None, [60]):
        try:
            check_minutes(bad)
        except ValueError:
            continue
        raise AssertionError(f"the timer accepted {bad!r}")
    # The whole gateway standing open gets a shorter leash than one device.
    assert check_minutes(BYPASS_MAX // 60, BYPASS_MAX // 60)
    try:
        check_minutes(BYPASS_MAX // 60 + 1, BYPASS_MAX // 60)
        raise AssertionError("the gateway was held open past its own limit")
    except ValueError:
        pass

    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "config.json")
        open(f, "w").close()
        os.chmod(f, 0o644)  # as if left over from an older version
        write_private(f, {"pw": {"hash": "secret"}})
        assert oct(os.stat(f).st_mode)[-3:] == "600", "the password hash is world-readable"

    # A restart of the process must not re-count the counters from scratch.
    cur, last, day = {"up_10_0_0_5": 1000, "down_10_0_0_5": 5000}, {}, {}
    devs = [{"ip": "10.0.0.5"}]
    assert apply_deltas(cur, last, day, devs) == {"10.0.0.5": [1000, 5000]}
    assert apply_deltas(cur, last, day, devs) == {}, "nothing moved without traffic"
    assert day["10.0.0.5"] == [1000, 5000], "a restart counted the readings a second time"
    cur = {"up_10_0_0_5": 1200, "down_10_0_0_5": 5000}
    assert apply_deltas(cur, last, day, devs) == {"10.0.0.5": [200, 0]}
    assert day["10.0.0.5"] == [1200, 5000], "the increment is measured from the baseline"
    apply_deltas({"up_10_0_0_5": 7, "down_10_0_0_5": 0}, last, day, devs)
    assert day["10.0.0.5"] == [1207, 5000], "a counter reset is taken in full"

    # Rates: a window too short to divide by holds the bytes over instead of
    # either inventing a spike or losing them.
    global _rate_at
    _rate.clear()
    _pend.clear()
    _rate_at = 1000.0
    rates({"10.0.0.5": [100, 400]}, devs, 1000.5)
    assert _rate == {}, "half a second is not a window"
    rates({"10.0.0.5": [100, 400]}, devs, 1010.0)
    assert _rate == {"10.0.0.5": [20, 80]}, "the held bytes must land in the rate"
    rates({}, devs, 1020.0)
    assert _rate == {"10.0.0.5": [0, 0]}, "a silent device must fall back to zero"
    # Whole bytes, or the page prints 957.4611172333846 B/s.
    rates({"10.0.0.5": [1, 2]}, devs, 1023.0)
    assert all(isinstance(v, int) for v in _rate["10.0.0.5"]), "a rate must be whole"

    _hours.clear()
    note_hour({"10.0.0.5": [5, 5]}, "2026-08-01 10")
    assert note_hour({"10.0.0.5": [1, 2]}, "2026-08-01 10") == {"10.0.0.5": [6, 7]}
    for i in range(30):
        note_hour({}, f"2026-08-02 {i:02d}")
    assert len(_hours) == 24, "the hourly ring must not grow past a day"
    assert "2026-08-01 10" not in _hours
    _hours.clear()

    assert prev_month("2026-08") == "2026-07"
    assert prev_month("2026-01") == "2025-12", "January reaches into last year"

    # /proc/stat as the kernel writes it: idle is field four, iowait five.
    st = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\nintr 9\n"
    assert cpu_jiffies(st) == (800, 1000)
    assert cpu_jiffies("Darwin has no procfs") is None
    assert cpu_jiffies("") is None
    assert cpu_pct((800, 1000), (900, 1100)) == 0.0, "every jiffy went to idle"
    assert cpu_pct((800, 1000), (800, 1100)) == 100.0, "none of them did"
    assert cpu_pct((800, 1000), (850, 1100)) == 50.0
    assert cpu_pct((800, 1000), (800, 1000)) is None, "no time passed, no answer"
    assert cpu_pct(None, (800, 1000)) is None

    mi = parse_meminfo("MemTotal:  2048 kB\nMemAvailable: 1024 kB\nHugePages_Total: 0\nx\n")
    assert mi["MemTotal"] == 2048 * 1024 and mi["MemAvailable"] == 1024 * 1024
    assert parse_meminfo("") == {}

    with tempfile.TemporaryDirectory() as td:
        for z, t in (("thermal_zone0", "41200"), ("thermal_zone1", "53900")):
            os.mkdir(f"{td}/{z}")
            with open(f"{td}/{z}/temp", "w") as f:
                f.write(t + "\n")
        with open(f"{td}/thermal_zone1/type", "w") as f:
            f.write("x86_pkg_temp\n")
        assert temp_c(td) == (53.9, "x86_pkg_temp"), \
            "the warmest sensor is the one worth showing, and it has a name"
        os.remove(f"{td}/thermal_zone1/type")
        assert temp_c(td) == (53.9, "thermal_zone1"), "no type file, so the directory"
        with open(f"{td}/thermal_zone0/temp", "w") as f:
            f.write("-273000\n")   # a disabled zone
        assert temp_c(td) == (53.9, "thermal_zone1"), "an absurd reading is not a sensor"
    assert temp_c("/no/such/place") is None

    arp = ("IP address       HW type  Flags  HW address         Mask  Device\n"
           "192.168.1.99     0x1      0x2    aa:bb:cc:dd:ee:ff  *     eno1\n"
           "192.168.1.98     0x1      0x0    00:00:00:00:00:00  *     eno1\n")
    assert parse_arp(arp) == {"192.168.1.99": "aa:bb:cc:dd:ee:ff"}, "an empty entry is not a device"
    # Who is on a listed address, when it is not the device the entry means.
    who = {"10.0.0.5": ["tv", "aa:bb:cc:dd:ee:ff"],
           "10.0.0.6": ["", "11:22:33:44:55:66"],
           "10.0.0.7": ["", ""]}
    assert clashes([{"ip": "10.0.0.5", "mac": "11:22:33:44:55:66"}], who) \
        == [["10.0.0.5", "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]], \
        "a listed address answering as somebody else has to be said out loud"
    assert clashes([{"ip": "10.0.0.6", "mac": "11:22:33:44:55:66"},
                    {"ip": "10.0.0.7", "mac": "11:22:33:44:55:66"},
                    {"ip": "10.0.0.5"}], who) == [], \
        "the device itself, an address nothing answers on, and an unbound entry"

    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "oui.txt")
        with open(f, "w") as fh:
            fh.write("00-0C-29   (hex)\t\tVMware, Inc.\n3C-5A-B4   (hex)\t\tGoogle\n")
        assert scan_oui(f, {"000c29"}, {}) == {"000c29": "VMware, Inc."}
        m = os.path.join(td, "manuf")
        with open(m, "w") as fh:
            fh.write("00:0C:29\tVMware\tVMware, Inc.\n00:1B:C5:00:00:0/36\tOpenMoko\n")
        assert scan_oui(m, {"000c29", "001bc5"}, {}) == {"000c29": "VMware"}, \
            "the short name, and never a 36-bit block's owner for the whole prefix"
    assert scan_oui("/no/such/list", {"000c29"}, {}) == {}, "a list nobody ships"

    assert vendors(["52:54:00:12:34:56"]) == {"52:54:00:12:34:56": "QEMU/KVM"}
    assert vendors(["aa:bb:cc:dd:ee:ff"]) == {"aa:bb:cc:dd:ee:ff": T["macRandom"]}, \
        "an address the device made up itself is not an unknown manufacturer"
    if not any(os.path.exists(p) for p in OUI_FILES):
        assert vendors(["00:11:22:33:44:55"]) == {"00:11:22:33:44:55": ""}, \
            "a prefix nothing on this machine knows must not be guessed at"
    assert parse_arp("") == {}
    leases = ("1786000000 aa:bb:cc:dd:ee:ff 192.168.1.99 quest-2 01:aa\n"
              "1786000000 11:22:33:44:55:66 192.168.1.97 * *\n")
    assert parse_leases(leases) == {"192.168.1.99": "quest-2"}, "* is a placeholder, not a name"
    assert parse_leases("") == {}
    assert parse_lease_macs(leases, 1785999999) == {
        "aa:bb:cc:dd:ee:ff": "192.168.1.99",
        "11:22:33:44:55:66": "192.168.1.97"}, "the lease says where a device is"
    assert parse_lease_macs(leases, 1786000001) == {}, \
        "a lease that has run out says nothing about where anything is"
    assert parse_lease_macs("0 aa:bb:cc:dd:ee:ff 192.168.1.99 q *", 9e9) == \
        {"aa:bb:cc:dd:ee:ff": "192.168.1.99"}, "0 is a lease that never runs out"
    assert parse_lease_macs("duid 00:01:00:01\n", 0) == {}, \
        "dnsmasq writes a DUID line into the same file"

    salt = secrets.token_bytes(16)
    h = pw_hash("correct horse", salt)
    assert h == pw_hash("correct horse", salt), "the hash must be deterministic"
    assert h != pw_hash("correct hors", salt)
    assert pw_hash("x", salt) != pw_hash("x", secrets.token_bytes(16)), "the salt does nothing"

    with tempfile.TemporaryDirectory() as td:
        global SESSIONS
        SESSIONS = os.path.join(td, "sessions.json")
        # Whatever the running panel has on disk is not this test's business.
        # Nothing is put back: --selftest exits right after.
        _sessions.clear()
        t = new_session()
        assert session_ok(t) and not session_ok("forged")
        assert _load_sessions() == _sessions, "a session must survive a restart"
        assert t not in open(SESSIONS).read(), "the cookie itself must not be on disk"
        drop_session(t)
        assert not session_ok(t) and _load_sessions() == {}, "logging out must revoke"
        u = new_session()
        _sessions[_tok(u)] = time.time() - 1
        assert not session_ok(u), "an expired session must be rejected"
        assert _load_sessions() == {}, "and it must not come back from disk"

    ip = "10.9.9.9"
    for _ in range(FAIL_LIMIT - 1):
        note_fail(ip)
    assert not fail_blocked(ip), "the block must not trigger before the limit"
    note_fail(ip)
    assert fail_blocked(ip), "after the limit of misses the address must sit it out"
    _fails.pop(ip)

    # A real answer from nft 1.1.6. What is left of the timeout is how long ago
    # the address last knocked — the kernel re-arms it on every dropped packet.
    assert parse_blocked(json.loads('{"nftables":[{"metainfo":{}},{"set":{"name":"blocked",'
        '"elem":[{"elem":{"val":"192.168.1.99","expires":21599}}]}}]}')["nftables"]) \
        == {"192.168.1.99": 1}
    assert parse_blocked([{"set": {"name": "blocked"}}]) == {}
    # Some builds write a duration as a string, and give the element a timeout
    # of its own rather than leaving it to the table's.
    assert parse_blocked([{"set": {"name": "blocked", "elem": [
        {"elem": {"val": "10.0.0.1", "expires": "1200s", "timeout": "1800s"}},
        {"elem": {"val": "10.0.0.2"}}, "10.0.0.3"]}}]) \
        == {"10.0.0.1": 600, "10.0.0.2": None, "10.0.0.3": None}, \
        "an element that says nothing about time must not invent a number"

    # The set costs no call of its own: the poll reads the whole table and
    # note_blocked keeps what came with it. The table carries `allowed` too,
    # and its elements are addresses that must not turn up as intruders.
    note_blocked([{"set": {"name": "allowed", "elem": ["10.0.0.7"]}},
                  {"counter": {"name": "up_10_0_0_5", "bytes": 7}},
                  {"set": {"name": "blocked",
                           "elem": [{"elem": {"val": "10.0.0.9", "expires": 21599}}]}}])
    assert blocked() == {"10.0.0.9": 1}, "the allowed set is not a list of intruders"
    assert counters([{"set": {"name": "allowed", "elem": ["10.0.0.7"]}},
                     {"counter": {"name": "up_10_0_0_5", "bytes": 7}}]) \
        == {"up_10_0_0_5": 7}, "one reading of the table answers both questions"

    assert lan_client(str(LAN.network_address + 9))
    assert not lan_client(str(SELF_IP)), "the gateway is not a client of itself"
    for junk in ("203.0.113.7", "2001:db8::1", "quest-2", ""):
        assert not lan_client(junk), f"the lease file offered {junk!r} and it was taken"

    days = {"2026-04-30": {"a": [1, 2]}, "2026-05": {"a": [10, 10]},
            "2026-05-02": {"a": [3, 4], "b": [5, 6]},
            "2026-06-11": {"a": [7, 8]}, "2026-08-01": {"a": [9, 9]}}
    was = {m: month_totals(days, m) for m in ("2026-04", "2026-05", "2026-06", "2026-08")}
    roll_up(days, "2026-08", keep=3)
    assert {m: month_totals(days, m) for m in was} == was, "a rollup must not lose a byte"
    assert days["2026-05"] == {"a": [13, 14], "b": [5, 6]}, "folded into the key that was there"
    assert days["2026-04"] == {"a": [1, 2]}, "and into a new one where there was none"
    assert [k for k in sorted(days) if len(k) == 10] == ["2026-06-11", "2026-08-01"], \
        "three months keep their days, everything older keeps only a total"
    assert roll_up({"2026-08-01": {"a": [1, 1]}}, "2026-08") == 0, \
        "a fresh install has nothing to fold"

    # The files lag memory on purpose. A poll that moved nothing has nothing to
    # write; a poll that moved bytes waits for the window; and what waits must
    # not be lost, so the same reading has to come back after a restart.
    with tempfile.TemporaryDirectory() as td:
        global TRAFFIC, TODAY, nft_table, load, _hist, _flushed, _dirty
        global _cold, _hot_date
        keep_io = (TRAFFIC, TODAY, nft_table, load)
        TRAFFIC = os.path.join(td, "traffic.json")
        TODAY = os.path.join(td, "today.json")
        # The table as nft prints it, so counters() is exercised rather than
        # replaced — it is the half of the reading the accounting hangs on.
        table = lambda up, down: [{"counter": {"name": "up_10_0_0_5", "bytes": up}},
                                  {"counter": {"name": "down_10_0_0_5", "bytes": down}}]
        nft_table = lambda: table(500, 900)
        load = lambda: [{"ip": "10.0.0.5", "name": "x", "on": True}]
        # Everything a fresh process starts with. Not named restart(): that is
        # already a function in this module, and one that re-execs the panel.
        reboot = lambda: globals().update(
            _hist=None, _flushed=0.0, _dirty=False, _cold=False, _hot_date=None)
        reboot()
        today = time.strftime("%Y-%m-%d")

        poll(force=True)                     # first reading, window wide open
        stamp = os.stat(TODAY).st_mtime_ns
        cold_stamp = os.stat(TRAFFIC).st_mtime_ns
        time.sleep(0.01)                     # so any write shows in the mtime
        _flushed = 0.0                       # even with the window wide open
        poll(force=True)
        assert os.stat(TODAY).st_mtime_ns == stamp, "an idle poll wrote the file"

        _flushed = time.time()               # and now the window is shut
        nft_table = lambda: table(700, 900)
        poll(force=True)                     # moved, but inside the window
        assert os.stat(TODAY).st_mtime_ns == stamp, "the write was not buffered"
        assert history()["days"][today] == {"10.0.0.5": [700, 900]}, \
            "the increment must be in memory the moment it is measured"
        _flushed = 0.0
        poll(force=True)
        assert os.stat(TODAY).st_mtime_ns != stamp, "the buffer was never flushed"
        assert json.load(open(TODAY))["day"] == {"10.0.0.5": [700, 900]}
        # And the point of the whole split: recording today did not touch the
        # months behind it. This is the assertion that keeps the daily write
        # volume where it is now — delete it and the file quietly grows back.
        assert os.stat(TRAFFIC).st_mtime_ns == cold_stamp, \
            "a day in progress must not rewrite the closed days"
        assert not [f for f in os.listdir(td) if f.endswith(".tmp")], \
            "an atomic write must not leave its temporary file behind"

        # What the buffer still holds is not lost when the process goes: the
        # baseline on disk is exactly as old as the totals beside it, so the
        # next poll measures the increment from there and arrives at the same
        # figure. Here that process is a fresh _hist read back off both files.
        nft_table = lambda: table(1500, 900)
        poll(force=True)                     # +800, buffered and then dropped
        reboot()
        poll(force=True)
        assert history()["days"][today] == {"10.0.0.5": [1500, 900]}, \
            "a reading lost with the buffer must come back from the counters"

        # Midnight. Yesterday moves to the cold file and stops being rewritten;
        # today stays in the hot one. Neither may lose a byte in the handover.
        # A real date, not a made-up one: an old key would be folded into its
        # month by the same rollover and never reach the cold file as a day.
        y = time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))
        _hist["days"][y] = {"10.0.0.5": [11, 22]}
        _hot_date = y
        _flushed = 0.0
        nft_table = lambda: table(1600, 900)
        poll(force=True)
        cold, hot = json.load(open(TRAFFIC)), json.load(open(TODAY))
        assert cold["days"][y] == {"10.0.0.5": [11, 22]}, \
            "the day that closed must be in the cold file"
        assert today not in cold["days"], "and the day in progress must not be"
        assert hot["date"] == today and hot["day"] == {"10.0.0.5": [1600, 900]}
        reboot()
        assert history()["days"][y] == {"10.0.0.5": [11, 22]} and \
            history()["days"][today] == {"10.0.0.5": [1600, 900]}, \
            "both halves have to come back as one history"

        # A file damaged by a version that wrote it without a rename costs its
        # own contents and nothing more: the panel still starts. Its complaint
        # is caught rather than printed: this is a selftest deliberately feeding
        # itself half a file, and the line scrolling past an installer's output
        # reads as a fault of the install. Caught, not silenced — that the
        # damage is reported at all is the other half of what is being tested.
        open(TRAFFIC, "w").write('{"days": {"2026-01-0')
        said = io.StringIO()
        with contextlib.redirect_stderr(said):
            reboot()
            assert history()["days"][today] == {"10.0.0.5": [1600, 900]}, \
                "half a cold file must not take the day in progress with it"
        assert TRAFFIC in said.getvalue(), \
            "a file that could not be read has to say so, once, on stderr"

        reboot()
        TRAFFIC, TODAY, nft_table, load = keep_io
    _rate.clear()
    _pend.clear()
    _hours.clear()

    days = {"2026-07": {"1.1.1.1": [5, 5]}, "2026-07-30": {"1.1.1.1": [10, 20]},
            "2026-08-01": {"1.1.1.1": [99, 99]}}
    assert month_totals(days, "2026-07") == {"1.1.1.1": [15, 25]}, "the old format is lost"
    # One pass for every month there is, rather than one pass per month: this is
    # the figure under the chart and in the strip, on every request.
    assert month_sums(days) == {"2026-07": 40, "2026-08": 198}, \
        "a month's total counts a folded figure and the days alike"
    assert month_sums({}) == {}

    # Devices: the file is read again only when it changes, a timer runs the
    # state back the other way once, and an entry follows its hardware address.
    with tempfile.TemporaryDirectory() as td:
        global DEVICES, apply, lan_names, lease_macs, _devs_stamp
        keep_dev = (DEVICES, TRAFFIC, TODAY, apply, lan_names, nft_table,
                    lease_macs)
        # A gateway running its own selftest has a real lease file, and the
        # addresses below are made up.
        lease_macs = lambda: {}
        DEVICES = os.path.join(td, "devices.json")
        TRAFFIC = os.path.join(td, "traffic.json")
        TODAY = os.path.join(td, "today.json")
        applied = []
        apply = lambda devs: applied.append([d["ip"] for d in devs])
        nft_table = lambda: []
        _devs["mtime"] = None
        globals().update(_hist=None, _flushed=0.0, _dirty=False, _cold=False,
                         _hot_date=None)
        a, b = str(LAN.network_address + 51), str(LAN.network_address + 55)
        today = time.strftime("%Y-%m-%d")

        save([{"ip": a, "name": "x", "on": True}])
        mine = load()
        mine[0]["name"] = "not saved"
        assert load()[0]["name"] == "x", "the cache lent out its own list"
        save([{"ip": a, "name": "y", "on": True}])
        assert load()[0]["name"] == "y", "a written file must be read again"

        save([{"ip": a, "on": True, "until": 100}])
        assert not expire(50), "a timer that has not run out must not fire"
        assert expire(100), "and one that has, must"
        assert load()[0] == {"ip": a, "on": False, "until": 0}, \
            "the state flips back and the timer is spent"
        assert not expire(200), "a spent timer must not fire twice"
        assert applied == [[a]], "the ruleset is rebuilt once, by the flip"

        # A device that has never been seen records the address it answers from.
        save([{"ip": b, "name": "quest", "on": True}])
        lan_names = lambda: {b: ["quest", "aa:bb:cc:dd:ee:ff"]}
        assert not track_macs(), "a device that is where it belongs has not moved"
        assert load()[0]["mac"] == "aa:bb:cc:dd:ee:ff", "the first sighting binds it"

        # ...and then DHCP moves it. The entry follows, history and all.
        save([{"ip": a, "name": "quest", "on": True, "mac": "aa:bb:cc:dd:ee:ff"}])
        with _lock:
            history()["days"][today] = {a: [1, 2]}
            history()["seen"][a] = 111
        applied.clear()
        assert track_macs(), "the address changed under a known device"
        assert load()[0]["ip"] == b and applied == [[b]], \
            "the entry and the ruleset both have to follow it"
        assert history()["days"][today] == {b: [1, 2]}, "its history moved with it"
        assert history()["seen"] == {b: 111}, "and so did when it was last seen"
        assert not track_macs(), "nothing moves the second time"

        # The gateway held open, and shutting itself again afterwards. The
        # config goes to the scratch directory: --selftest must not write to
        # /etc, and as a plain user it could not anyway.
        keep_cfg, CONFIG = CONFIG, os.path.join(td, "config.json")
        save([{"ip": a, "on": True}])
        applied.clear()
        bypass_until(1000)
        assert CFG["bypass"] == 1000 and json.load(open(CONFIG))["bypass"] == 1000, \
            "an open gateway has to survive a restart of the panel"
        assert not expire(999), "the window is still open"
        assert expire(1000), "and now it is not"
        assert CFG["bypass"] == 0 and applied == [[a]], \
            "shutting it again means rebuilding the table"
        CONFIG = keep_cfg

        # An address that already belongs to another entry is not taken.
        save([{"ip": a, "on": True, "mac": "11:22:33:44:55:66"},
              {"ip": b, "on": True, "mac": "aa:bb:cc:dd:ee:ff"}])
        lan_names = lambda: {b: ["", "11:22:33:44:55:66"]}
        assert not track_macs(), "two entries must never land on one address"
        assert [d["ip"] for d in load()] == [a, b]

        # The cache still holds the address the device left. Which of the two
        # comes last in it decided where the entry went, so the entry walked
        # back and forth between them, poll after poll.
        save([{"ip": a, "name": "quest", "on": True, "mac": "aa:bb:cc:dd:ee:ff"}])
        lan_names = lambda: {a: ["", "aa:bb:cc:dd:ee:ff"],
                             b: ["", "aa:bb:cc:dd:ee:ff"]}
        applied.clear()
        assert not track_macs(), "one device at two addresses is not a move"
        assert load()[0]["ip"] == a and not applied, "the entry stays put"
        lease_macs = lambda: {"aa:bb:cc:dd:ee:ff": b}
        assert track_macs(), "the lease breaks the tie"
        assert load()[0]["ip"] == b
        lease_macs = lambda: {"aa:bb:cc:dd:ee:ff": str(LAN.network_address + 200)}
        assert not track_macs(), \
            "a lease for an address nothing answers at is not where it is either"
        assert load()[0]["ip"] == b
        lease_macs = lambda: {}

        # A button pressed while the poller was working must not be undone.
        save([{"ip": a, "name": "quest", "on": True, "mac": "aa:bb:cc:dd:ee:ff"}])
        lan_names = lambda: {b: ["", "aa:bb:cc:dd:ee:ff"]}
        keep_stamp, _devs_stamp = _devs_stamp, lambda: secrets.token_hex(4)
        assert not track_macs(), "the list changed underneath — let go of it"
        assert load()[0]["ip"] == a, "and leave what they wrote alone"
        _devs_stamp = keep_stamp

        DEVICES, TRAFFIC, TODAY, apply, lan_names, nft_table, lease_macs = keep_dev
        _devs["mtime"] = None
        globals().update(_hist=None, _flushed=0.0, _dirty=False, _cold=False,
                         _hot_date=None)

    # The icon iOS puts on a home screen. Safari ignores the SVG one and takes a
    # screenshot of the page instead.
    png = base64.b64decode(ICON_PNG.split(",", 1)[1])
    assert png.startswith(b"\x89PNG\r\n\x1a\n") and b"IEND" in png
    assert zlib.decompress(png[png.index(b"IDAT") + 4:-12]).__len__() == 180 * (180 * 3 + 1), \
        "every row of the icon has to be there, filter byte and all"

    assert newer("v1.0.1", "1.0.0") == "v1.0.1"
    assert newer("v1.0.0", "1.0.0") is None, "the running version is not an update"
    assert newer("v0.9.0", "1.0.0") is None, "a downgrade must not be announced"
    assert newer("v1.10.0", "1.9.0"), "versions compare as numbers, not as text"
    assert newer("1.2", "1.2.0") is None, "a short tag is the same release"
    assert newer("nightly", "1.0.0") is None, "an odd tag is silence, not a banner"
    assert newer("v1.0.3", "1.0.2") == "v1.0.3", "a patch release is an update"
    assert newer("v1.0.3", "1.1.0") is None, "a minor release outranks a patch"

    # What the update button is allowed to fetch. The tag is the only part of
    # the address that does not come from a constant, so it is the only part
    # that has to be refused — this runs as root and unpacks what it gets.
    assert tar_url("v1.4.0") == TARBALL + "v1.4.0"
    for bad in ("", None, "nightly", "1.4.0 ; reboot", "../../etc/passwd",
                "https://evil.example/x", "1.4.0?x=1", "1.4.0/..", "v1.4.0\n"):
        try:
            tar_url(bad)
            raise AssertionError(f"{bad!r} must not become an address")
        except ValueError:
            pass

    # And what it is allowed to write out of the archive it fetched.
    with tempfile.TemporaryDirectory() as td:
        plain = os.path.join(td, "plain")
        with open(plain, "w") as f:
            f.write("x")
        arc = os.path.join(td, "t.tar")
        with tarfile.open(arc, "w") as tf:
            for name in ("rel/panel.py", "../escape.py", "/abs.py"):
                info = tarfile.TarInfo(name)
                info.size = 1
                with open(plain, "rb") as f:
                    tf.addfile(info, f)
            link = tarfile.TarInfo("rel/passwd")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tf.addfile(link)
        with tarfile.open(arc) as tf:
            kept = [m.name for m in _safe_members(tf)]
        assert kept == ["rel/panel.py"], f"only the archive's own files: {kept}"
    assert _ver(VERSION), f"VERSION {VERSION!r} does not compare against a tag"

    # The scheduled reboot. `up` is what keeps a machine that has just rebooted
    # from rebooting again while the window it woke up in is still open.
    at = lambda hh, mm, ss, up=9999, w=120: reboot_due(
        "05:30", time.struct_time((2026, 8, 5, hh, mm, ss, 2, 217, -1)), up, w)
    assert at(5, 30, 0) and at(5, 31, 59), "the window is a poll long"
    assert not at(5, 29, 59), "and it does not open early"
    assert not at(5, 32, 0), "nor stay open after it"
    assert not at(5, 30, 0, up=600), "a machine that just booted must not go down"
    assert not at(23, 59, 59) and not at(0, 0, 0)
    for off in ("", None, False):
        assert not reboot_due(off, time.localtime(), 9999, 86400), "the switch is off"
    for junk in ("полшестого", "5", "24:00:00"):
        assert not reboot_due(junk, time.localtime(), 9999, 86400), \
            f"{junk!r} must be silence, not a dead poller thread"
    assert not DEFAULTS["reboot"], "a fresh install must not reboot itself"

    base = dict(DEFAULTS)
    form = {"lang": "en", "update_check": False, "poll_sec": 30, "keep_months": 6,
            "reboot": True, "reboot_at": "5:30",
            "port": base["port"], "iface": base["iface"],
            "lan": "10.7.0.0/24", "self_ip": "10.7.0.1"}
    c = check_settings(form, base)
    assert (c["lang"], c["poll_sec"], c["keep_months"]) == ("en", 30, 6)
    assert (c["reboot"], c["reboot_at"]) == (True, "05:30"), \
        "the switch, and a time stored as <input type=time> wants it"
    assert check_settings(dict(form, reboot=False), base)["reboot_at"] == "05:30", \
        "turning the reboot off must keep the hour it was set to"
    assert c["update_check"] is False and c["lan"] == "10.7.0.0/24"
    assert c["update_notify"] is base["update_notify"], \
        "a field the form did not send keeps the value it had"
    assert check_settings(dict(form, update_notify=False), base)["update_notify"] \
        is False
    assert c["pw"] == base["pw"], "a settings save must not drop the password"
    assert check_settings({}, base) == base, "an empty form changes nothing"
    with socket.socket() as busy:
        busy.bind(("", 0))                  # a port nobody else can have
        busy.listen()
        taken = busy.getsockname()[1]
        for bad in ({"lan": "10.7.0.5/24"},              # host bits set
                    {"self_ip": "192.168.9.9"},         # outside the network
                    {"port": 0}, {"port": 70000}, {"port": "abc"},
                    {"port": taken},                    # would not come back up
                    {"poll_sec": 4}, {"poll_sec": 99999},
                    {"keep_months": 0}, {"keep_months": 25}, {"keep_months": "all"},
                    {"reboot_at": "25:00"}, {"reboot_at": "half past five"},
                    {"reboot_at": ""},   # the field cannot be emptied, only switched off
                    {"lang": "de"}, {"iface": "no-such-iface0"}):
            try:
                check_settings(dict(form, **bad), base)
            except ValueError:
                continue
            raise AssertionError(f"the settings form accepted {bad}")

    # The script drives the page by id. A rename on one side only leaves a card
    # silently empty in the browser, which no other check here would notice.
    page = render(PAGE_T)
    for needle in ('id="vpnList"', 'id="vpnKind"', 'id="vpnSecret"',
                   'aria-live="polite"', 'autocomplete="off"'):
        assert needle in page, f"the tunnel form has no {needle}"
    assert "PrivateKey" not in page and "PresharedKey" not in page, \
        "a tunnel secret leaked into the rendered page"
    for el in ("banners", "kt", "kdelta", "mtitle", "ksum", "seg",
               "chartbox", "mstrip", "sysbox", "tb",
               "unk", "ub",
               "flt", "srt", "srtd", "addrow", "lanips", "s_keep",
               "s_reboot", "s_reboot_at", "s_rb", "s_check", "bypbox", "allsw", "clash",
               "clashb", "s_theme", "sheet"):
        assert f"id={el}>" in page or f"id={el} " in page, f"the page has no {el}"

    # Цвет живёт в переменных, иначе одна из двух тем ломается молча. Литерал
    # ищется после двоеточия: так селектор вроде #chartbox не считается цветом.
    page_css = PAGE_T.split("<style>", 1)[1].split("</style>", 1)[0]
    for name, css in (("CSS", CSS[len(TOKENS):]),
                      ("PAGE_T", page_css.replace("{{CSS}}", ""))):
        bad = re.search(r":[^;{}]*(#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\()", css)
        assert not bad, f"{name}: цвет мимо токенов — {bad.group(0)!r}"
    assert "prefers-color-scheme" in TOKENS, "тёмная тема потерялась"
    assert "gwacl_theme" in HEAD, "тема будет мигать: нет скрипта в HEAD"
    assert "[data-theme=dark]" in TOKENS, "ручной выбор тёмной не переопределяет"

    ru = set(STRINGS["ru"])
    for lang, t in STRINGS.items():
        assert set(t) == ru, f"{lang}: key set diverged from Russian"
        for page in (render(PAGE_T, t), login_page("", t), login_page("<b>oops</b>", t)):
            assert "{{" not in page, f"{lang}: a placeholder survived in the page"
            assert str(SELF_IP) in page or "login" in page
        assert str(LAN.netmask) in render(PAGE_T, t), f"{lang}: the netmask was not substituted"
    print("selftest ok")


def main():
    if "--version" in sys.argv:
        print(VERSION)
    elif "--selftest" in sys.argv:
        selftest()
    elif "--dump" in sys.argv:
        print(ruleset(load()), end="")
    elif "--set-password" in sys.argv:
        pw = (getpass.getpass(f'{T["password"]}: ') if sys.stdin.isatty()
              else sys.stdin.readline())
        set_password(pw.strip("\n"))
        print(T["pwSaved"])
    else:
        if not os.path.isdir(f"/sys/class/net/{IFACE}"):
            sys.exit(T["noIface"].replace("{iface}", IFACE).replace("{cfg}", CONFIG))
        if not conf()["pw"]:
            print(T["noPwWarn"].replace("{cmd}", sys.argv[0]), file=sys.stderr)
        # Reconciliation is allowed to fail; the HTTP panel is how the broken
        # profile is repaired. Its only startup side effect here is the guard
        # flag — the real table is installed once, just below.
        try:
            reconcile_tunnels(applier=lambda devs: None)
        except Exception:
            if any(row.get("enabled") for row in load_tunnels()):
                set_transit_closed(True, lambda devs: None)
        apply(load())  # on start (a reboot included) raise the table from disk
        # systemd stops the service on every update; the buffered counters go
        # out with it rather than waiting for a flush that never comes.
        signal.signal(signal.SIGTERM, lambda *a: (stop(), sys.exit(0)))
        threading.Thread(target=poller, daemon=True).start()
        ThreadingHTTPServer(("", PORT), H).serve_forever()


if __name__ == "__main__":
    main()
