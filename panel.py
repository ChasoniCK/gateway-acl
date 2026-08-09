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
latest release tag on GitHub — once a day, and once more whenever the settings
are saved. `"update_check": false` turns it off.

Run as root: nft is required.
  --selftest        checks, never touches the network
  --dump            print the ruleset, handy to pipe into `nft -c -f -`
  --set-password    read a password from stdin and store only its hash
  --version         print the version and exit
"""
import base64
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import zlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Must equal the release tag this code is published under: the panel compares
# it against the newest tag on GitHub, so a forgotten bump makes every install
# claim to be older than it is and show a banner that never goes away. CI
# refuses a tag push where the two disagree.
VERSION = "1.3.4"
RELEASES_URL = "https://api.github.com/repos/ChasoniCK/gateway-acl/releases/latest"
RELEASES_PAGE = "https://github.com/ChasoniCK/gateway-acl/releases/latest"
UPDATE_EVERY = 86400

ETC = os.environ.get("GWACL_DIR", "/etc/gateway-acl")
CONFIG = f"{ETC}/config.json"
DEVICES = f"{ETC}/devices.json"
TRAFFIC = f"{ETC}/traffic.json"
TODAY = f"{ETC}/today.json"
SESSIONS = f"{ETC}/sessions.json"

DEFAULTS = {"iface": "eno1", "lan": "192.168.1.0/24", "self_ip": "192.168.1.10",
            "port": 8080, "poll_sec": 60, "pw": None, "lang": "ru",
            "update_check": True, "keep_months": 3,
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
            # config. 0x2023 is what sing-box's auto_route/auto_redirect treats
            # as "not mine"; wg-quick uses its own port number (51820). 0 turns
            # the whole feature off. See docs/singbox.md.
            "vpn_mark": 0x2023}
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
_state = {"at": 0.0, "month": None, "val": None}   # the last answer /api gave
_sessions = {}          # digest of the token -> when it expires
_fails = {}             # address -> (misses, blocked until)
_upd = {"at": 0, "new": None}   # last check, and the tag worth showing


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


def write_private(path, obj):
    """Write json so that only the owner can read it.

    The chmod is required: the mode given to os.open applies only when the file
    is created, and config.json holds the password hash — it may have been left
    at 644 by an earlier version.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1)
    os.chmod(path, 0o600)


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
    write_private(CONFIG, c)
    _state["val"] = None   # the page asks again in a moment; it must see this


STRINGS = {
    "ru": {
        "title": "Шлюз",
        "h1": "Устройства через шлюз",
        "logout": "выйти",
        "monthUse": "Расход за месяц",
        "total": "всего",
        "inbound": "входящий",
        "outbound": "исходящий",
        "perDay": "в среднем в день",
        "devicesTitle": "Устройства",
        "colAddr": "адрес",
        "colName": "имя",
        "colTraffic": "трафик",
        "colSeen": "активность",
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
        "updateHint": "Обновить: <code>git pull</code> в каталоге с исходниками, "
                      "затем <code>sudo ./install.sh</code>. Список устройств и "
                      "статистика не тронутся. Проверку можно выключить "
                      "в настройках.",
        "settingsTitle": "Настройки",
        "sLang": "язык панели",
        "sUpdate": "сообщать о новых версиях",
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
        "cumul": "накопительно",
        "vsPrev": "к прошлому месяцу",
        "noHours": "часы копятся с запуска панели — подождите немного",
        "showAll": "показать все",
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
        "monthUse": "Monthly usage",
        "total": "total",
        "inbound": "inbound",
        "outbound": "outbound",
        "perDay": "daily average",
        "devicesTitle": "Devices",
        "colAddr": "address",
        "colName": "name",
        "colTraffic": "traffic",
        "colSeen": "activity",
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
        "updateHint": "To upgrade: <code>git pull</code> in the source directory, then "
                      "<code>sudo ./install.sh</code>. Your device list and statistics "
                      "are left alone. The check can be turned off in the "
                      "settings.",
        "settingsTitle": "Settings",
        "sLang": "panel language",
        "sUpdate": "tell me about new versions",
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
        "cumul": "cumulative",
        "vsPrev": "against the previous month",
        "noHours": "hours accrue from the panel's start — give it a moment",
        "showAll": "show all",
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
    c = conf()
    c["pw"] = {"salt": salt.hex(), "hash": pw_hash(password, salt)}
    save_conf(c)


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

def ruleset(devs, bypass=None):
    """The whole table as one string. `bypass` is the moment the gateway stops
    letting everyone through — resolved from the config when it is not given,
    because a reload_conf()-managed value must never be frozen into a default.
    """
    # While that moment is in the future the chain keeps everything it does
    # except the verdict: the counters still run, and `update @blocked` still
    # records every address that came in past the list — so when the window
    # shuts, who used it is on the page rather than lost.
    open_now = (CFG["bypass"] if bypass is None else bypass) > time.time()
    verdict = "" if open_now else "\n    drop"
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
    # sing-box's auto_route installs `ip rule fwmark 0x2023 lookup main` and its
    # auto_redirect chain returns on the same mark, wg-quick writes `ip rule not
    # fwmark 51820`, and both then route the packet by the main table and out of
    # the uplink. Which is why this is set at raw — before the routing decision
    # and before any redirect chain, the two places that read it.
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
  }}
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
    CFG["bypass"] = int(when)
    save_conf(CFG)


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
    devs = load()
    due = [d for d in devs if 0 < d.get("until", 0) <= now]
    over = 0 < CFG["bypass"] <= now      # the open gateway, shutting again
    if not due and not over:
        return False
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


def check_update():
    """Ask GitHub, at most once a day, whether a newer release is tagged.

    Every failure is silence: a gateway that cannot reach the internet is a
    supported setup, not a fault to report on the panel. The timestamp is
    written before the request, so an unreachable GitHub is tried once a day
    too, not once a minute. The whole body is inside the try — this runs in the
    poller thread, and an answer of an unexpected shape must not take the
    traffic counters down with it.
    """
    if not CFG.get("update_check", True) or time.time() - _upd["at"] < UPDATE_EVERY:
        return
    _upd["at"] = time.time()
    try:
        req = urllib.request.Request(RELEASES_URL, headers={
            "Accept": "application/vnd.github+json",
            # GitHub answers 403 to a request without a User-Agent.
            "User-Agent": f"gateway-acl/{VERSION}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            _upd["new"] = newer(json.loads(r.read(1 << 20)).get("tag_name") or "")
    except Exception:
        pass


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


def lan_names():
    """{address: [hostname, mac]} — whatever the system already knows.

    Hardware addresses come from the kernel's ARP cache, names from dnsmasq if
    it happens to run on this gateway. Both are a courtesy: without them the
    unknown-devices list is a column of bare numbers, and with them it says
    which box in the flat is knocking.
    """
    out = {ip: ["", mac] for ip, mac in parse_arp(_read("/proc/net/arp")).items()}
    for path in LEASES:
        text = _read(path)
        if text:
            for ip, host in parse_leases(text).items():
                out.setdefault(ip, ["", ""])[0] = host
            break
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
    """
    names = lan_names()
    at = {mac: ip for ip, (_, mac) in names.items() if mac and lan_client(ip)}
    devs = load()
    taken = {d["ip"] for d in devs}
    moves, learned = [], False
    for d in devs:
        mac = d.get("mac") or names.get(d["ip"], ["", ""])[1]
        if not mac:
            continue
        learned = learned or mac != d.get("mac")
        d["mac"] = mac
        new = at.get(mac)
        # `taken`: two entries must never end up on one address, and an entry
        # whose new address is already somebody else's is left where it is.
        if not new or new == d["ip"] or new in taken:
            continue
        moves.append((d["ip"], new))
        taken.discard(d["ip"])
        taken.add(new)
        d["ip"] = new
    if moves:
        # Bank what the old address moved before the list stops mentioning it:
        # poll() reads the counters against whatever load() says, and the next
        # one will be reading them against the new address.
        poll(force=True)
        for old, new in moves:
            rekey(old, new)
    if moves or learned:
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

CSS = """
 :root{--bg:#101216;--card:#171a20;--line:#262a33;--fg:#d8dce3;--dim:#767d8a;
       --up:#a8763f;--down:#5b9bb5;--warn:#c4756a;
       /* Everything below is the same palette one step further in: the fields
          and the popovers, the grey a bar is drawn in, the borders that answer
          to the pointer. They are variables so that the light theme is a block
          of values rather than a second copy of the stylesheet. */
       --in:#1c2027;--edge:#4a505c;--mut:#2f3542;--mut2:#485162;--pick:#1b2029;
       --track:#22262e;--live:#6f9f6f;--ok:#8fae8f;--okline:#3c4d3c;
       --link:#8ab6c8;--sh:#000a}
 /* Whatever the machine on the other side is set to. The panel is looked at
    from a phone in a dark flat and from a laptop by a window, and a page that
    ignores that is the one that has to be squinted at. */
 @media (prefers-color-scheme:light){
  :root{--bg:#eef0f3;--card:#fff;--line:#dfe2e8;--fg:#1c2027;--dim:#697180;
        --up:#96662f;--down:#2c7b99;--warn:#b3564a;
        --in:#f7f8fa;--edge:#9aa3b2;--mut:#ccd2dc;--mut2:#aeb7c5;--pick:#eaf0f6;
        --track:#e3e6ec;--live:#4a8a52;--ok:#3f7a48;--okline:#b9cdb9;
        --link:#1f6f8c;--sh:#0002}
 }
 *{box-sizing:border-box}
 /* The page takes the whole window. Nothing here is prose, so a reading
    measure would only push the numbers apart. */
 body{font:15px/1.55 system-ui,sans-serif;margin:0;
      padding:1.5rem 1.75rem 4rem;background:var(--bg);color:var(--fg)}
 h1{font-size:1.05rem;font-weight:600;margin:0;letter-spacing:.01em}
 select,input,button{font:inherit;background:var(--in);border:1px solid var(--line);
   color:var(--fg);border-radius:5px;padding:.32rem .55rem}
 button{cursor:pointer}
 .card{background:var(--card);border:1px solid var(--line);border-radius:9px;
       padding:1rem 1.1rem;margin-bottom:1rem}
 .card h2{font-size:.78rem;font-weight:600;letter-spacing:.09em;
          text-transform:uppercase;color:var(--dim);margin:0 0 .9rem}
 .num{font-family:ui-monospace,SFMono-Regular,monospace;font-variant-numeric:tabular-nums;
      white-space:nowrap}
 /* overflow-wrap: a hint carries file paths, and one long path would otherwise
    push a phone screen sideways. */
 .hint{color:var(--dim);font-size:.83rem;margin:.4rem 0 0;overflow-wrap:anywhere}
"""

# ponytail: one inline glyph instead of a file to serve — it also stops the
# browser asking for /favicon.ico on every page.
ICON = ("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>"
        "<rect width='16' height='16' rx='3' fill='%23171a20'/>"
        "<circle cx='8' cy='8' r='3.4' fill='%235b9bb5'/></svg>")


def png_icon(size=180, bg=(23, 26, 32), fg=(91, 155, 181)):
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
<meta name=theme-color content="#101216" media="(prefers-color-scheme: dark)">
<meta name=theme-color content="#eef0f3" media="(prefers-color-scheme: light)">
<link rel=icon href="{{ICON}}">
<link rel=apple-touch-icon href="{{ICONPNG}}">"""

LOGIN_T = """<!doctype html><meta charset=utf-8>
{{HEAD}}
<title>{{t.loginTitle}}</title>
<style>{{CSS}}
 body{max-width:22rem;margin:0 auto;padding-top:22vh}
 form{display:flex;gap:.5rem;margin-top:.9rem}
 input{flex:1;min-width:0}
 .err{color:var(--warn);font-size:.85rem;margin-top:.7rem}
</style>
<div class=card>
 <h2>{{t.panelTitle}}</h2>
 <form method=post action=/login>
  <input type=password name=password placeholder="{{t.password}}"
         autocomplete=current-password autofocus required>
  <button>{{t.signIn}}</button>
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
               .replace("{{EXAMPLE}}",
                        str(LAN.network_address + min(56, LAN.num_addresses - 2))))


def login_page(msg="", t=None):
    return render(LOGIN_T, t).replace("{{MSG}}", msg)


PAGE_T = """<!doctype html><meta charset=utf-8>
{{HEAD}}
<title>{{t.title}}</title>
<style>{{CSS}}
 .bar{display:flex;align-items:baseline;gap:.75rem;flex-wrap:wrap;margin-bottom:1.25rem}
 .bar .sp{flex:1}
 .big{font-size:1.5rem}
 /* The chart earns the width, the machine's numbers do not. */
 .row{display:grid;gap:1rem;grid-template-columns:minmax(0,2fr) minmax(0,24rem);
      align-items:start}
 .ch{display:flex;align-items:baseline;gap:.6rem;margin-bottom:.9rem}
 .ch h2{margin:0}
 .ch .sp{flex:1}
 .sub{font-size:.72rem;font-weight:600;letter-spacing:.09em;text-transform:uppercase;
      color:var(--dim);margin:1.2rem 0 .5rem}
 .kpi{display:flex;gap:2rem;flex-wrap:wrap;margin-bottom:.4rem}
 .kpi div{min-width:6rem}
 .kpi span{display:block;font-size:.75rem;color:var(--dim);letter-spacing:.05em}
 .delta{font-style:normal;font-size:.8rem;color:var(--dim);margin-left:.45rem}
 #chartbox svg{display:block;width:100%;height:auto}
 /* One bar per month, click to go there. The height is the month's total, so
    a glance says whether this one is out of the ordinary. */
 .months{display:flex;gap:.25rem;align-items:flex-end}
 .mo{flex:1;min-width:0;background:none;border:0;padding:.15rem 0;display:flex;
     flex-direction:column;justify-content:flex-end;align-items:center;gap:.3rem}
 /* Narrow: at full page width a bar as wide as its cell reads as a tile, and
    the differences in height stop being the thing you notice. */
 .mo i{display:block;width:100%;max-width:1.6rem;background:var(--mut);border-radius:2px}
 .mo:hover i{background:var(--mut2)}
 .mo.cur i{background:var(--down)}
 .mo span{font-size:.68rem;color:var(--dim);font-family:ui-monospace,monospace}
 .mo.cur span{color:var(--fg)}
 .srow{display:grid;grid-template-columns:7rem minmax(0,1fr);gap:.2rem .8rem;
       align-items:baseline;padding:.45rem 0;border-bottom:1px solid var(--line)}
 /* Not a title attribute: this card is rebuilt on every poll, and the browser
    drops a pending native tooltip whenever the node under the cursor is
    replaced. A CSS one survives that, opens on focus as well as on hover — so
    a tap works too — and shows up in a screenshot. */
 .q{position:relative;margin-left:.3rem;padding:0 .3rem;border:1px solid var(--line);
    border-radius:50%;color:var(--dim);font-size:.62rem;font-style:normal;cursor:help}
 .q:hover,.q:focus{color:var(--fg);border-color:var(--edge);outline:none}
 .q>span{display:none;position:absolute;z-index:9;left:-.5rem;top:calc(100% + .5rem);
    width:min(15rem,62vw);padding:.55rem .65rem;background:var(--in);
    border:1px solid var(--edge);border-radius:6px;box-shadow:0 10px 26px var(--sh);
    color:var(--fg);font-size:.76rem;line-height:1.45;white-space:normal}
 .q:hover>span,.q:focus>span{display:block}
 .srow:last-child{border-bottom:0}
 .srow>span{font-size:.78rem;color:var(--dim)}
 /* Beats .num's nowrap: the load line carries the core count and an interface
    name can be anything, so a long value wraps instead of leaving the card. */
 .srow b{white-space:normal;overflow-wrap:anywhere}
 .meter{grid-column:2;height:3px;border-radius:2px;background:var(--track)}
 .meter i{display:block;height:100%;border-radius:2px;background:var(--down)}
 /* Every row carries the dot, so the column keeps its shape and the eye reads
    a colour change rather than something appearing out of nowhere. */
 .dot{display:inline-block;width:6px;height:6px;border-radius:50%;
      background:var(--mut2);margin-right:.45rem;vertical-align:middle}
 .dot.live{background:var(--live)}
 table{width:100%;border-collapse:collapse}
 th{font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
    color:var(--dim);text-align:left;padding:0 .4rem .5rem;border-bottom:1px solid var(--line)}
 th.r,td.r{text-align:right}
 th.s{cursor:pointer;user-select:none}
 th.s:hover,th.s:focus-visible{color:var(--fg)}
 td{padding:.55rem .4rem;border-bottom:1px solid var(--line);vertical-align:middle}
 tbody tr:last-child td{border-bottom:0}
 td.ip{font-family:ui-monospace,monospace;white-space:nowrap;cursor:pointer}
 td.ip:hover{color:var(--link)}
 tr.pick td.ip{color:var(--down)}
 tr.pick{background:var(--pick)}
 td input{width:100%;background:transparent;border:1px solid transparent;padding:.2rem .35rem}
 td input:hover{border-color:var(--line)}
 td input:focus{background:var(--in);border-color:var(--edge);outline:none}
 .off td.ip,.off td input{color:var(--dim)}
 .me{color:var(--dim);font-size:.72rem;margin-left:.4rem}
 #flt{max-width:9rem}
 #off{color:var(--warn);font-size:.82rem}
 /* Which version this gateway is on, where one goes to ask. Pushed left so it
    sits opposite the save button instead of costing the card a line. */
 .ver{margin-right:auto;color:var(--dim);font-size:.78rem;
      font-family:ui-monospace,monospace;align-self:center}
 /* Every sparkline is scaled to the same peak day, so the rows compare
    against each other and not only against themselves. */
 .spark{display:block;margin:.25rem 0 0 auto}
 .mini{font-size:.78rem;color:var(--dim);white-space:nowrap}
 /* wrap: four controls in a cell, and one of them appears only when a tunnel
    mark is configured — on a narrow screen they go to a second line rather
    than pushing the table sideways. */
 .act{display:flex;gap:.35rem;justify-content:flex-end;flex-wrap:wrap}
 /* Address, whatever the network knows it as, and the button. It wraps: on a
    phone the three of them do not fit on one line. */
 .blk{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin:.35rem 0}
 .blk .num{min-width:9rem}
 /* A basis, not flex:1 — the button belongs next to the address it acts on,
    not pushed to the far edge of a full-width card. */
 .blk .mini{flex:0 1 21rem;min-width:7rem;overflow-wrap:anywhere;white-space:normal}
 /* When it last knocked: its own width, so it does not share the name's. */
 .blk .knock{flex:0 0 auto;min-width:6.5rem}
 /* The one control that suspends the whole point of the program says so in the
    panel's warning colour, wherever it sits. */
 button.warn{color:var(--warn);border-color:var(--warn)}
 /* The name a device gives the network, offered as a name to keep. It sits at
    the end of the field rather than beside it: a button of its own at the far
    edge of the column reads as belonging to the next column along. The field
    is empty whenever it exists, and the padding keeps it that way while
    somebody is typing over it. */
 .nm{position:relative;display:flex;align-items:center}
 .nm input{padding-right:1.5rem}
 .ghost{position:absolute;right:.15rem;padding:0 .3rem;font-size:.82rem;
        color:var(--dim);background:none;border-color:var(--line)}
 .ghost:hover{color:var(--fg);border-color:var(--edge)}
 /* At rest it would be a mark floating in the middle of a row: the field it
    belongs to has no border until the pointer is on it. So it appears with
    that border — but only where there is a pointer at all, or a phone would
    hide it for good. */
 @media (hover:hover){.nm .ghost{opacity:0;transition:opacity .1s}
  tr:hover .ghost,.ghost:focus{opacity:1}}
 .act button,.act select{padding:.22rem .5rem;font-size:.82rem;color:var(--dim)}
 .act select{padding-right:.3rem}
 .act button:hover,.act select:hover{color:var(--fg);border-color:var(--edge)}
 .act .on{color:var(--ok);border-color:var(--okline)}
 /* The settings live in the corner: a summary that looks like the buttons
    beside it, and a card that drops out of it. details does the opening on
    its own — no script, and it works in whatever browser is at hand. */
 .gear{position:relative}
 .gear>summary{cursor:pointer;list-style:none;padding:.32rem .55rem;
   border:1px solid var(--line);border-radius:5px;background:var(--in)}
 .gear>summary::-webkit-details-marker{display:none}
 .gear[open]>summary,.gear>summary:hover{border-color:var(--edge)}
 .gear>.card{position:absolute;right:0;top:calc(100% + .4rem);z-index:5;
   width:min(36rem,88vw);margin:0;box-shadow:0 12px 34px var(--sh)}
 .set{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));
      gap:.7rem .9rem;margin-bottom:.9rem}
 .set label{display:block;font-size:.75rem;color:var(--dim);letter-spacing:.04em}
 .set input,.set select{width:100%;margin-top:.2rem}
 .set .chk,.chk input{display:flex;align-items:center;width:auto;margin:0}
 /* wrap: the reboot row carries a field after its text and the column is
    narrow — a label that overflowed its cell would sit on top of the next. */
 .set .chk{gap:.45rem;align-self:end;padding-bottom:.4rem;flex-wrap:wrap}
 /* A switch, in the panel's own two colours: it is still the checkbox itself,
    stripped of its native look, and the knob is its ::before sliding across.
    No wrapper span, so the label, the keyboard and :checked all keep working. */
 /* .set .sw, not .sw: the width has to outrank the .chk input above it. */
 .set .sw{appearance:none;-webkit-appearance:none;flex:none;position:relative;
     width:34px;height:18px;padding:0;border-radius:9px;cursor:pointer;
     transition:background .15s,border-color .15s}
 .sw::before{content:"";position:absolute;top:2px;left:2px;width:12px;height:12px;
     border-radius:50%;background:var(--dim);transition:transform .15s,background .15s}
 .sw:checked{background:var(--down);border-color:var(--down)}
 .sw:checked::before{background:var(--fg);transform:translateX(16px)}
 /* A switched-off field must still look like a field. Browsers grey a disabled
    input down to nearly the card behind it, and WebKit overrides `color` with
    its own fill — the hour is worth reading while the switch is off. */
 .set input:disabled{opacity:1;color:var(--dim);-webkit-text-fill-color:var(--dim);
   background:var(--bg);border-style:dashed;cursor:not-allowed}
 .legend{display:flex;gap:1rem;font-size:.78rem;color:var(--dim);margin-top:.5rem}
 .legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:.35rem}
 .legend i.dash{width:14px;height:0;border-radius:0;border-top:1.5px dashed var(--dim);
                vertical-align:middle}
 /* The legend paints every <i> as a swatch — the question mark is not one. */
 .legend .q{width:auto;height:auto;border-radius:50%;margin:0 0 0 .3rem}
 a{color:var(--link)}
 form{display:flex;gap:.5rem;flex-wrap:wrap}
 form input{flex:1;min-width:8rem}
 @media (max-width:900px){.row{grid-template-columns:1fr}}
 /* On a phone the columns do not fit — a row becomes a block of two lines:
    address with name, then traffic, activity and buttons. */
 @media (max-width:620px){
  body{padding:1rem .7rem 3rem}
  .card{padding:.8rem .75rem}
  .kpi{gap:1.1rem}
  .big{font-size:1.25rem}
  thead{display:none}
  table,tbody{display:block}
  tr{display:flex;flex-wrap:wrap;align-items:center;gap:.35rem .9rem;
     padding:.6rem 0;border-bottom:1px solid var(--line)}
  tbody tr:last-child{border-bottom:0}
  td{display:block;border:0;padding:0}
  td:nth-child(2){flex:1 1 8rem}
  td.r{text-align:left}
  .spark{display:none}
  .srow{grid-template-columns:7rem minmax(0,1fr)}
  .act{justify-content:flex-start}
  /* Too narrow to hang off the corner: a sheet at the bottom instead, so it
     never covers the button that opened it. */
  .gear>.card{position:fixed;left:.7rem;right:.7rem;bottom:.7rem;top:auto;
    width:auto;max-height:78vh;overflow:auto}
 }
</style>
<div class=bar>
 <h1>{{t.h1}}</h1><span id=off hidden></span><span class=sp></span>
 <select id=msel onchange="load(this.value)"></select>
 <span id=bypbox></span>
 <button onclick=csv() title="{{t.csvWhat}}">CSV</button>
 <details class=gear>
  <summary>{{t.settingsTitle}}</summary>
  <div class=card>
   <div class=set>
    <label>{{t.sLang}}<select id=s_lang>
     <option value=ru{{SEL_RU}}>Русский<option value=en{{SEL_EN}}>English</select></label>
    <label>{{t.sPoll}}<input id=s_poll type=number min=5 max=3600 value="{{POLL}}"></label>
    <label title="{{t.sKeepWhat}}"
     >{{t.sKeep}}<input id=s_keep type=number min=1 max=24 value="{{KEEP}}"></label>
    <!-- The switch is the label of the field it turns on, so the two cannot
         drift apart; the hour stays visible while it is off, only greyed. -->
    <label class=chk title="{{t.sRebootAtWhat}}"><input id=s_rb class=sw type=checkbox{{RB}}
      onchange="s_reboot_at.disabled=!this.checked">{{t.sRebootAt}}
     <!-- lang, not the page's: <input type=time> takes its 12/24-hour face from
          a locale, and en-GB is the one that is 24-hour in every language. -->
     <input id=s_reboot_at type=time lang=en-GB value="{{REBOOT_AT}}"{{RB_OFF}}></label>
    <label>{{t.sPort}}<input id=s_port type=number min=1 max=65535 value="{{PORT}}"></label>
    <label>{{t.sIface}}<input id=s_iface value="{{IFACE}}"></label>
    <label>{{t.sLan}}<input id=s_lan value="{{LANCIDR}}"></label>
    <label>{{t.sSelfIp}}<input id=s_self value="{{GW}}"></label>
    <label>{{t.sPw}}<input id=s_pw type=password autocomplete=new-password
      placeholder="{{t.sPwKeep}}"></label>
    <label class=chk><input id=s_upd class=sw type=checkbox{{UPD}}>{{t.sUpdate}}</label>
   </div>
   <div class=act><span class=ver>gateway-acl {{VERSION}}</span>
    <button id=s_reboot onclick=rebootHost()>{{t.sReboot}}</button>
    <button onclick=saveCfg()>{{t.sSave}}</button></div>
   <p class=hint>{{t.sNetHint}}</p>
  </div>
 </details>
 <button onclick="location='/logout'">{{t.logout}}</button>
</div>

<div class=card id=upd hidden>
 <h2>{{t.updateTitle}}</h2>
 <p id=updtext style="margin:0"></p>
 <!-- A fixed address, not one taken from the answer: the tag comes off the
      network, the link must not. -->
 <p style="margin:.35rem 0 0"><a href="{{RELEASES}}" target=_blank
    rel="noopener noreferrer">{{t.updateWhat}}</a></p>
 <p class=hint>{{t.updateHint}}</p>
</div>

<div class=row>
 <div class=card>
  <div class=ch>
   <h2>{{t.monthUse}}</h2><span id=chsel></span><span class=sp></span>
   <div class=act>
    <button id=bday onclick="setMode('day')">{{t.byDay}}</button>
    <button id=bhour onclick="setMode('hour')">{{t.byHour}}</button>
   </div>
  </div>
  <div class=kpi>
   <div><span>{{t.total}}</span><b class="num big" id=kt></b><em class=delta id=kdelta></em></div>
   <div><span>{{t.inbound}}</span><b class=num id=kd></b></div>
   <div><span>{{t.outbound}}</span><b class=num id=ku></b></div>
   <div><span>{{t.perDay}}</span><b class=num id=ka></b></div>
   <div id=kotherbox hidden><span>{{t.other}}</span><b class=num id=kother></b></div>
  </div>
  <div id=chartbox></div>
  <div class=legend><span><i style="background:var(--down)"></i>{{t.inbound}}</span>
   <span><i style="background:var(--up)"></i>{{t.outbound}}</span>
   <span id=othlbl hidden><i style="background:var(--mut)"></i>{{t.other}}<i class=q
     tabindex=0>?<span>{{t.otherWhat}}</span></i></span>
   <span id=cumlbl><i class=dash></i>{{t.cumul}}</span></div>
  <h3 class=sub>{{t.byMonth}}</h3>
  <div id=mstrip></div>
 </div>

 <div class=card>
  <div class=ch><h2>{{t.sysTitle}}</h2></div>
  <div id=sysbox></div>
 </div>
</div>

<div class=card>
 <div class=ch><h2>{{t.devicesTitle}}</h2><span class=sp></span>
  <button id=allsw onclick=toggleAll() title="{{t.allWhat}}"></button>
  <input id=flt placeholder="{{t.filter}}" aria-label="{{t.filter}}" oninput=draw()>
 </div>
 <table><thead><tr>
  <th class=s id=h_ip onclick="sortBy('ip')">
  <th class=s id=h_name onclick="sortBy('name')">
  <th class="r s" id=h_traf onclick="sortBy('traf')">
  <th class="r s" id=h_now onclick="sortBy('now')">
  <th class="r s" id=h_seen onclick="sortBy('seen')">
  <th></tr></thead>
 <tbody id=tb></tbody></table>
 <form id=f style="margin-top:1rem">
  <!-- The list is what ARP and the DHCP leases already know and this table
       does not: a native datalist, so the browser does the completing. -->
  <input name=ip placeholder="{{EXAMPLE}}" list=lanips required>
  <datalist id=lanips></datalist>
  <input name=nm placeholder="{{t.phName}}">
  <button>{{t.add}}</button>
 </form>
 <p class=hint>{{t.hint}}</p>
</div>

<div class=card id=clash hidden>
 <h2>{{t.clashTitle}}</h2>
 <div id=clashb></div>
 <p class=hint>{{t.clashHint}}</p>
</div>

<div class=card id=unk hidden>
 <h2>{{t.blockedTitle}}</h2>
 <div id=ub></div>
 <p class=hint>{{t.blockedHint}}</p>
</div>

<script>
const T = {{T_JSON}};
const esc = s => (s||'').replace(/[<&">]/g, c => ({'<':'&lt;','&':'&amp;','"':'&quot;','>':'&gt;'}[c]));
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
const bypass = (v, el) => {
  if (el) el.value = '';
  if (v === '') return;
  if (+v && !confirm(T.confirmByp)) return;
  fetch('/bypass', {method:'POST', body: JSON.stringify({for: +v})})
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
let S = null, month = null, sel = null, mode = 'day', sortk = 'ip', sortd = 1,
    oth = 0, mtot = 0;

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
  // A month with a total but no days behind it is one that has been rolled up.
  // "no data" would contradict the figure standing right above the chart.
  if (!rs.length) return `<p class=hint>${mode === 'hour' ? T.noHours
    : mtot ? T.rolled : T.noData}</p>`;
  // Take the actual width: one viewBox unit is then one pixel, and the
  // labels do not shrink on a phone.
  const W = Math.max(chartbox.clientWidth || 720, 280), H = 190,
        L = 54, B = 20, top = 10;
  const max = Math.max(...rs.map(d => d[1] + d[2] + d[4]), 1024);
  const bw = (W - L) / rs.length, plot = H - B - top;
  const y = v => top + plot - (v / max) * plot;
  let g = '';
  for (const f of [0, .5, 1]) g += `<line x1=${L} x2=${W} y1=${y(max*f)} y2=${y(max*f)} `
    + `stroke="var(--line)"/><text x=${L-8} y=${y(max*f)+4} text-anchor=end fill="var(--dim)" `
    + `font-size=10 font-family=ui-monospace>${f ? fmtAx(max*f) : 0}</text>`;
  const bars = rs.map((d, i) => {
    const x = L + i*bw + bw*.18, w = Math.max(1, bw*.64), o = d[4];
    const hu = (d[1]/max)*plot, hd = (d[2]/max)*plot;
    const lbl = rs.length > 20 ? (i % 5 === 0) : true;
    return `<g><title>${d[3]}  ↓ ${fmt(d[2])}  ↑ ${fmt(d[1])}`
      + `${o ? `  ${T.other} ${fmt(o)}` : ''}</title>`
      + (o ? `<rect x=${x} y=${y(d[1]+d[2]+o)} width=${w} height=${(o/max)*plot} `
           + `fill="var(--mut)"/>` : '')
      + `<rect x=${x} y=${y(d[1]+d[2])} width=${w} height=${hu} fill="var(--up)"/>`
      + `<rect x=${x} y=${y(d[2])} width=${w} height=${hd} fill="var(--down)"/>`
      + `<rect x=${L+i*bw} y=${top} width=${bw} height=${plot} fill="none" pointer-events="all"/></g>`
      + (lbl ? `<text x=${x+w/2} y=${H-5} text-anchor=middle fill="var(--dim)" font-size=10 font-family=ui-monospace>${d[0]}</text>` : '');
  }).join('');
  // The running total, scaled so the end of the line is the top of the plot:
  // the shape answers "are we going faster than last time", the tooltip the
  // exact figure. A second axis would cost more than it explains.
  let line = '';
  const tot = rs.reduce((a, d) => a + d[1] + d[2] + d[4], 0);
  if (cum && rs.length > 1 && tot) {
    let run = 0;
    const pts = rs.map((d, i) => { run += d[1] + d[2] + d[4];
      return `${(L + i*bw + bw/2).toFixed(1)},${(top + plot - run/tot*plot).toFixed(1)}`;
    }).join(' ');
    line = `<polyline fill=none stroke="var(--dim)" stroke-width=1.4 stroke-dasharray="3 3"`
      + ` points="${pts}"><title>${T.cumul}  ${fmt(tot)}</title></polyline>`;
  }
  return `<svg viewBox="0 0 ${W} ${H}">${g}${bars}${line}</svg>`;
};

const spark = (ser, max, on) => {
  if (!ser || ser.length < 2) return '';
  const w = 72, h = 15, bw = w/ser.length;
  return `<svg class=spark viewBox="0 0 ${w} ${h}" width=${w} height=${h} `
    + `fill="var(--down)"${on ? '' : ' opacity=.35'}>`
    + ser.map((v, i) => { const t = (v[0]+v[1])/max*h;
        // Quoted: an unquoted last attribute would swallow the closing slash.
        return t < .4 ? '' : `<rect x="${(i*bw).toFixed(2)}" y="${(h-t).toFixed(2)}" `
          + `width="${Math.max(.7, bw*.72).toFixed(2)}" height="${t.toFixed(2)}"/>`;
      }).join('') + `</svg>`;
};

const strip = () => {
  const ms = S.months.slice(-12), max = Math.max(...ms.map(m => m[1]), 1);
  return `<div class=months>` + ms.map(m =>
    `<button class="mo${m[0] === S.month ? ' cur' : ''}" onclick="load('${m[0]}')" `
    + `title="${m[0]}  ${fmt(m[1])}"><i style="height:${Math.max(2, m[1]/max*46).toFixed(0)}px">`
    + `</i><span>${m[0].slice(5)}</span></button>`).join('') + `</div>`;
};

// A number nobody can interpret is not a metric. Hover says which sensor.
const q = text => `<i class=q tabindex=0>?<span>${esc(text)}</span></i>`;
const meter = (pct, warn) => `<div class=meter><i style="width:${Math.min(100, Math.max(0, pct)).toFixed(0)}%`
  + `${pct >= warn ? ';background:var(--warn)' : ''}"></i></div>`;
const srow = (label, val, pct, warn) => `<div class=srow><span>${label}</span>`
  + `<b class=num>${val}</b>${pct === null ? '' : meter(pct, warn)}</div>`;

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
      + (s.cores ? '  · ' + n(T.cores, s.cores) : ''),
      s.cores ? s.load[0]/s.cores*100 : null, 100);
  if (s.temp) h += srow(T.sTemp + q(n(T.tempWhat, s.temp[1])),
                        s.temp[0].toFixed(0) + ' °C', (s.temp[0]-30)/50*100, 80);
  if (s.up) h += srow(T.sUptime, upfmt(s.up), null);
  return h || `<p class=hint>${T.sysNone}</p>`;
};

const HEADS = {ip: 'colAddr', name: 'colName', traf: 'colTraffic',
               now: 'colNow', seen: 'colSeen'};
const CMP = {
  // Octets padded, or 192.168.1.9 would sort after 192.168.1.10.
  ip: x => x.ip.split('.').map(o => o.padStart(3, '0')).join('.'),
  name: x => (x.name || '￿').toLowerCase(),
  traf: x => x.up + x.down,
  now: x => x.rate[0] + x.rate[1],
  seen: x => x.seen,
};
// The view someone left behind, so a reload does not throw them back to the
// default sort. In a private window localStorage throws — then it is simply
// not remembered. The picked device is not here: it lives in the address bar.
const keep = () => { try {
  localStorage.gwacl = JSON.stringify({mode, sortk, sortd});
} catch (e) {} };
const sortBy = k => {
  // Names and addresses read best ascending, quantities biggest-first.
  sortd = sortk === k ? -sortd : (k === 'ip' || k === 'name' ? 1 : -1);
  sortk = k;
  keep(); draw();
};
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

const draw = () => {
  if (!S) return;
  if (sel && !S.devices.some(x => x.ip === sel)) sel = null;
  const one = sel && S.devices.find(x => x.ip === sel);
  msel.innerHTML = S.months.map(m =>
    `<option${m[0] === S.month ? ' selected' : ''}>${m[0]}</option>`).join('');
  for (const k in HEADS) {
    const th = document.getElementById('h_' + k), on = sortk === k;
    th.textContent = T[HEADS[k]] + (on ? (sortd > 0 ? ' ↑' : ' ↓') : '');
    // The arrow says it to the eye, aria-sort to everything else.
    th.setAttribute('aria-sort', on ? (sortd > 0 ? 'ascending' : 'descending') : 'none');
  }
  // Open, and how much longer — or the menu that opens it.
  bypbox.innerHTML = S.bypass > S.now
    ? `<button class=warn title="${T.bypWhat}" onclick="bypass(0)">${T.bypOn} `
      + `${left(S.bypass - S.now)} ×</button>`
    : `<select title="${T.bypWhat}" onchange="bypass(this.value,this)">`
      + `<option value="">${T.byp}</option>`
      + BYP.map(([v, k]) => `<option value="${v}">${T[k]}</option>`).join('')
      + `</select>`;
  const others = S.devices.filter(x => x.ip !== S.you);
  allsw.hidden = !others.length;
  allsw.textContent = others.some(x => x.on) ? T.allOff : T.allOn;
  bday.className = mode === 'day' ? 'on' : '';
  bhour.className = mode === 'hour' ? 'on' : '';
  chsel.innerHTML = one ? `<button onclick="pickDev(null)" title="${T.showAll}">`
    + `${esc(one.name || one.ip)} ×</button>` : '';

  const dv = one ? [one] : S.devices;
  const U = dv.reduce((a,x) => a+x.up, 0), D = dv.reduce((a,x) => a+x.down, 0);
  // The month's total counts every address the history knows of, the devices
  // only those still on the list. What is left over is "other" — hence a total
  // that is more than inbound plus outbound, and a tile that says why.
  mtot = (S.months.find(m => m[0] === S.month) || [0, 0])[1];
  oth = one ? 0 : Math.max(0, mtot - S.devices.reduce((a,x) => a+x.up+x.down, 0));
  kt.textContent = fmt(U+D+oth); kd.textContent = fmt(D); ku.textContent = fmt(U);
  ka.textContent = fmt(Math.round((U+D+oth) / Math.max(S.days.length, 1)));
  kother.textContent = fmt(oth);
  kotherbox.hidden = othlbl.hidden = !oth;
  // Only against the whole month: a single device against everything last
  // month would be a comparison of two different things.
  const pc = (!one && S.prev) ? Math.round((U+D+oth-S.prev)/S.prev*100) : null;
  kdelta.textContent = pc === null ? '' : (pc > 0 ? '+' : '') + pc + '%';
  kdelta.title = pc === null ? '' : T.vsPrev;
  chartbox.innerHTML = chart(rows(), mode === 'day');
  cumlbl.hidden = mode !== 'day';
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
    return `<tr class="${x.on ? '' : 'off'}${x.ip === sel ? ' pick' : ''}">`
     + `<td class=ip title="${esc(x.mac)}" onclick="pickDev('${esc(x.ip)}')">`
     // The dot carries its meaning in colour alone; the title is the rest of it.
     + `<i class="dot${live ? ' live' : ''}" title="${live ? T.dotLive : T.dotQuiet}"></i>`
     + `${esc(x.ip)}${me ? `<span class=me>${T.youAre}</span>` : ''}</td>`
     + `<td><div class=nm><input value="${esc(x.name)}" `
     + `placeholder="${esc(x.host || T.phName)}" `
     + `onchange="setName('${esc(x.ip)}',this.value)">`
     // Through data-, not into the onclick: the hostname comes out of a lease
     // file this program does not own. addKnown already posts exactly this.
     + (!x.name && x.host ? `<button class=ghost data-ip="${esc(x.ip)}" `
        + `data-nm="${esc(x.host)}" onclick="addKnown(this)" `
        + `title="${esc(n(T.useHost, x.host))}">+</button>` : '')
     + `</div></td>`
     + `<td class="r num">${fmt(t)}${spark(x.series, peak, x.on)}</td>`
     + `<td class="r num mini">${r > 0 ? `↓ ${fmt(x.rate[1])}${T.perSec}`
        + `  ↑ ${fmt(x.rate[0])}${T.perSec}` : '—'}</td>`
     + `<td class="r mini">${x.seen ? ago(S.now - x.seen) : '—'}</td>`
     + `<td><div class=act><button class="${x.on ? '' : 'on'}" `
     + `onclick="post({ip:'${esc(x.ip)}',on:${!x.on}})">${x.on ? T.turnOff : T.turnOn}</button>`
     // Same shape as the switch above it: the label is what pressing it does,
     // and the green is the way back — a device standing outside the tunnel is
     // the state one eventually wants undone.
     + (S.vpnable ? `<button class="${x.vpn ? '' : 'on'}" title="${T.vpnWhat}" `
        + `onclick="post({ip:'${esc(x.ip)}',vpn:${!x.vpn}})">`
        + `${x.vpn ? T.vpnOff : T.vpnOn}</button>` : '')
     // Whichever way it stands, the menu offers the other one for a while.
     + (x.until > S.now
        ? `<button title="${T.tmCancel}" onclick="post({ip:'${esc(x.ip)}',for:0})">`
          + `${left(x.until - S.now)} ×</button>`
        : `<select title="${T.tmWhat}" onchange="timer('${esc(x.ip)}',${!x.on},this)">`
          + `<option value="">${T.tmFor}</option>`
          + TIMES.map(([v, k]) => `<option value="${v}">${T[k]}</option>`).join('')
          + `</select>`)
     + `<button onclick="del('${esc(x.ip)}',${me})">${T.del}</button></div></td></tr>`;
  }).join('') || `<tr><td colspan=6 class=hint>${fq ? T.noMatch : T.empty}</td></tr>`;

  upd.hidden = !S.update;
  // textContent, not innerHTML: the tag comes off the network.
  if (S.update) updtext.textContent = T.updateNew.replace('{v}', S.update);
  // A listed address that answers as somebody else — the rule is now written
  // for whoever took it.
  clash.hidden = !S.clash.length;
  clashb.innerHTML = S.clash.map(([ip, was, now, ven]) =>
    `<div class=blk><span class=num>${esc(ip)}</span>`
    + `<span class=mini>${esc(T.clashLine.replace('{a}', was).replace('{b}', now))}`
    + `${ven ? ' · ' + esc(ven) : ''}</span></div>`).join('');

  unk.hidden = !S.blocked.length;
  // The name and the hardware address go through data-, not into the onclick:
  // both come out of a lease file this program does not own.
  ub.innerHTML = S.blocked.map(([ip, host, mac, knocked, ven]) =>
    `<div class=blk><span class=num>${esc(ip)}</span>`
    + `<span class=mini>${esc(host)}${host && mac ? ' · ' : ''}${esc(mac)}`
    + `${ven ? ' · ' + esc(ven) : ''}</span>`
    + `<span class="mini knock">${knocked === null ? '' : ago(knocked)}</span>`
    + `<button data-ip="${esc(ip)}" data-nm="${esc(host)}" onclick="addKnown(this)">`
    + `${T.add}</button></div>`).join('');

  lanips.innerHTML = S.lan.map(([ip, host]) =>
    `<option value="${esc(ip)}">${esc(host)}</option>`).join('');
};

// Without this the page keeps showing the last good numbers for as long as it
// is open: the service restarts, the gateway goes down, and nothing on screen
// changes. The header says so instead, and names the time it last heard back.
let okAt = null;
const stale = bad => {
  off.hidden = !bad;
  if (bad) off.textContent = T.offline.replace('{t}', okAt
    ? okAt.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}) : '—');
  else okAt = new Date();
};
const load = m => fetch('/api?month=' + (month = m || month || ''))
  .then(r => r.status === 401 ? location.reload()
    : r.json().then(s => { S = s; draw(); }))
  .then(() => stale(0), () => stale(1));
const post = body => fetch('/api', {method:'POST', body: JSON.stringify(body)})
  .then(r => r.ok ? load() : r.text().then(alert));
const setName = (ip, name) => post({ip, name});
const del = (ip, me) => confirm((me ? T.confirmDelMe : T.confirmDel).replace('{ip}', ip))
  && fetch('/api?ip=' + encodeURIComponent(ip), {method:'DELETE'})
     .then(r => r.ok ? load() : r.text().then(alert));
f.onsubmit = e => { e.preventDefault();
  post({ip: f.ip.value, name: f.nm.value}).then(() => f.reset()); };
// The answer is the new address when the port changed, and empty otherwise:
// everything else is already live, the reload is only to redraw the labels.
const saveCfg = () => fetch('/settings', {method:'POST', body: JSON.stringify({
    lang: s_lang.value, update_check: s_upd.checked, poll_sec: +s_poll.value,
    keep_months: +s_keep.value, reboot: s_rb.checked, reboot_at: s_reboot_at.value,
    port: +s_port.value, iface: s_iface.value,
    lan: s_lan.value, self_ip: s_self.value, pw: s_pw.value})})
  .then(r => r.text().then(x => !r.ok ? alert(x)
    : x ? alert(T.sRestart.replace('{url}', x)) : location.reload()));
// The one button here that cannot be taken back, so it asks first. Nothing is
// reloaded afterwards: the answer is the last thing that arrives before the
// machine goes down, and the page is expected to sit there stale until it is back.
const rebootHost = () => confirm(T.confirmReboot)
  && fetch('/reboot', {method:'POST'}).then(r => r.text().then(alert));
// Only the chart depends on the pixel width. Redrawing the table here would
// take the cursor out of a name someone is in the middle of typing.
onresize = () => { if (S) chartbox.innerHTML = chart(rows(), mode === 'day'); };

// The sort headers are cells, not buttons — a tab stop and the two keys a
// button would answer to cost less than rebuilding the row out of buttons.
for (const th of document.querySelectorAll('th.s')) {
  th.tabIndex = 0;
  th.onkeydown = e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); th.click(); }
  };
}

// "/" is where one starts typing at a table, in every other program.
document.onkeydown = e => {
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

    def _authed(self):
        m = SimpleCookie(self.headers.get("Cookie") or "").get("sess")
        return session_ok(m.value if m else None)

    def _deny(self):
        """A live page gets 401, an ordinary navigation gets the login form."""
        if self.path.startswith("/api"):
            self._send(401, T["needLogin"], "text/plain")
        else:
            self._send(200, login_page())

    def do_GET(self):
        if self.path == "/logout":
            raw = self.headers.get("Cookie")
            if raw and "sess" in SimpleCookie(raw):
                drop_session(SimpleCookie(raw)["sess"].value)
            self._send(200, login_page(f'<p class=hint>{T["loggedOut"]}</p>'),
                       cookie="sess=; Path=/; Max-Age=0")
            return
        if not self._authed():
            self._deny()
            return
        if self.path == "/":
            self._send(200, PAGE)
        elif self.path.startswith("/api"):
            month = parse_qs(urlparse(self.path).query).get("month", [None])[0]
            # A copy: the answer is shared between everyone asking at once, and
            # only this one key is the asker's own.
            s = dict(state(month))
            s["you"] = self.client_address[0]
            self._send(200, json.dumps(s), "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        if self.path == "/login":
            self._login(raw)
            return
        if not self._authed():
            self._deny()
            return
        if self.path == "/settings":
            self._settings(raw)
            return
        if self.path == "/reboot":
            self._send(200, T["rebooting"], "text/plain")
            reboot_host()
            return
        if self.path == "/bypass":
            self._bypass(raw)
            return
        try:
            body = json.loads(raw or b"{}")
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
            # A timer says when the state just set runs out. Setting a state
            # without one is a decision, so it drops whatever was pending —
            # otherwise the switch would flip back by itself hours later and
            # nothing on the page would say why.
            mins = check_minutes(body["for"]) if "for" in body else None
            if mins is not None:
                cur["until"] = int(time.time()) + mins * 60 if mins else 0
            elif "on" in body:
                cur["until"] = 0
            save(devs)
            # A rename leaves the ruleset identical — nft untouched, counters intact.
            if ruleset(devs) != before:
                apply(devs)
            self._send(200, "ok", "text/plain")
        except ValueError as e:
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
            base = conf()
            c = check_settings(body, base)
            pw = str(body.get("pw") or "")
            if pw and len(pw) < 8:
                raise ValueError(T["pwShort"])   # before anything is written
            save_conf(c)
            if pw:
                set_password(pw)   # re-reads the config just written
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
        if not self._authed():
            self._deny()
            return
        ip = parse_qs(urlparse(self.path).query).get("ip", [""])[0]
        devs = [d for d in load() if d["ip"] != ip]
        save(devs)
        apply(devs)
        self._send(200, "ok", "text/plain")

    def log_message(self, *a):
        pass


def poller():
    while True:
        time.sleep(POLL_SEC)
        poll()
        expire()        # a timer that has run out
        track_macs()    # a device DHCP has moved to another address
        check_update()
        # A minute of slack so two ticks cannot leave a gap between windows.
        if reboot_due(CFG["reboot"] and CFG["reboot_at"],
                      time.localtime(), uptime(), POLL_SEC + 60):
            reboot_host()


def selftest():
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

    # Past the tunnel is not off the network: the device keeps its place in the
    # allowed set, and the mark is stamped before the rule that accepts it away.
    old, CFG["vpn_mark"] = CFG.get("vpn_mark"), 0x2023
    v = ruleset([dict(d[0], vpn=False), d[1]])
    assert f"ip saddr {a} meta mark set 0x2023" in v, "no MAC known, the address it is"
    assert f"elements = {{ {a} }}" in v, "sent past the vpn, still allowed through"
    assert v.index("meta mark set") < v.index("ip saddr @allowed accept"), \
        "a mark stamped after the accept would never be read"
    assert ruleset(d) != v, "and unlike a rename, this one has to reach nftables"
    assert "meta mark" not in ruleset(d), "nobody sent past it, nothing stamped"

    # With a hardware address the rule is written against that instead, and it
    # has to stand above the line that lets IPv6 out of the chain — that line is
    # why the first release of this marked v4 and left v6 in the tunnel.
    m = ruleset([dict(d[0], vpn=False, mac="aa:bb:cc:dd:ee:ff"), d[1]])
    assert "ether saddr aa:bb:cc:dd:ee:ff meta mark set 0x2023" in m
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

    import tempfile
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
        # own contents and nothing more: the panel still starts.
        open(TRAFFIC, "w").write('{"days": {"2026-01-0')
        reboot()
        assert history()["days"][today] == {"10.0.0.5": [1600, 900]}, \
            "half a cold file must not take the day in progress with it"

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
        global DEVICES, apply, lan_names
        keep_dev = (DEVICES, TRAFFIC, TODAY, apply, lan_names, nft_table)
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
        global CONFIG
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

        DEVICES, TRAFFIC, TODAY, apply, lan_names, nft_table = keep_dev
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
    for el in ("msel", "upd", "updtext", "kt", "kd", "ku", "ka", "kdelta", "chsel",
               "bday", "bhour", "chartbox", "cumlbl", "mstrip", "sysbox", "tb",
               "h_ip", "h_name", "h_traf", "h_now", "h_seen", "unk", "ub",
               "flt", "off", "kother", "kotherbox", "othlbl", "lanips", "s_keep",
               "s_reboot", "s_reboot_at", "s_rb", "bypbox", "allsw", "clash",
               "clashb"):
        assert f"id={el}>" in page or f"id={el} " in page, f"the page has no {el}"

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
        apply(load())  # on start (a reboot included) raise the table from disk
        # systemd stops the service on every update; the buffered counters go
        # out with it rather than waiting for a flush that never comes.
        signal.signal(signal.SIGTERM, lambda *a: (stop(), sys.exit(0)))
        threading.Thread(target=poller, daemon=True).start()
        ThreadingHTTPServer(("", PORT), H).serve_forever()


if __name__ == "__main__":
    main()
