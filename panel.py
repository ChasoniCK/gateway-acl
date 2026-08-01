#!/usr/bin/env python3
"""gateway-acl — who routes through this Linux gateway, and how much they used.

devices.json is the source of truth. Any change to the list, or to a device's
"on" flag, regenerates the whole nftables table in a single atomic transaction.
Nothing else on the system is touched.

Traffic is counted by named nftables counters, two per device (up/down). They
are zeroed when the table is rebuilt and on reboot, so the poller accumulates
bytes into traffic.json per day, detecting resets (see accrue).

Whoever knocks without being allowed is recorded by the kernel itself into the
dynamic `blocked` set with a timeout — that is the unknown-devices list.

The only request this program ever makes to the internet is a daily check of
the latest release tag on GitHub, and `"update_check": false` turns it off.

Run as root: nft is required.
  --selftest        checks, never touches the network
  --dump            print the ruleset, handy to pipe into `nft -c -f -`
  --set-password    read a password from stdin and store only its hash
"""
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.0.0"
RELEASES_URL = "https://api.github.com/repos/ChasoniCK/gateway-acl/releases/latest"
UPDATE_EVERY = 86400

ETC = os.environ.get("GWACL_DIR", "/etc/gateway-acl")
CONFIG = f"{ETC}/config.json"
DEVICES = f"{ETC}/devices.json"
TRAFFIC = f"{ETC}/traffic.json"

DEFAULTS = {"iface": "eno1", "lan": "192.168.1.0/24", "self_ip": "192.168.1.10",
            "port": 8080, "poll_sec": 60, "pw": None, "lang": "ru",
            "update_check": True}
SESSION_TTL = 7 * 86400
FAIL_LIMIT = 5          # misses in a row from one address
FAIL_BLOCK = 60         # and that is how long it then sits out

_lock = threading.Lock()
_sessions = {}          # token -> when it expires
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


def save_conf(c):
    write_private(CONFIG, c)


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
        "phName": "чьё устройство",
        "add": "добавить",
        "hint": "На устройстве прописать вручную: шлюз <b>{{GW}}</b>, маска "
                "<b>{{MASK}}</b> (Android и Quest спрашивают длину префикса — "
                "<b>{{PFX}}</b>), DNS <b>1.1.1.1</b>. Кого нет в списке — тот через "
                "шлюз не ходит вообще. «Выключить» оставляет устройство в списке "
                "вместе с историей и именем, но закрывает ему выход.",
        "blockedTitle": "Стучались, но не пущены",
        "blockedHint": "Ядро запомнило адреса, чьи пакеты дропнуты за последние 6 часов.",
        "noData": "за этот месяц данных ещё нет",
        "youAre": "Вы",
        "turnOff": "выключить",
        "turnOn": "включить",
        "del": "удалить",
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
        "sIface": "интерфейс",
        "sLan": "локальная сеть",
        "sSelfIp": "адрес шлюза в ней",
        "sPort": "порт панели",
        "sPw": "новый пароль",
        "sPwKeep": "оставить прежний",
        "sSave": "сохранить",
        "sNetHint": "Первые три поля — то же, что нашёл установщик. Меняйте их, только "
                    "если сеть действительно переехала: правила nftables пересобираются "
                    "сразу, а устройства вне новой сети добавить будет уже нельзя. "
                    "Смена порта перезапускает панель. Всё лежит в {{CFG}}.",
        "sRestart": "Порт изменён. Панель перезапускается — откройте {url}",
        "badLang": "языка {lang} нет",
        "badNumber": "здесь нужно число",
        "badPoll": "опрос — от 5 до 3600 секунд",
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
        "phName": "whose device",
        "add": "add",
        "hint": "Set manually on the device: gateway <b>{{GW}}</b>, netmask "
                "<b>{{MASK}}</b> (Android and Quest ask for prefix length — "
                "<b>{{PFX}}</b>), DNS <b>1.1.1.1</b>. Anything not on the list does not "
                "route through the gateway at all. &ldquo;Turn off&rdquo; keeps a device "
                "listed with its name and history, but closes its way out.",
        "blockedTitle": "Knocked, not allowed",
        "blockedHint": "The kernel recorded the addresses whose packets it dropped "
                       "in the last 6 hours.",
        "noData": "no data for this month yet",
        "youAre": "You",
        "turnOff": "turn off",
        "turnOn": "turn on",
        "del": "delete",
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
        "sIface": "interface",
        "sLan": "local network",
        "sSelfIp": "this gateway in it",
        "sPort": "panel port",
        "sPw": "new password",
        "sPwKeep": "leave the current one",
        "sSave": "save",
        "sNetHint": "The first three are what the installer found. Change them only if "
                    "the network really moved: the nftables rules are rebuilt at once, "
                    "and devices outside the new network can no longer be added. "
                    "Changing the port restarts the panel. All of it lives in {{CFG}}.",
        "sRestart": "The port changed. The panel is restarting — open {url}",
        "badLang": "there is no {lang} language",
        "badNumber": "a number is expected here",
        "badPoll": "the poll interval is 5 to 3600 seconds",
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
    },
}


def reload_conf():
    """Re-read config.json into the globals and rebuild the page.

    Called once at import and again whenever the settings form saves, so a
    changed language or network takes effect without a restart. Only the port
    cannot be picked up this way — the socket is already bound (see restart).
    """
    global CFG, LANG, T, IFACE, PORT, POLL_SEC, LAN, SELF_IP, PAGE
    CFG = conf()
    LANG = CFG.get("lang") if CFG.get("lang") in STRINGS else "ru"
    T = STRINGS[LANG]
    IFACE = CFG["iface"]
    PORT = int(CFG["port"])
    POLL_SEC = int(CFG["poll_sec"])
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
    except (TypeError, ValueError):
        raise ValueError(T["badNumber"])
    if not 5 <= poll_sec <= 3600:
        raise ValueError(T["badPoll"])
    if not 1 <= port <= 65535:
        raise ValueError(T["badPort"])
    c["poll_sec"], c["port"] = poll_sec, port

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


def restart():
    """Replace this process, the only way to bind a changed port."""
    # ponytail: a fixed delay instead of a shutdown handshake — long enough for
    # the reply to leave, and the browser is told to reconnect by hand anyway.
    threading.Timer(0.7, lambda: os.execv(sys.executable,
                                          [sys.executable] + sys.argv)).start()


def load():
    try:
        with open(DEVICES) as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def save(devs):
    with open(DEVICES, "w") as f:
        json.dump(devs, f, indent=1, ensure_ascii=False)


def validate(ip):
    a = ipaddress.ip_address(ip.strip())  # raises ValueError on junk
    if a not in LAN or a == SELF_IP:
        raise ValueError(T["badIp"].replace("{ip}", str(a)).replace("{lan}", str(LAN)))
    return str(a)


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


def new_session():
    t = secrets.token_urlsafe(32)
    _sessions[t] = time.time() + SESSION_TTL
    return t


def session_ok(token):
    exp = _sessions.get(token or "")
    if exp and exp > time.time():
        return True
    _sessions.pop(token or "", None)
    return False


def note_fail(ip):
    n, until = _fails.get(ip, (0, 0))
    n = 1 if 0 < until < time.time() else n + 1
    _fails[ip] = (n, time.time() + FAIL_BLOCK if n >= FAIL_LIMIT else until)


def fail_blocked(ip):
    return time.time() < _fails.get(ip, (0, 0))[1]


# --- nftables ---------------------------------------------------------------

def ruleset(devs):
    on = [d for d in devs if d.get("on", True)]
    ips = ", ".join(d["ip"] for d in on)
    elems = f"\n    elements = {{ {ips} }}" if ips else ""
    ctrs = "\n".join(f"  counter {cname(w, d['ip'])} {{ }}"
                     for d in devs for w in ("up", "down"))
    up = "\n".join(f"    ip saddr {d['ip']} counter name {cname('up', d['ip'])}"
                   for d in devs)
    down = "\n".join(f"    ip daddr {d['ip']} counter name {cname('down', d['ip'])}"
                     for d in devs)
    # `table` before `delete` — so delete never fails on a first run.
    # priority raw (-300) — ahead of any redirect chains (auto_redirect, in the
    # case of sing-box), otherwise the verdict comes after the interception.
    # fib daddr type != unicast lets through everything addressed to the host
    # itself: SSH and the panel stay reachable even to a blocked device.
    # Counting happens before the verdict: upload on the way in, download on
    # the way out (replies go through forward, NAT does not rewrite them).
    # ponytail: a switched-off device still accrues its own doomed retries as
    # upload. A few kilobytes, and it makes the knocking visible.
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
    timeout 6h
  }}
  chain prerouting {{
    type filter hook prerouting priority raw; policy accept;
    iifname != "{IFACE}" accept
    meta nfproto != ipv4 accept
{up}
    ip saddr @allowed accept
    fib daddr type != unicast accept
    update @blocked {{ ip saddr }}
    drop
  }}
  chain postrouting {{
    type filter hook postrouting priority 0; policy accept;
    oifname != "{IFACE}" accept
{down}
  }}
}}
"""
# ponytail: IPv6 passes through untouched — a typical gateway has v6
# forwarding off. When it is needed: a second set and rules on ip6 saddr/daddr.


def nft_json(*args):
    out = subprocess.run(["nft", "-j", "list", *args],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)["nftables"]


def counters():
    return {o["counter"]["name"]: o["counter"]["bytes"]
            for o in nft_json("counters", "table", "inet", "gwacl") if "counter" in o}


def parse_blocked(objs):
    """Addresses from the dynamic set. Without a timeout an element is a
    string, with one it is a dict.
    """
    for o in objs:
        if "set" in o:
            return sorted({e["elem"]["val"] if isinstance(e, dict) else e
                           for e in o["set"].get("elem", [])})
    return []


def blocked():
    try:
        return parse_blocked(nft_json("set", "inet", "gwacl", "blocked"))
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError):
        return []


def apply(devs):
    poll()  # sample the counters before the rebuild zeroes them
    subprocess.run(["nft", "-f", "-"], input=ruleset(devs), text=True, check=True)
    # The baseline is deliberately left alone: after the rebuild a counter is
    # below it, and accrue reads that as a reset and returns zero.


# --- traffic accounting -----------------------------------------------------

def accrue(prev, cur):
    """Counter increment. A drop means a table rebuild or a reboot."""
    return cur if cur < prev else cur - prev


def history():
    try:
        with open(TRAFFIC) as f:
            h = json.load(f)
    except FileNotFoundError:
        h = {"days": {}}
    if "days" not in h:  # old format: month keys straight in the root
        h = {"days": h}
    h.setdefault("seen", {})
    h.setdefault("last", {})
    return h


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
    if dt < 2:
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
    Storing them would multiply traffic.json by twenty-four for a chart whose
    whole point is the last day — the month is already on disk.
    """
    bucket = _hours.setdefault(key or time.strftime("%Y-%m-%d %H"), {})
    for ip, (u, d) in moved.items():
        row = bucket.setdefault(ip, [0, 0])
        row[0] += u
        row[1] += d
    for old in sorted(_hours)[:-24]:
        del _hours[old]
    return bucket


def poll():
    """Sample the nftables counters and add the increment to today."""
    with _lock:
        try:
            cur = counters()
        except (OSError, subprocess.CalledProcessError, ValueError, KeyError):
            return  # no table yet — first run
        h = history()
        day = h["days"].setdefault(time.strftime("%Y-%m-%d"), {})
        now = time.time()
        devs = load()
        moved = apply_deltas(cur, h["last"], day, devs)
        for ip in moved:
            h["seen"][ip] = int(now)
        note_hour(moved)
        rates(moved, devs, now)
        # Counters of removed devices are not kept in the baseline.
        h["last"] = {k: v for k, v in h["last"].items() if k in cur}
        with open(TRAFFIC, "w") as f:
            json.dump(h, f)


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
_sys = {"at": 0.0, "cpu": None, "net": None, "pct": None, "bps": [0, 0]}


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
    """
    with _syslock:
        now = time.time()
        dt = now - _sys["at"]
        cpu = cpu_jiffies(_read("/proc/stat"))
        net = [_num(_read(f"/sys/class/net/{IFACE}/statistics/{w}_bytes"))
               for w in ("rx", "tx")]
        if dt >= 2:
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
        return {
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


def state(month=None):
    poll()
    h = history()
    months = sorted({k[:7] for k in h["days"]} | {time.strftime("%Y-%m")})
    if month not in months:
        month = time.strftime("%Y-%m")
    tot = month_totals(h["days"], month)
    known = {d["ip"] for d in load()}
    # len == 10 filters out old-format keys ("2026-07"): they still count
    # towards the month total, but never into the per-day chart.
    day_keys = sorted(k for k in h["days"] if k.startswith(month) and len(k) == 10)
    hour_keys = sorted(_hours)
    names = lan_names()

    def total(m):
        return sum(sum(v) for v in month_totals(h["days"], m).values())

    return {
        "month": month,
        # Every month is offered in the picker; the strip below the chart draws
        # the last twelve of them.
        "months": [[m, total(m)] for m in months],
        "prev": total(prev_month(month)),
        "now": int(time.time()),
        "poll": POLL_SEC,
        "devices": [dict(d, on=d.get("on", True),
                         up=tot.get(d["ip"], [0, 0])[0],
                         down=tot.get(d["ip"], [0, 0])[1],
                         seen=h["seen"].get(d["ip"], 0),
                         rate=_rate.get(d["ip"], [0, 0]),
                         host=names.get(d["ip"], ["", ""])[0],
                         mac=names.get(d["ip"], ["", ""])[1],
                         series=[h["days"][k].get(d["ip"], [0, 0]) for k in day_keys],
                         # .get: the poller may drop the oldest hour between
                         # the snapshot of the keys and the read.
                         hseries=[_hours.get(k, {}).get(d["ip"], [0, 0])
                                  for k in hour_keys])
                    for d in load()],
        "days": [[k, sum(v[0] for v in h["days"][k].values()),
                  sum(v[1] for v in h["days"][k].values())] for k in day_keys],
        "hours": [[k[-2:], sum(v[0] for v in _hours.get(k, {}).values()),
                   sum(v[1] for v in _hours.get(k, {}).values())] for k in hour_keys],
        "blocked": [[ip] + names.get(ip, ["", ""])
                    for ip in blocked() if ip not in known],
        "sys": sysinfo(),
        "update": _upd["new"],
    }


# --- pages ------------------------------------------------------------------

CSS = """
 :root{--bg:#101216;--card:#171a20;--line:#262a33;--fg:#d8dce3;--dim:#767d8a;
       --up:#a8763f;--down:#5b9bb5;--warn:#c4756a}
 *{box-sizing:border-box}
 /* The page takes the whole window. Nothing here is prose, so a reading
    measure would only push the numbers apart. */
 body{font:15px/1.55 system-ui,sans-serif;margin:0;
      padding:1.5rem 1.75rem 4rem;background:var(--bg);color:var(--fg)}
 h1{font-size:1.05rem;font-weight:600;margin:0;letter-spacing:.01em}
 select,input,button{font:inherit;background:#1c2027;border:1px solid var(--line);
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

LOGIN_T = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{{t.loginTitle}}</title>
<style>{{CSS}}
 body{max-width:22rem;margin:0 auto;padding-top:22vh}
 form{display:flex;gap:.5rem;margin-top:.9rem}
 input{flex:1;min-width:0}
 .err{color:#d08a8a;font-size:.85rem;margin-top:.7rem}
</style>
<div class=card>
 <h2>{{t.panelTitle}}</h2>
 <form method=post action=/login>
  <input type=password name=password placeholder="{{t.password}}" autofocus required>
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
    return (out.replace("{{GW}}", str(SELF_IP))
               .replace("{{MASK}}", str(LAN.netmask))
               .replace("{{PFX}}", str(LAN.prefixlen))
               .replace("{{VERSION}}", VERSION)
               .replace("{{CFG}}", CONFIG)
               # The settings form is filled in from the running config.
               .replace("{{IFACE}}", html.escape(IFACE, quote=True))
               .replace("{{LANCIDR}}", str(LAN))
               .replace("{{PORT}}", str(PORT))
               .replace("{{POLL}}", str(POLL_SEC))
               .replace("{{SEL_RU}}", " selected" if LANG == "ru" else "")
               .replace("{{SEL_EN}}", " selected" if LANG == "en" else "")
               .replace("{{UPD}}", " checked" if CFG["update_check"] else "")
               .replace("{{EXAMPLE}}",
                        str(LAN.network_address + min(56, LAN.num_addresses - 2))))


def login_page(msg="", t=None):
    return render(LOGIN_T, t).replace("{{MSG}}", msg)


PAGE_T = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
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
 .mo i{display:block;width:100%;max-width:1.6rem;background:#2f3542;border-radius:2px}
 .mo:hover i{background:#485162}
 .mo.cur i{background:var(--down)}
 .mo span{font-size:.68rem;color:var(--dim);font-family:ui-monospace,monospace}
 .mo.cur span{color:var(--fg)}
 .srow{display:grid;grid-template-columns:7rem minmax(0,1fr);gap:.2rem .8rem;
       align-items:baseline;padding:.45rem 0;border-bottom:1px solid var(--line)}
 .q{margin-left:.3rem;padding:0 .3rem;border:1px solid var(--line);border-radius:50%;
    color:var(--dim);font-size:.62rem;font-style:normal;cursor:help}
 .srow:last-child{border-bottom:0}
 .srow>span{font-size:.78rem;color:var(--dim)}
 /* Beats .num's nowrap: the load line carries the core count and an interface
    name can be anything, so a long value wraps instead of leaving the card. */
 .srow b{white-space:normal;overflow-wrap:anywhere}
 .meter{grid-column:2;height:3px;border-radius:2px;background:#22262e}
 .meter i{display:block;height:100%;border-radius:2px;background:var(--down)}
 /* Every row carries the dot, so the column keeps its shape and the eye reads
    a colour change rather than something appearing out of nowhere. */
 .dot{display:inline-block;width:6px;height:6px;border-radius:50%;
      background:#484e5a;margin-right:.45rem;vertical-align:middle}
 .dot.live{background:#6f9f6f}
 table{width:100%;border-collapse:collapse}
 th{font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
    color:var(--dim);text-align:left;padding:0 .4rem .5rem;border-bottom:1px solid var(--line)}
 th.r,td.r{text-align:right}
 th.s{cursor:pointer;user-select:none}
 th.s:hover{color:var(--fg)}
 td{padding:.55rem .4rem;border-bottom:1px solid var(--line);vertical-align:middle}
 tbody tr:last-child td{border-bottom:0}
 td.ip{font-family:ui-monospace,monospace;white-space:nowrap;cursor:pointer}
 td.ip:hover{color:#9cc4d6}
 tr.pick td.ip{color:var(--down)}
 tr.pick{background:#1b2029}
 td input{width:100%;background:transparent;border:1px solid transparent;padding:.2rem .35rem}
 td input:hover{border-color:var(--line)}
 td input:focus{background:#1c2027;border-color:#3d434f;outline:none}
 .off td.ip,.off td input{color:var(--dim)}
 .me{color:var(--dim);font-size:.72rem;margin-left:.4rem}
 /* Every sparkline is scaled to the same peak day, so the rows compare
    against each other and not only against themselves. */
 .spark{display:block;margin:.25rem 0 0 auto}
 .mini{font-size:.78rem;color:var(--dim);white-space:nowrap}
 .act{display:flex;gap:.35rem;justify-content:flex-end}
 /* Address, whatever the network knows it as, and the button. It wraps: on a
    phone the three of them do not fit on one line. */
 .blk{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin:.35rem 0}
 .blk .num{min-width:9rem}
 /* A basis, not flex:1 — the button belongs next to the address it acts on,
    not pushed to the far edge of a full-width card. */
 .blk .mini{flex:0 1 16rem;min-width:7rem;overflow-wrap:anywhere;white-space:normal}
 .act button{padding:.22rem .5rem;font-size:.82rem;color:var(--dim)}
 .act button:hover{color:var(--fg);border-color:#4a505c}
 .act .on{color:#8fae8f;border-color:#3c4d3c}
 /* The settings live in the corner: a summary that looks like the buttons
    beside it, and a card that drops out of it. details does the opening on
    its own — no script, and it works in whatever browser is at hand. */
 .gear{position:relative}
 .gear>summary{cursor:pointer;list-style:none;padding:.32rem .55rem;
   border:1px solid var(--line);border-radius:5px;background:#1c2027}
 .gear>summary::-webkit-details-marker{display:none}
 .gear[open]>summary,.gear>summary:hover{border-color:#4a505c}
 .gear>.card{position:absolute;right:0;top:calc(100% + .4rem);z-index:5;
   width:min(36rem,88vw);margin:0;box-shadow:0 12px 34px #000a}
 .set{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));
      gap:.7rem .9rem;margin-bottom:.9rem}
 .set label{display:block;font-size:.75rem;color:var(--dim);letter-spacing:.04em}
 .set input,.set select{width:100%;margin-top:.2rem}
 .set .chk,.chk input{display:flex;align-items:center;width:auto;margin:0}
 .set .chk{gap:.45rem;align-self:end;padding-bottom:.4rem}
 .chk input{accent-color:var(--down)}
 .legend{display:flex;gap:1rem;font-size:.78rem;color:var(--dim);margin-top:.5rem}
 .legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:.35rem}
 .legend i.dash{width:14px;height:0;border-radius:0;border-top:1.5px dashed #6d7686;
                vertical-align:middle}
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
 <h1>{{t.h1}}</h1><span class=sp></span>
 <select id=msel onchange="load(this.value)"></select>
 <details class=gear>
  <summary>{{t.settingsTitle}}</summary>
  <div class=card>
   <div class=set>
    <label>{{t.sLang}}<select id=s_lang>
     <option value=ru{{SEL_RU}}>Русский<option value=en{{SEL_EN}}>English</select></label>
    <label>{{t.sPoll}}<input id=s_poll type=number min=5 max=3600 value="{{POLL}}"></label>
    <label>{{t.sPort}}<input id=s_port type=number min=1 max=65535 value="{{PORT}}"></label>
    <label>{{t.sIface}}<input id=s_iface value="{{IFACE}}"></label>
    <label>{{t.sLan}}<input id=s_lan value="{{LANCIDR}}"></label>
    <label>{{t.sSelfIp}}<input id=s_self value="{{GW}}"></label>
    <label>{{t.sPw}}<input id=s_pw type=password autocomplete=new-password
      placeholder="{{t.sPwKeep}}"></label>
    <label class=chk><input id=s_upd type=checkbox{{UPD}}>{{t.sUpdate}}</label>
   </div>
   <div class=act><button onclick=saveCfg()>{{t.sSave}}</button></div>
   <p class=hint>{{t.sNetHint}}</p>
  </div>
 </details>
 <button onclick="location='/logout'">{{t.logout}}</button>
</div>

<div class=card id=upd hidden>
 <h2>{{t.updateTitle}}</h2>
 <p id=updtext style="margin:0"></p>
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
  </div>
  <div id=chartbox></div>
  <div class=legend><span><i style="background:var(--down)"></i>{{t.inbound}}</span>
   <span><i style="background:var(--up)"></i>{{t.outbound}}</span>
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
 <h2>{{t.devicesTitle}}</h2>
 <table><thead><tr>
  <th class=s id=h_ip onclick="sortBy('ip')">
  <th class=s id=h_name onclick="sortBy('name')">
  <th class="r s" id=h_traf onclick="sortBy('traf')">
  <th class="r s" id=h_now onclick="sortBy('now')">
  <th class="r s" id=h_seen onclick="sortBy('seen')">
  <th></tr></thead>
 <tbody id=tb></tbody></table>
 <form id=f style="margin-top:1rem">
  <input name=ip placeholder="{{EXAMPLE}}" required>
  <input name=nm placeholder="{{t.phName}}">
  <button>{{t.add}}</button>
 </form>
 <p class=hint>{{t.hint}}</p>
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

const upfmt = s => {
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600);
  return (d ? d + T.dShort + ' ' : '') + h + T.hShort;
};

// S is the last answer from the server, kept so that sorting, the day/hour
// switch and picking a device redraw from memory instead of asking again.
let S = null, month = null, sel = null, mode = 'day', sortk = 'ip', sortd = 1;

// [short label, up, down, full label] — the chart draws whatever this returns,
// so the month, the last 24 hours and one device's slice are the same code.
const rows = () => {
  const src = mode === 'hour' ? S.hours : S.days;
  const d = sel && S.devices.find(x => x.ip === sel);
  const ser = d && (mode === 'hour' ? d.hseries : d.series);
  return src.map((r, i) => [mode === 'hour' ? r[0] : String(+r[0].slice(8)),
                            ser ? ser[i][0] : r[1], ser ? ser[i][1] : r[2], r[0]]);
};

const chart = (rs, cum) => {
  if (!rs.length) return `<p class=hint>${mode === 'hour' ? T.noHours : T.noData}</p>`;
  // Take the actual width: one viewBox unit is then one pixel, and the
  // labels do not shrink on a phone.
  const W = Math.max(chartbox.clientWidth || 720, 280), H = 190,
        L = 54, B = 20, top = 10;
  const max = Math.max(...rs.map(d => d[1] + d[2]), 1024);
  const bw = (W - L) / rs.length, plot = H - B - top;
  const y = v => top + plot - (v / max) * plot;
  let g = '';
  for (const f of [0, .5, 1]) g += `<line x1=${L} x2=${W} y1=${y(max*f)} y2=${y(max*f)} `
    + `stroke="#262a33"/><text x=${L-8} y=${y(max*f)+4} text-anchor=end fill="#767d8a" `
    + `font-size=10 font-family=ui-monospace>${f ? fmtAx(max*f) : 0}</text>`;
  const bars = rs.map((d, i) => {
    const x = L + i*bw + bw*.18, w = Math.max(1, bw*.64);
    const hu = (d[1]/max)*plot, hd = (d[2]/max)*plot;
    const lbl = rs.length > 20 ? (i % 5 === 0) : true;
    return `<g><title>${d[3]}  ↓ ${fmt(d[2])}  ↑ ${fmt(d[1])}</title>`
      + `<rect x=${x} y=${y(d[1]+d[2])} width=${w} height=${hu} fill="var(--up)"/>`
      + `<rect x=${x} y=${y(d[2])} width=${w} height=${hd} fill="var(--down)"/>`
      + `<rect x=${L+i*bw} y=${top} width=${bw} height=${plot} fill="none" pointer-events="all"/></g>`
      + (lbl ? `<text x=${x+w/2} y=${H-5} text-anchor=middle fill="#767d8a" font-size=10 font-family=ui-monospace>${d[0]}</text>` : '');
  }).join('');
  // The running total, scaled so the end of the line is the top of the plot:
  // the shape answers "are we going faster than last time", the tooltip the
  // exact figure. A second axis would cost more than it explains.
  let line = '';
  const tot = rs.reduce((a, d) => a + d[1] + d[2], 0);
  if (cum && rs.length > 1 && tot) {
    let run = 0;
    const pts = rs.map((d, i) => { run += d[1] + d[2];
      return `${(L + i*bw + bw/2).toFixed(1)},${(top + plot - run/tot*plot).toFixed(1)}`;
    }).join(' ');
    line = `<polyline fill=none stroke="#6d7686" stroke-width=1.4 stroke-dasharray="3 3"`
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
const q = title => `<i class=q title="${esc(title)}">?</i>`;
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
const sortBy = k => {
  // Names and addresses read best ascending, quantities biggest-first.
  sortd = sortk === k ? -sortd : (k === 'ip' || k === 'name' ? 1 : -1);
  sortk = k;
  draw();
};
const setMode = m => { mode = m; draw(); };
const pickDev = ip => { sel = sel === ip ? null : ip; draw(); };
const addKnown = b => post({ip: b.dataset.ip, name: b.dataset.nm});

const draw = () => {
  if (!S) return;
  if (sel && !S.devices.some(x => x.ip === sel)) sel = null;
  const one = sel && S.devices.find(x => x.ip === sel);
  msel.innerHTML = S.months.map(m =>
    `<option${m[0] === S.month ? ' selected' : ''}>${m[0]}</option>`).join('');
  for (const k in HEADS) document.getElementById('h_' + k).textContent =
    T[HEADS[k]] + (sortk === k ? (sortd > 0 ? ' ↑' : ' ↓') : '');
  bday.className = mode === 'day' ? 'on' : '';
  bhour.className = mode === 'hour' ? 'on' : '';
  chsel.innerHTML = one ? `<button onclick="pickDev(null)" title="${T.showAll}">`
    + `${esc(one.name || one.ip)} ×</button>` : '';

  const dv = one ? [one] : S.devices;
  const U = dv.reduce((a,x) => a+x.up, 0), D = dv.reduce((a,x) => a+x.down, 0);
  kt.textContent = fmt(U+D); kd.textContent = fmt(D); ku.textContent = fmt(U);
  ka.textContent = fmt(Math.round((U+D) / Math.max(S.days.length, 1)));
  // Only against the whole month: a single device against everything last
  // month would be a comparison of two different things.
  const pc = (!one && S.prev) ? Math.round((U+D-S.prev)/S.prev*100) : null;
  kdelta.textContent = pc === null ? '' : (pc > 0 ? '+' : '') + pc + '%';
  kdelta.title = pc === null ? '' : T.vsPrev;
  chartbox.innerHTML = chart(rows(), mode === 'day');
  cumlbl.hidden = mode !== 'day';
  mstrip.innerHTML = strip();
  sysbox.innerHTML = S.sys ? machine(S.sys) : `<p class=hint>${T.sysNone}</p>`;

  const peak = Math.max(1, ...S.devices.flatMap(x => x.series.map(v => v[0]+v[1])));
  const fresh = Math.max(120, S.poll * 2);
  const list = S.devices.slice().sort((a, b) => {
    const p = CMP[sortk](a), q = CMP[sortk](b);
    return (p < q ? -1 : p > q ? 1 : 0) * sortd;
  });
  tb.innerHTML = list.map(x => {
    const t = x.up + x.down, me = x.ip === S.you, r = x.rate[0] + x.rate[1];
    return `<tr class="${x.on ? '' : 'off'}${x.ip === sel ? ' pick' : ''}">`
     + `<td class=ip title="${esc(x.mac)}" onclick="pickDev('${esc(x.ip)}')">`
     + `<i class="dot${r > 0 || (x.seen && S.now - x.seen < fresh) ? ' live' : ''}"></i>`
     + `${esc(x.ip)}${me ? `<span class=me>${T.youAre}</span>` : ''}</td>`
     + `<td><input value="${esc(x.name)}" placeholder="${esc(x.host || T.phName)}" `
     + `onchange="setName('${esc(x.ip)}',this.value)"></td>`
     + `<td class="r num">${fmt(t)}${spark(x.series, peak, x.on)}</td>`
     + `<td class="r num mini">${r > 0 ? `↓ ${fmt(x.rate[1])}${T.perSec}`
        + `  ↑ ${fmt(x.rate[0])}${T.perSec}` : '—'}</td>`
     + `<td class="r mini">${x.seen ? ago(S.now - x.seen) : '—'}</td>`
     + `<td><div class=act><button class="${x.on ? '' : 'on'}" `
     + `onclick="post({ip:'${esc(x.ip)}',on:${!x.on}})">${x.on ? T.turnOff : T.turnOn}</button>`
     + `<button onclick="del('${esc(x.ip)}',${me})">${T.del}</button></div></td></tr>`;
  }).join('') || `<tr><td colspan=6 class=hint>${T.empty}</td></tr>`;

  upd.hidden = !S.update;
  // textContent, not innerHTML: the tag comes off the network.
  if (S.update) updtext.textContent = T.updateNew.replace('{v}', S.update);
  unk.hidden = !S.blocked.length;
  // The name and the hardware address go through data-, not into the onclick:
  // both come out of a lease file this program does not own.
  ub.innerHTML = S.blocked.map(([ip, host, mac]) =>
    `<div class=blk><span class=num>${esc(ip)}</span>`
    + `<span class=mini>${esc(host)}${host && mac ? ' · ' : ''}${esc(mac)}</span>`
    + `<button data-ip="${esc(ip)}" data-nm="${esc(host)}" onclick="addKnown(this)">`
    + `${T.add}</button></div>`).join('');
};

const load = m => fetch('/api?month=' + (month = m || month || ''))
  .then(r => r.status === 401 ? location.reload()
    : r.json().then(s => { S = s; draw(); }));
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
    port: +s_port.value, iface: s_iface.value, lan: s_lan.value,
    self_ip: s_self.value, pw: s_pw.value})})
  .then(r => r.text().then(x => !r.ok ? alert(x)
    : x ? alert(T.sRestart.replace('{url}', x)) : location.reload()));
// Only the chart depends on the pixel width. Redrawing the table here would
// take the cursor out of a name someone is in the middle of typing.
onresize = () => { if (S) chartbox.innerHTML = chart(rows(), mode === 'day'); };
load();
setInterval(() => document.activeElement.tagName === 'INPUT' || load(), 15000);
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
                _sessions.pop(SimpleCookie(raw)["sess"].value, None)
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
            s = state(month)
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
        try:
            body = json.loads(raw or b"{}")
            ip = validate(body.get("ip", ""))
            devs = load()
            before = ruleset(devs)
            cur = next((d for d in devs if d["ip"] == ip), None)
            if cur is None:
                cur = {"ip": ip, "name": "", "on": True}
                devs.append(cur)
                devs.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
            if "name" in body:
                cur["name"] = str(body.get("name") or "").strip()[:40]
            if "on" in body:
                cur["on"] = bool(body["on"])
            save(devs)
            # A rename leaves the ruleset identical — nft untouched, counters intact.
            if ruleset(devs) != before:
                apply(devs)
            self._send(200, "ok", "text/plain")
        except ValueError as e:
            self._send(400, str(e), "text/plain")

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
        check_update()


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
    assert "dport" not in r, "the panel port is open to the whole LAN, the password guards it"
    assert "elements" not in ruleset([]), "an empty set breaks nft syntax"
    assert ruleset([]).count("drop") == 1
    # Renaming must not touch nftables.
    assert ruleset(d) == ruleset([dict(d[0], name="Mac"), d[1]])

    assert validate(f" {a} ") == a
    # 203.0.113.0/24 is TEST-NET-3, never a home network.
    for bad in (str(SELF_IP), "203.0.113.7", "8.8.8.8", "nope", ""):
        try:
            validate(bad)
        except ValueError:
            continue
        raise AssertionError(f"junk accepted: {bad!r}")

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

    t = new_session()
    assert session_ok(t) and not session_ok("forged")
    _sessions[t] = time.time() - 1
    assert not session_ok(t), "an expired session must be rejected"

    ip = "10.9.9.9"
    for _ in range(FAIL_LIMIT - 1):
        note_fail(ip)
    assert not fail_blocked(ip), "the block must not trigger before the limit"
    note_fail(ip)
    assert fail_blocked(ip), "after the limit of misses the address must sit it out"
    _fails.pop(ip)

    # A real answer from nft 1.1.6.
    assert parse_blocked(json.loads('{"nftables":[{"metainfo":{}},{"set":{"name":"blocked",'
        '"elem":[{"elem":{"val":"192.168.1.99","expires":21599}}]}}]}')["nftables"]) \
        == ["192.168.1.99"]
    assert parse_blocked([{"set": {"name": "blocked"}}]) == []

    days = {"2026-07": {"1.1.1.1": [5, 5]}, "2026-07-30": {"1.1.1.1": [10, 20]},
            "2026-08-01": {"1.1.1.1": [99, 99]}}
    assert month_totals(days, "2026-07") == {"1.1.1.1": [15, 25]}, "the old format is lost"

    assert newer("v1.0.1", "1.0.0") == "v1.0.1"
    assert newer("v1.0.0", "1.0.0") is None, "the running version is not an update"
    assert newer("v0.9.0", "1.0.0") is None, "a downgrade must not be announced"
    assert newer("v1.10.0", "1.9.0"), "versions compare as numbers, not as text"
    assert newer("1.2", "1.2.0") is None, "a short tag is the same release"
    assert newer("nightly", "1.0.0") is None, "an odd tag is silence, not a banner"
    assert _ver(VERSION), f"VERSION {VERSION!r} does not compare against a tag"

    base = dict(DEFAULTS)
    form = {"lang": "en", "update_check": False, "poll_sec": 30,
            "port": base["port"], "iface": base["iface"],
            "lan": "10.7.0.0/24", "self_ip": "10.7.0.1"}
    c = check_settings(form, base)
    assert (c["lang"], c["poll_sec"]) == ("en", 30)
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
               "h_ip", "h_name", "h_traf", "h_now", "h_seen", "unk", "ub"):
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
    if "--selftest" in sys.argv:
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
        threading.Thread(target=poller, daemon=True).start()
        ThreadingHTTPServer(("", PORT), H).serve_forever()


if __name__ == "__main__":
    main()
