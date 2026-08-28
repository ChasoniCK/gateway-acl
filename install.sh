#!/usr/bin/env bash
# gateway-acl — install, upgrade and removal.
# Idempotent: running it again updates the code without touching the device
# list or the statistics.
set -Eeuo pipefail

ETC=/etc/gateway-acl
UNIT=/etc/systemd/system/gateway-acl.service
SYSCTL=/etc/sysctl.d/99-gateway-acl.conf
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

YES=0
PW_STDIN=0
TOUCHED=0
HAD_UNIT=0
UILANG=""          # not LANG: that one affects child processes' locale

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)         YES=1 ;;
    --password-stdin) PW_STDIN=1 ;;
    --lang)           UILANG="${2:-}"; shift ;;
    --lang=*)         UILANG="${1#*=}" ;;
    --uninstall)      ACTION=uninstall ;;
    --purge)          ACTION=uninstall; PURGE=1 ;;
    -h|--help)
      cat <<'EOF'
gateway-acl — панель управления доступом для Linux-шлюза.
gateway-acl — access-control panel for a Linux gateway.

  sudo ./install.sh                    установка или обновление / install or upgrade
  sudo ./install.sh --lang en          язык панели и установщика / UI and installer language
  sudo ./install.sh --yes              без вопросов / no questions asked
  sudo ./install.sh --password-stdin   пароль со stdin / read password from stdin
  sudo ./install.sh --uninstall        снять службу и правила / remove service and rules
  sudo ./install.sh --purge            то же плюс данные / the same plus the data
EOF
      exit 0 ;;
    *) echo "неизвестный аргумент / unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
ACTION="${ACTION:-install}"
PURGE="${PURGE:-0}"

[ "$(id -u)" = 0 ] || { echo "нужен root / root required: sudo $0" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "только Linux / Linux only" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "нужен systemd / systemd required" >&2; exit 1; }

# --- what the installed panel already knows ---------------------------------

# Every answer of the previous run is in config.json. Re-reading it is what makes
# a second run — and the upgrade button, which runs this with --yes — keep the
# network it was configured with instead of detecting the host all over again.
cfg() { # cfg key -> the value, or empty
  [ -f "$ETC/config.json" ] || return 0
  python3 -c 'import json,sys
try: v = json.load(open(sys.argv[1])).get(sys.argv[2])
except Exception: v = None
print("" if v is None else v)' "$ETC/config.json" "$1" 2>/dev/null || true
}

# --- language ---------------------------------------------------------------

# An installed panel already knows its language — do not ask again on upgrade.
[ -n "$UILANG" ] || UILANG=$(cfg lang)
if [ -z "$UILANG" ] && [ "$YES" = 0 ]; then
  read -r -p "  Язык / Language [ru/en]: " UILANG </dev/tty || true
fi
case "$UILANG" in en|EN|eng|english|English) UILANG=en ;; *) UILANG=ru ;; esac

if [ "$UILANG" = en ]; then
  M_ENV="Environment";           M_PARAMS="Settings  (Enter accepts the default)"
  M_PW="Panel password";         M_WHO="Who may go out"
  M_INSTALL="Installing";        M_REMOVE="Removing"
  M_NEEDPY="python3 is required (standard library is enough)"
  M_NONFT="nft not found and no known package manager — install nftables yourself"
  M_INSTALLNFT="install:";       M_NFTFAIL="installing nftables failed"
  M_NONFT2="nftables is required"
  M_FWDOFF="ip_forward is off — without it the host does not route at all."
  M_FWDASK="enable it and persist in $SYSCTL ?"
  M_FWDON="enabled and persisted"
  M_FWDLEFT="0 — the panel installs, traffic will not flow"
  M_IFACE="LAN interface";       M_NOIFACE="no such interface:"
  M_ADDR="gateway address";      M_NET="network";       M_PORT="panel port"
  M_NOIP="has no IPv4 address — configure it before installing"
  M_BADNET="address or network is invalid"
  M_PWSEEN="The panel is reachable from the whole LAN; the password is the only guard."
  M_PWHTTP="It travels over plain HTTP: fine on a network you control, not on one you do not."
  M_PWSHORT="password shorter than 8 characters"
  M_PWKEPT="already set, left unchanged"
  M_PWNEW="    new password (8+ chars): "; M_PWAGAIN="    again: "
  M_PWMISMATCH="did not match, try again"; M_PWTOOSHORT="too short, try again"
  M_TOOLS="Tunnel tools"
  M_TOOLSHINT="The panel manages subscriptions, WireGuard and AmneziaWG itself, but it runs the programs — it does not carry them."
  M_TOOLSASK="install what is missing?"
  M_TOOLSSKIP="skipped — tunnels stay unavailable until these are installed"
  M_SBOK="ok"; M_SBOLD="too old for the config the panel writes, replacing"
  M_SBFETCH="fetching the latest release"
  M_SBNOARCH="no published build for this architecture:"
  M_SBNODL="neither curl nor wget — install sing-box yourself"
  M_SBFAIL="could not be installed — subscriptions will not come up"
  M_SBUNIT="unit written"; M_SBUNITKEPT="unit already present"
  M_SBUNITOWN="existing unit pointed at the replaced binary, ExecStart overridden"
  M_WGOK="ok"; M_WGFAIL="not installed — WireGuard profiles will not come up"
  M_AWGFAIL="not installed — AmneziaWG profiles will not come up; the package is"
  M_ONLYLIST="After this, ONLY the devices on the list will route through this host."
  M_SEEN="Currently visible on the network:"
  M_NOARP="ARP table is empty — add devices from the panel later."
  M_KEPTOLD="previous version saved"
  M_DEVKEPT="kept, devices:";     M_DEVNEW="created, devices:"
  M_PWWRITTEN="stored (scrypt, random salt)"
  M_SELFTEST_FAIL="selftest failed — not installing"
  M_RULEFAIL="the kernel rejected the ruleset — not installing"
  M_UNITOK="installed, service restarted"
  M_NOSTART="service did not come up: journalctl -u gateway-acl -n 30"
  M_NOPORT="port is not listening:"; M_NOTABLE="the nftables table was not created"
  M_ACTIVE="active";              M_LISTEN="listening"; M_INKERNEL="in the kernel"
  M_ROLLED_SOFT="Rolled back: previous version restored, access rules untouched."
  M_ROLLED_HARD="Rolled back: service and rules removed, data untouched."
  M_STOPPED="stopped"; M_UNITGONE="removed"; M_RULESGONE="removed"
  M_KEPTDIR="kept (list and statistics intact)"; M_PURGED="deleted"
  M_UNTOUCHED="Done. ip_forward and $SYSCTL were not touched."
  M_READY="Done.  Panel: http://{ip}:{port}"
  M_CLIENT="  On a client device set manually:"
  M_CLIENT2="    gateway {ip}, netmask {mask}, DNS 1.1.1.1"
  M_CHPW="  Change password:"; M_UPD="  Upgrade:"; M_DEL="  Remove:"
  M_ERR="Error:"
  L_SVC="service"; L_UNIT="unit"; L_PW="password"
else
  M_ENV="Окружение";             M_PARAMS="Параметры  (Enter — принять предложенное)"
  M_PW="Пароль панели";          M_WHO="Кому можно наружу"
  M_INSTALL="Установка";         M_REMOVE="Удаление"
  M_NEEDPY="нужен python3 (стандартной библиотеки хватит)"
  M_NONFT="nft не найден, и пакетный менеджер не опознан — поставьте nftables сами"
  M_INSTALLNFT="поставить:";     M_NFTFAIL="установка nftables не удалась"
  M_NONFT2="без nftables работать нечему"
  M_FWDOFF="ip_forward выключен — без него хост не маршрутизирует вообще."
  M_FWDASK="включить и закрепить в $SYSCTL ?"
  M_FWDON="включён и закреплён"
  M_FWDLEFT="0 — панель поставится, но трафик не пойдёт"
  M_IFACE="интерфейс LAN";       M_NOIFACE="интерфейса не существует:"
  M_ADDR="адрес шлюза";          M_NET="сеть";          M_PORT="порт панели"
  M_NOIP="не имеет адреса IPv4 — задайте его до установки"
  M_BADNET="адрес или сеть заданы неверно"
  M_PWSEEN="Панель видна всей сети, пароль — единственная защита."
  M_PWHTTP="Идёт по HTTP: в своей сети приемлемо, в чужой не используйте."
  M_PWSHORT="пароль короче 8 символов"
  M_PWKEPT="уже задан, оставлен без изменений"
  M_PWNEW="    новый пароль (от 8 символов): "; M_PWAGAIN="    ещё раз: "
  M_PWMISMATCH="не совпали, ещё раз";  M_PWTOOSHORT="слишком короткий, ещё раз"
  M_TOOLS="Программы для туннелей"
  M_TOOLSHINT="Подписками, WireGuard и AmneziaWG управляет панель, но она их запускает, а не содержит в себе."
  M_TOOLSASK="поставить недостающее?"
  M_TOOLSSKIP="пропущено — туннели не заработают, пока этого нет"
  M_SBOLD="слишком старый для конфига, который пишет панель, заменяю"
  M_SBOK="ok"
  M_SBFETCH="качаю последний релиз"
  M_SBNOARCH="под эту архитектуру сборки нет:"
  M_SBNODL="нет ни curl, ни wget — поставьте sing-box сами"
  M_SBFAIL="поставить не удалось — подписки не поднимутся"
  M_SBUNIT="юнит записан"; M_SBUNITKEPT="юнит уже есть"
  M_SBUNITOWN="юнит указывал на заменённый бинарник, ExecStart переопределён"
  M_WGOK="ok"; M_WGFAIL="не установлен — профили WireGuard не поднимутся"
  M_AWGFAIL="не установлен — профили AmneziaWG не поднимутся; пакет"
  M_ONLYLIST="После установки через этот хост пойдут ТОЛЬКО те, кто в списке."
  M_SEEN="Сейчас в сети видно:"
  M_NOARP="ARP-таблица пуста — добавите устройства через панель."
  M_KEPTOLD="прежняя версия сохранена"
  M_DEVKEPT="оставлен, устройств:"; M_DEVNEW="создан, устройств:"
  M_PWWRITTEN="записан (scrypt, соль случайная)"
  M_SELFTEST_FAIL="selftest не прошёл — не ставлю"
  M_RULEFAIL="ruleset не принят ядром — не ставлю"
  M_UNITOK="установлен, служба перезапущена"
  M_NOSTART="служба не поднялась: journalctl -u gateway-acl -n 30"
  M_NOPORT="порт не слушается:";  M_NOTABLE="таблица nftables не создалась"
  M_ACTIVE="active";              M_LISTEN="слушает";   M_INKERNEL="в ядре"
  M_ROLLED_SOFT="Откат: возвращена прежняя версия, правила доступа не тронуты."
  M_ROLLED_HARD="Откат: служба и правила сняты, данные не тронуты."
  M_STOPPED="остановлена"; M_UNITGONE="снят"; M_RULESGONE="сняты"
  M_KEPTDIR="оставлен (список и статистика целы)"; M_PURGED="удалён"
  M_UNTOUCHED="Готово. ip_forward и $SYSCTL не трогались."
  M_READY="Готово.  Панель: http://{ip}:{port}"
  M_CLIENT="  На клиентском устройстве прописать вручную:"
  M_CLIENT2="    шлюз {ip}, маска {mask}, DNS 1.1.1.1"
  M_CHPW="  Сменить пароль:"; M_UPD="  Обновить:"; M_DEL="  Снести:"
  M_ERR="Ошибка:"
  L_SVC="служба"; L_UNIT="юнит"; L_PW="пароль"
fi

# --- helpers ----------------------------------------------------------------

rollback() {
  [ "${TOUCHED:-0}" = 1 ] || return 0
  if [ "${HAD_UNIT:-0}" = 1 ] && [ -f "$ETC/panel.py.bak" ]; then
    # The upgrade failed: put the previous code back, but leave the access
    # rules in place — dropping them would open the way out for everyone.
    install -m 755 "$ETC/panel.py.bak" "$ETC/panel.py"
    systemctl restart gateway-acl >/dev/null 2>&1 || true
    printf '\n%s\n' "$M_ROLLED_SOFT" >&2
  else
    systemctl disable --now gateway-acl >/dev/null 2>&1 || true
    rm -f "$UNIT"; systemctl daemon-reload
    nft delete table inet gwacl >/dev/null 2>&1 || true
    printf '\n%s\n' "$M_ROLLED_HARD" >&2
  fi
}

say()  { printf '  %s\n' "$*"; }
step() { printf '\n%s\n' "$*"; }
ok()   { printf '    %-22s %s\n' "$1" "$2"; }
die()  { printf '\n%s %s\n' "$M_ERR" "$*" >&2; rollback; exit 1; }

ask() { # ask "question" "default" -> stdout
  local q="$1" d="${2:-}" a
  if [ "$YES" = 1 ]; then printf '%s' "$d"; return; fi
  read -r -p "    $q [$d] " a </dev/tty || true
  printf '%s' "${a:-$d}"
}

yesno() { # yesno "question" -> 0/1, defaults to yes
  local a
  if [ "$YES" = 1 ]; then return 0; fi
  read -r -p "    $1 [Y/n] " a </dev/tty || true
  case "$a" in [nNнН]*) return 1 ;; *) return 0 ;; esac
}

# --- removal ----------------------------------------------------------------

if [ "$ACTION" = uninstall ]; then
  step "$M_REMOVE"
  systemctl disable --now gateway-acl >/dev/null 2>&1 || true
  ok "$L_SVC" "$M_STOPPED"
  rm -f "$UNIT"; systemctl daemon-reload
  ok "$L_UNIT" "$M_UNITGONE"
  nft delete table inet gwacl >/dev/null 2>&1 || true
  ok "nftables" "$M_RULESGONE"
  if [ "$PURGE" = 1 ]; then rm -rf "$ETC"; ok "$ETC" "$M_PURGED"
  else ok "$ETC" "$M_KEPTDIR"; fi
  printf '\n%s\n' "$M_UNTOUCHED"
  exit 0
fi

# --- environment ------------------------------------------------------------

step "$M_ENV"
command -v python3 >/dev/null || die "$M_NEEDPY"
ok "python3" "$(python3 -c 'import platform;print(platform.python_version())')"
ok "systemd" "ok"

if ! command -v nft >/dev/null; then
  if   command -v pacman  >/dev/null; then PKG="pacman -S --needed --noconfirm nftables"
  elif command -v apt-get >/dev/null; then PKG="apt-get install -y nftables"
  else die "$M_NONFT"; fi
  yesno "$M_INSTALLNFT $PKG ?" || die "$M_NONFT2"
  # shellcheck disable=SC2086
  $PKG >/dev/null || die "$M_NFTFAIL"
fi
ok "nftables" "$(nft --version | awk '{print $2}')"

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
  say "$M_FWDOFF"
  if yesno "$M_FWDASK"; then
    echo 'net.ipv4.ip_forward=1' > "$SYSCTL"
    sysctl -qw net.ipv4.ip_forward=1
    ok "ip_forward" "$M_FWDON"
  else
    ok "ip_forward" "$M_FWDLEFT"
  fi
else
  ok "ip_forward" "1"
fi

# --- tunnel tools -----------------------------------------------------------
#
# The panel manages tunnels; it does not carry them. It shells out to sing-box
# for a subscription and to wg-quick/awg-quick for a profile, and every one of
# those failures reaches the browser as a two-word code — "нужная программа не
# установлена" is what a panel with no sing-box says about every subscription
# anyone ever tries to enable. So they are installed here, next to nftables,
# and nothing in this step may abort the install: a mirror that is down must
# not cost somebody their access-control panel.

# The oldest sing-box that reads the config singbox_sub.py writes: 1.12 is
# where `action: sniff`, the typed `dns.servers` entries and
# `default_domain_resolver` arrived, and where the older forms stopped working.
# The distributions ship 1.8 and 1.10, which is why this is checked and not
# assumed — an old binary rejects the config, and the panel reports the
# subscription as failing validation with nothing to say it is the tool.
SB_MIN_MAJOR=1
SB_MIN_MINOR=12
SB_LATEST="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
SB_DOWNLOAD="https://github.com/SagerNet/sing-box/releases/download"
SB_UNIT=/etc/systemd/system/sing-box.service
SB_BIN=/usr/local/bin/sing-box
SB_OWN=0                  # 1 once this script has put its own binary in place

sb_version() { sing-box version 2>/dev/null | awk '/^sing-box version/{print $3; exit}'; }

sb_recent() { # sb_recent -> 0 when the installed sing-box can read our config
  local v major minor
  v=$(sb_version) || return 1
  [ -n "$v" ] || return 1
  major=${v%%.*}; v=${v#*.}; minor=${v%%.*}
  case "$major$minor" in *[!0-9]*|"") return 1 ;; esac
  # Written as an if and not as `[ ] && return 0`: a false AND-list is a failed
  # statement, and under `set -e` that is an exit rather than a "no".
  if [ "$major" -gt "$SB_MIN_MAJOR" ]; then return 0; fi
  [ "$major" -eq "$SB_MIN_MAJOR" ] && [ "$minor" -ge "$SB_MIN_MINOR" ]
}

fetch() { # fetch url -> stdout; whichever of the two this host has
  if   command -v curl >/dev/null; then curl -fsSL --max-time 60 "$1"
  elif command -v wget >/dev/null; then wget -qO- --timeout=60 "$1"
  else return 1; fi
}

sb_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo amd64 ;;
    aarch64|arm64)  echo arm64 ;;
    armv7l|armv7|armhf) echo armv7 ;;
    i686|i386)      echo 386 ;;
    riscv64)        echo riscv64 ;;
    *)              return 1 ;;
  esac
}

sb_from_github() {
  local arch tag ver tmp url
  arch=$(sb_arch) || { ok "sing-box" "$M_SBNOARCH $(uname -m)"; return 1; }
  command -v curl >/dev/null || command -v wget >/dev/null \
    || { ok "sing-box" "$M_SBNODL"; return 1; }
  ok "sing-box" "$M_SBFETCH"
  tag=$(fetch "$SB_LATEST" 2>/dev/null \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1) || true
  # Only the tag comes off the network, and only if it looks like a tag: the
  # same rule the panel's update button follows, for the same reason.
  case "$tag" in
    v[0-9]*) ;;
    *) return 1 ;;
  esac
  case "$tag" in *[!v0-9.]*) return 1 ;; esac
  ver=${tag#v}
  url="$SB_DOWNLOAD/$tag/sing-box-$ver-linux-$arch.tar.gz"
  tmp=$(mktemp -d) || return 1
  if fetch "$url" > "$tmp/sb.tgz" 2>/dev/null \
     && tar -xzf "$tmp/sb.tgz" -C "$tmp" "sing-box-$ver-linux-$arch/sing-box" \
     && install -m 755 "$tmp/sing-box-$ver-linux-$arch/sing-box" "$SB_BIN"; then
    rm -rf "$tmp"
    hash -r 2>/dev/null || true
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

sb_unit() {
  if [ -f "$SB_UNIT" ] || [ -f /lib/systemd/system/sing-box.service ] \
     || [ -f /usr/lib/systemd/system/sing-box.service ]; then
    # A unit that came with a package points at /usr/bin/sing-box, and that is
    # the binary this script has just decided is too old. Overriding ExecStart
    # rather than the whole unit keeps everything else the packager set, and
    # without it the service would go on starting the version we replaced.
    if [ "$SB_OWN" = 1 ]; then
      install -d -m 755 /etc/systemd/system/sing-box.service.d
      cat > /etc/systemd/system/sing-box.service.d/10-gateway-acl.conf <<EOF
[Service]
ExecStart=
ExecStart=$SB_BIN -D /var/lib/sing-box -c /etc/sing-box/config.json run
EOF
      chmod 644 /etc/systemd/system/sing-box.service.d/10-gateway-acl.conf
      install -d -m 755 /etc/sing-box /var/lib/sing-box
      systemctl daemon-reload
      ok "sing-box.service" "$M_SBUNITOWN"
      return 0
    fi
    ok "sing-box.service" "$M_SBUNITKEPT"
    return 0
  fi
  install -d -m 755 /etc/sing-box /var/lib/sing-box
  # -c and not -C: -C loads every .json in the directory, and the panel keeps
  # exactly one config there. The path is the one panel.py writes and the one
  # `sing-box check` is run against, so what starts is what was checked.
  cat > "$SB_UNIT" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=$(command -v sing-box || echo "$SB_BIN") -D /var/lib/sing-box -c /etc/sing-box/config.json run
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
  # The whole step runs as `sb_unit || true`, which means `set -e` is off
  # inside it and a failed write would go by unnoticed while the line below
  # said the unit was there. Report what is actually on disk.
  if [ -s "$SB_UNIT" ]; then
    chmod 644 "$SB_UNIT"
    systemctl daemon-reload
    ok "sing-box.service" "$M_SBUNIT"
  else
    ok "sing-box.service" "$M_SBFAIL"
  fi
}

pkg_install() { # pkg_install pkg... -> quietly, and never fatal
  if   command -v pacman  >/dev/null; then pacman -S --needed --noconfirm "$@" >/dev/null 2>&1
  elif command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1
  else return 1; fi
}

step "$M_TOOLS"
say "$M_TOOLSHINT"
if yesno "$M_TOOLSASK"; then
  if sb_recent; then
    ok "sing-box" "$(sb_version)  $M_SBOK"
  else
    [ -z "$(sb_version)" ] || ok "sing-box" "$(sb_version)  $M_SBOLD"
    # The distributions are tried first and kept only if what they ship is new
    # enough; otherwise the published build for this architecture goes into
    # /usr/local/bin, which comes before /usr/bin on every sane PATH.
    pkg_install sing-box || true
    hash -r 2>/dev/null || true
    if ! sb_recent; then
      if sb_from_github; then SB_OWN=1; fi
    fi
    if sb_recent; then ok "sing-box" "$(sb_version)  $M_SBOK"
    else ok "sing-box" "$M_SBFAIL"; fi
  fi
  # The unit is written whatever happened above: without one, "enable the
  # subscription" in the panel is `systemctl restart sing-box` against nothing.
  sb_unit || true
  # Enabled only once there is something to start. A unit that fails at every
  # boot because no subscription has been added yet is a red service and a
  # question; the panel starts sing-box itself the moment one is enabled, and
  # its own startup reconciliation brings it back after a reboot.
  [ -f /etc/sing-box/config.json ] && systemctl enable sing-box >/dev/null 2>&1 || true

  command -v wg-quick >/dev/null || pkg_install wireguard-tools || true
  if command -v wg-quick >/dev/null; then ok "wireguard-tools" "$M_WGOK"
  else ok "wireguard-tools" "$M_WGFAIL"; fi

  # AmneziaWG is not in the distributions' own archives; where it is packaged
  # at all it is under these names. Best effort, and the message names the
  # package so somebody can go and get it.
  command -v awg-quick >/dev/null \
    || pkg_install amneziawg-tools amneziawg-dkms \
    || pkg_install amneziawg-tools || true
  if command -v awg-quick >/dev/null; then ok "amneziawg-tools" "$M_WGOK"
  else ok "amneziawg-tools" "$M_AWGFAIL amneziawg-tools"; fi
else
  ok "sing-box / wireguard" "$M_TOOLSSKIP"
fi

# --- settings ---------------------------------------------------------------

DEF_IFACE=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}' || true)
[ -n "${DEF_IFACE:-}" ] || DEF_IFACE=$(ip -o -4 addr show scope global | awk '{print $2; exit}')
# The configured interface wins over the detected one, but only while it exists:
# a card renamed between reboots must not turn an upgrade into a dead end.
OLD_IFACE=$(cfg iface)
[ -z "$OLD_IFACE" ] || [ ! -d "/sys/class/net/$OLD_IFACE" ] || DEF_IFACE="$OLD_IFACE"

step "$M_PARAMS"
IFACE=$(ask "$M_IFACE" "$DEF_IFACE")
[ -d "/sys/class/net/$IFACE" ] || die "$M_NOIFACE $IFACE"

CIDR=$(ip -o -4 addr show dev "$IFACE" | awk '{print $4; exit}')
[ -n "$CIDR" ] || die "$IFACE $M_NOIP"
DEF_LAN=$(python3 -c 'import ipaddress,sys;print(ipaddress.ip_interface(sys.argv[1]).network)' "$CIDR")

DEF_SELF=$(cfg self_ip); [ -n "$DEF_SELF" ] || DEF_SELF="${CIDR%/*}"
DEF_NET=$(cfg lan);       [ -n "$DEF_NET" ]  || DEF_NET="$DEF_LAN"
DEF_PORT=$(cfg port);     [ -n "$DEF_PORT" ] || DEF_PORT=8080

SELF_IP=$(ask "$M_ADDR" "$DEF_SELF")
LAN=$(ask "$M_NET" "$DEF_NET")
PORT=$(ask "$M_PORT" "$DEF_PORT")
python3 -c 'import ipaddress,sys;ipaddress.ip_address(sys.argv[1]);ipaddress.ip_network(sys.argv[2])' \
  "$SELF_IP" "$LAN" || die "$M_BADNET"

# --- password ---------------------------------------------------------------

step "$M_PW"
say "$M_PWSEEN"
say "$M_PWHTTP"
if [ "$PW_STDIN" = 1 ]; then
  IFS= read -r PW
  [ ${#PW} -ge 8 ] || die "$M_PWSHORT"
elif [ -f "$ETC/config.json" ] && python3 -c "import json,sys;sys.exit(0 if json.load(open('$ETC/config.json')).get('pw') else 1)" 2>/dev/null; then
  PW=""
  ok "$L_PW" "$M_PWKEPT"
else
  while :; do
    read -rsp "$M_PWNEW" PW </dev/tty; echo
    read -rsp "$M_PWAGAIN" PW2 </dev/tty; echo
    [ "$PW" = "$PW2" ] || { say "$M_PWMISMATCH"; continue; }
    [ ${#PW} -ge 8 ] || { say "$M_PWTOOSHORT"; continue; }
    break
  done
fi

# --- device list ------------------------------------------------------------

FRESH=0
[ -f "$ETC/devices.json" ] || FRESH=1
SEED="[]"
if [ "$FRESH" = 1 ]; then
  step "$M_WHO"
  say "$M_ONLYLIST"
  ROUTER=$(ip -o -4 route show default 2>/dev/null | awk '{print $3; exit}' || true)
  NEIGH=$(ip -4 neigh show dev "$IFACE" 2>/dev/null \
          | awk -v me="$SELF_IP" -v gw="${ROUTER:-}" \
                '$1 != me && $1 != gw && $2 == "lladdr" && $NF != "FAILED" {print $1"\t"$3}' || true)
  PICKED=""
  if [ -n "$NEIGH" ]; then
    say "$M_SEEN"
    while IFS="$(printf '\t')" read -r nip nmac; do
      [ -n "$nip" ] || continue
      if yesno "$(printf '%-15s %s' "$nip" "$nmac")"; then
        PICKED="$PICKED$nip
"
      fi
    done <<EOF
$NEIGH
EOF
  else
    say "$M_NOARP"
  fi
  SEED=$(printf '%s' "$PICKED" | python3 -c '
import json, sys
ips = [l.strip() for l in sys.stdin if l.strip()]
print(json.dumps([{"ip": i, "name": "", "on": True} for i in ips]))')
fi

# --- installation -----------------------------------------------------------

trap 'rollback' ERR

step "$M_INSTALL"
[ -f "$UNIT" ] && HAD_UNIT=1
install -d -m 755 "$ETC"
if [ -f "$ETC/panel.py" ]; then
  cp -a "$ETC/panel.py" "$ETC/panel.py.bak"
  ok "panel.py.bak" "$M_KEPTOLD"
fi
install -m 755 "$SRC/panel.py" "$ETC/panel.py"
TOUCHED=1
ok "panel.py" "ok"
install -m 755 "$SRC/singbox_sub.py" "$ETC/singbox_sub.py"
ok "singbox_sub.py" "ok"

python3 - "$ETC/config.json" "$IFACE" "$LAN" "$SELF_IP" "$PORT" "$UILANG" <<'PY'
import json, os, sys
path, iface, lan, self_ip, port, lang = sys.argv[1:7]
try:
    with open(path) as f: c = json.load(f)
except FileNotFoundError:
    c = {}
c.update(iface=iface, lan=lan, self_ip=self_ip, port=int(port), lang=lang)
c.setdefault("poll_sec", 60)
c.setdefault("pw", None)
c.setdefault("update_check", True)  # written out so it is visible and easy to flip
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f: json.dump(c, f, indent=1)
os.chmod(path, 0o600)  # O_CREAT does not change the mode of an existing file
PY
ok "config.json" "iface=$IFACE  lan=$LAN  port=$PORT  lang=$UILANG"

COUNT='import json,sys;print(len(json.load(open(sys.argv[1]))))'
if [ "$FRESH" = 1 ]; then
  printf '%s' "$SEED" > "$ETC/devices.json"
  ok "devices.json" "$M_DEVNEW $(python3 -c "$COUNT" "$ETC/devices.json")"
else
  ok "devices.json" "$M_DEVKEPT $(python3 -c "$COUNT" "$ETC/devices.json")"
fi

if [ -n "$PW" ]; then
  printf '%s\n' "$PW" | python3 "$ETC/panel.py" --set-password >/dev/null
  ok "$L_PW" "$M_PWWRITTEN"
fi
unset PW PW2 2>/dev/null || true

if ! python3 "$ETC/panel.py" --selftest >/dev/null \
    || ! python3 "$ETC/singbox_sub.py" --selftest >/dev/null; then
  die "$M_SELFTEST_FAIL"
fi
ok "selftest" "ok"
python3 "$ETC/panel.py" --dump | nft -c -f - || die "$M_RULEFAIL"
ok "ruleset" "ok"

install -m 644 "$SRC/gateway-acl.service" "$UNIT"
systemctl daemon-reload
systemctl enable gateway-acl >/dev/null 2>&1
# restart, not `enable --now`: on an already running service start is a no-op,
# and an upgrade would leave the previous code in memory.
systemctl restart gateway-acl
ok "systemd" "$M_UNITOK"

sleep 1
systemctl is-active --quiet gateway-acl || die "$M_NOSTART"
ok "gateway-acl" "$M_ACTIVE"
ss -H -tln "sport = :$PORT" | grep -q . || die "$M_NOPORT $PORT"
ok "$PORT" "$M_LISTEN"
nft list table inet gwacl >/dev/null || die "$M_NOTABLE"
ok "inet gwacl" "$M_INKERNEL"

trap - ERR
MASK=$(python3 -c 'import ipaddress,sys;print(ipaddress.ip_network(sys.argv[1]).netmask)' "$LAN")

# Подстановка по имени, а не формат printf: формат из переменной — это SC2059,
# и та же схема с {ip} уже используется в строках панели.
fill() { # fill "строка" ключ значение ключ значение ...
  local out="$1"; shift
  while [ $# -ge 2 ]; do out="${out//\{$1\}/$2}"; shift 2; done
  printf '%s\n' "$out"
}

echo
fill "$M_READY" ip "$SELF_IP" port "$PORT"
echo
printf '%s\n' "$M_CLIENT"
fill "$M_CLIENT2" ip "$SELF_IP" mask "$MASK"
echo
printf '%s sudo python3 %s/panel.py --set-password\n' "$M_CHPW" "$ETC"
printf '%s sudo ./install.sh\n' "$M_UPD"
printf '%s sudo ./install.sh --uninstall\n' "$M_DEL"
