# gateway-acl

A small web panel that decides **which devices on the network are allowed to
route through this Linux host** — and shows how much traffic each of them used.

It suits any Linux machine that other devices use as their gateway: a spare
desktop, a single-board computer, a virtual machine, a router running a normal
distribution. Whatever it forwards traffic into — a VPN tunnel or a plain
uplink — the problem that follows is the same: anyone who points at that
address gets a free ride. This is the allowlist.

Русская версия: [README.ru.md](README.ru.md).

```
device ──► this Linux host ──► uplink or tunnel (sing-box / WireGuard / any) ──► internet
                │
                └── gateway-acl decides who gets through
```

![The panel](docs/panel-en.png)

*Screenshot taken with made-up devices and traffic — none of it is real.*

## What it does

- **Allowlist by IP.** Not on the list, not routed. One nftables table, rebuilt
  atomically on every change.
- **Per-device traffic**, upload and download, accumulated per day and summed per
  month. A daily chart with the running total drawn over it, the last 24 hours,
  a bar per month, a sparkline in every row, and any single device on its own —
  click its address. All inline SVG, no external libraries.
- **Live speed.** The poll that accrues the counters also divides them by the
  window it covered, so each row says what that device is pulling right now.
- **The machine itself.** Processor, memory, swap, disk, load, temperature,
  uptime and the interface's throughput, read straight out of `/proc` and
  `/sys`.
- **Turn a device off** without deleting it — keeps its name and history.
- **...or off for a while.** Next to the switch, a menu: fifteen minutes, an
  hour, three, eight, or until seven in the morning. When the time is up the
  device goes back to the state it was in, by itself. It reads the other way
  round just as well — a device that is off can be let out for an hour.
- **...or past the VPN instead of off.** A second button sends one device around
  the tunnel: it keeps its internet, straight out through the gateway, while
  everything else stays inside. Its packets are stamped with an fwmark the
  tunnel treats as none of its business — `"vpn_mark"` in `config.json`, `8228`
  (`0x2024`) for sing-box, `51820` for a stock wg-quick, `0` to hide the button.
  Read that number off your own host — the neighbouring mark does the opposite.
  Marked by hardware address, so IPv4 and IPv6 leave together: half a device out
  of the tunnel is a device every site still places at the exit node. See
  [docs/singbox.md](docs/singbox.md).
- **Devices follow their hardware address.** DHCP hands a known device another
  address, and the entry moves there with its name, its switch and all of its
  traffic history — instead of quietly becoming a rule for nobody.
- **Let everyone in for a while.** One menu in the corner suspends the list
  itself for five minutes, fifteen or an hour — for guests, or for working out
  why something will not connect. The accounting carries on and the kernel goes
  on recording who came, so when the window shuts, everything that used it is
  listed below and one click from being allowed for good.
- **Turn everyone off at once**, except the address that pressed the button.
  The same button brings them back.
- **A warning when an address is answering as somebody else** — the entry is
  bound to one piece of hardware and a different one is on that address now, so
  the rule written for your tablet is currently the rule for whatever took its
  place.
- **Unknown devices.** The kernel records who it dropped into a timeout set; the
  panel lists them, with the hostname out of the DHCP leases, the hardware
  address out of the ARP cache and who made the thing — the system's IEEE list
  if it ships one, a short built-in table if not — says how long ago each one
  last knocked, and allows one in a click. The field for a new address offers
  everything the system knows about the network, so nothing has to be typed
  from memory.
- **Rename devices** inline, or take the name the device gives the network: it
  is offered at the end of the field while that is still empty. Renaming never
  touches nftables, so counters survive. Sort the table by any column — with the
  mouse or the keyboard — filter it by address, name or hostname, and download
  the selected month as CSV.
- **Update notice.** Once a day the panel asks GitHub for the latest release tag
  and shows a banner if yours is older. Off with one checkbox.
- **Settings in the corner.** Language, update notice, poll interval, LAN
  interface, network, gateway address, port and the password — all of
  `config.json` behind one form, validated before it is written. Next to the
  save button, a reboot for the gateway itself — it asks first.
- **A nightly reboot** on a switch — off by default, 05:30 when you turn it on.
- **Light and dark**, whichever the machine looking at it is set to. Kept on a
  phone's home screen it gets its own icon and paints the status bar to match.

Everything is Python standard library and inline SVG. No pip, no npm, no CDN —
the panel works with no internet at all.

## Requirements

- Linux with systemd and `nftables`
- Python 3.9+ (standard library only)
- The host already routes traffic somehow — a VPN tunnel, plain NAT, whatever.
  **gateway-acl decides who may use that route; it does not create one.**

## Install

```bash
git clone https://github.com/ChasoniCK/gateway-acl
cd gateway-acl
sudo ./install.sh
```

The first question is the language — Russian or English. It sets both the
installer's own output and the panel's interface, and is remembered in
`config.json`, so an upgrade never asks again. To skip the question:

```bash
sudo ./install.sh --lang en
```

The installer detects your LAN interface, address and subnet, offers to enable
`ip_forward`, asks for a panel password, and — on a first install — lists the
devices currently visible in the ARP table so you can allow them before the rule
takes effect. It refuses to enable anything until `panel.py --selftest` passes
and the kernel accepts the generated ruleset.

Re-running it upgrades the code in place; your device list and statistics are
left alone.

```bash
sudo ./install.sh --uninstall   # remove service and rules, keep data
sudo ./install.sh --purge       # also delete /etc/gateway-acl
```

## Client setup

On each device, set manually:

| | |
|---|---|
| Gateway | the address of this host |
| Netmask | your LAN mask (Android and Quest ask for prefix length instead) |
| DNS | a public resolver such as `1.1.1.1` |

Do not point clients at the gateway's own IP for DNS — see
[docs/singbox.md](docs/singbox.md) for why that quietly fails.

## Security, stated plainly

The panel is reachable from the whole LAN and protected by **one password**.

- Stored as scrypt with a random salt, never in plaintext. The installer reads it
  and pipes it straight into `panel.py --set-password`.
- Session cookie is `HttpOnly`, `SameSite=Strict`, seven days. Sessions are kept
  in `sessions.json` (mode 0600) as digests, so they survive a restart of the
  service — an upgrade no longer signs everyone out — while the file on its own
  opens nothing: what is in it cannot be presented as a cookie. Logging out
  really does revoke.
- Five wrong guesses from one address, and that address waits a minute.

**It is plain HTTP.** The password crosses the network unencrypted. On a small
network you control that is a reasonable trade; on one you do not, it is not.
Put it behind a TLS reverse proxy, or reach it through an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 you@gateway
```

Anyone who knows the password can change the allowlist. There are no roles and
no audit log — it is built for a network small enough that everyone with the
password is meant to have it.

**The panel reaches out exactly once a day** — a GET to
`api.github.com/repos/ChasoniCK/gateway-acl/releases/latest` for the latest
release tag. Nothing about you is sent, but the request itself is visible to
GitHub: your address and the time. The check is on by default; the switch is
under **Settings** in the corner of the panel, and takes effect at once. On a gateway
with no internet the request simply fails and the panel stays quiet.

## Settings

Everything in `config.json` is editable from the panel — language, the update
notice, the poll interval, the LAN interface, the network, the gateway address,
the panel port and the password. The form is validated as a whole before
anything is written: a network with host bits set, a gateway address outside its
own network, an interface that does not exist or a port already in use are
refused, and nothing is saved.

Language, the update notice, the poll interval and the password apply
immediately. A changed network rebuilds the nftables rules on the spot. Only a
changed port needs the process replaced — the panel does that itself and tells
you the new address.

## How it works

One nftables table, `inet gwacl`, on the `prerouting` hook at priority `raw`
(−300) — deliberately earlier than any redirect chains a tunnel might install.
Packets from an unlisted address are dropped unless they are addressed to the
host itself, so **SSH always stays reachable** even from a device you just
blocked.

Details, including how the traffic accounting survives counter resets and how to
test a ruleset without touching your host: [docs/design.md](docs/design.md).

## Limitations

- IPv4 only. IPv6 is passed through untouched.
- Traffic to the host itself (SSH, the panel) is counted too.
- A timer is as precise as the counter poll — a device set to come back at 07:00
  comes back at the first poll past it. Same for a device that DHCP has moved:
  the panel notices at the next poll, not the instant the lease changes, and it
  can only follow a device the ARP cache has an entry for.
- A device that moves to another address keeps its history but not its counters:
  the two named counters belong to the address, and the new ones start at zero.
- An open gateway is written to the config, so it survives a restart of the
  service — that is the point, but it also means closing the tab does not close
  the gateway. It shuts itself at the end of the window, six hours at the very
  most.
- Manufacturer names are a hint: the full IEEE list if this system ships one
  (`ieee-data`, wireshark), otherwise a short built-in table that knows the
  usual suspects and nothing else. Phones that randomise their address per
  network are named as exactly that, since there is no manufacturer in a made-up
  address.
- A device that is switched off still accrues a few kilobytes of its own retries.
- Sending a device past the VPN is a mark and nothing more. Whether the tunnel
  honours it belongs to the tunnel, which this program does not configure and
  cannot ask. A wrong `vpn_mark` does not fail loudly, and need not even fail in
  the harmless direction: sing-box's `0x2023` sits next to the one you want and
  forces the device *into* the tunnel instead. Check it
  once from the device, and check **both** protocols: `curl -4 https://api.ipify.org`
  and `curl -6 https://api6.ipify.org` should both be your own address, or
  IPv6 should not answer at all. A network with no IPv6 outside the tunnel
  loses IPv6 for that device rather than routing it around — v4 carries it.
- Traffic history is kept per address and outlives the device. Bytes of deleted
  ones stay in the month's totals — the panel shows them as a separate "other"
  share, because there is nobody left to attribute them to.
- Counters accrue in memory and reach `today.json` at most once every five
  minutes; the days already closed sit in `traffic.json`, which is rewritten
  only when a day ends. Recording the day in progress therefore costs about a
  kilobyte, not the whole history — under half a megabyte a day on the flash of
  a machine that is never turned off. A clean stop loses nothing, and neither
  does a crash — the baseline on disk is exactly as old as the totals beside it,
  so the next poll measures the difference from there. Only a sudden reboot
  costs up to five minutes of accounting, because that is when the kernel's
  counters go too.
- The day-by-day chart covers the last three months, `keep days by day` in the
  settings, 1 to 24. Anything older is folded into one figure per month: the
  monthly totals and the strip below the chart stay exact to the byte, but the
  daily breakdown of an old month is gone. Lowering the number folds what is
  over the line as soon as the form is saved.

## License

MIT — see [LICENSE](LICENSE).
