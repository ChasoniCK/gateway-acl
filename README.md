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
  month. Daily chart, month picker, no external libraries.
- **Turn a device off** without deleting it — keeps its name and history.
- **Unknown devices.** The kernel records who it dropped into a timeout set;
  the panel lists them with a one-click "allow".
- **Rename devices** inline. Renaming never touches nftables, so counters survive.

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
- Session cookie is `HttpOnly`, `SameSite=Strict`, seven days. Sessions live in
  memory, so a restart logs everyone out.
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
- A device that is switched off still accrues a few kilobytes of its own retries.
- Sessions do not survive a restart of the service.

## License

MIT — see [LICENSE](LICENSE).
