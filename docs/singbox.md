# Using this with sing-box

gateway-acl does not configure, install or read your sing-box config. It only
decides who is allowed to use the route sing-box provides. This page records the
things that actually bite when the two run on the same host — learned from a
working setup, not from documentation.

No credentials, server addresses or subscription links belong in this repository,
and none are here.

## The shape of the setup

A Linux host on the LAN runs sing-box with a `tun` inbound and
`auto_route` / `auto_redirect` / `strict_route` enabled. Other devices set that
host as their default gateway by hand; the router is not touched at all.
`net.ipv4.ip_forward` is 1.

```
router ──┬── gateway host (sing-box + gateway-acl)
         ├── phone      → gateway = this host
         ├── desktop    → gateway = this host
         └── everything else → straight through the router
```

The cost of this shape is worth stating: when the gateway host is off, the
switched devices have **no internet at all**, not merely no VPN.

## auto_redirect does intercept transit traffic

It is easy to assume the tunnel only captures traffic originating on the host.
It does not — with `auto_redirect`, TCP, UDP and DNS hijacking all apply to
forwarded traffic from other machines. The journal shows the full chain for one
session, correlated by the id in brackets:

```
[1673014949] inbound/tun[tun-in]: inbound redirect connection from 192.168.1.50:61843
[1673014949] inbound/tun[tun-in]: inbound connection to 17.188.180.147:443
[1673014949] outbound/vless[node]: outbound connection to 17.188.180.147:443
```

`inbound redirect connection` is TCP from a LAN client, `inbound packet
connection` is UDP.

The practical consequence for gateway-acl: because the redirect happens in
`prerouting`, an ACL in the `forward` chain would see almost nothing. Hence
priority `raw`, which runs first. See [design.md](design.md).

## Do not give clients the gateway's own IP as DNS

Point clients at a public resolver (`1.1.1.1`). Two separate reasons:

- sing-box on Linux does not intercept DNS addressed to the host's own
  interfaces, so it bypasses `hijack-dns`.
- DNS aimed at the router never passes through the gateway at all.

On Windows, leave DNS-over-HTTPS **off** — otherwise the query leaves as ordinary
TCP to `1.1.1.1:443` and misses the hijack entirely.

## TUN address ranges

If you exclude private ranges from the tunnel via `route_exclude_address`, do not
include the range the TUN interface itself lives in. A TUN at `172.19.0.1/30`
falls inside `172.16.0.0/12`, and excluding that breaks the tunnel.

## Matching happens by IP, not only by name

Checking whether a domain is covered by a rule-set is not enough — look at where
it resolves. Domains can be absent from every list while their addresses are
covered, so traffic is tunnelled anyway. Verify with the address, not the name:

```bash
sing-box rule-set match -f binary ruleset.srs 93.184.216.34
```

The `-f binary` flag is required for compiled `.srs` files; without it the
command fails with `invalid character 'S'`.

## Measurement traps

Each of these produced a confidently wrong conclusion at some point:

- **`connect()` through a TUN always succeeds in a few milliseconds**, even when
  the upstream is unreachable — the local handshake completes immediately.
  Measure with real transfer: `curl --max-time`.
- **`/tmp` is cleared on reboot.** A check that greps the output of a command
  reading a vanished file sees "no match" and reports "everything goes direct".
  Always assert the input exists, and keep one control case with a known result.
- **`journalctl -f` redirected to a file in the background does not flush** and
  yields zero lines. Record a timestamp, run the test, then use
  `journalctl --since`.
- **Measurement window boundaries.** `--since "-5min"` can reach back past a
  service restart. Use
  `systemctl show sing-box -p ActiveEnterTimestamp --value`.

## Where gateway-acl fits

It does not care which tunnel you use. sing-box, WireGuard, plain NAT — as long
as the host forwards traffic, the allowlist works the same way, because it acts
before any of them.
