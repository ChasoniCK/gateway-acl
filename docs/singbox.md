# Using this with sing-box

gateway-acl does not configure, install or read your sing-box config. It only
decides who is allowed to use the route sing-box provides. This page records the
things that actually bite when the two run on the same host — learned from a
working setup, not from documentation.

No credentials, server addresses or subscription links belong in this repository,
and none are here. The installer can be *given* a link — see below — and keeps it
in `/etc/gateway-acl/sub.url`, mode 0600, on your host and nowhere else.

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

## A connection that opens quietly loses its domain

A routing rule that matches on domain needs one, and for a forwarded connection the
domain comes from sniffing the TLS ClientHello. The sniffer gives up after **300 ms**.
A client that opens the socket ahead of time and says nothing therefore gets routed
with no domain at all — only the address is left to match on, and a domain list, however
correct, is inert for that connection.

The same destination, twice, one second apart:

```
[3950739284   0ms] inbound connection to 185.206.27.17:443
[3950739284 301ms] outbound/direct[direct]:  185.206.27.17:443   ← socket held silent
[1585253673   0ms] inbound connection to 185.206.27.17:443
[1585253673   0ms] outbound/vless[node]:     185.206.27.17:443   ← ClientHello at once
```

The duration on the `outbound` line is the tell: a little over 300 ms means the sniffer
timed out, not that the route was slow.

This is not exotic. Any client that keeps a pool of pre-opened connections behaves this
way — MEGA raises about ten sockets to its storage nodes before it has even resolved
them, so a download runs outside the tunnel while the API, opened on demand, runs inside
it. The service then sees one session arriving from two different addresses and stalls.

Route such a service by address. Raising the global sniff timeout also works and is one
line, but every silent connection on the host pays it, SSH included.

## A direct outbound with no interface loops UDP against the tun

Symptom: sing-box at 300–400 % CPU on an idle gateway, no warning in the journal, and
traffic that works normally the whole time. Nothing about it is visible from the outside
— none of that load reaches the wire.

```
tun0  tx  355 000 pkt/s   22 MB/s     ← the kernel handing them to sing-box
eno1  tx       39 pkt/s   14 kB/s     ← nothing leaves the host
Udp:OutDatagrams  335 471/s           ← all of it generated locally, 66 B per packet
```

A UDP session routed to a `direct` outbound gets an unbound socket. Its packets match
the tun's own route table (`0.0.0.0/5 … 224.0.0.0/3 via tun0 table 2022`), so they go
back into `tun0`, where sing-box reads them and hands them to the same session again.
No new connection is ever opened, so nothing is logged; the loop is silent. The
aggregate settles at whatever a single tun reader can manage and stays there until the
process is restarted.

Two commands separate this from real traffic:

```bash
grep -c . /proc/net/udp        # ≈ one socket per live direct UDP session
awk '/tun0|eno1/' /proc/net/dev
```

A tun transmitting hundreds of thousands of packets a second while the uplink is idle
is the whole diagnosis. To confirm which outbound is at fault, send one datagram to an
address that routes `direct` and watch the socket count: it goes up by one and stays.
The same test against a proxied address adds no socket at all — UDP through `vless`
never touches a local socket, which is why only `direct` loops.

The fix is to bind the direct outbound to the uplink, so its packets leave by the
interface instead of by the route table:

```json
{ "type": "direct", "tag": "direct", "bind_interface": "eno1" }
```

`"route": { "auto_detect_interface": true }` does the same without naming the
interface and survives a move to another uplink. Upstream report, closed as stale:
[#4086](https://github.com/SagerNet/sing-box/issues/4086).

## Measurement traps

Each of these produced a confidently wrong conclusion at some point:

- **`curl` proves nothing about an application's connections.** It sends the ClientHello
  immediately, so it is always sniffed and always routed by domain. The application next
  to it may be taking the opposite route for the same host.

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

## Sending one device past the tunnel

A device can be let through the gateway without being let into the VPN — the
`no VPN` button on its row. gateway-acl stamps its packets with an fwmark in
`prerouting` and stops there; everything after that is sing-box's own doing.

`auto_route` installs a policy rule that sends everything to the tun's table and
one exception above it for the mark it uses for its own packets — without that
exception the tunnel's output would be routed back into the tunnel. The same
mark makes its `prerouting` chain return instead of queueing. So a packet
carrying it is routed by `main` and leaves by the uplink, and the router NATs it
like traffic from any other machine on the LAN.

### There are three marks, and two of them are not the one you want

This cost a release to learn. sing-box uses a small block of adjacent numbers,
and the neighbour of the one you want does the exact opposite:

| mark | `ip rule` | in the chain | means |
|---|---|---|---|
| `0x2023` | `fwmark 0x2023 lookup 2022` | — | **into** the tun |
| `0x2024` | `fwmark 0x2024 goto` → `nop` → `main` | `meta mark 0x2024 … return` | **past** the tun |
| `0x2025` | — | `reject with tcp reset` | refused |

`0x2023` is `AutoRedirectInputMark`, `0x2024` is `AutoRedirectOutputMark` — the
one sing-box puts on its own output. Setting `0x2023` as `vpn_mark` does not
fail loudly: the device is forced *into* the tunnel, past whatever routing rules
would have sent some of its traffic direct, and the panel goes on saying it is
out. The symptom is a device that looks more tunnelled than before.

**So read the mark off the host rather than trusting a number in a document**,
this one included — the block has moved between versions:

```bash
ip rule
```

```bash
nft list table inet sing-box | grep -i 'meta mark'
```

Look for the rule that leads to `main` (wg-quick writes it inverted — `not
fwmark 51820 lookup 51820` — which comes to the same thing), *not* for the one
naming the tun's own table. Put that number in `config.json` as `"vpn_mark"` —
JSON has no hex, so `0x2024` is written `8228`. `0` removes the button.

Verify from the device itself, not from the gateway — the panel cannot tell
whether the tunnel honoured the mark, only that it set one. **Both protocols,
separately**, and this is not a formality: a browser on a dual-stack network
prefers IPv6, so a v6 leak is what every site will report, whatever v4 does.

```bash
curl -4 -s https://api.ipify.org; curl -6 -s https://api6.ipify.org
```

The gateway marks by hardware address exactly so that one rule covers both. If
`-6` still answers with the exit node while `-4` is your own address, the mark
is not reaching the v6 packets — check that the rule sits above
`meta nfproto != ipv4 accept` in `nft list table inet gwacl`, and that
`ip -6 rule` has the same fwmark exception as `ip rule` does.

Note what this does **not** do: sniffing, DNS hijacking and routing rules inside
sing-box are untouched. A device sent past the tunnel resolves and connects on
its own, so a domain rule-set that was doing the deciding for it no longer
applies to anything it does.

## The subscription the installer asks for

`install.sh` asks for a subscription link, and `singbox_sub.py` turns it into
outbounds. This is the installer's doing, not the panel's: `panel.py` neither
imports that file nor reads a sing-box config, and the link never reaches the
panel or any page it serves.

The tool owns exactly two things in an existing config: outbounds whose tag
starts with `sub-`, and the member list of the `proxy` group. Everything else —
`route`, `dns`, `inbounds`, `experimental`, and any outbound you wrote yourself —
is copied through unchanged, which is the only reason a config tuned by hand over
months can survive a subscription refresh. Hand-written outbounds are dropped
from the group but never deleted from the file: a route rule may still name one,
and sing-box would refuse to start if it disappeared.

The prefix is the whole basis of that ownership. Rename a `sub-` outbound and the
next refresh will treat it as yours and leave it alone; that is the supported way
to keep a node the subscription has stopped listing.

### A urltest group always picks the node nearest home

The group is a `urltest`: it fetches `generate_204` through every member and
keeps the quickest. That is the right rule for choosing between two foreign
nodes and exactly the wrong one the moment the subscription contains a node in
your own country — it is nearest, so it wins every election, and the tunnel
exits where it started. The journal names the winner on every connection, which
is the fastest way to see it:

```
outbound/vless[sub-RU node]: outbound connection to 160.79.104.10:443
```

Nothing in the config can tell where a node is; only the name the provider gave
it can. So the installer asks for a regular expression, keeps it in
`/etc/gateway-acl/sub.exclude`, and `singbox_sub.py --exclude` leaves the
matching nodes out of the file altogether — not merely out of the group, since
an outbound nothing points at is one a hand-written rule can still fall onto.

Two symptoms of a domestic exit, both easy to misread as something else: sites
report the home country while the tunnel is plainly up, and everything blocked
from there stays blocked. A site being *slow* is a node problem; a site being
*geographically wrong* is this.

The expression is worth reading the node list for first. A provider names a node
by where it is **entered**, not by where it leaves: `Россия (Reality)` exits in
Russia, while `Россия через Финляндию` enters in Russia and exits in Finland.
The second kind exists precisely because the direct foreign addresses are what
the ISP blocks, so it is frequently the only kind that connects at all — an
expression matching plain `Росс` takes both and leaves a group whose every
member times out:

```
ERROR outbound/urltest[proxy]: dial tcp 144.31.232.142:443: i/o timeout
```

That line is the tell, and it is one sing-box only ever writes about its own
dial to a node's server — the tunnel reaching outwards, not a client reaching
through it.

Testing this from the gateway is harder than it looks: `auto_route` catches the
host's own traffic too, so `curl` to a node's address is answered by the tunnel
in a fraction of a millisecond and proves nothing about the wire. `--interface`
does not save you either — `auto_redirect`'s nft rules run before the routing
decision. The journal is the only honest witness.

Do not use a public IP-echo to check where you come out, either: in a config
with split routing it is very likely to be a `direct` destination, and it then
reports the home address no matter how well the tunnel works.

```
INFO outbound/direct[direct]: outbound connection to 34.117.59.81:443   ← ipinfo.io, not proxied
```

### xhttp is not implemented

```
FATAL decode config: outbounds[1].transport: unknown transport type: xhttp
```

xhttp is Xray's transport and sing-box does not have it — not in 1.13, and not in
the 1.14 betas either: `constant/v2ray.go` lists five transports (`http`, `ws`,
`quic`, `grpc`, `httpupgrade`) and nothing else, and the two pull requests that
added XHTTP were both closed without being merged. Upgrading sing-box is
therefore not the way to get those nodes. Subscriptions that
offer it usually offer the same servers over Reality or Shadowsocks as well, so
the tool reports each skipped node by protocol and host and converts the rest. It
never writes a node this sing-box would refuse to load — a config that will not
parse is a gateway that does not come up.

### What a 1.13 refuses to start on

Each of these was found by running `sing-box check` against a generated config,
one FATAL at a time, and each is asserted in `singbox_sub.py --selftest` so the
template cannot quietly regress to the older shape:

- The pre-1.12 DNS format (`{"address": "https://1.1.1.1/dns-query"}`) —
  *legacy DNS servers is deprecated ... set ENABLE_DEPRECATED_LEGACY_DNS_SERVERS*.
  The shape that works is `{"type": "https", "server": "1.1.1.1"}`.
- No `route.default_domain_resolver` — *missing `route.default_domain_resolver`
  or `domain_resolver` in dial fields*. It names the server that resolves an
  outbound's domain when a connection is dialled.
- `sniff` as an inbound field. Since 1.12 it is a route action, and it is the
  first rule: `{"action": "sniff", "timeout": "300ms"}`. The timeout is not
  decoration — see "A connection that opens quietly loses its domain" above.

A generated fresh config is otherwise the shape at the top of this page: `tun`
with `auto_route`, `auto_redirect` and `strict_route`, DNS hijacked into the
tunnel, `ip_is_private` sent out `direct`, and `direct` bound to the interface
the installer was given — the `bind_interface` whose absence loops UDP against
the tun.

## Where gateway-acl fits

It does not care which tunnel you use. sing-box, WireGuard, plain NAT — as long
as the host forwards traffic, the allowlist works the same way, because it acts
before any of them.
