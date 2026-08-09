# Design notes

Why the thing is built the way it is, and how to poke at it without breaking
your own network.

## One table, rebuilt whole

Everything lives in a single nftables table, `inet gwacl`. Nothing else on the
system is touched — no shared chains, no edits to someone else's ruleset, no
`iptables` compatibility layer.

Every change regenerates that table from `devices.json` and feeds it to
`nft -f -` as one transaction, prefixed with the standard idiom:

```
table inet gwacl
delete table inet gwacl
table inet gwacl { ... }
```

The bare `table` line creates it if absent, so `delete` never fails on a first
run. Because `nft -f` is atomic, a ruleset that does not parse changes nothing —
the old rules stay live. That is the whole rollback story.

## The chain

```
chain prerouting {
  type filter hook prerouting priority raw; policy accept;
  iifname != "eth0" accept
  meta nfproto != ipv4 accept
  ip saddr 192.168.1.51 counter name up_192_168_1_51    # one per device
  ...
  ip saddr @allowed accept
  fib daddr type != unicast accept
  update @blocked { ip saddr }
  drop
}
```

**`priority raw` (−300).** Earlier than conntrack (−200), earlier than dstnat
(−100), earlier than filter (0). This matters when a tunnel is in play: sing-box
with `auto_redirect` installs its own prerouting chains that pull transit traffic
into a TUN device, at which point the packet is locally destined and never
reaches `forward`. A rule in the `forward` chain would therefore see almost
nothing. Running before the redirect avoids the whole question.

**`fib daddr type != unicast accept`** is the escape hatch. It accepts anything
addressed to the host itself (`local`), plus broadcast and multicast. Two
consequences worth knowing:

- SSH to the gateway keeps working from a device you just blocked. You cannot
  lock yourself out of the machine with this tool.
- The panel is reachable from the entire LAN. That is intentional here — access
  is gated by a password, not by the firewall. An earlier revision dropped
  `tcp dport 8080` for non-allowlisted sources instead; that works too, but it
  means whoever holds a DHCP lease that changed cannot reach the panel to fix it.

**Verdicts are not final across tables.** `accept` in our chain lets the packet
continue to other tables and later hooks; only `drop` ends it. So accepting here
does not bypass the tunnel's own chains.

## Traffic accounting

Two named counters per device, `up_<ip>` and `down_<ip>` with dots replaced by
underscores. Upload is counted in `prerouting` (packets arriving from the LAN
interface), download in `postrouting` (packets leaving towards it). Replies from
a proxy come back through `forward` and out the LAN interface with the client's
real address as destination, so no NAT rewriting confuses the count.

Counting happens **before** the accept/drop verdict. That is a deliberate
simplification: a device you switched off keeps accruing the few kilobytes of its
own doomed retries, which is arguably useful — you can see it knocking.

### Surviving resets

Kernel counters reset whenever the table is rebuilt, and on reboot. So the panel
polls them every 60 seconds and accumulates deltas bucketed by day, into
`today.json` while the day is running and `traffic.json` once it has closed:

```python
def accrue(prev, cur):
    return cur if cur < prev else cur - prev
```

A counter that went *down* means it was reset, so the current value is the whole
delta. `apply()` calls `poll()` **before** running `nft -f`, so a rebuild loses
nothing rather than losing everything since the last tick. A reboot loses at most
`poll_sec` seconds of traffic.

Monthly totals are the sum of every day key starting with `YYYY-MM`. Day keys are
ten characters; anything shorter is a leftover from an older month-keyed format
and is still summed, just not charted.

### Two files, because only one of them changes

Recording the last five minutes used to mean rewriting the entire history: one
file held today's bucket, the baseline and every month behind them, and `flush()`
wrote the lot. On ten devices with three months of days that is a 57 KB file
rewritten every 30 seconds — **161 MB a day** onto the flash of a machine that is
never turned off, and near a gigabyte on a busy network.

Almost none of it can change. A closed day is closed. So the split is by write
frequency, not by subject:

| file | holds | written |
|---|---|---|
| `today.json` | the day in progress, `seen`, the counter baseline | every `FLUSH_EVERY` |
| `traffic.json` | days already closed, and folded months | when a day closes |

About a kilobyte per write instead of fifty-odd, and the same ten devices now
cost **under half a megabyte a day**. In memory the two are one dict — only
`_read_history` and `flush` know there are two files, so `month_totals`, the
charts and `snapshot` were not touched.

The day in progress lives in exactly one of them. `traffic.json` keeps a copy of
it only in the gap between an upgrade from a single-file version and the next
midnight, and `_read_history` resolves that by letting `today.json` win.

Both are written to `path.tmp` and renamed, with an `fsync` in between: `open(path,
"w")` truncates before it writes, and a power cut inside that window used to leave
half a file — which is not json, and took the panel down on every start after,
`Restart=always` looping it into the same crash. A file damaged by a version that
wrote it the old way is now reported to the journal and skipped, not fatal.

### Retention

Even split, the closed days grow without end: a key per day per device is a file
every start has to read, for the rest of the gateway's life.

So `roll_up` folds the day buckets of months older than `keep_months` (default 3,
1–24 in the settings) into a single `"YYYY-MM"` key. That shape is one the
program already reads:
`month_totals` counts it, and the per-day chart skips it on key length
(`len(k) == 10`). The monthly totals and the strip below the chart therefore
stay exact to the byte — what is given up is the day-by-day chart of an old
month, and the page says so rather than claiming there is no data.

The fold runs at the rollover, not on every poll: a month can only age past the
line when the day changes, so checking 120 keys four times a minute bought
nothing. Saving the settings form is the one exception (`refold`) — somebody who
just lowered the number did it for the space, and would read "tomorrow" as
broken.

### Renames are free

Device names exist only in `devices.json` — they never appear in the ruleset. The
panel exploits this directly:

```python
before = ruleset(devs)
...mutate...
if ruleset(devs) != before:
    apply(devs)
```

Comparing generated text is exact and needs no reasoning about which fields
matter. Renaming produces identical text, so nftables is never touched and the
counters keep running. A timer that is set or dropped without changing the
switch is free for exactly the same reason.

### Timers, and one field for both directions

A device may carry `until`: the moment the state it stands in now runs out.
Which way it flips then is not stored, because it cannot be anything else — a
timer always undoes whatever set it. "Off until seven" and "on for an hour" are
therefore the same field, the same validation and the same line in `expire()`,
which the poller calls on every tick. Precision is `poll_sec`, like the nightly
reboot: a thread that already wakes on a schedule is the whole mechanism, and a
second one would not be worth its own bugs.

The browser sends **minutes**, never a moment. It is the side that knows what
"until 07:00" means in the timezone the person is standing in; the gateway is
the side that knows what time it is. A clock skew on either would otherwise turn
into a device let out for a day.

### Following a device that DHCP moved

Everything hangs off the address: the rule, the two counters, the day buckets.
A new lease therefore turns an entry into a rule for nobody — the device is
silently outside the gateway, or silently through it, and the panel goes on
reporting the old address as quiet. `track_macs()` runs on the poller's tick,
takes the hardware address out of the ARP cache the panel already reads for
names, and moves the entry to wherever that address answers from now. A device
first seen records its MAC; two entries never land on one address.

`rekey()` carries the history across — day buckets, hour buckets, `seen` —
because leaving it behind would file the device's past under "other" and start
its month from zero, which is the pair of symptoms that reads as lost data. The
baseline is dropped rather than moved: the new address gets new counters and
they start at zero.

## Sessions

Tokens live in `sessions.json` (0600) as SHA-256 digests, so the file grants
nothing if it leaks — what is on disk cannot be presented as a cookie. They are
loaded at startup and expired entries are dropped on the way in.

They are on disk at all because updating means `install.sh`, which restarts the
service: being logged out by one's own upgrade is where it stings most. A write
happens only on sign-in and sign-out, and a failed write is not an error —
a read-only `/etc` simply puts the session back to living in memory only.

## Unknown devices

```
set blocked {
  type ipv4_addr
  flags dynamic,timeout
  timeout 21600s
}
```

`update @blocked { ip saddr }` sits immediately before the final `drop`, so the
kernel itself records every source it refused, and forgets them six hours later.
The panel subtracts known devices and shows the rest.

The kernel re-arms the timeout on every packet it drops, so what is left of it
is how long ago that address last knocked — `BLOCK_TTL` minus the `expires` nft
reports for the element. That is the difference between something hammering the
gateway right now and something that gave up hours ago, and it costs nothing:
the number is already in the answer the panel parses — the same one the counters
come in, since `poll()` lists the whole table in one call. `parse_blocked()`
therefore picks the set out **by name**: `allowed` is in that answer too, and its
elements are bare addresses that would otherwise read as a list of intruders.

This is strictly better than scanning ARP for this purpose: it lists exactly the
devices that tried to route through the host and were refused, rather than
everything that happens to be on the wire.

## Rates, and the hour

`apply_deltas` returns what moved, so the same poll that fills the day bucket
also feeds a rate. The awkward part is the window: `poll()` runs both on the
poller's tick and on every page refresh, so the gap between two calls is
anything from a second to a minute, and dividing by a one-second gap invents
spikes.

```python
def rates(moved, devs, now):
    for ip, (u, d) in moved.items():
        p = _pend.setdefault(ip, [0, 0]); p[0] += u; p[1] += d
    dt = now - _rate_at
    if dt < POLL_MIN:
        return
```

Increments are therefore held in `_pend` until the window is at least two
seconds wide. Holding rather than discarding matters: the bytes have already
gone into the day's total, and dropping them from the rate would make a busy
device look idle whenever two browsers happened to refresh together. A device
that sent nothing is written as zero rather than left at its last value, or a
machine that went quiet would keep claiming throughput forever.

`POLL_MIN` is also what `poll()` itself refuses to run inside. Below that window
there is no new rate to compute, so a second poll a second after the first would
spend an `nft` call to learn nothing — and with three tabs open, each refreshing
twelve times a minute, most of the calls are exactly that. `apply()` forces its
way through regardless: that call exists to read the counters before the rebuild
zeroes them, and skipping it would throw away whatever they hold.

### What a refresh costs

The page reloads itself every five seconds, because the "now" column is a rate
measured over exactly that window — the interval is how alive the panel is
allowed to look. Three things keep the price of that down, and they were put
there in this order after measuring:

- The counters are behind `POLL_MIN`, so several tabs collapse into one `nft`.
- That one `nft` reads the whole table — `nft -j list table inet gwacl` — and the
  blocked set comes back with it. The set used to be a call of its own, once per
  request with no window in front of it, and it was the busiest call the panel
  made; now `note_blocked()` keeps whatever the poll saw and `blocked()` spawns
  nothing at all.
- The whole answer is cached for `STATE_CACHE`. Below `POLL_MIN` on purpose, so
  it only collapses the work the poll window was already declining to redo: the
  copy of the history, the ARP table, the lease file, the walk through `/proc`.
  A phone and a laptop left open on the same page stop costing twice.
- The device list is re-read only when `devices.json` changes (`st_mtime_ns`),
  and `sysinfo()` holds its whole answer for two seconds — the same window its
  two rates already needed.
- Nothing is written unless something in it changed. A poll where no device
  moved a byte leaves the day, `seen` and the baseline exactly as they were
  read, and rewriting a file identically is the whole cost of that poll.
- What did change waits in memory. `flush()` writes at most every
  `FLUSH_EVERY`, so the interval the page refreshes at and the rate the file is
  rewritten at are no longer the same number.
- What is written is only the day in progress. The months behind it are a
  separate file that a poll cannot touch.

Measured on ten devices with three months of history, one tab refreshing every
five seconds, per minute: fourteen `nft` calls, and **one** write of about a
kilobyte every five minutes with traffic flowing, none with the network asleep.
Under **0.5 MB a day**, against the 535 MB writing the whole history on every
poll would have cost — and against 161 MB for the same history at the
thirty-second `FLUSH_EVERY` this replaced.

### What the buffer risks

Less than it looks. What is buffered is one object: today's bucket and `last`,
the baseline every increment is measured from. They go into `today.json`
together, so the copy on disk is always self-consistent — merely old.

- A **clean stop** loses nothing: systemd sends SIGTERM, the handler flushes.
  That covers every update, since `install.sh` restarts the service.
- A **crash or a kill** loses nothing either, which is the part worth stating
  plainly: the baseline on disk is exactly as old as the totals beside it, so
  the next poll measures the increment from that older baseline and arrives at
  the same figure. The kernel's counters kept running through all of it.
- A **reboot or a power cut** costs up to `FLUSH_EVERY` seconds, because that is
  the one case where the kernel's counters are lost at the same moment.

`apply()` is the exception that forces a write: it samples the counters
precisely because the rebuild is about to zero them, and a baseline older than
that sampling would read the drop as a reset and lose what stood between.

The hourly chart is the same deltas in a second bucket, `_hours`, twenty-four
keys wide and **in memory only**. Storing it would multiply `today.json` — the
file written on the clock — by twenty-four for a view whose whole point is the
last day, and the month is already
on disk. The cost is that a restart of the service starts the day over, which
the panel says out loud rather than drawing a chart that is quietly missing its
left half.

## The machine

`sysinfo()` reads `/proc/stat`, `/proc/meminfo`, `/proc/uptime`,
`/sys/class/net/<iface>/statistics/` and `/sys/class/thermal/`, plus
`os.statvfs` and `os.getloadavg`. Everything is optional: a file that is not
there yields `None` and the panel leaves that row out instead of refusing to
draw. That is what makes `--selftest` pass on a machine without procfs at all.

Two of the numbers — processor share and interface throughput — are rates and
need two readings, so the first call after a start reports zero. They are kept
under their own lock, apart from the traffic counters: a kernel that stops
answering questions about itself must not stop the accounting.

Idle counts `iowait` as well. A gateway waiting on its disk is not busy, and
calling it busy would light the meter for no reason.

Temperature is the **warmest** of the kernel's thermal zones, and which zone
that is depends entirely on the machine — `x86_pkg_temp` or `coretemp` on a
typical x86 box, `cpu-thermal` on a Pi, sometimes `acpitz`, `nvme` or a wifi
chip. A bare number would therefore mean something different on every host, so
`temp_c` returns the zone's `type` alongside it and the panel puts it behind
the `?` next to the row. Zones with no `type` file are named after their
directory.

## Names for the unknown

The blocked list is a column of bare addresses, which does not answer *whose
box is knocking*. Two files the system already keeps do: the kernel's ARP cache
at `/proc/net/arp` for hardware addresses, and dnsmasq's lease file for
hostnames, when dnsmasq happens to run on this gateway. Both are a courtesy —
absent files simply mean the list looks the way it always did. A lease name
never reaches the page through an `onclick`; it goes through a `data-`
attribute, because this program does not own that file.

A third answer is the first three bytes of the hardware address, which say who
made the thing. The IEEE list is what answers it, and a distribution that ships
one puts it at a handful of known paths (`ieee-data`, wireshark's `manuf`); a
gateway installed from a minimal image has none of them, hence the short
built-in table of what actually turns up on a home network. One pass answers
every prefix on the page at once and the answers are kept, empty ones included,
so the file is opened again only when something with an unseen prefix turns up.
Nothing is printed when nothing knows: a wrong manufacturer is worse than none.

An address with the locally-administered bit set was made up by the device
rather than assigned to its maker, which is what a modern phone does per
network. Saying so is more useful than the blank a lookup would leave.

## When the entry and the wire disagree

`track_macs()` follows a device that moved. What is left over is the other
case: the entry stays where it is and something *else* answers on its address.
Then the rule written for the tablet is the rule for whoever took its place —
the one failure of an allowlist that looks like nothing at all from the panel,
because the address in the table is exactly the address that was allowed.
`clashes()` compares the hardware address the entry is bound to against the one
ARP reports there now, and the page says so in a card of its own. It cannot be
fixed automatically: which of the two is supposed to have the address is not a
question this program can answer.

## Letting everyone in for a while

Guests, or a device that will not connect and has to be watched connecting.
`CFG["bypass"]` is the moment the gateway stops being open, and while it is in
the future `ruleset()` leaves out one line — the final `drop`. Everything else
stays: the counters still run, and `update @blocked { ip saddr }` still records
every address that came in past the list, so when the window shuts, whoever
used it is in the panel's own list of strangers and one click from being
allowed for good. That is the whole feature — one line of the ruleset and one
number.

The number lives in `config.json` rather than in memory. The table is rebuilt
from disk on every start, and an open gateway that evaporated on restart would
shut on a room full of guests the moment the service is updated. It is capped at
`BYPASS_MAX`, well under a device's own timer: this one suspends the entire
point of the program, and nobody means "until tomorrow" by *let the guests in*.
`expire()` closes it on the same tick that flips back device timers.

## Letting one device out past the tunnel

The switch is binary — routed or not — and the thing people actually want in
between is a device that has internet but is not inside the VPN: a TV that
refuses to play from a foreign address, a work laptop, a console. That is not a
verdict this program can make, because it does not own the tunnel. What it can
do is say *this packet is not yours*:

```
ether saddr 3c:22:fb:aa:bb:cc meta mark set 0x2024
```

Every tunnel that installs policy routing already has such a mark, because it
needs one for its own packets — otherwise they would be routed back into
itself. sing-box's `auto_route` writes `ip rule ... fwmark 0x2024 goto` past the
tun's own lookup and its chain returns on the same mark; wg-quick writes
`ip rule add not fwmark 51820 lookup 51820`, which is the same statement in the
other direction. Setting the mark therefore puts the packet on the main routing
table and past any redirect chain, and it leaves by the uplink like traffic from
any other machine on the LAN.

**Which number it is, is read off the host — never assumed.** sing-box keeps a
block of adjacent marks and `0x2023`, one below the one wanted, does the
opposite: `ip rule ... fwmark 0x2023 lookup 2022` puts the packet *into* the
tun. Set as `vpn_mark` it fails silently and backwards — the device is forced
through the tunnel, past whatever routing rules would have sent part of its
traffic direct, while the panel says it is out. That is not a hypothetical; it
is what v1.3.3 and v1.3.4 shipped as the default. See [singbox.md](singbox.md)
for the three marks and how to read them.

It is one rule per marked device in the same `prerouting` chain, and `raw` is
early enough for both readers of the mark: the routing decision that follows
`prerouting`, and the redirect chain at a later priority.

**By the hardware address, and above `meta nfproto != ipv4 accept`.** Both of
those are the same lesson, learned the hard way. v1.3.3 wrote `ip saddr` and put
the rule where every other device rule lives — below the line that lets IPv6
out of the chain. So a device sent past the tunnel went direct over v4 and
straight on through the tunnel over v6, and every site that asked it where it
was answered with the exit node, because a site with an AAAA record prefers v6.
The panel said the device was out. It was half out, in the half nobody looks at.

A device's IPv6 address cannot go in `devices.json` — the network hands it out,
there are several at once and they rotate. The MAC does not change between the
two protocols, and the panel already keeps one for every device, because
`track_macs()` needs it to follow a lease. One `ether saddr` rule therefore
covers both, and it has to stand above the `nfproto` line or the v6 packet is
long gone before it is read.

The fallback is `ip saddr` — v4 only, for a device the ARP cache has not
answered for yet. And what goes into the rule is checked first (`is_mac`):
`/proc/net/arp` and dnsmasq's lease file are written by other programs, and one
junk field there would make `nft -f` reject the table. Atomically, which is the
bad part — the old rules stay live, the panel goes on answering, and nothing
anyone does to a device takes effect again.

What a marked v6 packet then does depends on the network: with native IPv6 from
the ISP it is routed by `main` and goes direct like the v4. With no v6 outside
the tunnel there is no route for it, so it fails at once and the device falls
back to v4 — which is also the honest answer, and the one thing that must not
happen is what happened before: a device quietly still in the tunnel.

The mark is `vpn_mark` in `config.json` and not on the settings form, for the
same reason `bypass` is not: it is a number that belongs to the *other* program,
and whoever needs to change it is already editing that program's config. `0`
means there is no such mark on this host, and then the panel does not draw the
button at all rather than offering one that does nothing.

What this cannot do is verify any of it. If the mark is wrong the ruleset is
still valid, the button still lights, and the traffic still goes through the
tunnel — the failure is entirely on the other side of a contract nftables cannot
check. One look at the address the device reports for itself settles it.

## The version constant

`VERSION` is what every install compares against the newest tag on GitHub. It
is a hand-written constant, which is exactly the kind of thing that gets left
behind — and when it does, the install decides it is out of date and shows a
banner that no upgrade will ever clear, because the number it reports about
itself never changes.

So CI refuses the tag rather than trusting anyone to remember:

```yaml
- name: VERSION matches the tag
  if: startsWith(github.ref, 'refs/tags/v')
```

The answer is cached for a day (`UPDATE_EVERY`), so several releases cut in one
afternoon are not visible to a running panel until tomorrow. Saving the
settings form resets that timer: it is the one moment the user is demonstrably
asking about updates, and it gives them a way to force a check without
restarting the service.

## Testing a ruleset without risking the host

`nft -c -f file` checks a ruleset, but still needs `CAP_NET_ADMIN` and will not
run as a regular user. To validate the real thing on a real kernel without
touching your live network:

```bash
python3 panel.py --dump > /tmp/gwacl.nft
unshare -rn nft -f /tmp/gwacl.nft && echo OK
```

`unshare -rn` puts you in a fresh user and network namespace where you are root
and the ruleset applies to nothing. Interface names in the rules are just
strings, so they need not exist. You can go further and inspect the result:

```bash
unshare -rn bash -c 'nft -f /tmp/gwacl.nft && nft -j list table inet gwacl'
```

`install.sh` runs the privileged `nft -c -f -` variant before enabling anything.

## Language

Two languages, Russian and English, chosen at install time, changed later in the
panel's settings, and stored as `lang` in `config.json`. Strings live in one `STRINGS` dict in `panel.py`; templates
carry `{{t.key}}` placeholders and the same dict is injected into the page as a
`T` object so the JavaScript uses the same source. `install.sh` keeps its own
messages in two variable blocks.

Both halves are checked mechanically rather than by eye: the selftest asserts
that the two key sets are identical and that no placeholder survives rendering
in either language, and the same comparison is done for the installer's two
message blocks. A forgotten translation fails the build instead of reaching a
user as a stray Russian word in an English panel.

## Deliberately not done

- **IPv6.** Neither counted nor filtered — `meta nfproto != ipv4 accept`, and a
  typical gateway has v6 forwarding off. Supporting it means a second set and a
  second pair of rules per device. It *is* marked, above that line: a device let
  past the tunnel over v4 while its v6 still went through it reads, to every
  site that asks, as a device still in the tunnel.
- **No NAT.** This project never adds masquerade rules. Routing is somebody
  else's job — usually a tunnel.
- **No per-port or per-time rules.** An address is allowed or it is not.
- **Hourly history on disk.** The last day lives in memory and dies with the
  process; the month is what `traffic.json` is for.
- **No roles, and no audit log.** One password, and everyone who has it can do
  everything. Which of them acted is outside what this program can know.
