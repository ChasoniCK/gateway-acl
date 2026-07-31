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
polls them every 60 seconds and accumulates deltas into `traffic.json`, bucketed
by day:

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
counters keep running.

## Unknown devices

```
set blocked {
  type ipv4_addr
  flags dynamic,timeout
  timeout 6h
}
```

`update @blocked { ip saddr }` sits immediately before the final `drop`, so the
kernel itself records every source it refused, and forgets them six hours later.
The panel subtracts known devices and shows the rest.

This is strictly better than scanning ARP for this purpose: it lists exactly the
devices that tried to route through the host and were refused, rather than
everything that happens to be on the wire.

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
unshare -rn bash -c 'nft -f /tmp/gwacl.nft && nft -j list counters table inet gwacl'
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

- **IPv6.** Passed through with `meta nfproto != ipv4 accept`. A typical gateway
  has v6 forwarding off. Supporting it means a second set and a second pair of
  rules per device.
- **No NAT.** This project never adds masquerade rules. Routing is somebody
  else's job — usually a tunnel.
- **No per-port or per-time rules.** An address is allowed or it is not.
- **Sessions in memory.** Restarting the service logs everyone out. Persisting
  them would mean writing a secret to disk to sign cookies, for a panel that is
  already only as strong as its password.
