# AGENTS.md
This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
python3 panel.py --selftest      # the whole test suite; asserts only, no network touched
python3 panel.py --dump          # print the generated ruleset
python3 panel.py --version
python3 singbox_sub.py --selftest   # the converter's own asserts, no network
bash -n install.sh && shellcheck install.sh
```

There is no test framework and no single-test runner. `selftest()` in
[panel.py](panel.py) is one function of bare `assert`s. To run part of it, comment out
the rest or call the helper directly with `python3 -c 'import panel; ...'`.

Run against a scratch directory instead of `/etc/gateway-acl`. This is the only way
to exercise anything config-driven without root:

```bash
mkdir -p etc && GWACL_DIR=etc python3 panel.py --dump | nft -c -f -
```

A missing `config.json` silently falls back to `DEFAULTS`. An unreadable one (it is 0600,
it holds the password hash) falls back too but warns on stderr, because a silently wrong
iface and network look like healthy work.

CI ([.github/workflows/check.yml](.github/workflows/check.yml)) runs exactly the five
commands above plus `nft -c -f -` on the generated ruleset, and, on a tag push, a
check that the tag equals `VERSION`.

Installer: `sudo ./install.sh [--lang en|ru] [--yes] [--password-stdin]`,
`--uninstall` (keeps data), `--purge` (deletes `/etc/gateway-acl`). Every prompt
defaults to what `config.json` already holds (`cfg key`), and only falls back to
detecting the host when the config has nothing or names an interface that no
longer exists. `--yes` is therefore a re-run with the previous answers, which is
exactly what the update button needs and what it did **not** do before v1.4.0.

## Constraints that shape everything

- **Python standard library only.** No pip, no npm, no CDN. The panel is expected to
  work on a gateway with no internet. Charts are inline SVG written by hand, and the
  HTML, CSS and JS all live inside `panel.py`. Adding a dependency breaks the premise.
- **`VERSION` ([panel.py:64](panel.py:64)) must equal the release tag.** Every install
  compares its own constant against the newest GitHub tag, so a forgotten bump makes
  every install show an update banner forever. CI rejects a mismatched tag push.
- **Root is required** for anything that calls `nft`. `--selftest`, `--dump` and
  `--version` are the exceptions.

## Architecture

Single file, ~6900 lines, sectioned by `# --- name ---` comments. The system is a state
machine over the JSON files in `/etc/gateway-acl` (`GWACL_DIR`):

`devices.json` is the source of truth (`ip`, `name`, `on`, and optionally `until` and
`mac`). Any change to it, or to a device's `on` flag, regenerates the entire
`inet gwacl` nftables table via `ruleset()` → `apply()` and feeds it to `nft -f -` as
one atomic transaction. Nothing else on the host is touched, and a ruleset that fails
to parse changes nothing. The chain sits on `prerouting` at priority `raw` (−300),
deliberately earlier than redirect chains a tunnel may install. Traffic to the host
itself is always accepted, so SSH survives blocking your own device.

It is written through `write_atomic()` like everything else here, and read through a
`load()` that survives damage: an unparseable file hands back the last list that
parsed, reports itself once on stderr and sets `_devs["bad"]`, which reaches the page
as `state()["broken"]` and draws a red banner with the diagnostics button in it.
`devices_ok()` is that flag, and `apply()` refuses to rebuild the table when the list
it was handed is empty **and** the file is unreadable. An empty list is a valid answer
and would drop the whole network silently; leaving the rules alone lets everyone
through the way `bypass` does, which is the direction this program fails in.

Traffic history is accumulated, not authoritative. Two named nftables counters per device
(`cname('up'|'down', ip)`) are read by the poller and folded in by `accrue()`, which
treats a decrease as a counter reset and takes the new value whole. Counters are zeroed
by a table rebuild and by reboot. `apply_deltas()` keeps a `last` baseline so a process
restart does not re-count.

It lives in **two** files, split by write frequency rather than by subject. The panel
runs on flash that is never turned off, and rewriting the whole history to record the
last five minutes cost hundreds of MB a day:

| file | holds | written by `flush()` |
|---|---|---|
| `today.json` | the day in progress, `seen`, the `last` baseline | every `FLUSH_EVERY` |
| `traffic.json` | days already closed, folded months | only when `_cold` is set |

In memory they are one dict. Only `_read_history()` and `flush()` know there are two, so
`month_totals`, the charts, `snapshot()` and the CSV are all unaware. Today's bucket lives
in exactly one file. `traffic.json` holds a stale copy of it only between an upgrade from
the single-file format and the next midnight, and `_read_history()` resolves that by
letting `today.json` win. Both are written through `write_atomic()` (`.tmp` → `fsync` →
`os.replace` → `fsync` of the directory) and read through `_load_json()`, which reports
damage to stderr and carries on rather than crash-looping under `Restart=always`.
`_load_json()` only catches a file that is not json; a file that **is** json but of the
wrong shape is caught by `_buckets()` and `_counts()` in `_read_history()`, which drop
whatever is not a mapping of names to whole numbers. `null` in either file used to be a
crash on every start, for ever.

`poll()` detects a day change by comparing `_hot_date` against today, and that rollover is
the only place `roll_up()` runs, because a month cannot age past `keep_months` inside a
day. The first poll of a process counts as a rollover, so an install that was off for
months folds on startup. `refold()` is the one exception, called from the settings handler
because somebody who just lowered `keep_months` did it to get the space back now.

Two invariants worth not breaking: the baseline on disk is always exactly as old as the
totals beside it (a crash therefore costs nothing, since the next poll measures from the
older baseline and lands on the same figure), and a poll during the day must not touch
`traffic.json` (the selftest asserts the mtime).

`snapshot()` is how a reader outside `_lock` gets the history, and it carries the hourly
ring `_hours` as well as the days. Reading `_hours` live is "dictionary changed size
during iteration" on the next page refresh; `selftest()` asserts `_hours` is not among
`build_state.__code__.co_names`.

`tick()` is the poller's whole body and catches everything. An exception used to end the
thread while the HTTP server carried on, so the panel looked healthy with every timer,
`track_macs()`, the subscription schedule and the nightly reboot silently stopped. A
failed step costs its tick; the fault is printed once per distinct message.

Unknown devices are not tracked by the program at all. The chain's last rule does
`update @blocked { ip saddr }` into a dynamic kernel set with `BLOCK_TTL`, and
`parse_blocked()` reads it back, deriving "last knocked" from the remaining timeout.
It picks the set out **by name**, because `poll()` lists the whole table in one `nft` call
(`nft_table()`), so `allowed` is in the same answer and its bare-string elements would
otherwise read as intruders. `blocked()` spawns nothing; it hands back what
`note_blocked()` kept from that reading.

Two things the poller does besides polling, both on its own tick, both as precise as
`poll_sec`: `expire()` flips back a device whose `until` has passed (one field for both
directions, because a timer always undoes what set it; the browser sends *minutes*, the
gateway turns them into a moment), and `track_macs()` moves an entry whose `mac` the ARP
cache now reports at another address, with `rekey()` carrying its history across.

`CFG["bypass"]` is the moment the gateway stops standing open. While it is in the future
`ruleset()` omits exactly one line, the final `drop`, so the counters and
`update @blocked` keep running and everything that used the window is in the strangers
list when it shuts. It is in `config.json` and not in memory because the table is rebuilt
from disk on every start. `expire()` closes it, and `check_minutes()` caps it at
`BYPASS_MAX`. It is **not** a settings-form field, so the six-places rule below does not
apply to it: `check_settings()` carries it through untouched with the rest of the config.

A device with `"vpn": false` is allowed but sent around the tunnel. `ruleset()` adds one
`meta mark set` line, keyed on `ether saddr` when `is_mac()` accepts the device's MAC and
on `ip saddr` when it does not, **above** `meta nfproto != ipv4 accept`. That position is
the whole point: below that line an IPv6 packet has already left the chain, and a device
marked only on v4 goes on leaving by the tunnel over v6 while the panel says it is out.
Every policy-routing tunnel already has a mark it treats as not its own, the one it puts
on its own output so that what it sends is not swallowed by itself again.
`CFG["vpn_mark"]` holds it, and getting the number wrong is **not** a no-op: sing-box
keeps a block of adjacent marks where `0x2024` means "past the tun" and `0x2023` means
"into the tun", and the wrong one silently forces the device through the tunnel while the
panel says it is out. That was the default in v1.3.3–v1.3.4. Read it off the host
(`ip rule`, `nft list table inet sing-box`), never from a document, this one included.
Like `bypass`, it is in `config.json` and not on the form, so the six-places rule does not
apply. `0` means no mark on this host, and `build_state()` then reports `vpnable: false`
so the page does not draw a button that would do nothing. Nothing here can verify that the
tunnel honours the mark. That is the one contract the ruleset cannot check.

`clashes()` is the case `track_macs()` cannot fix: the entry stays put and something else
answers on its address, which is an allowlist quietly admitting the wrong device.
`vendors()` names hardware from the system's IEEE list when one is installed, from the
short `OUI` table when not, and says "randomised" for a locally-administered address.
Never a guess.

Four caches, all of them removing work nothing was waiting for: `load()` re-reads
`devices.json` only on an `st_mtime_ns` change and hands out copies (callers mutate what
they get); `state()` reuses its whole answer for `STATE_CACHE`, invalidated by `save()`
so a button never looks like it did nothing; `sysinfo()` holds its answer for the two
seconds its rates already needed; `month_sums()` is one pass over the days for every
month, where asking `month_totals()` per month was one pass per month, per request.

Config lives in module globals (`CFG`, `LANG`, `T`, `LAN`, `SELF_IP`, `PORT`, `POLL_SEC`,
`KEEP_MONTHS`, `PAGE`), all reassigned by `reload_conf()`. The settings form calls it so a
changed language or network applies without a restart. Only a changed port needs
`restart()`, which `os.execv`s the process. `check_settings()` validates the form as a
whole before anything is written. Adding a setting means touching six places: `DEFAULTS`,
`check_settings()`, `reload_conf()` if it needs a global, the `STRINGS` label in both
languages, the `{{...}}` in `render()` and `PAGE_T`, and the body of `saveCfg()`.

Pages are string templates with `{{t.key}}` and `{{GW}}`-style placeholders substituted
by `render()`. **Order matters**: translated strings first, network values second,
because the network placeholders live inside translated hints. `STRINGS` holds the full
ru/en tables and is also dumped into the page as `{{T_JSON}}` for the client-side JS.

**Tunnels are the panel's; the programs that run them are the installer's.**
`panel.py` owns the catalog (`tunnels.json`), the secrets under
`$GWACL_DIR/tunnels/`, `/etc/sing-box/config.json` and the `wg-quick`/`awg-quick`
commands. [singbox_sub.py](singbox_sub.py) stays a pure converter (it prints and
writes nothing) and owns two things in the config it merges into: outbounds
tagged `sub-*` and the member list of the `proxy` group. That prefix is the
entire ownership rule, and `merge()`'s selftest asserts every other key comes out
byte-identical. A node sing-box cannot load (`xhttp`) is reported and skipped,
never written, because an unparseable config is a gateway that does not come up. The
per-profile exclusion (a regex over the provider's node names) drops nodes
entirely, and it is not a nicety: the group is a `urltest`, so a node in the
user's own country is always the fastest and therefore always the one chosen.

`install.sh` no longer asks for a link. It installs **sing-box 1.12 or newer**
(the version the generated config needs: `action: sniff`, typed `dns.servers`,
`default_domain_resolver`), `wireguard-tools` and `amneziawg-tools`, and writes a
`sing-box.service` if the host has none. Distributions ship 1.8–1.10, so the
version is checked and not assumed. When it is too old the published build for
the architecture goes to `/usr/local/bin`, with only the tag taken off the
network and only if it matches a tag. Nothing in that step may abort an install.
Leaving it out is what made **every** subscription fail: with no sing-box the
enable path dies in `_check_singbox_candidate` as `tool-missing`, and with an old
one as `validation-failed`, which reads as a bad subscription. `vpn_public()`
reports `tools` for exactly that reason and the page names what is missing.

**A running sing-box is checked by its unit and by nothing else.**
`_backend_up()` used to also demand a default route in a policy table, and that
is wrong on any host using `auto_redirect`: forwarded traffic is put into the
tun by nftables rather than routed, so a working tunnel has no such route and
the panel closed transit, rolled the switch back and stopped a sing-box that was
proxying happily, every single time. Never make health depend on one of the two
routing mechanisms. The unit is a real check because the candidate has already
passed `sing-box check`, so a config it cannot run makes the process exit.

**Nothing that was just started is checked immediately.** `systemctl restart`
returns when the process is running, and sing-box installs its nftables mark a
moment later. `_check_backend`/`backend_mark` therefore take a `wait` and poll
over `BACKEND_WAIT`. The default is 0, because the poll path is a
health check rather than a start, and the callers that started something pass the
constant. `BACKEND_WAIT` is a module global resolved in the body, never a default
argument, because `selftest()` sets it to 0.

**A subscription's node selection lives with the subscription, not in the
catalog.** `tunnels/<id>.json` holds `skip` (labels the user turned off), `up`
and `ms` (what the last probe found per label) beside the link and cached body.
`_tunnel_row()` whitelists the catalog and would drop them anyway. A *label* is
an outbound tag minus its `sub-<id>-` prefix (`Germany` / `Germany 2`), and
`convert()` allocates the tag before honouring `skip`, so dropping one node never
renumbers its namesakes and never invalidates the other stored labels. The label
does **not** go to the browser: a link with no `#fragment` is named after its own
server, so the page gets `node_id()` (a digest) plus a name that falls back to
`#N` whenever the label is the address. Every read of a cached body goes through
`sub_convert()`, which applies both the exclusion regex and `skip`. A caller
that forgets one builds a config the panel does not claim to have built.

**A probe is a reading and changes nothing.** `vpn_check()` answers "would this
profile work" while the live backend keeps running. A subscription is converted
into a `fresh()` config of its own, checked by `sing-box check` and knocked on
node by node over TCP (deduplicated, capped at `PROBE_NODES`, all at once). A
quick profile is brought up on `PROBE_IF` with one route to `PROBE_DST`, an
RFC 5737 address, so the route cannot take real traffic, and torn down in a
`finally` whatever happens. It takes the same two steps `wg-quick`'s `add_if`
does, in the same order: ask the kernel for the link type, and fall back to
`PROBE_USERSPACE` (`wireguard-go` / `amneziawg-go`) when it has none. Skipping
that fallback would call every profile on a host without the kernel module
`tool-missing` while `awg-quick up` worked perfectly, which on a distribution
with its own kernel is the normal way to have AmneziaWG at all. It runs
**outside** `_vpn_lock`, under `_probe_lock` of its own: a dead subscription
costs a connect timeout and a silent peer costs the handshake window, and the
poller must not queue behind a button. The catalog gets `probe`/`reach`/`nodes`,
the fastest `probe_ms` and `probe_at`; the private file gets per-label readings.
The row is re-found under the lock because the profile may have been deleted
while a socket was waiting, and the reading is dropped outright when
`_probe_subject()` no longer matches what it measured: a refresh can replace
the node list mid-probe, and a summary written after that would describe a
subscription this profile is not. That subject is the *converted* outbounds
and not the secret file, so a refresh that only brought the cached body up to
date does not throw a good reading away. "Check all" is browser-side
sequencing over the same action because every quick probe shares `PROBE_IF`.

**A provider's refresh interval is a default, a person's value is an
override.** `Profile-Update-Interval` is parsed as hours, saved as
`provider_hours` and used as `refresh_hours` until `vpn_schedule()` sets
`refresh_manual`. Zero disables the schedule. `vpn_auto_refresh()` takes at
most one due subscription per poll and uses the ordinary refresh/rollback path.
Failure records `refresh_error` without touching the cache or backend and
retries after `AUTO_REFRESH_RETRY`.

What decides whether anything is committed is the **outbounds** the body
converts to, never the bytes it arrived as. Providers put a "traffic left" or
"expires on" node in the list and rewrite it on every fetch, so comparing
bodies closed transit and restarted sing-box on the provider's schedule, for a
config that came out identical. When `outs` equals what the cache already
converts to, the refresh updates the cache and the timestamps and touches
nothing else: no restart, and the probe results still describe the running
config. A cache too damaged to convert counts as a change, because a refresh
is how somebody repairs one. The download itself happens **outside**
`_vpn_lock`: the poller takes this path on its own tick, and twenty seconds of
somebody else's server must not be twenty seconds of a panel that answers
nothing. Everything after it re-reads under the lock, because the selection
may have moved while the socket was waiting.

**Diagnostics are broad, but browser-safe.** `/diagnostics` is authenticated
and combines sanitized public state with fixed read-only commands, bounded
output and timeouts, one bundle at a time under `_diag_lock`.
`_redact_diagnostics()` runs after the whole report is assembled and must
remove subscription URLs and endpoints, UUIDs, tokens, passwords and
quick-profile keys. Addresses go through `is_global`, in **both** families:
`ip -6 addr` and `ip -6 route show table all` are in the bundle, so a v4-only
redactor handed over the gateway's own public prefix and the tunnel's peers in
a report whose first line says the secrets were removed. The v6 pattern runs
first and is deliberately loose, because `ipaddress` is what validates it and
a timestamp or a MAC that matches the shape is simply handed back. Multicast
and everything `is_global` rejects stay, since a routing table is mostly that
and removing it would remove the fault. Never add a raw secret file, command
built from request data, or unredacted journal response to this endpoint.

**The update button is the one place the panel runs code it downloaded.**
`tar_url()` builds the address from constants and accepts a tag only if it matches
`v?\d+(\.\d+){0,3}`, so nothing in GitHub's answer can choose what root fetches.
`_safe_members()` drops anything absolute, climbing out with `..`, or not a plain
file (not `tarfile`'s `filter=`, which needs 3.12 and the gateway has what it
has). The archive must report the announced version and pass its own `--selftest`
before `install.sh --yes` is started with `start_new_session=True`, because the
installer restarts the service and so must outlive the process that asked. All of
it is logged to `update.log`, since after the restart nobody is left to tell.

Auth is a password (scrypt + random salt) and a session cookie whose digest is stored in
`sessions.json` (mode 0600), so sessions survive a service restart while the file alone
grants nothing. `write_private()` enforces 0600 even on a file left world-readable by an
older version.

## When editing

- Renaming a device must never change the ruleset, or counters would be zeroed. The
  selftest asserts this. The same holds for setting or dropping a timer alone.
- Colours live in three token strings, not two. `LIGHT` sits in bare `:root` as the
  default, because the panel follows whoever hasn't chosen, and `DARK` is written exactly
  once, then substituted into both places that can win over it: the
  `prefers-color-scheme:dark` media query, guarded by `:not([data-theme=light])` so an
  explicit light pick still beats a dark OS, and `:root[data-theme=dark]` for an
  explicit dark pick. One string, two selectors, so a colour never needs to be kept in
  sync by hand. Shape, type size and the spacing scale don't depend on the theme, so
  they all live in `SHAPE`, declared once with no counterpart. `selftest()` greps `CSS`
  and the page's inline `<style>` for a hex literal or `rgba(` outside these three
  token strings and fails if it finds one. The only exception it lets through is the
  pair of `theme-color` metas in `HEAD`, which paint the browser's own chrome and
  can't read a CSS variable. The manual light/dark pick itself lives in `localStorage`,
  not `config.json`, because it's a preference of the browser looking at the panel, not
  of the gateway, so it isn't a settings-form field and the six-places rule above
  doesn't apply to it.
- An empty device list must not emit `elements = { }`; that is invalid nft syntax.
- Never use a `reload_conf()`-managed global as a **default argument**: the default binds
  at import and would freeze the value the process started with. `roll_up(days, month,
  keep=None)` resolves `KEEP_MONTHS` in the body for exactly this reason.
- Anything added to the hot poll path is paid ~288 times a day, forever. Check whether it
  belongs at the rollover instead.
- **A duration is measured with `time.monotonic()`, a moment with `time.time()`.** Every
  window that lives only in memory (`_flushed`, `_polled`, `_rate_at`, the `state()` and
  `sysinfo()` caches, the update gates, the failed-login block) is monotonic, because a
  wall clock steps backwards: one NTP correction of an hour put `_flushed` an hour into
  the future and `flush()` returned False for that hour, with the history in memory the
  whole time. Anything a person reads or that outlives the process stays wall clock:
  `seen`, `until`, `bypass`, session expiry, `probe_at`, `refresh_at`. `poll()` takes
  both, on purpose.
- A string in `STRINGS` that nothing shows is a string that rots into a difference
  between the two languages. `selftest()` looks for one along all four roads to a
  string: `{{t.key}}`, `T.key`, `["key"]` in either language, and a bare `'key'` inside
  one of the page script's own tables. `sRebootAtWhat` sat written in both languages and
  wired to nothing, which is how the check came to exist.
- `_clean_tunnel_orphans()` reads the catalog **raw** as well as through `load_tunnels()`.
  The parsed list drops a row it could not read, and going by that alone deleted the
  secret of a profile the catalog still names: a subscription link with its token, or a
  private key, gone on the next start with nothing said. Rolling the panel back one
  version was enough to do it.
- `MULTI_QUICK` (`address`, `dns`, `allowedips`) is the set of keys `wg-quick` and `wg`
  accumulate rather than overwrite, so a config with one address per line is joined with
  commas instead of refused. Every other key stays one to a section. `FORBIDDEN_QUICK`
  is untouched by this and must stay that way.
- `docs/design.md` explains the nftables model and how to test a ruleset without touching
  a live host; `docs/singbox.md` records real-world interactions with `auto_redirect`.
  Both are written for humans and should stay in sync with behaviour changes.
- README.md is primary; README.ru.md is a full translation, not a summary, so
  user-visible changes need both. `AGENTS.md` is a byte-for-byte copy of this file with
  its first line swapped; regenerate it rather than editing it twice.
- Never focus a `<select>` to move focus into something. On a phone that is an
  open native picker, which is what greeted anyone opening Settings before
  v1.5.2. The sheet's own container carries `tabindex=-1` for this.
- A missing tool is only red when a *saved* profile needs it. A red line nobody
  can act on ("install awg-quick" to somebody who has never wanted AmneziaWG)
  is a line that trains people to ignore the red lines that matter.
- The page must not scroll sideways on a phone. Two rules keep it that way:
  a grid column is `minmax(0,1fr)` and never `1fr` (`1fr` is `minmax(auto,1fr)`,
  and `auto` is the item's min-content, so one `white-space:nowrap` line is enough
  to push the column past the screen), and any field a finger can focus is at
  least 16px on a coarse pointer, because Safari zooms the page in below that and
  never zooms back out.
- The panel must never learn the subscription link: not in `config.json`, not in
  `state()`, not in a page. It is the installer's secret, and `sub.url` is where
  it stops.
