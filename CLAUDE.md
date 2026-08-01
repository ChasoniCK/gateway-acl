# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
python3 panel.py --selftest      # the whole test suite; asserts only, no network touched
python3 panel.py --dump          # print the generated ruleset
python3 panel.py --version
bash -n install.sh && shellcheck install.sh
```

There is no test framework and no single-test runner: `selftest()` in
[panel.py](panel.py) is one function of bare `assert`s. To run part of it, comment out
the rest or call the helper directly with `python3 -c 'import panel; ...'`.

Run against a scratch directory instead of `/etc/gateway-acl` — this is the only way
to exercise anything config-driven without root:

```bash
mkdir -p etc && GWACL_DIR=etc python3 panel.py --dump | nft -c -f -
```

A missing `config.json` silently falls back to `DEFAULTS`; an unreadable one (it is 0600,
it holds the password hash) falls back too but warns on stderr, because a silently wrong
iface and network look like healthy work.

CI ([.github/workflows/check.yml](.github/workflows/check.yml)) runs exactly the four
commands above plus `nft -c -f -` on the generated ruleset, and — on a tag push — a
check that the tag equals `VERSION`.

Installer: `sudo ./install.sh [--lang en|ru] [--yes] [--password-stdin]`,
`--uninstall` (keeps data), `--purge` (deletes `/etc/gateway-acl`).

## Constraints that shape everything

- **Python standard library only.** No pip, no npm, no CDN — the panel is expected to
  work on a gateway with no internet. Charts are inline SVG written by hand; the HTML,
  CSS and JS all live inside `panel.py`. Adding a dependency breaks the premise.
- **`VERSION` ([panel.py:50](panel.py:50)) must equal the release tag.** Every install
  compares its own constant against the newest GitHub tag; a forgotten bump makes every
  install show an update banner forever. CI rejects a mismatched tag push.
- **Root is required** for anything that calls `nft`. `--selftest`, `--dump` and
  `--version` are the exceptions.

## Architecture

Single file, ~2500 lines, sectioned by `# --- name ---` comments. The system is a state
machine over the JSON files in `/etc/gateway-acl` (`GWACL_DIR`):

`devices.json` is the source of truth. Any change to it — or to a device's `on` flag —
regenerates the entire `inet gwacl` nftables table via `ruleset()` → `apply()` and feeds
it to `nft -f -` as one atomic transaction. Nothing else on the host is touched, and a
ruleset that fails to parse changes nothing. The chain sits on `prerouting` at priority
`raw` (−300), deliberately earlier than redirect chains a tunnel may install; traffic to
the host itself is always accepted, so SSH survives blocking your own device.

Traffic history is accumulated, not authoritative. Two named nftables counters per device
(`cname('up'|'down', ip)`) are read by the poller and folded in by `accrue()`, which
treats a decrease as a counter reset and takes the new value whole — counters are zeroed
by a table rebuild and by reboot. `apply_deltas()` keeps a `last` baseline so a process
restart does not re-count.

It lives in **two** files, split by write frequency, not by subject — the panel runs on
flash that is never turned off, and rewriting the whole history to record the last five
minutes cost hundreds of MB a day:

| file | holds | written by `flush()` |
|---|---|---|
| `today.json` | the day in progress, `seen`, the `last` baseline | every `FLUSH_EVERY` |
| `traffic.json` | days already closed, folded months | only when `_cold` is set |

In memory they are one dict — only `_read_history()` and `flush()` know there are two, so
`month_totals`, the charts, `snapshot()` and the CSV are all unaware. Today's bucket lives
in exactly one file; `traffic.json` holds a stale copy of it only between an upgrade from
the single-file format and the next midnight, and `_read_history()` resolves that by
letting `today.json` win. Both are written through `write_atomic()` (`.tmp` → `fsync` →
`os.replace`) and read through `_load_json()`, which reports damage to stderr and carries
on rather than crash-looping under `Restart=always`.

`poll()` detects a day change by comparing `_hot_date` against today, and that rollover is
the only place `roll_up()` runs — a month cannot age past `keep_months` inside a day. The
first poll of a process counts as a rollover, so an install that was off for months folds
on startup. `refold()` is the one exception, called from the settings handler because
somebody who just lowered `keep_months` did it to get the space back now.

Two invariants worth not breaking: the baseline on disk is always exactly as old as the
totals beside it (a crash therefore costs nothing — the next poll measures from the older
baseline and lands on the same figure), and a poll during the day must not touch
`traffic.json` (the selftest asserts the mtime).

Unknown devices are not tracked by the program at all: the chain's last rule does
`update @blocked { ip saddr }` into a dynamic kernel set with `BLOCK_TTL`, and
`parse_blocked()` reads it back, deriving "last knocked" from the remaining timeout.

Config lives in module globals (`CFG`, `LANG`, `T`, `LAN`, `SELF_IP`, `PORT`, `POLL_SEC`,
`KEEP_MONTHS`, `PAGE`), all reassigned by `reload_conf()`. The settings form calls it so a
changed language or network applies without a restart; only a changed port needs
`restart()`, which `os.execv`s the process. `check_settings()` validates the form as a
whole before anything is written. Adding a setting means touching six places: `DEFAULTS`,
`check_settings()`, `reload_conf()` if it needs a global, the `STRINGS` label in both
languages, the `{{...}}` in `render()` and `PAGE_T`, and the body of `saveCfg()`.

Pages are string templates with `{{t.key}}` and `{{GW}}`-style placeholders substituted
by `render()`; **order matters** — translated strings first, network values second,
because the network placeholders live inside translated hints. `STRINGS` holds the full
ru/en tables and is also dumped into the page as `{{T_JSON}}` for the client-side JS.

Auth is a password (scrypt + random salt) and a session cookie whose digest is stored in
`sessions.json` (mode 0600), so sessions survive a service restart while the file alone
grants nothing. `write_private()` enforces 0600 even on a file left world-readable by an
older version.

## When editing

- Renaming a device must never change the ruleset — counters would be zeroed. The
  selftest asserts this.
- An empty device list must not emit `elements = { }`; that is invalid nft syntax.
- Never use a `reload_conf()`-managed global as a **default argument**: the default binds
  at import and would freeze the value the process started with. `roll_up(days, month,
  keep=None)` resolves `KEEP_MONTHS` in the body for exactly this reason.
- Anything added to the hot poll path is paid ~288 times a day, forever. Check whether it
  belongs at the rollover instead.
- `docs/design.md` explains the nftables model and how to test a ruleset without touching
  a live host; `docs/singbox.md` records real-world interactions with `auto_redirect`.
  Both are written for humans and should stay in sync with behaviour changes.
- README.md is primary; README.ru.md is a full translation, not a summary — user-visible
  changes need both.
