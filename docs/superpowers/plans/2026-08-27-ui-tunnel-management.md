# UI Tunnel Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Дать администратору полный CRUD и безопасное переключение нескольких sing-box подписок, WireGuard и AmneziaWG прямо в существующей панели.

**Architecture:** Сохраняем однопроцессную архитектуру: HTTP, каталог профилей и lifecycle остаются в `panel.py`, а `singbox_sub.py` остаётся импортируемым конвертером. Метаданные и секреты разделены; один lock сериализует lifecycle, один private-atomic writer защищает все секретные файлы, а временный nftables forward-gate закрывает только транзит на время switch/rollback. Внешние команды выбираются сервером из фиксированной таблицы и во всех тестах заменяются fake runner.

**Tech Stack:** Python 3 standard library, `BaseHTTPRequestHandler`, nftables, sing-box, `wg-quick`, `awg-quick`, встроенные bare-`assert` selftests, POSIX shell.

**Spec:** `docs/superpowers/specs/2026-08-27-ui-tunnel-management-design.md`

## Global Constraints

- Не добавлять зависимости, новый daemon, универсальный service manager или произвольные shell-команды.
- Не раскрывать URL подписки, subscription body, private/preshared keys, endpoint или полный конфиг в HTML, JSON, exception text, stdout/stderr либо argv.
- Все production-изменения делать red-green: сначала новый assert и наблюдаемый FAIL, затем минимальный код и PASS.
- Все config-driven проверки запускать с временным `GWACL_DIR`; не писать в `/etc/gateway-acl` на Mac.
- Не менять VPN, Wi-Fi, Ethernet, utun, default route или firewall macOS-хоста. Live WG/AWG разрешён только в отдельном Linux guest/namespace с собственной routing table.
- Не добавлять в git пользовательский untracked `AGENTS.md`.

---

### Task 1: Multi-source sing-box converter

**Files:**
- Modify: `singbox_sub.py:18-224`
- Test: `singbox_sub.py:289-390`

- [ ] **Step 1: Write failing multi-source and API-safe error asserts**

Добавить в `selftest()` два body с одинаковыми именами узлов и проверить общий `taken`, разные profile-prefix и обычный `ValueError`:

```python
taken = set()
a = convert(plain, prefix="sub-t000000000001-", taken=taken)
b = convert(plain, prefix="sub-t000000000002-", taken=taken)
assert all(o["tag"].startswith("sub-t000000000001-") for o in a)
assert all(o["tag"].startswith("sub-t000000000002-") for o in b)
assert len({o["tag"] for o in a + b}) == len(a + b)
try:
    convert(plain, exclude="[")
    raise AssertionError("bad regex must be an API-safe error")
except ValueError:
    pass
```

- [ ] **Step 2: Run the focused selftest and verify RED**

Run: `python3 singbox_sub.py --selftest`

Expected: `TypeError` for the new `prefix`/`taken` parameters or `SystemExit` for the invalid regex.

- [ ] **Step 3: Add the minimum reusable converter parameters**

Implement these exact signatures and reuse existing parsing:

```python
SUB_BODY_MAX = 128 << 10

def tag_for(link, taken, prefix=OWNED):
    ...

def convert(body, warn=lambda s: None, exclude=None, prefix=OWNED, taken=None):
    taken = taken if taken is not None else set()
    ...

def build(body, base=None, iface=None, warn=lambda s: None, exclude=None,
          prefix=OWNED, taken=None):
    outs = convert(body, warn, exclude, prefix, taken)
    if not outs:
        raise ValueError("подписка не дала ни одного пригодного узла / "
                         "the subscription yielded no usable node")
    ...
```

`main()` alone catches `ValueError` and converts it to CLI `SystemExit`; imported callers receive a normal exception.

- [ ] **Step 4: Harden subscription fetching**

Implement `fetch(url, timeout=TIMEOUT, limit=SUB_BODY_MAX)` with HTTPS validation, `limit + 1`, and a redirect handler that rejects a changed hostname:

```python
class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise ValueError("subscription redirect changed host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)
```

The function must reject a non-HTTPS URL before opening it, enforce a monotonic
overall deadline while reading, and never include the URL in an error.

- [ ] **Step 5: Verify GREEN and regression**

Run:

```bash
python3 singbox_sub.py --selftest
python3 panel.py --selftest
```

Expected: both exit 0.

- [ ] **Step 6: Commit**

```bash
git add singbox_sub.py
git commit -m "Поддержать несколько источников подписок"
```

---

### Task 2: Private-atomic storage and synchronized config writes

**Files:**
- Modify: `panel.py:70-190`
- Test: `panel.py:3420-4060`

- [ ] **Step 1: Write failing storage asserts in a scratch directory**

Temporarily redirect module paths in `selftest()` and assert mode, replacement and cleanup:

```python
with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, "secret.json")
    write_private(p, {"v": 1})
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    old = os.stat(p).st_ino
    write_private(p, {"v": 2})
    assert json.load(open(p)) == {"v": 2}
    assert os.stat(p).st_ino != old
    assert not os.path.exists(p + ".tmp")
```

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

Expected: inode replacement assertion fails because current `write_private()` truncates in place.

- [ ] **Step 3: Implement one private-atomic primitive**

Add `_write_private_bytes(path, data)` and make JSON/text wrappers use it:

```python
def _write_private_bytes(path, data):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=parent)
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        dfd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass

def write_private(path, obj):
    _write_private_bytes(path, json.dumps(obj, indent=1).encode())

def write_private_text(path, text):
    _write_private_bytes(path, text.encode())
```

Generic writing must not chmod an existing parent such as `/etc/gateway-acl`.
Catalog setup separately creates/chmods only `TUNNEL_DIR` to `0700`.

- [ ] **Step 4: Serialize read-modify-write of `config.json`**

Add `_conf_lock = threading.RLock()` and:

```python
def update_conf(change):
    with _conf_lock:
        c = conf()
        change(c)
        save_conf(c)
        return c
```

Move settings saving and future `vpn_mark` saving through this function; do not bind reloadable globals as default arguments.

- [ ] **Step 5: Verify and commit**

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
git add panel.py
git commit -m "Писать приватные настройки атомарно"
```

---

### Task 3: Tunnel catalog, secret paths, validation, and legacy migration

**Files:**
- Modify: `panel.py:75-150`
- Modify: `panel.py` new section `# --- tunnels ---` before machine/system information
- Test: `panel.py:selftest()`

- [ ] **Step 1: Write failing catalog and non-disclosure asserts**

Cover exact server IDs, traversal rejection, modes, public projection and one-shot migration:

```python
assert re.fullmatch(r"t[0-9a-f]{12}", new_tunnel_id([]))
for bad in ("../x", "t1/../x", "", "t" + "0" * 13):
    try:
        check_tunnel_id(bad)
        raise AssertionError(bad)
    except ValueError:
        pass
public = public_tunnels([{"id": "t000000000001", "name": "x",
                          "kind": "wireguard", "enabled": False,
                          "error": "", "nodes": 0}])
assert "PrivateKey" not in json.dumps(public)
```

In a temporary `GWACL_DIR`, create `sub.url`/`sub.exclude`, call migration twice, then assert one profile, `legacy=True`, no cache, unchanged sing-box runtime fixture, and legacy files removed only after catalog+secret exist.

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

Expected: `NameError` for the new catalog helpers.

- [ ] **Step 3: Add constants and strict storage helpers**

```python
TUNNELS = os.path.join(DIR, "tunnels.json")
TUNNEL_DIR = os.path.join(DIR, "tunnels")
TUNNEL_ID_RE = re.compile(r"t[0-9a-f]{12}\Z")
TUNNEL_KINDS = ("subscription", "wireguard", "amneziawg")
VPN_MAX = 128 << 10
_vpn_lock = threading.RLock()

def check_tunnel_id(value): ...
def tunnel_path(tid, suffix): ...
def load_tunnels(): ...
def save_tunnels(rows): ...
def new_tunnel_id(rows): ...
def public_tunnels(rows=None, runner=None): ...
def migrate_legacy_subscription(): ...
```

Normalize catalog records to exactly `id,name,kind,enabled,error,nodes` plus internal migration state. Never copy a secret field into metadata or public output.

- [ ] **Step 4: Add subscription form validation**

```python
def check_subscription(url, exclude):
    p = urlsplit(str(url).strip())
    if p.scheme != "https" or not p.hostname:
        raise ValueError(T["vpnHttps"])
    exclude = str(exclude or "")
    if len(exclude) > 128:
        raise ValueError(T["vpnExcludeLong"])
    try:
        re.compile(exclude, re.I)
    except re.error:
        raise ValueError(T["vpnExcludeBad"])
    return p.geturl(), exclude
```

- [ ] **Step 5: Implement one-shot migration and verify**

Migration order is secret → catalog → remove legacy files. It must not rebuild/restart sing-box.

Run:

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
```

- [ ] **Step 6: Commit**

```bash
git add panel.py
git commit -m "Добавить защищенный каталог VPN-профилей"
```

---

### Task 4: WireGuard and AmneziaWG config validation

**Files:**
- Modify: `panel.py` tunnels section
- Test: `panel.py:selftest()`

- [ ] **Step 1: Add a table of failing parser cases**

Use one minimal WG and one minimal AWG fixture containing fake keys. Assert rejection of NUL, `VPN_MAX + 1`, duplicate/missing sections, missing required fields, hooks, `SaveConfig`, missing `0.0.0.0/0`, `Table=off/custom`, WG with AWG-only keys, and AWG without AWG-only keys.

```python
bad = {
    "hook": wg.replace("DNS = 1.1.1.1", "PostUp = touch /tmp/x"),
    "split": wg.replace("0.0.0.0/0", "10.0.0.0/8"),
    "awg-as-wg": awg,
}
for why, text in bad.items():
    try:
        check_quick_config("wireguard", text, runner=fake_missing_tool)
        raise AssertionError(why)
    except ValueError:
        pass
```

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

Expected: `NameError: check_quick_config`.

- [ ] **Step 3: Implement a small INI-aware structural parser**

Do not use `configparser` interpolation or merge duplicate sections. Parse lines into ordered `(section,key,value)` triples, strip comments, compare keys case-insensitively, and reject forbidden keys before any command.

```python
AWG_KEYS = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
            "h1", "h2", "h3", "h4"}
FORBIDDEN_QUICK = {"preup", "postup", "predown", "postdown", "saveconfig"}
QUICK_TOOL = {"wireguard": "wg-quick", "amneziawg": "awg-quick"}

def check_quick_config(kind, text, runner=None):
    ...
    return {"ipv6": "::/0" in allowed, "verified": tool_present}
```

If tool is present, use a private temporary directory and a basename no longer
than the quick-tool interface limit (the generated 13-character server ID is
valid), then call fixed argv `[tool, "strip", path]`. Missing tool permits
disabled save but sets `verified=False`; any non-zero strip rejects
activation/save as appropriate without returning raw stderr.

- [ ] **Step 4: Verify GREEN and run both selftests**

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
```

- [ ] **Step 5: Commit**

```bash
git add panel.py
git commit -m "Проверять конфиги WireGuard и AmneziaWG"
```

---

### Task 5: Build aggregated sing-box candidates and parse runtime marks

**Files:**
- Modify: `panel.py` tunnels section
- Test: `panel.py:selftest()`

- [ ] **Step 1: Write failing two-source build and mark asserts**

Create two private subscription fixtures in scratch storage. Assert one proxy group contains both prefix families; changing/deleting A leaves B byte-equivalent. Add mark fixtures for decimal, hex, empty and ambiguous output:

```python
c, counts = build_singbox(rows, base_fixture)
members = next(o for o in c["outbounds"] if o["tag"] == "proxy")["outbounds"]
assert any(x.startswith("sub-t000000000001-") for x in members)
assert any(x.startswith("sub-t000000000002-") for x in members)
assert backend_mark({"kind": "wireguard", "id": tid}, fake("0xca6c")) == 0xca6c
assert backend_mark({"kind": "wireguard", "id": tid}, fake("off")) == 0
assert parse_singbox_mark("0x2024\n0x2023\n") == 0
```

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

Expected: missing build/mark helpers.

- [ ] **Step 3: Implement candidate building with one merge**

```python
def build_singbox(rows, base, secrets=None):
    taken, outs, counts = set(), [], {}
    for row in rows:
        if row["kind"] != "subscription" or not row["enabled"]:
            continue
        secret = (secrets or load_subscription_secret)(row["id"])
        one = singbox_sub.convert(secret["body"], exclude=secret.get("exclude"),
                                  prefix=f"sub-{row['id']}-", taken=taken)
        if not one:
            raise VpnError("subscription has no usable nodes")
        counts[row["id"]] = len(one)
        outs.extend(one)
    return singbox_sub.merge(base, outs), counts
```

Use safe `VpnError` messages only. Add `vpn_exec`, `backend_state` and `backend_mark` with fixed command tables and sanitized private paths; the runner default resolves inside the function.

- [ ] **Step 4: Verify commands contain no user-controlled name or secret**

Assert every recorded argv starts with one of `sing-box`, `systemctl`, `wg`, `awg`, `wg-quick`, `awg-quick`, `ip`, `nft`, and paths contain the validated server ID but never the display name or secret content.

- [ ] **Step 5: Verify and commit**

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
git add panel.py
git commit -m "Собирать единый backend из подписок"
```

---

### Task 6: Transit gate and transactional lifecycle

**Files:**
- Modify: `panel.py:964-1145`
- Modify: `panel.py` tunnels section
- Test: `panel.py:selftest()`

- [ ] **Step 1: Write failing nft gate asserts**

```python
closed = ruleset(d, vpn_closed=True)
open_ = ruleset(d, vpn_closed=False)
assert "chain vpn_guard" in closed and "drop" in closed
assert "chain vpn_guard" not in open_
assert "hook forward" in closed
assert "hook input" not in closed
```

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

Expected: `ruleset()` rejects `vpn_closed` or lacks the guard.

- [ ] **Step 3: Add the minimal forward-only gate**

Extend `ruleset(devs, bypass=None, vpn_closed=None)`; when closed, emit one base chain in `inet gwacl`:

```nft
chain vpn_guard {
    type filter hook forward priority raw; policy accept;
    iifname "<LAN_IFACE>" drop
}
```

`set_transit_closed(closed)` updates `_vpn_closed` under the lifecycle lock and applies the full existing ruleset. It never changes host routes, input hooks, macOS state or unmanaged nft tables.

- [ ] **Step 4: Write lifecycle success and rollback asserts**

Use a stateful fake runner and real scratch files/catalog. Cover `none→sing-box`, `sing-box→WG`, `WG→sing-box`, disable/delete last. For failpoints at stop-old, start-new, health, mark, config replace and final apply, assert:

```python
assert load_tunnels() == old_rows
assert conf()["vpn_mark"] == old_mark
assert read_private(old_secret) == old_secret_value
assert fake.active == old_backend
assert fake.candidate_stopped
assert not _vpn_closed
```

Also simulate failure while restoring the old backend. In that case the old
catalog/config remains authoritative, the safe error is recorded, and
`_vpn_closed` must remain true; never open direct transit after a failed rollback.

- [ ] **Step 5: Implement `switch_backend` in the tested order**

```python
def switch_backend(current, candidate, runner=None):
    validate_candidate(candidate, runner)
    set_transit_closed(True)
    try:
        stop_backend(current, runner)
        start_backend(candidate, runner)
        check_backend(candidate, runner)
        return backend_mark(candidate, runner)
    except Exception:
        stop_backend(candidate, runner, quiet=True)
        start_backend(current, runner)
        check_backend(current, runner)
        raise
```

The caller commits config/catalog only after success; on commit/apply failure it invokes the same reverse switch, restores prior files/mark/catalog, and only then opens transit.

For sing-box, starting the candidate necessarily swaps the checked private
temporary config into `SINGBOX_CONFIG` before restart. Keep the previous bytes
and mode in memory until commit; any start/health/commit failure atomically puts
them back before restarting the old backend. Refuse the operation, without
stopping anything, when runtime inspection finds an unmanaged default-route
tunnel.

- [ ] **Step 6: Implement fixed public operations under one lock**

```python
def vpn_add(body, runner=None): ...
def vpn_enable(tid, runner=None): ...
def vpn_disable(tid, runner=None): ...
def vpn_refresh(tid, runner=None, fetcher=None): ...
def vpn_delete(tid, runner=None): ...

def vpn_action(action, body, runner=None):
    with _vpn_lock:
        return {"add": vpn_add, "enable": vpn_enable,
                "disable": vpn_disable, "refresh": vpn_refresh}[action](...)
```

Add operations save new profiles disabled; active subscription refresh commits cache only after candidate check/restart; deleting one subscription rebuilds from remaining caches; stopping the last backend opens direct transit only after successful stop and catalog commit.

- [ ] **Step 7: Verify all rollback fixtures and commit**

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
git add panel.py
git commit -m "Переключать VPN с закрытым транзитом и откатом"
```

---

### Task 7: Startup reconciliation and crash detection

**Files:**
- Modify: `panel.py:3407-3420`
- Modify: `panel.py:4038-4075`
- Modify: `panel.py` tunnels section
- Test: `panel.py:selftest()`

- [ ] **Step 1: Write failing reconciliation asserts**

Cover missing secret, owned orphan `.tmp`, saved active backend that starts, saved active backend that fails without killing HTTP initialization, and runtime disappearance that closes transit.

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

- [ ] **Step 3: Implement bounded reconciliation**

```python
def reconcile_tunnels(runner=None):
    with _vpn_lock:
        migrate_legacy_subscription()
        ...  # only panel-owned tmp files and validated IDs

def vpn_poll(runner=None):
    with _vpn_lock:
        active = active_backend(load_tunnels())
        if active and not backend_state(active, runner)["active"]:
            set_transit_closed(True)
            record_safe_error(active["id"], T["vpnStopped"])
```

`main()` calls reconciliation inside `try/except` after configuration load and before serving; failure records a safe status and leaves the panel reachable. `poller()` calls `vpn_poll()` once per existing tick.

- [ ] **Step 4: Verify and commit**

```bash
python3 panel.py --selftest
git add panel.py
git commit -m "Восстанавливать и контролировать VPN backend"
```

---

### Task 8: Exact HTTP routing, body limits, and CSRF

**Files:**
- Modify: `panel.py:3172-3406`
- Test: `panel.py:selftest()`

- [ ] **Step 1: Build a socket-free handler fixture and failing security asserts**

Instantiate `H` with `object.__new__(H)`, `BytesIO` headers/body and a `BombReader` that raises on read. Assert unauthenticated mutation and bad CSRF never read the body. Add missing/nonnumeric/negative/oversize/Transfer-Encoding cases, exact `/api`/`/vpn`, `/apiX`/`/vpnX` 404, and POST-only logout.

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

Expected: current handler reads the body before auth and accepts fallback paths.

- [ ] **Step 3: Add session/CSRF/body helpers**

```python
_csrf_secret = secrets.token_bytes(32)

def csrf_for(token):
    return hmac.new(_csrf_secret, token.encode(), hashlib.sha256).hexdigest()

class H(BaseHTTPRequestHandler):
    def _session_token(self): ...
    def _csrf_ok(self):
        token = self._session_token()
        got = self.headers.get("X-CSRF-Token") or ""
        return bool(token) and hmac.compare_digest(got, csrf_for(token))
    def _read_body(self, limit=VPN_MAX): ...
    def _json_body(self): ...
```

Reject `Transfer-Encoding`; missing length with 411; malformed/negative with 400; `limit + 1` with 413. Authenticate, then check CSRF, then read authenticated mutation bodies. `/login` alone reads its limited body before auth.

- [ ] **Step 4: Replace prefix/fallback routing with exact parsed paths**

Use `path = urlparse(self.path).path`. Allow only:

- GET `/`, `/api`, `/vpn`;
- POST `/login`, `/logout`, `/settings`, `/reboot`, `/check`, `/update`, `/bypass`, `/api`, `/vpn`;
- DELETE `/api?ip=<validated address>`, `/vpn?id=<validated server id>`.

Unknown methods/paths return 404 and never mutate. Add `csrf` to authenticated `/api` and `/vpn`; `GET /vpn` uses `vpn_public()`. `POST /vpn` accepts only `add|enable|disable|refresh` and returns safe JSON.

- [ ] **Step 5: Verify non-disclosure and security regression**

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
```

- [ ] **Step 6: Commit**

```bash
git add panel.py
git commit -m "Защитить API туннелей точной маршрутизацией"
```

---

### Task 9: Tunnel UI in the existing settings sheet

**Files:**
- Modify: `panel.py:197-640` translation tables
- Modify: `panel.py:1800-3170` CSS/HTML/JS templates
- Test: `panel.py:selftest()`

- [ ] **Step 1: Write failing render/accessibility asserts**

```python
assert set(STRINGS["ru"]) == set(STRINGS["en"])
for needle in ('id="vpnList"', 'id="vpnKind"', 'id="vpnSecret"',
               'aria-live="polite"', 'autocomplete="off"'):
    assert needle in PAGE
assert "PrivateKey" not in PAGE and "PresharedKey" not in PAGE
```

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

- [ ] **Step 3: Add native controls using existing styles**

Inside Settings after Network add one `.group` with list rows, explicit type `<select>`, name input, HTTPS URL/exclude fields, config `<textarea>`, add button and `role="status" aria-live="polite"`. Reuse existing `.row`, `.btn`, `.dot`, `.hint`, `.sheet` styles; add only selectors that are missing.

- [ ] **Step 4: Add lazy `/vpn` loading and fixed UI actions**

Fetch `/vpn` only when Settings opens. Keep current CSRF token from `/api`; send it on every mutation. Render with `textContent`, never `innerHTML` for server data. After every response clear URL/config secret inputs. Confirm disabling the last active backend before POST.

```javascript
async function vpnCall(action, body = {}) {
  const r = await fetch('/vpn', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
    body: JSON.stringify({action, ...body})
  });
  vpnSecret.value = '';
  vpnUrl.value = '';
  ...
}
```

Convert logout to a form/button that sends CSRF-protected POST.

- [ ] **Step 5: Verify and commit**

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
git add panel.py
git commit -m "Добавить управление туннелями в интерфейс"
```

---

### Task 10: Installer, docs, and version

**Files:**
- Modify: `install.sh`
- Modify: `README.md`
- Modify: `README.ru.md`
- Modify: `docs/design.md`
- Modify: `docs/singbox.md`
- Modify: `panel.py:62`
- Test: `panel.py:selftest()` and shell checks

- [ ] **Step 1: Record a failing installer ownership check**

Run a focused `rg`/shell check proving the unattended update branch still fetches
a subscription or restarts sing-box. Do not put a source-tree-dependent check in
`panel.py --selftest`, because installed copies do not contain `install.sh`.

- [ ] **Step 2: Run and verify RED**

Run: `python3 panel.py --selftest`

- [ ] **Step 3: Remove installer-owned refresh after migration**

Keep copying `singbox_sub.py` and existing legacy data. Remove the update path that fetches/merges/restarts sing-box on every `--yes`; the panel owns post-migration refresh. Do not install WG/AWG packages from the installer.

- [ ] **Step 4: Document the exact behavior and limits in both languages**

Document CRUD, multiple subscriptions, one backend class, required tools, secrets, no hook support, direct-route warning, transactional rollback, poll-window crash limitation, and isolated live-test rule. Keep README EN/RU semantically identical. Update design/sing-box ownership rules.

- [ ] **Step 5: Bump version**

Change `VERSION = "1.5.0"` to `VERSION = "1.6.0"` and mention that a release tag must be exactly `v1.6.0`/`1.6.0` according to existing CI convention.

- [ ] **Step 6: Verify and commit**

```bash
python3 panel.py --selftest
python3 singbox_sub.py --selftest
bash -n install.sh
shellcheck install.sh
python3 panel.py --version
git add panel.py install.sh README.md README.ru.md docs/design.md docs/singbox.md
git commit -m "Документировать управление VPN из панели"
```

---

### Task 11: Full verification, review, and isolated internet tests

**Files:**
- Inspect: all changed files
- Do not commit: screenshot-derived config or any generated secret/log

- [ ] **Step 1: Run the complete local suite from `AGENTS.md`**

```bash
python3 panel.py --selftest
python3 panel.py --dump
python3 panel.py --version
python3 singbox_sub.py --selftest
bash -n install.sh
shellcheck install.sh
```

On isolated Linux only, validate generated nft syntax:

```bash
tmp=$(mktemp -d)
mkdir "$tmp/etc"
GWACL_DIR="$tmp/etc" python3 panel.py --dump > "$tmp/gwacl.nft"
nft -c -f "$tmp/gwacl.nft"
```

- [ ] **Step 2: Inspect environment without mutating the Mac network**

Record before/after read-only snapshots with `route -n get default`, `netstat -rn -f inet`, `scutil --nc list`, and `ifconfig`. Determine whether a separate Linux VM with `awg-quick`, `wg-quick`, sing-box, nft and NET_ADMIN is already available. Do not install or start a host VPN.

- [ ] **Step 3: Run screenshot config through parser/UI only**

Extract it to a `mktemp` file mode 0600 outside the repo without printing content. Validate add/render/delete against scratch storage, then remove the temp file. Do not start it: the same peer key may roam and disconnect the laptop. A live handshake requires a disposable peer with different keys.

- [ ] **Step 4: Run live tests only in a qualifying Linux guest**

Inside the guest verify `awg-quick strip`, enable, interface/routes, handshake/transfer, DNS, IPv4 HTTPS, optional IPv6, disable/re-enable, failed candidate rollback, and transit closure after simulated crash. Use a user-provided subscription URL or controlled local fixture only.

- [ ] **Step 5: If isolation/tools/peer are absent, record an environment block**

Do not weaken the safety constraint. Report exactly which binary/capability/disposable peer is missing and which automatic/parser/rollback tests passed instead.

- [ ] **Step 6: Perform two final reviews**

Run a spec-compliance review and a code-quality/security review. Fix findings with a new failing assert first, rerun the full suite, then inspect:

```bash
git status --short
git diff --check c6622fb..HEAD
git log --oneline -12
```

Confirm `AGENTS.md` remains untracked and no secret-bearing file is tracked.

- [ ] **Step 7: Final commit if review produced fixes**

```bash
git add panel.py singbox_sub.py install.sh README.md README.ru.md docs/design.md docs/singbox.md
git commit -m "Завершить проверку управления VPN"
```
