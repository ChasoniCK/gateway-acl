#!/usr/bin/env python3
"""Turn subscription links into sing-box outbounds.

The installer uses the CLI for legacy setup and the panel imports the same
parser for managed profiles. A URL is passed directly only by the legacy CLI;
the panel keeps it in its private tunnel storage and never puts it in argv.

It prints a complete config to stdout and touches nothing on disk, so the caller
keeps the backup, the `sing-box check` and the rollback. Given `--base`, only two
things in that config change: outbounds tagged `sub-*`, and the member list of
the selector group. Routing rules, DNS, inbounds and hand-written outbounds come
out exactly as they went in — a config tuned by hand over months must survive a
subscription refresh.

    python3 singbox_sub.py --url URL --base /etc/sing-box/config.json > new.json
    python3 singbox_sub.py --url URL --iface eno1 > new.json   # a fresh install
    python3 singbox_sub.py --url URL --exclude 'Росс|Russia' > new.json
    python3 singbox_sub.py --selftest
"""

import argparse
import base64
import json
import re
import sys
import time
import urllib.request
from urllib.parse import parse_qsl, unquote, urlsplit

GROUP = "proxy"          # the tag every route rule in a generated config points at
DIRECT = "direct"
OWNED = "sub-"           # what this program is allowed to delete and rewrite
TIMEOUT = 20
SUB_BODY_MAX = 128 << 10

# sing-box does not implement Xray's xhttp transport and shows no sign of
# starting to: 1.13 and the 1.14 betas both know exactly five (http, ws, quic,
# grpc, httpupgrade) and two pull requests adding XHTTP were closed unmerged.
# Upgrading is not the fix, so the node is skipped — loudly, never silently: one
# quietly missing from the group is a slower tunnel with no explanation.
TRANSPORTS = ("tcp", "")


class Unsupported(Exception):
    """A node this sing-box cannot be told to use. Carries the reason shown."""


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Keep a secret subscription request on its original HTTPS host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise ValueError("unsafe subscription redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(req, timeout):
    return urllib.request.build_opener(SameHostRedirect()).open(req, timeout=timeout)


def _b64(s):
    """Base64 in any of the four shapes a subscription uses: standard or
    URL-safe alphabet, padded or not."""
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    # validate=True, or a plain-text subscription "decodes" into rubbish:
    # b64decode drops every character outside the alphabet by default, and the
    # list of links would come back empty with nothing said about it.
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def fetch(url, timeout=TIMEOUT, limit=SUB_BODY_MAX):
    """The subscription body. The User-Agent matters: providers hand out Clash
    YAML to some clients and the plain list to others."""
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname:
        raise ValueError("subscription URL must use HTTPS")
    if timeout <= 0 or limit < 1:
        raise ValueError("invalid subscription fetch limits")
    deadline = time.monotonic() + timeout
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box/1.13"})
    try:
        with _open(req, max(0.001, deadline - time.monotonic())) as r:
            final = urlsplit(r.geturl())
            if final.scheme != "https" or final.hostname != p.hostname:
                raise ValueError("unsafe subscription redirect")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("subscription download timed out")
            sock = getattr(getattr(getattr(r, "fp", None), "raw", None),
                           "_sock", None)
            if sock is not None:
                sock.settimeout(remaining)
            body = r.read(limit + 1)
            if time.monotonic() > deadline:
                raise ValueError("subscription download timed out")
            if len(body) > limit:
                raise ValueError("subscription response is too large")
            return body.decode("utf-8", "replace")
    except ValueError:
        raise
    except Exception:
        raise ValueError("subscription download failed") from None


def links(body):
    """The `scheme://` lines of a subscription, whether or not it is base64.

    Decoding is tried first and its failure is not an error: some providers
    answer with the bare list.
    """
    try:
        body = _b64(body).decode("utf-8", "replace")
    except Exception:
        pass
    return [l.strip() for l in body.splitlines() if "://" in l]


def _tls(q, host):
    """The tls block for a link, or None when the node is plaintext."""
    sec = q.get("security", "none")
    if sec in ("", "none"):
        return None
    tls = {"enabled": True, "server_name": q.get("sni") or host}
    if q.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
    if sec == "reality":
        if not q.get("pbk"):
            raise Unsupported("reality without a public key")
        tls["reality"] = {"enabled": True, "public_key": q["pbk"],
                          "short_id": q.get("sid", "")}
    elif sec != "tls":
        raise Unsupported(f"security {sec}")
    return tls


def _vless(p, q, tag):
    kind = q.get("type", "tcp")
    if kind not in TRANSPORTS:
        raise Unsupported(f"transport {kind}")
    if not p.username:
        raise Unsupported("no uuid")
    o = {"type": "vless", "tag": tag, "server": p.hostname,
         "server_port": p.port or 443, "uuid": unquote(p.username)}
    if q.get("flow"):
        o["flow"] = q["flow"]
    tls = _tls(q, p.hostname)
    if tls:
        o["tls"] = tls
    return o


def _ss(p, tag):
    """Shadowsocks in both shapes: SIP002 (`b64(method:pass)@host:port`) and the
    older whole-thing-in-base64 form."""
    if p.username and p.hostname:
        method, _, password = _b64(unquote(p.username)).decode(
            "utf-8", "replace").partition(":")
        host, port = p.hostname, p.port
    else:
        body = _b64(p.netloc).decode("utf-8", "replace")
        head, _, hostport = body.rpartition("@")
        method, _, password = head.partition(":")
        host, _, port = hostport.partition(":")
    if not (method and host and port):
        raise Unsupported("unreadable shadowsocks link")
    return {"type": "shadowsocks", "tag": tag, "server": host,
            "server_port": int(port), "method": method, "password": password}


def outbound(link, tag):
    """One subscription link as one sing-box outbound.

    Raises Unsupported for anything this sing-box would refuse to load; the
    caller reports it and carries on with the rest of the list.
    """
    p = urlsplit(link)
    q = dict(parse_qsl(p.query))
    if p.scheme == "vless":
        return _vless(p, q, tag)
    if p.scheme == "ss":
        return _ss(p, tag)
    raise Unsupported(f"protocol {p.scheme}")


def node_name(link):
    """What the provider called the node — the flag and country in practice."""
    p = urlsplit(link)
    return " ".join((unquote(p.fragment).strip() or p.hostname or "node").split())


def tag_for(link, taken, prefix=OWNED):
    """An ownership prefix plus the provider's node name, made unique.

    The prefix is the ownership mark — it is the whole basis on which a refresh
    knows which outbounds are its own to delete. The name is kept because it is
    what shows up in the journal when a node misbehaves.
    """
    name = node_name(link)
    tag = prefix + name
    n = 2
    while tag in taken:
        tag, n = f"{prefix}{name} {n}", n + 1
    taken.add(tag)
    return tag


def convert(body, warn=lambda s: None, exclude=None, prefix=OWNED, taken=None):
    """Every usable node of a subscription, in the order the provider listed.

    `exclude` is a regular expression matched against the provider's name for
    the node, and it exists because the group is a `urltest`: it picks by
    latency, so a domestic node is always the fastest and therefore always the
    one chosen — the tunnel then exits in the country it was meant to leave.
    Nothing here can tell where a node is; only its name can, and only the
    person reading it knows what the names mean.
    """
    try:
        rx = re.compile(exclude, re.I) if exclude else None
    except re.error as e:  # the caller typed it; a traceback is not an answer
        raise ValueError(f"--exclude: неверное регулярное выражение / "
                         f"bad regular expression: {e}") from None
    outs = []
    taken = taken if taken is not None else set()
    for link in links(body):
        name = node_name(link)
        if rx and rx.search(name):
            warn(f"{name}: исключён / excluded")
            continue
        try:
            outs.append(outbound(link, tag_for(link, taken, prefix)))
        except Unsupported as e:
            warn(f"{urlsplit(link).scheme}://{urlsplit(link).hostname}: {e}")
        except Exception as e:  # a malformed link is one node, not the run
            warn(f"unreadable link: {e}")
    return outs


def merge(base, outs, group=GROUP):
    """The config with its `sub-*` outbounds replaced and nothing else moved.

    Hand-written outbounds are left in the file even when they leave the group:
    deleting an outbound a route rule still names would stop sing-box from
    loading at all, and this program cannot know which of them you still want.
    """
    c = json.loads(json.dumps(base))          # the caller's dict stays untouched
    kept = [o for o in c.get("outbounds", []) if not str(o.get("tag", "")).startswith(OWNED)]
    tags = [o["tag"] for o in outs]
    for o in kept:
        if o.get("tag") == group:
            o["outbounds"] = tags
            break
    else:
        kept.insert(0, {"type": "urltest", "tag": group, "outbounds": tags,
                        "url": "https://www.gstatic.com/generate_204",
                        "interval": "3m", "tolerance": 50})
    c["outbounds"] = kept + outs
    return c


def fresh(outs, iface, group=GROUP):
    """A config for a host that has none: the shape docs/singbox.md describes.

    tun with auto_route and auto_redirect, so traffic forwarded from the LAN is
    intercepted too; DNS hijacked into the tunnel; everything not local sent to
    the group. `bind_interface` on direct is what keeps the tunnel's own packets
    from being fed back into it.
    """
    return {
        "log": {"level": "warn", "timestamp": True},
        # The 1.12 server format, not the older `address` string: sing-box 1.13
        # refuses to start on the legacy one without an environment variable,
        # and 1.14 drops it altogether.
        "dns": {
            "servers": [
                {"type": "https", "tag": "remote", "server": "1.1.1.1",
                 "detour": group},
                {"type": "udp", "tag": "local", "server": "1.1.1.1",
                 "detour": DIRECT},
            ],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            "address": ["172.19.0.1/30"],
            "auto_route": True, "auto_redirect": True, "strict_route": True,
        }],
        # Group, then everything not from the subscription, then the nodes —
        # the order merge() produces. They have to agree: the installer decides
        # whether to restart sing-box by comparing bytes, and a config that
        # merely reshuffles itself would restart the tunnel on every run.
        "outbounds": [
            {"type": "urltest", "tag": group, "outbounds": [o["tag"] for o in outs],
             "url": "https://www.gstatic.com/generate_204",
             "interval": "3m", "tolerance": 50,
             "interrupt_exist_connections": False},
            {"type": DIRECT, "tag": DIRECT, "bind_interface": iface},
            *outs,
        ],
        "route": {
            # Sniffing is a route action since 1.12, not an inbound field. It
            # comes first: the rules below it are allowed to look at a domain,
            # and 300 ms is the timeout a pre-opened silent connection needs.
            "rules": [
                {"action": "sniff", "timeout": "300ms"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": DIRECT},
            ],
            "final": group,
            # Which resolver turns a server's domain into an address when a
            # connection is dialled. Required since 1.12: without it sing-box
            # refuses to start rather than guess.
            "default_domain_resolver": {"server": "local"},
            "auto_detect_interface": True,
        },
        "experimental": {"cache_file": {"enabled": True}},
    }


def build(body, base=None, iface=None, warn=lambda s: None, exclude=None,
          prefix=OWNED, taken=None):
    outs = convert(body, warn, exclude, prefix, taken)
    if not outs:
        raise ValueError("подписка не дала ни одного пригодного узла / "
                         "the subscription yielded no usable node")
    return merge(base, outs) if base is not None else fresh(outs, iface or "eth0"), outs


# --- selftest ---------------------------------------------------------------

def selftest():
    """Bare asserts, no network. Same shape as panel.py's."""
    global _open
    for bad_url in ("data:text/plain,vless://secret", "file:///etc/passwd",
                    "http://provider.example/sub"):
        try:
            fetch(bad_url)
            raise AssertionError("subscription fetch must be HTTPS only")
        except ValueError:
            pass

    class Response:
        def __init__(self, body, final="https://provider.example/sub"):
            self.body, self.final = body, final

        def __enter__(self):
            return self

        def __exit__(self, *unused):
            pass

        def read(self, size):
            return self.body[:size]

        def geturl(self):
            return self.final

    real_open = _open
    real_clock = time.monotonic
    try:
        _open = lambda req, timeout: Response(b"123456789")
        try:
            fetch("https://provider.example/sub", limit=8)
            raise AssertionError("oversized subscription must not be truncated")
        except ValueError:
            pass
        _open = lambda req, timeout: Response(b"12345678")
        assert fetch("https://provider.example/sub", limit=8) == "12345678"
        _open = lambda req, timeout: Response(
            b"ok", "https://redirected.example/sub")
        try:
            fetch("https://provider.example/sub", limit=8)
            raise AssertionError("cross-host redirect must be rejected")
        except ValueError:
            pass
        _open = lambda req, timeout: (_ for _ in ()).throw(
            RuntimeError("https://provider.example/secret-token"))
        try:
            fetch("https://provider.example/secret-token", limit=8)
            raise AssertionError("download failure must stay a failure")
        except ValueError as e:
            assert "secret-token" not in str(e)
        ticks = iter((0.0, 0.0, 2.0))
        time.monotonic = lambda: next(ticks, 2.0)
        _open = lambda req, timeout: Response(b"ok")
        try:
            fetch("https://provider.example/sub", timeout=1, limit=8)
            raise AssertionError("subscription fetch needs one overall deadline")
        except ValueError:
            pass
    finally:
        _open = real_open
        time.monotonic = real_clock
    for redirected in ("https://other.example/sub",
                       "http://provider.example/sub"):
        try:
            SameHostRedirect().redirect_request(
                type("Req", (), {"full_url": "https://provider.example/sub"})(),
                None, 302, "", {}, redirected)
            raise AssertionError("unsafe redirect must be rejected before opening")
        except ValueError:
            pass

    pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    uid = "5eb99d66-0000-0000-0000-000000000000"
    vision = (f"vless://{uid}@a.example:9443?encryption=none&flow=xtls-rprx-vision"
              f"&security=reality&sni=s.example&fp=randomized&pbk={pbk}&sid=ab12"
              "&type=tcp#%F0%9F%87%B7%F0%9F%87%BA%20Rossiya")
    o = outbound(vision, "sub-x")
    assert o == {"type": "vless", "tag": "sub-x", "server": "a.example",
                 "server_port": 9443, "uuid": uid, "flow": "xtls-rprx-vision",
                 "tls": {"enabled": True, "server_name": "s.example",
                         "utls": {"enabled": True, "fingerprint": "randomized"},
                         "reality": {"enabled": True, "public_key": pbk,
                                     "short_id": "ab12"}}}, o
    assert tag_for(vision, set()) == "sub-🇷🇺 Rossiya", "the provider's name is the tag"
    taken = {"sub-n"}
    assert tag_for(f"vless://{uid}@a.example:443#n", taken) == "sub-n 2", \
        "two nodes of one name are two tags"

    # Two enabled sources share one namespace, but each keeps an ownership
    # prefix so refreshing or deleting one cannot rewrite the other.
    taken = set()
    one = convert(vision, prefix="sub-t000000000001-", taken=taken)
    two = convert(vision, prefix="sub-t000000000002-", taken=taken)
    assert one[0]["tag"].startswith("sub-t000000000001-")
    assert two[0]["tag"].startswith("sub-t000000000002-")
    assert one[0]["tag"] != two[0]["tag"]
    try:
        convert(vision, exclude="[")
        raise AssertionError("bad regex must be an API-safe error")
    except ValueError:
        pass

    # sing-box has no xhttp: it must be reported, not written into the config.
    said = []
    xh = f"vless://{uid}@a.example:8443?security=reality&pbk={pbk}&type=xhttp&path=/x#x"
    try:
        outbound(xh, "sub-x")
        raise AssertionError("xhttp must not convert")
    except Unsupported:
        pass
    assert convert(xh, said.append) == [] and said, "a skipped node is announced"

    secret = base64.b64encode(b"2022-blake3-aes-256-gcm:pw==").decode()
    sip002 = f"ss://{secret}@b.example:8388#fi"
    legacy = "ss://" + base64.b64encode(
        b"2022-blake3-aes-256-gcm:pw==@b.example:8388").decode() + "#fi"
    want = {"type": "shadowsocks", "tag": "t", "server": "b.example",
            "server_port": 8388, "method": "2022-blake3-aes-256-gcm",
            "password": "pw=="}
    assert outbound(sip002, "t") == want, outbound(sip002, "t")
    assert outbound(legacy, "t") == want, "the older shape is the same node"

    plain = f"{vision}\n{sip002}\n"
    assert links(plain) == links(base64.b64encode(plain.encode()).decode()), \
        "base64 or not is the same list"
    assert len(convert(plain)) == 2

    # A urltest group picks by latency, so a node at home always wins and the
    # tunnel exits where it was meant to leave. Excluded means absent from the
    # file, not merely out of the group: an outbound nothing points at is a node
    # nothing can fall back onto by accident.
    said = []
    kept = convert(plain, said.append, "Rossiya")
    assert [o["tag"] for o in kept] == ["sub-fi"], kept
    assert said and "Rossiya" in said[0], "an excluded node is announced too"
    assert len(convert(plain, exclude="россия")) == 2, "no match excludes nothing"
    assert convert(plain, exclude="i") == [], "the regex may take everything"

    # The whole point of merge(): everything that is not ours comes out identical.
    base = {"dns": {"servers": [{"address": "1.1.1.1"}]},
            "inbounds": [{"type": "tun", "tag": "tun-in"}],
            "outbounds": [
                {"type": "urltest", "tag": GROUP, "outbounds": ["hand"],
                 "interval": "1m", "tolerance": 42},
                {"type": "vless", "tag": "hand", "server": "old.example"},
                {"type": "vless", "tag": "sub-gone", "server": "gone.example"},
                {"type": "direct", "tag": "direct", "bind_interface": "eno1"}],
            "route": {"rules": [{"action": "sniff"}], "final": GROUP}}
    keep = json.dumps({k: v for k, v in base.items() if k != "outbounds"}, sort_keys=True)
    got = merge(base, convert(plain))
    assert json.dumps({k: v for k, v in got.items() if k != "outbounds"},
                      sort_keys=True) == keep, "only outbounds may change"
    tags = [o["tag"] for o in got["outbounds"]]
    assert "sub-gone" not in tags, "a node the subscription dropped goes away"
    assert "hand" in tags, "a hand-written outbound is never deleted"
    grp = next(o for o in got["outbounds"] if o["tag"] == GROUP)
    assert grp["outbounds"] == [o["tag"] for o in convert(plain)], \
        "the group holds exactly the subscription"
    assert grp["tolerance"] == 42, "the group's own settings are the user's"
    assert base["outbounds"][2]["tag"] == "sub-gone", "the caller's dict is untouched"

    both = merge(base, one + two)
    grp = next(o for o in both["outbounds"] if o["tag"] == GROUP)
    assert grp["outbounds"] == [o["tag"] for o in one + two]
    only_two = merge(both, two)
    tags = [o["tag"] for o in only_two["outbounds"]]
    assert not any(t.startswith("sub-t000000000001-") for t in tags)
    assert all(o["tag"] in tags for o in two), \
        "removing one source must leave the other byte-for-byte"

    empty = merge({"outbounds": [{"type": "direct", "tag": "direct"}]}, convert(plain))
    assert any(o["tag"] == GROUP and o["type"] == "urltest" for o in empty["outbounds"]), \
        "a config without a group gets one"

    f = fresh(convert(plain), "eno1")
    assert f["route"]["final"] == GROUP and f["inbounds"][0]["auto_redirect"] is True
    # The three things sing-box 1.13 refuses to start without. Each of them was
    # found by `sing-box check`, one FATAL at a time; a template that regresses
    # to the 1.11 shape installs a gateway that never comes up.
    assert all("type" in d for d in f["dns"]["servers"]), "the 1.12 DNS format"
    assert f["route"]["default_domain_resolver"], "dialling needs a resolver"
    assert "sniff" not in f["inbounds"][0], "sniffing is a route action now"
    assert f["outbounds"][1] == {"type": "direct", "tag": "direct",
                                 "bind_interface": "eno1"}
    # A fresh config fed back through merge() has to come out identical, or the
    # second run of the installer restarts sing-box for nothing.
    assert merge(f, convert(plain)) == f, "generate then merge is a fixed point"
    assert [o["tag"] for o in f["outbounds"] if o["tag"].startswith(OWNED)] == \
        f["outbounds"][0]["outbounds"], "the group lists every node it was given"
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url")
    ap.add_argument("--base", help="existing config to keep; omit for a fresh one")
    ap.add_argument("--iface", default="eth0", help="what direct binds to when fresh")
    ap.add_argument("--exclude", help="regex; nodes whose provider name matches "
                                      "are left out of the config entirely")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if not a.url:
        ap.error("--url is required")
    base = None
    if a.base:
        with open(a.base) as f:
            base = json.load(f)
    warned = []
    try:
        cfg, outs = build(fetch(a.url), base, a.iface, warned.append, a.exclude)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    for w in warned:
        print(f"  пропущен / skipped: {w}", file=sys.stderr)
    print(f"  узлов / nodes: {len(outs)}", file=sys.stderr)
    json.dump(cfg, sys.stdout, indent=2, ensure_ascii=False)
    print()


if __name__ == "__main__":
    main()
