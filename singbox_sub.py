#!/usr/bin/env python3
"""Turn a subscription link into sing-box outbounds.

This is the installer's tool, not the panel's: `install.sh` runs it, `panel.py`
never imports it. The panel still does not read, write or care about a sing-box
config — see docs/singbox.md. The link itself is kept in $GWACL_DIR/sub.url,
mode 0600, and is never copied into the panel's own config or its pages.

It prints a complete config to stdout and touches nothing on disk, so the caller
keeps the backup, the `sing-box check` and the rollback. Given `--base`, only two
things in that config change: outbounds tagged `sub-*`, and the member list of
the selector group. Routing rules, DNS, inbounds and hand-written outbounds come
out exactly as they went in — a config tuned by hand over months must survive a
subscription refresh.

    python3 singbox_sub.py --url URL --base /etc/sing-box/config.json > new.json
    python3 singbox_sub.py --url URL --iface eno1 > new.json   # a fresh install
    python3 singbox_sub.py --selftest
"""

import argparse
import base64
import json
import sys
import urllib.request
from urllib.parse import parse_qsl, unquote, urlsplit

GROUP = "proxy"          # the tag every route rule in a generated config points at
DIRECT = "direct"
OWNED = "sub-"           # what this program is allowed to delete and rewrite
TIMEOUT = 20

# sing-box does not implement Xray's xhttp transport and shows no sign of
# starting to: 1.13 and the 1.14 betas both know exactly five (http, ws, quic,
# grpc, httpupgrade) and two pull requests adding XHTTP were closed unmerged.
# Upgrading is not the fix, so the node is skipped — loudly, never silently: one
# quietly missing from the group is a slower tunnel with no explanation.
TRANSPORTS = ("tcp", "")


class Unsupported(Exception):
    """A node this sing-box cannot be told to use. Carries the reason shown."""


def _b64(s):
    """Base64 in any of the four shapes a subscription uses: standard or
    URL-safe alphabet, padded or not."""
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    # validate=True, or a plain-text subscription "decodes" into rubbish:
    # b64decode drops every character outside the alphabet by default, and the
    # list of links would come back empty with nothing said about it.
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def fetch(url, timeout=TIMEOUT):
    """The subscription body. The User-Agent matters: providers hand out Clash
    YAML to some clients and the plain list to others."""
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box/1.13"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(1 << 22).decode("utf-8", "replace")


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


def tag_for(link, taken):
    """`sub-` plus the name the provider gave the node, made unique.

    The prefix is the ownership mark — it is the whole basis on which a refresh
    knows which outbounds are its own to delete. The name is kept because it is
    what shows up in the journal when a node misbehaves.
    """
    name = unquote(urlsplit(link).fragment).strip() or urlsplit(link).hostname or "node"
    name = " ".join(name.split())
    tag = OWNED + name
    n = 2
    while tag in taken:
        tag, n = f"{OWNED}{name} {n}", n + 1
    taken.add(tag)
    return tag


def convert(body, warn=lambda s: None):
    """Every usable node of a subscription, in the order the provider listed."""
    outs, taken = [], set()
    for link in links(body):
        try:
            outs.append(outbound(link, tag_for(link, taken)))
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


def build(body, base=None, iface=None, warn=lambda s: None):
    outs = convert(body, warn)
    if not outs:
        raise SystemExit("подписка не дала ни одного пригодного узла / "
                         "the subscription yielded no usable node")
    return merge(base, outs) if base is not None else fresh(outs, iface or "eth0"), outs


# --- selftest ---------------------------------------------------------------

def selftest():
    """Bare asserts, no network. Same shape as panel.py's."""
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
    cfg, outs = build(fetch(a.url), base, a.iface, warned.append)
    for w in warned:
        print(f"  пропущен / skipped: {w}", file=sys.stderr)
    print(f"  узлов / nodes: {len(outs)}", file=sys.stderr)
    json.dump(cfg, sys.stdout, indent=2, ensure_ascii=False)
    print()


if __name__ == "__main__":
    main()
