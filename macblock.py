#!/usr/bin/env python3
"""
macblock - a small, self-updating, adaptive DNS ad/tracker blocker for macOS.

How it works
  * Runs a DNS server on 127.0.0.1:53, then drops root. guard.sh (root) points
    macOS at it while it answers and restores your DNS when it doesn't.
  * Blocked names get 0.0.0.0 / :: back; everything else is forwarded over
    DNS-over-HTTPS, falling back to the network's own DNS when that fails.
  * Blocklists are re-downloaded every `update_hours` and hot-reloaded.
  * Adaptive layer:
      - CNAME uncloaking: if an allowed name's answer CNAMEs to a blocked
        tracker, the name is blocked and remembered ("learned").
      - Heuristic scoring: unknown names that look like trackers land in a
        review queue (`macblock review`). Optional auto-block for high scores.

Commands (changes need sudo):
  macblock run                 run the DNS server (launchd does this)
  macblock update              download + merge blocklists now
  macblock status              is it running, counts, top blocked
  macblock recent              the last names blocked (to fix a broken page)
  macblock review [--all]      show suspicious domains waiting for a decision
  macblock block DOMAIN...     always block (and everything under it)
  macblock allow DOMAIN...     never block (fixes a broken site)
  macblock test DOMAIN         show what macblock would do with a name
  macblock pause [MINUTES]     stop blocking for a while (default 10)
  macblock resume              end a pause
  macblock dns on|off|toggle   point macOS DNS at macblock / restore previous
"""
import argparse
import http.client
import json
import math
import os
import pwd
import re
import signal
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, OrderedDict, deque
from pathlib import Path

HOME = Path(os.environ.get("MACBLOCK_HOME", "/usr/local/macblock"))
DATA = HOME / "data"                      # writable by the unprivileged daemon
CONFIG = HOME / "config.json"
USER_ALLOW = HOME / "allowlist.txt"       # yours: never block
USER_DENY = HOME / "denylist.txt"         # yours: always block
ENABLED = HOME / "enabled"                # written by guard.sh
PAUSE = HOME / "pause_until"
GUARD = HOME / "guard.sh"
BLOCKLIST = DATA / "blocklist.txt"        # merged downloaded lists (generated)
LIST_ALLOW = DATA / "list_allow.txt"      # @@ exceptions from lists (generated)
DB = DATA / "state.db"
PIDFILE = DATA / "macblock.pid"
STATS = DATA / "stats.json"
RECENT = DATA / "recent.json"
LOGFILE = DATA / "macblock.log"
LOG_MAX_BYTES = 1_000_000

DEFAULT_CONFIG = {
    "listen": "127.0.0.1",
    "port": 53,
    "user": "nobody",        # the daemon switches to this after binding the port
    # https:// is DNS-over-HTTPS; a bare address is plain, unencrypted DNS
    "upstreams": ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"],
    # use the network's (DHCP) DNS for local names, names the upstreams don't
    # know, and when no upstream is reachable (captive portals)
    "network_fallback": True,
    "update_hours": 24,
    "lists": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    ],
    "review_score": 3,       # score at which a name enters the review queue
    "auto_block": False,     # block high-scoring names automatically?
    "auto_block_score": 6,
    "auto_block_min_hits": 3,
    "cache_size": 10000,
    "learned_days": 30,      # CNAME-learned blocks are re-checked after this
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
_log_file = None          # set in the daemon; CLI commands print to the terminal
_log_lock = threading.Lock()


def log(*a):
    line = " ".join([time.strftime("%Y-%m-%d %H:%M:%S"), *map(str, a)])
    if _log_file is None:
        print(line, flush=True)
        return
    with _log_lock:
        try:
            if _log_file.exists() and _log_file.stat().st_size > LOG_MAX_BYTES:
                os.replace(_log_file, str(_log_file) + ".1")      # keep one old file
            with open(_log_file, "a") as f:
                f.write(line + "\n")
        except OSError as e:
            print(line, f"(log file: {e})", file=sys.stderr, flush=True)


# lists that moved; existing config.json files still name the old address
MOVED_LISTS = {
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt":
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG.exists():
        cfg.update(json.loads(CONFIG.read_text()))
    else:
        try:
            HOME.mkdir(parents=True, exist_ok=True)
            CONFIG.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        except PermissionError:
            pass                    # not root: run on the defaults
    cfg["lists"] = [MOVED_LISTS.get(u, u) for u in cfg["lists"]]
    return cfg


def read_set(path):
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip().lower().rstrip(".")
        if line:
            out.add(line)
    return out


def write_atomic(path, text):
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def append_line(path, line):
    with open(path, "a") as f:
        f.write(line + "\n")


def match(name, domains):
    """Return the entry in `domains` that covers `name` (itself or a parent)."""
    labels = name.split(".")
    for i in range(len(labels) - 1):          # never match a bare TLD
        cand = ".".join(labels[i:])
        if cand in domains:
            return cand
    return None


TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "ne.jp", "co.ke", "or.ke", "ac.ke", "go.ke", "com.br",
    "com.cn", "com.mx", "co.za", "co.in", "com.tr", "com.sg", "com.hk",
}


def base_domain(name):
    """Rough registrable domain (good enough without a full public-suffix list)."""
    p = name.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def split_upstream(up):
    """'1.1.1.1', '1.1.1.1:5353', '2606:4700::1111' or '[2606:4700::1111]:53'."""
    if up.startswith("["):
        host, _, rest = up[1:].partition("]")
        return host, int(rest.lstrip(":") or 53)
    if up.count(":") > 1:
        return up, 53
    host, _, port = up.partition(":")
    return host, int(port or 53)


def remove_entry(path, domain):
    """Drop `domain` from a user list, keeping comments and other lines."""
    if domain not in read_set(path):
        return False
    keep = [l for l in path.read_text().splitlines()
            if l.split("#", 1)[0].strip().lower().rstrip(".") != domain]
    write_atomic(path, "".join(l + "\n" for l in keep))
    return True


def pid_alive():
    try:
        pid = int(PIDFILE.read_text())
        os.kill(pid, 0)
        return pid
    except PermissionError:      # alive, but owned by root and we are not
        return pid
    except (OSError, ValueError):
        return None


def signal_reload():
    pid = pid_alive()
    if pid and pid > 1:
        try:
            os.kill(pid, signal.SIGHUP)
            return True
        except PermissionError:
            print("Couldn't signal the daemon - run with sudo.")
    return False


# --------------------------------------------------------------------------- #
# list parsing / updating
# --------------------------------------------------------------------------- #
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$"
)
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "::0", "0:0:0:0:0:0:0:0"}
IGNORE = {"localhost", "localhost.localdomain", "local", "broadcasthost",
          "ip6-localhost", "ip6-loopback", "0.0.0.0"}
COSMETIC = re.compile(r"#[@?$%]?#")


def _clean(d):
    d = d.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if d in IGNORE or not DOMAIN_RE.match(d):
        return None
    return d


def parse_list(text):
    """Understands hosts files, plain domain lists, and DNS-style adblock rules."""
    block, allow = set(), set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#![":
            continue
        if COSMETIC.search(line):                 # example.com##.ad  -> page rule, skip
            continue
        if line.startswith("@@||") or line.startswith("||"):
            exception = line.startswith("@@")
            body = line[4:] if exception else line[2:]
            opts = ""
            if "$" in body:
                body, opts = body.split("$", 1)
            if opts and opts not in ("important",):
                continue                              # third-party, client=... etc.
            if not body.endswith("^") and not body.endswith("^|"):
                continue
            d = _clean(body.rstrip("|").rstrip("^"))
            if d:
                (allow if exception else block).add(d)
            continue
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2 and parts[0] in HOSTS_IPS:
            for p in parts[1:]:
                d = _clean(p)
                if d:
                    block.add(d)
        elif len(parts) == 1:
            d = _clean(parts[0])
            if d:
                block.add(d)
    return block, allow


def fetch(url):
    if url.startswith("/"):
        return Path(url).read_text(errors="ignore")
    req = urllib.request.Request(url, headers={"User-Agent": "macblock/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="ignore")


def collapse(domains):
    """Drop names a listed parent already covers; saves memory, same verdicts."""
    return {d for d in domains if match(d.partition(".")[2], domains) is None}


def update_lists(cfg):
    block, allow = set(), set()
    ok = 0
    for url in cfg["lists"]:
        try:
            b, a = parse_list(fetch(url))
            block |= b
            allow |= a
            ok += 1
            log(f"list ok   {len(b):>7} domains  {url}")
        except Exception as e:
            log(f"list FAIL {url}: {e}")
    if ok == 0 or len(block) < 100:
        log("update aborted - keeping previous blocklist")
        return False
    block -= allow
    block = collapse(block)
    header = f"# generated by macblock {time.ctime()} from {ok} lists\n"
    DATA.mkdir(parents=True, exist_ok=True)
    write_atomic(BLOCKLIST, header + "\n".join(sorted(block)) + "\n")
    write_atomic(LIST_ALLOW, header + "\n".join(sorted(allow)) + "\n")
    log(f"blocklist updated: {len(block)} domains, {len(allow)} list exceptions")
    return True


# --------------------------------------------------------------------------- #
# heuristics
# --------------------------------------------------------------------------- #
STRONG_TOKENS = {"ad", "ads", "adv", "track", "tracker", "pixel", "beacon",
                 "telemetry", "analytics", "metrics", "affiliate", "clicks", "click", "banner", "banners",
                 "adserver", "doubleclick", "crashlytics", "sentry", "tracking"}
STRONG_SUBSTR = ("adserv", "adsystem", "adservice", "doubleclick", "telemetry",
                 "analytics", "tracking", "tracker", "pixel", "beacon",
                 "metrics", "advert", "syndication", "insight")
WEAK_TOKENS = {"log", "logs", "events", "event", "collect", "collector", "sdk",
               "measure", "sync", "rum", "ping", "data", "promo",
               "stats", "stat", "tag", "tags"}


def entropy(s):
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def score_name(name, blocked_bases, cname_targets=()):
    """Return (score, [reasons]). Higher = more tracker-like."""
    score, why = 0, []
    sub = name[: -len(base_domain(name))].rstrip(".")
    tokens = [t for t in re.split(r"[.\-_\d]+", name) if t]

    strong = {t for t in tokens if t in STRONG_TOKENS}
    strong |= {s for s in STRONG_SUBSTR for t in tokens if s in t and t not in STRONG_TOKENS}
    if strong:
        score += min(6, 3 * len(strong))
        why.append("keyword:" + ",".join(sorted(strong)))
    weak = {t for t in tokens if t in WEAK_TOKENS}
    if weak:
        score += 1
        why.append("weak:" + ",".join(sorted(weak)))

    for label in sub.split(".") if sub else []:
        if len(label) >= 12 and entropy(label) > 3.5 and any(ch.isdigit() for ch in label):
            score += 2
            why.append("random-label")
            break

    if name.count(".") >= 4:
        score += 1
        why.append("deep")

    # only corroborating evidence: google.com etc. all have a blocked subdomain
    if score and base_domain(name) in blocked_bases:
        score += 2
        why.append("sibling-of-blocked")

    for t in cname_targets:
        if base_domain(t) != base_domain(name):
            score += 2
            why.append(f"cname->{t}")
            break
    return score, why


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, path, readonly=False):
        self.lock = threading.Lock()
        # Rollback journal, not WAL: non-root users must be able to read the
        # daemon's database, and WAL readers need write access to its directory.
        if readonly:
            self.db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True,
                                      check_same_thread=False)
            return
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS candidates(
                domain TEXT PRIMARY KEY, score INT, reasons TEXT,
                first_seen INT, last_seen INT, hits INT DEFAULT 1,
                status TEXT DEFAULT 'pending');
            CREATE TABLE IF NOT EXISTS learned(
                domain TEXT PRIMARY KEY, reason TEXT, added INT);
            """
        )

    def learned(self, max_age_days):
        # CNAME entries expire so a fixed or delisted name gets unblocked; if it
        # is still cloaked, the next lookup learns it again. Auto blocks stay.
        cutoff = int(time.time() - max_age_days * 86400)
        with self.lock:
            return {r[0] for r in self.db.execute(
                "SELECT domain FROM learned WHERE added>=? OR reason NOT LIKE 'cname->%'",
                (cutoff,))}

    def learn(self, domain, reason):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO learned VALUES(?,?,?)",
                            (domain, reason, int(time.time())))

    def unlearn(self, domain):
        with self.lock:
            self.db.execute("DELETE FROM learned WHERE domain=?", (domain,))

    def candidate(self, domain, score, reasons):
        now = int(time.time())
        with self.lock:
            self.db.execute(
                """INSERT INTO candidates(domain,score,reasons,first_seen,last_seen)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET hits=hits+1,
                   last_seen=excluded.last_seen, score=excluded.score,
                   reasons=excluded.reasons""",
                (domain, score, " ".join(reasons), now, now))
            return self.db.execute("SELECT hits,status FROM candidates WHERE domain=?",
                                   (domain,)).fetchone()

    def set_status(self, domain, status):
        with self.lock:
            self.db.execute("UPDATE candidates SET status=? WHERE domain=?", (status, domain))

    def pending(self, include_all=False):
        q = "SELECT domain,score,hits,reasons,status FROM candidates"
        if not include_all:
            q += " WHERE status='pending'"
        q += " ORDER BY score*hits DESC LIMIT 100"
        with self.lock:
            return self.db.execute(q).fetchall()


# --------------------------------------------------------------------------- #
# upstreams
# --------------------------------------------------------------------------- #
DOWN_SECONDS = 60          # how long a failed upstream is skipped
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".home.arpa", ".localdomain")


class DoH:
    """DNS-over-HTTPS with kept-alive connections, so TLS is not redone per query."""

    def __init__(self, url, timeout=3):
        u = urllib.parse.urlsplit(url)
        self.host, self.port, self.path = u.hostname, u.port or 443, u.path or "/dns-query"
        self.timeout = timeout
        self.context = ssl.create_default_context()
        self.idle = deque(maxlen=8)

    def query(self, packet):
        for fresh in (False, True):
            try:
                conn = None if fresh else self.idle.pop()
            except IndexError:
                continue
            if conn is None:
                conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                                   context=self.context)
            try:
                conn.request("POST", self.path, body=packet, headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message"})
                r = conn.getresponse()
                body = r.read()
                if r.status != 200:
                    raise OSError(f"HTTP {r.status}")
                self.idle.append(conn)
                return body
            except Exception:
                conn.close()
                if fresh:            # a reused connection may just have gone stale
                    raise


_network_dns = (0.0, [])


def network_dns():
    """The DNS servers the current network handed out over DHCP (cached 30s)."""
    global _network_dns
    when, servers = _network_dns
    if time.time() - when < 30:
        return servers
    servers = []
    try:
        ifaces = subprocess.run(["/sbin/ifconfig", "-l"], capture_output=True, text=True,
                                timeout=2).stdout.split()
        for iface in (i for i in ifaces if i.startswith("en")):
            out = subprocess.run(["/usr/sbin/ipconfig", "getpacket", iface],
                                 capture_output=True, text=True, timeout=2).stdout
            for found in re.findall(r"domain_name_server \(ip_mult\): \{([^}]*)\}", out):
                for ip in (x.strip() for x in found.split(",")):
                    if ip and not ip.startswith("127.") and ip not in servers:
                        servers.append(ip)
    except Exception as e:
        log(f"could not read the network's DNS servers: {e!r}")
    _network_dns = (time.time(), servers)
    return servers


def is_local_name(name):
    return "." not in name or name.endswith(LOCAL_SUFFIXES) or name.endswith(
        (".10.in-addr.arpa", ".168.192.in-addr.arpa"))


def paused_until():
    try:
        return float(PAUSE.read_text())
    except (OSError, ValueError):
        return 0.0


# --------------------------------------------------------------------------- #
# DNS server
# --------------------------------------------------------------------------- #
def make_resolver(cfg, store):
    from dnslib import DNSRecord, RR, QTYPE, A, AAAA, RCODE
    from dnslib.server import BaseResolver

    class Resolver(BaseResolver):
        def __init__(self):
            self.lock = threading.RLock()
            self.cache = OrderedDict()
            self.blocked_count = Counter()
            self.totals = Counter()
            self.recent = deque(maxlen=50)
            self.recent_dirty = False
            self.down = {}                    # upstream -> skip until
            self.doh = {u: DoH(u) for u in cfg["upstreams"] if u.startswith("https://")}
            self.pause_checked = 0.0
            self.paused = False
            self.restore_stats()
            self.load()

        def restore_stats(self):
            try:
                old = json.loads(STATS.read_text())
                self.totals.update(blocked=old["blocked"], allowed=old["allowed"])
                self.blocked_count.update(dict(old["top_blocked"]))
                self.recent.extend(json.loads(RECENT.read_text()))
            except FileNotFoundError:
                pass
            except Exception as e:
                log(f"could not restore stats: {e!r}")

        def is_paused(self):
            now = time.time()
            if now - self.pause_checked >= 1:
                self.pause_checked = now
                paused = paused_until() > now
                if paused != self.paused:
                    self.paused = paused
                    with self.lock:
                        self.cache.clear()    # may hold answers fetched while paused
                    log("paused" if paused else "blocking again")
            return self.paused

        # ---- lists -------------------------------------------------------
        def load(self):
            block = read_set(BLOCKLIST)
            data = dict(
                block=block,
                list_allow=read_set(LIST_ALLOW),
                user_allow=read_set(USER_ALLOW),
                user_deny=read_set(USER_DENY),
                learned=store.learned(cfg["learned_days"]),
                blocked_bases={base_domain(d) for d in block},
            )
            with self.lock:
                self.__dict__.update(data)
                self.cache.clear()
            log(f"loaded {len(block)} blocked, {len(data['user_allow'])} allowed, "
                f"{len(data['user_deny'])} denied, {len(data['learned'])} learned")

        def verdict(self, name):
            with self.lock:
                m = match(name, self.user_allow)
                if m: return "allow", f"allowlist:{m}"
                m = match(name, self.user_deny)
                if m: return "block", f"denylist:{m}"
                m = match(name, self.learned)
                if m: return "block", f"learned:{m}"
                m = match(name, self.list_allow)
                if m: return "allow", f"list-exception:{m}"
                m = match(name, self.block)
                if m: return "block", f"list:{m}"
            return None, None

        # ---- DNS plumbing ------------------------------------------------
        def blocked_reply(self, request):
            r = request.reply()
            q = request.q
            if q.qtype == QTYPE.A:
                r.add_answer(RR(q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            elif q.qtype == QTYPE.AAAA:
                r.add_answer(RR(q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=60))
            return r          # other types (HTTPS, SVCB...) -> empty NOERROR

        def ask(self, up, request):
            if up in self.doh:
                reply = DNSRecord.parse(self.doh[up].query(request.pack()))
                if reply.header.id != request.header.id:
                    raise OSError("reply id mismatch")
                return reply
            host, port = split_upstream(up)
            v6 = ":" in host
            reply = DNSRecord.parse(request.send(host, port, timeout=3, ipv6=v6))
            if reply.header.tc:
                reply = DNSRecord.parse(request.send(host, port, tcp=True, timeout=5, ipv6=v6))
            if reply.header.id != request.header.id:
                raise OSError("reply id mismatch")
            return reply

        def first_answer(self, upstreams, request):
            for up in upstreams:
                if self.down.get(up, 0) > time.time():
                    continue
                try:
                    reply = self.ask(up, request)
                    self.down.pop(up, None)
                    return reply
                except Exception as e:
                    self.down[up] = time.time() + DOWN_SECONDS
                    log(f"upstream {up} failed, skipping it for {DOWN_SECONDS}s: {e!r}")
            return None

        def forward(self, request):
            name = str(request.q.qname).rstrip(".").lower()
            local = network_dns() if cfg["network_fallback"] else []
            if local and is_local_name(name):
                reply = self.first_answer(local, request)
                if reply is not None:
                    return reply
            reply = self.first_answer(cfg["upstreams"], request)
            if reply is None:                  # all down: captive portal, DoH blocked
                return self.first_answer(local, request)
            if local and reply.header.rcode == RCODE.NXDOMAIN:
                other = self.first_answer(local, request)      # internal hostnames
                if other is not None and other.header.rcode == RCODE.NOERROR and other.rr:
                    return other
            return reply

        def cache_get(self, key):
            with self.lock:
                item = self.cache.get(key)
                if not item:
                    return None
                if item[0] < time.time():
                    del self.cache[key]
                    return None
                self.cache.move_to_end(key)
                return item[1]

        def cache_put(self, key, reply):
            ttls = [rr.ttl for rr in reply.rr]
            ttl = max(30, min(3600, min(ttls) if ttls else 60))
            with self.lock:
                self.cache[key] = (time.time() + ttl, reply.pack())
                while len(self.cache) > cfg["cache_size"]:
                    self.cache.popitem(last=False)

        def deny(self, request, name, why):
            self.totals["blocked"] += 1
            self.blocked_count[name] += 1
            if len(self.blocked_count) > 5000:
                self.blocked_count = Counter(dict(self.blocked_count.most_common(1000)))
            with self.lock:
                # one row per name; apps retry blocked names constantly
                for row in list(self.recent):
                    if row[1] == name:
                        self.recent.remove(row)
                self.recent.append([int(time.time()), name, why])
                self.recent_dirty = True
            return self.blocked_reply(request)

        def resolve(self, request, handler):
            try:
                return self._resolve(request)
            except Exception as e:           # never leave the Mac without DNS
                log(f"error resolving {request.q.qname}: {e!r}")
                r = request.reply()
                r.header.rcode = RCODE.SERVFAIL
                return r

        def _resolve(self, request):
            q = request.q
            name = str(q.qname).rstrip(".").lower()
            if name == "health.macblock.test":      # guard.sh asks this
                r = request.reply()
                if q.qtype == QTYPE.A:
                    r.add_answer(RR(q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=0))
                return r
            if name == "use-application-dns.net":   # tells Firefox not to bypass us
                r = request.reply()
                r.header.rcode = RCODE.NXDOMAIN
                return r
            paused = self.is_paused()
            v, why = self.verdict(name) if name and not paused else (None, None)
            if v == "block":
                return self.deny(request, name, why)

            key = (name, q.qtype, q.qclass)
            packed = self.cache_get(key)
            if packed:
                reply = DNSRecord.parse(packed)
                reply.header.id = request.header.id
                self.totals["allowed"] += 1
                return reply

            reply = self.forward(request)
            if reply is None:
                r = request.reply()
                r.header.rcode = RCODE.SERVFAIL
                return r

            if v != "allow" and not paused:      # adaptive checks
                targets = [str(rr.rdata.label).rstrip(".").lower()
                           for rr in reply.rr if rr.rtype == QTYPE.CNAME]
                for t in targets:
                    tv, twhy = self.verdict(t)
                    if tv == "block":
                        log(f"LEARNED {name}  (CNAME-cloaked -> {t}, {twhy})")
                        store.learn(name, f"cname->{t}")
                        with self.lock:
                            self.learned.add(name)
                        return self.deny(request, name, f"cname->{t}")
                if q.qtype in (QTYPE.A, QTYPE.AAAA):
                    self.observe(name, targets)

            if reply.header.rcode != RCODE.SERVFAIL and not is_local_name(name):
                self.cache_put(key, reply)         # local answers change per network
            self.totals["allowed"] += 1
            return reply

        def observe(self, name, targets):
            score, why = score_name(name, self.blocked_bases, targets)
            if score < cfg["review_score"]:
                return
            hits, status = store.candidate(name, score, why)
            if (cfg["auto_block"] and status == "pending"
                    and score >= cfg["auto_block_score"]
                    and hits >= cfg["auto_block_min_hits"]):
                log(f"AUTO-BLOCKED {name} score={score} {' '.join(why)}")
                store.learn(name, "auto:" + " ".join(why))
                store.set_status(name, "auto")
                with self.lock:
                    self.learned.add(name)

        def dump_stats(self):
            data = {
                "updated": time.ctime(),
                "blocked": self.totals["blocked"],
                "allowed": self.totals["allowed"],
                "top_blocked": self.blocked_count.most_common(25),
            }
            write_atomic(STATS, json.dumps(data, indent=1))
            self.dump_recent()

        def dump_recent(self):
            with self.lock:
                rows, self.recent_dirty = list(self.recent), False
            write_atomic(RECENT, json.dumps(rows))

    return Resolver()


def drop_privileges(user):
    if os.getuid() != 0 or not user:
        return
    entry = pwd.getpwnam(user)
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)
    if os.getuid() == 0:
        raise SystemExit("could not drop root")


def cmd_run(cfg):
    global _log_file
    from dnslib.server import DNSServer, DNSLogger
    quiet = DNSLogger(log="-request,-reply,-truncated,-recv,-send,-data", prefix=False)

    class Deferred:                     # the port is bound before the resolver exists
        resolver = None

        def resolve(self, request, handler):
            return self.resolver.resolve(request, handler)

    front = Deferred()
    servers = [DNSServer(front, port=cfg["port"], address=cfg["listen"], logger=quiet, tcp=t)
               for t in (False, True)]
    drop_privileges(cfg["user"])        # nothing from the network is read as root
    DATA.mkdir(parents=True, exist_ok=True)
    _log_file = LOGFILE
    store = Store(DB)
    front.resolver = resolver = make_resolver(cfg, store)
    for s in servers:
        s.start_thread()
    write_atomic(PIDFILE, str(os.getpid()))
    log(f"macblock listening on {cfg['listen']}:{cfg['port']} as uid {os.getuid()} "
        f"-> {cfg['upstreams']}")

    reload_flag = threading.Event()
    signal.signal(signal.SIGHUP, lambda *_: reload_flag.set())
    stop = threading.Event()
    def _stop(*_):
        stop.set()
        reload_flag.set()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    def updater():
        while not stop.is_set():
            age = time.time() - (BLOCKLIST.stat().st_mtime if BLOCKLIST.exists() else 0)
            wait = cfg["update_hours"] * 3600 - age
            if wait <= 0:
                if update_lists(cfg):
                    reload_flag.set()
                wait = cfg["update_hours"] * 3600
            stop.wait(min(wait, 3600))
    threading.Thread(target=updater, daemon=True).start()

    last_stats = 0.0
    while not stop.is_set():
        if reload_flag.wait(2):
            reload_flag.clear()
            if stop.is_set():
                break
            resolver.load()
        try:
            resolver.is_paused()
            if time.time() - last_stats >= 30:
                resolver.dump_stats()
                last_stats = time.time()
            elif resolver.recent_dirty:
                resolver.dump_recent()
        except Exception as e:
            log("stats error", e)
    for s in servers:
        s.stop()
    try:
        resolver.dump_stats()
        PIDFILE.unlink()
    except OSError as e:
        log(f"shutdown: {e}")
    log("stopped")


# --------------------------------------------------------------------------- #
# CLI commands
# --------------------------------------------------------------------------- #
def cmd_status(cfg):
    pid = pid_alive()
    print(f"daemon:    {'running (pid %d)' % pid if pid else 'NOT running'}")
    print(f"blocking:  {'ON' if ENABLED.exists() else 'OFF'}"
          + (f" (paused until {time.strftime('%H:%M', time.localtime(paused_until()))})"
             if paused_until() > time.time() else ""))
    if BLOCKLIST.exists():
        print(f"blocklist: {len(read_set(BLOCKLIST))} domains, updated "
              f"{time.ctime(BLOCKLIST.stat().st_mtime)}")
    print(f"allowlist: {len(read_set(USER_ALLOW))}   denylist: {len(read_set(USER_DENY))}")
    if DB.exists():
        s = Store(DB, readonly=True)
        print(f"learned:   {len(s.learned(cfg['learned_days']))}   review queue: {len(s.pending())}")
    if STATS.exists():
        st = json.loads(STATS.read_text())
        total = st["blocked"] + st["allowed"]
        pct = 100 * st["blocked"] / total if total else 0
        print(f"since start: {st['blocked']} blocked / {total} queries ({pct:.1f}%)")
        for d, n in st["top_blocked"][:10]:
            print(f"   {n:>6}  {d}")


def cmd_recent():
    rows = json.loads(RECENT.read_text()) if RECENT.exists() else []
    if not rows:
        print("Nothing blocked yet.")
        return
    for when, name, why in reversed(rows):
        print(f"{time.strftime('%H:%M:%S', time.localtime(when))}  {name:<45} {why}")
    print("\nUnblock with:  sudo macblock allow <domain>")


def cmd_pause(minutes):
    write_atomic(PAUSE, str(time.time() + minutes * 60) if minutes > 0 else "0")
    flush_mac_dns_cache()
    print(f"macblock paused for {minutes:g} minutes" if minutes > 0 else "macblock is blocking again")


def cmd_review(args):
    rows = Store(DB, readonly=True).pending(args.all)
    if not rows:
        print("Nothing to review.")
        return
    print(f"{'SCORE':>5} {'HITS':>5}  {'DOMAIN':<45} REASONS")
    for domain, score, hits, reasons, status in rows:
        tag = "" if status == "pending" else f"[{status}] "
        print(f"{score:>5} {hits:>5}  {domain:<45} {tag}{reasons}")
    print("\nDecide with:  sudo macblock block <domain>   |   sudo macblock allow <domain>")


def cmd_list_edit(args, path, status):
    store = Store(DB)
    existing = read_set(path)
    for d in args.domains:
        d = _clean(d) or d.lower().strip()
        if d not in existing:
            append_line(path, d)
        store.set_status(d, status)
        if status == "allowed":
            store.unlearn(d)
            remove_entry(USER_DENY, d)
        else:
            remove_entry(USER_ALLOW, d)       # the allowlist would win otherwise
        print(f"{status}: {d}")
        covering = match(d, read_set(USER_ALLOW))
        if status == "blocked" and covering:
            print(f"  warning: still allowed because {covering} is on your allowlist")
    if signal_reload():
        print("daemon reloaded")
    flush_mac_dns_cache()


def cmd_test(cfg, domain):
    store = Store(DB, readonly=True)

    class Probe:
        pass
    r = Probe()
    r.user_allow, r.user_deny = read_set(USER_ALLOW), read_set(USER_DENY)
    r.learned, r.list_allow, r.block = store.learned(cfg["learned_days"]), read_set(LIST_ALLOW), read_set(BLOCKLIST)
    name = domain.lower().rstrip(".")
    for label, s, v in (("allowlist", r.user_allow, "ALLOW"), ("denylist", r.user_deny, "BLOCK"),
                        ("learned", r.learned, "BLOCK"), ("list exception", r.list_allow, "ALLOW"),
                        ("blocklist", r.block, "BLOCK")):
        m = match(name, s)
        if m:
            print(f"{v}  ({label}: {m})")
            break
    else:
        print("PASS  (not on any list)")
    score, why = score_name(name, {base_domain(d) for d in r.block})
    print(f"heuristic score {score}: {' '.join(why) or '-'}")


# ---- macOS DNS switching (the work happens in guard.sh) ------------------- #
def flush_mac_dns_cache():
    if sys.platform == "darwin":
        subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)
        subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True)


def cmd_dns(state):
    if state == "toggle":
        state = "off" if ENABLED.exists() else "on"
    if state == "on" and not pid_alive():      # would leave the Mac with no DNS
        sys.exit("macblock isn't running - leaving DNS unchanged")
    if subprocess.run(["/bin/bash", str(GUARD), state]).returncode:
        sys.exit("changing DNS failed - run with sudo")
    if state == "on":
        cmd_pause(0)
    print(f"macblock is now {state.upper()}")


def main():
    p = argparse.ArgumentParser(prog="macblock", description="Self-updating DNS ad blocker for macOS")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    sub.add_parser("update")
    sub.add_parser("status")
    sub.add_parser("recent")
    sub.add_parser("resume")
    z = sub.add_parser("pause"); z.add_argument("minutes", type=float, nargs="?", default=10)
    r = sub.add_parser("review"); r.add_argument("--all", action="store_true")
    b = sub.add_parser("block"); b.add_argument("domains", nargs="+")
    a = sub.add_parser("allow"); a.add_argument("domains", nargs="+")
    t = sub.add_parser("test"); t.add_argument("domain")
    d = sub.add_parser("dns"); d.add_argument("state", choices=["on", "off", "toggle"])
    args = p.parse_args()
    cfg = load_config()

    if args.cmd == "run":
        cmd_run(cfg)
    elif args.cmd == "update":
        if update_lists(cfg):
            signal_reload()
    elif args.cmd == "status":
        cmd_status(cfg)
    elif args.cmd == "recent":
        cmd_recent()
    elif args.cmd == "pause":
        cmd_pause(args.minutes)
    elif args.cmd == "resume":
        cmd_pause(0)
    elif args.cmd == "review":
        cmd_review(args)
    elif args.cmd == "block":
        cmd_list_edit(args, USER_DENY, "blocked")
    elif args.cmd == "allow":
        cmd_list_edit(args, USER_ALLOW, "allowed")
    elif args.cmd == "test":
        cmd_test(cfg, args.domain)
    elif args.cmd == "dns":
        cmd_dns(args.state)


if __name__ == "__main__":
    try:
        main()
    except PermissionError as e:
        sys.exit(f"{e.strerror}: {e.filename or ''} - run with sudo")
