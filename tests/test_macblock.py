"""Run from the project root:  python3 -m unittest discover tests   (needs dnslib)

Nothing here touches the real DNS settings: macblock runs against a temporary
home directory and guard.sh against a fake networksetup and dig.
"""
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_home = tempfile.TemporaryDirectory()
os.environ["MACBLOCK_HOME"] = _home.name
sys.path.insert(0, str(ROOT))
import macblock as mb  # noqa: E402

from dnslib import A, CNAME, QTYPE, RCODE, RR, DNSRecord  # noqa: E402
from dnslib.server import BaseResolver, DNSLogger, DNSServer  # noqa: E402

mb.flush_mac_dns_cache = lambda: None
mb.signal_reload = lambda: False


def reset():
    mb.DATA.mkdir(exist_ok=True)
    for f in [*mb.HOME.glob("*"), *mb.DATA.glob("*")]:
        if f.is_file():
            f.unlink()


class Lists(unittest.TestCase):
    def setUp(self):
        reset()

    def test_parse(self):
        block, allow = mb.parse_list(
            "||a.com^\n@@||b.com^|\n||c.com^$third-party\n0.0.0.0 d.com # x\ne.com##.ad\n")
        self.assertEqual((block, allow), ({"a.com", "d.com"}, {"b.com"}))

    def test_collapse(self):
        self.assertEqual(mb.collapse({"x.com", "ads.x.com", "a.b.x.com", "y.net"}),
                         {"x.com", "y.net"})

    def test_block_after_allow_and_back(self):
        args = types.SimpleNamespace(domains=["foo.com"])
        mb.cmd_list_edit(args, mb.USER_ALLOW, "allowed")
        mb.cmd_list_edit(args, mb.USER_DENY, "blocked")
        self.assertEqual((mb.read_set(mb.USER_ALLOW), mb.read_set(mb.USER_DENY)), (set(), {"foo.com"}))
        mb.cmd_list_edit(args, mb.USER_ALLOW, "allowed")
        self.assertEqual((mb.read_set(mb.USER_ALLOW), mb.read_set(mb.USER_DENY)), ({"foo.com"}, set()))

    def test_heuristics(self):
        self.assertEqual(mb.score_name("api.google.com", {"google.com"})[0], 0)
        self.assertLess(mb.score_name("stats.github.com", set())[0], 3)
        self.assertGreaterEqual(mb.score_name("adserver.example.com", set())[0], 3)

    def test_upstream_forms(self):
        self.assertEqual(mb.split_upstream("1.1.1.1:5353"), ("1.1.1.1", 5353))
        self.assertEqual(mb.split_upstream("[2606:4700::1111]:53"), ("2606:4700::1111", 53))


class Fake(BaseResolver):
    def __init__(self, ip, nx=()):
        self.ip, self.nx = ip, nx

    def resolve(self, request, handler):
        reply, name = request.reply(), str(request.q.qname).rstrip(".")
        if name in self.nx:
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        if name == "metrics.shop.test":
            reply.add_answer(RR(name, QTYPE.CNAME, rdata=CNAME("t.tracker.test"), ttl=60))
        reply.add_answer(RR(name, QTYPE.A, rdata=A(self.ip), ttl=60))
        return reply


def serve(resolver):
    server = DNSServer(resolver, address="127.0.0.1", port=0,
                       logger=DNSLogger("-request,-reply", False))
    server.start_thread()
    return server, f"127.0.0.1:{server.server.server_address[1]}"


class Resolving(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up, cls.up_addr = serve(Fake("10.0.0.1", nx=("intranet.corp.test",)))
        cls.net, cls.net_addr = serve(Fake("10.0.0.2"))

    @classmethod
    def tearDownClass(cls):
        cls.up.stop()
        cls.net.stop()

    def setUp(self):
        reset()
        mb.BLOCKLIST.write_text("tracker.test\n")
        self.real_network_dns = mb.network_dns
        mb.network_dns = lambda: [self.net_addr]
        self.make(upstreams=[self.up_addr])

    def tearDown(self):
        mb.network_dns = self.real_network_dns

    def make(self, **over):
        self.r = mb.make_resolver(dict(mb.DEFAULT_CONFIG, **over), mb.Store(mb.DB))

    def ask(self, name):
        reply = self.r._resolve(DNSRecord.question(name))
        return reply.header.rcode, [str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A]

    def test_block_cname_and_recent(self):
        self.assertEqual(self.ask("x.tracker.test")[1], ["0.0.0.0"])
        self.assertEqual(self.ask("ok.test")[1], ["10.0.0.1"])
        self.assertEqual(self.ask("metrics.shop.test")[1], ["0.0.0.0"])
        self.ask("x.tracker.test")
        self.assertEqual([row[1] for row in self.r.recent], ["metrics.shop.test", "x.tracker.test"])

    def test_health_and_canary(self):
        self.assertEqual(self.ask("health.macblock.test")[1], ["127.0.0.1"])
        self.assertEqual(self.ask("use-application-dns.net")[0], RCODE.NXDOMAIN)

    def test_network_fallback(self):
        self.assertEqual(self.ask("printer.lan")[1], ["10.0.0.2"])
        self.assertEqual(self.ask("intranet.corp.test")[1], ["10.0.0.2"])

    def test_dead_upstream_is_skipped(self):
        self.make(upstreams=["127.0.0.1:1", self.up_addr])
        self.assertEqual(self.ask("one.test")[1], ["10.0.0.1"])
        started = time.time()
        self.assertEqual(self.ask("two.test")[1], ["10.0.0.1"])
        self.assertLess(time.time() - started, 1)

    def test_all_upstreams_down(self):
        self.make(upstreams=["127.0.0.1:1"])
        self.assertEqual(self.ask("portal.test")[1], ["10.0.0.2"])

    def test_pause(self):
        mb.cmd_pause(10)
        self.assertEqual(self.ask("x.tracker.test")[1], ["10.0.0.1"])
        mb.cmd_pause(0)
        self.r.pause_checked = 0
        self.assertEqual(self.ask("x.tracker.test")[1], ["0.0.0.0"])

    def test_stats_survive_restart(self):
        self.ask("x.tracker.test")
        self.r.dump_stats()
        self.make(upstreams=[self.up_addr])
        self.assertEqual((self.r.totals["blocked"], len(self.r.recent)), (1, 1))


FAKE_NS = '''#!/bin/bash
f="$FAKE/$2"
case "$1" in
  -listallnetworkservices) echo header; echo "Wi-Fi"; echo "USB 10/100 LAN"; echo "*Off" ;;
  -getdnsservers) f="$FAKE/${2//\\//_}"; if [[ -s $f ]]; then tr ' ' '\\n' <"$f"; else echo "There aren't any DNS Servers set on $2."; fi ;;
  -setdnsservers) f="$FAKE/${2//\\//_}"; shift 2; if [[ $1 == Empty ]]; then : >"$f"; else echo "$*" >"$f"; fi ;;
esac
'''


class Guard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "ns").write_text(FAKE_NS)
        (self.dir / "dig").write_text('#!/bin/bash\n[[ -e $FAKE/healthy ]] && echo 127.0.0.1\n')
        for tool in ("ns", "dig"):
            (self.dir / tool).chmod(0o755)
        (self.dir / "Wi-Fi").write_text("192.168.1.1 192.168.1.2\n")
        self.env = dict(os.environ, FAKE=str(self.dir), MACBLOCK_HOME=str(self.dir),
                        MACBLOCK_NETWORKSETUP=str(self.dir / "ns"), MACBLOCK_DIG=str(self.dir / "dig"))

    def tearDown(self):
        self.tmp.cleanup()

    def sh(self, script):
        # flush() is stubbed so the test never touches the real DNS cache
        prelude = f'source "{ROOT}/guard.sh" >/dev/null; flush() {{ :; }}; '
        subprocess.run(["/bin/bash", "-c", prelude + script], env=self.env, check=True,
                       capture_output=True)

    def dns(self):
        return [(self.dir / n).read_text().strip() if (self.dir / n).exists() else ""
                for n in ("Wi-Fi", "USB 10_100 LAN")]

    def test_on_twice_then_off_restores_original(self):
        original = ["192.168.1.1 192.168.1.2", ""]
        self.sh('touch "$ENABLED"; point_at_us; point_at_us')
        self.assertEqual(self.dns(), ["127.0.0.1", "127.0.0.1"])
        self.sh("restore")
        self.assertEqual(self.dns(), original)

    def test_fails_open_and_recovers(self):
        (self.dir / "healthy").touch()
        self.sh('touch "$ENABLED"; FAILS=0; tick')
        self.assertEqual(self.dns()[0], "127.0.0.1")
        (self.dir / "healthy").unlink()
        self.sh("FAILS=0; tick; tick")
        self.assertEqual(self.dns()[0], "127.0.0.1")          # two misses: wait
        self.sh("FAILS=0; tick; tick; tick")
        self.assertEqual(self.dns()[0], "192.168.1.1 192.168.1.2")
        (self.dir / "healthy").touch()
        self.sh("FAILS=0; tick")
        self.assertEqual(self.dns()[0], "127.0.0.1")

    def test_does_nothing_when_off(self):
        (self.dir / "healthy").touch()
        self.sh("FAILS=0; tick")
        self.assertEqual(self.dns()[0], "192.168.1.1 192.168.1.2")


if __name__ == "__main__":
    unittest.main()
