import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve()
ROOT = next(p for p in HERE.parents if (p / "lib/tailscale-web/configure.py").exists())
spec = importlib.util.spec_from_file_location("web", ROOT / "lib/tailscale-web/configure.py")
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)

HOST = "openclaw.example.ts.net"
IP = "100.64.0.10"


class Checks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.hosts = Path(self.temp.name) / "hosts"
        self.hosts.write_text("127.0.0.1 localhost\n")
        self.config = Path(self.temp.name) / "tailscale-web.conf"
        self.calls = []
        self.stdins = []
        self.route = "dev tailscale0"
        self.peer_ip = IP
        self.env = {"TAILSCALE_WEB_HOST": HOST, "TAILSCALE_WEB_IP": IP}

    def run_cmd(self, *args, stdin=None):
        self.calls.append(args)
        self.stdins.append(stdin)
        if args[0] == "tailscale":
            out = json.dumps({"Peer": {"key": {"DNSName": HOST + ".", "TailscaleIPs": [self.peer_ip]}}})
        elif args[0] == "ip":
            out = self.route
        elif args[:3] == ("nft", "list", "tables"):
            out = "table inet " + web.TABLE + "\n"
        elif args[0] == "curl":
            out = "200"
        else:
            out = ""
        return SimpleNamespace(stdout=out)

    def invoke(self, action="apply"):
        with patch.dict(os.environ, self.env), \
             patch.object(web, "CONFIG", self.config), \
             patch.object(web, "HOSTS", self.hosts), \
             patch.object(web.os, "geteuid", return_value=0), \
             patch.object(web, "run", side_effect=self.run_cmd), \
             patch("sys.argv", ["configure.py", action]):
            web.main()

    def test_wrong_route_does_not_touch_firewall_or_hosts(self):
        self.route = "dev wlp47s0f0"
        with self.assertRaises(SystemExit):
            self.invoke()
        self.assertFalse(any(c[0] == "nft" for c in self.calls))
        self.assertEqual(self.hosts.read_text(), "127.0.0.1 localhost\n")

    def test_changed_peer_does_not_touch_firewall(self):
        self.peer_ip = "100.64.0.99"
        with self.assertRaises(SystemExit):
            self.invoke()
        self.assertFalse(any(c[0] == "nft" for c in self.calls))

    def test_conflicting_hosts_does_not_touch_network(self):
        self.hosts.write_text("192.0.2.1 " + HOST + "\n")
        with self.assertRaises(SystemExit):
            self.invoke()
        self.assertEqual(self.calls, [])

    def test_reapply_and_remove_preserve_unrelated_hosts(self):
        self.invoke()
        self.invoke()
        self.assertEqual(self.hosts.read_text().count(web.entry(HOST, IP)), 1)
        curl = next(c for c in self.calls if c[0] == "curl")
        self.assertNotIn("--insecure", curl)
        self.assertNotIn("-k", curl)
        self.invoke("remove")
        self.assertEqual(self.hosts.read_text(), "127.0.0.1 localhost\n")

    def test_missing_peer_config_changes_nothing(self):
        self.env = {"TAILSCALE_WEB_HOST": "", "TAILSCALE_WEB_IP": ""}
        with self.assertRaises(SystemExit):
            self.invoke()
        self.assertEqual(self.calls, [])

    def test_peer_from_config_file(self):
        self.env = {"TAILSCALE_WEB_HOST": "", "TAILSCALE_WEB_IP": ""}
        self.config.write_text("# tailnet peer\nHOST=\"" + HOST + "\"\nIP = " + IP + "\n")
        self.invoke()
        self.assertIn(web.entry(HOST, IP), self.hosts.read_text())

    def test_rules_are_loaded_through_stdin(self):
        self.invoke()
        loads = [(c, s) for c, s in zip(self.calls, self.stdins) if c[:2] == ("nft", "--file")]
        self.assertEqual(1, len(loads))
        self.assertEqual(("nft", "--file", "-"), loads[0][0])
        self.assertIn("ip daddr " + IP + " tcp dport 443", loads[0][1])


if __name__ == "__main__":
    unittest.main()
