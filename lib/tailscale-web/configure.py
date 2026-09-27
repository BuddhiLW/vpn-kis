#!/usr/bin/env python3
"""Apply/remove a notebook-only OpenClaw exception; run explicitly with sudo.

Firewall rule is runtime-only for initial verification. Hosts entry survives
reboot. Does not change Mullvad, Tailscale DNS settings, or system DNS servers.

The tailnet peer comes from /etc/vpn-killswitch/tailscale-web.conf
(HOST=<name>.<tailnet>.ts.net and IP=<its 100.x address> lines), or from the
TAILSCALE_WEB_HOST / TAILSCALE_WEB_IP environment variables.
"""
import argparse
import os
import json
from pathlib import Path
import subprocess

CONFIG = Path(os.environ.get("TAILSCALE_WEB_CONF", "/etc/vpn-killswitch/tailscale-web.conf"))
TABLE = "hive_openclaw_client"
HOSTS = Path("/etc/hosts")


def run(*args, stdin=None):
    return subprocess.run(args, input=stdin, check=True, capture_output=True, text=True)


def peer():
    """(host, ip) of the tailnet peer; SystemExit when either is missing."""
    values = {}
    if CONFIG.exists():
        for line in CONFIG.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and not key.strip().startswith("#"):
                values[key.strip()] = value.strip().strip("\"'")
    host = os.environ.get("TAILSCALE_WEB_HOST") or values.get("HOST")
    ip = os.environ.get("TAILSCALE_WEB_IP") or values.get("IP")
    if not host or not ip:
        raise SystemExit(f"Set HOST= and IP= of the tailnet peer in {CONFIG} "
                         "(or TAILSCALE_WEB_HOST / TAILSCALE_WEB_IP); no changes made.")
    return host, ip


def entry(host, ip):
    return f"{ip} {host} # hive-openclaw-client"


def ruleset(ip):
    """Notebook-only exception: routing stays on Tailscale, no Mullvad routing
    mark, browser and general DNS not exempted. Priority -10 runs after
    conntrack (-200), before Mullvad's output filter (0)."""
    return (f"table inet {TABLE}\n"
            f"flush table inet {TABLE}\n"
            f"table inet {TABLE} {{\n"
            "    chain output {\n"
            "        type filter hook output priority -10; policy accept;\n"
            f'        oifname "tailscale0" ip daddr {ip} tcp dport 443 ct mark set 0x00000f41'
            ' comment "OpenClaw HTTPS over Tailscale only"\n'
            "    }\n"
            "}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["apply", "remove"])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Requires sudo to manage this nftables table and /etc/hosts.")
    original = HOSTS.read_text()
    if args.action == "remove":
        existing = run("nft", "list", "tables").stdout
        if f"table inet {TABLE}" in existing.splitlines():
            run("nft", "delete", "table", "inet", TABLE)
        try:
            host, ip = peer()
        except SystemExit:
            print("Removed managed rule; no peer configured, /etc/hosts left as is.")
            return
        HOSTS.write_text("".join(line for line in original.splitlines(keepends=True)
                                 if line.rstrip("\r\n") != entry(host, ip)))
        print("Removed managed rule and hostname entry; existing connections may persist until closed.")
        return
    host, ip = peer()
    for line in original.splitlines():
        fields = line.split("#", 1)[0].split()
        if host in fields[1:] and fields[0] != ip:
            raise SystemExit("Conflicting /etc/hosts entry; no changes made.")
    peers = json.loads(run("tailscale", "status", "--json").stdout).get("Peer") or {}
    matching = [p for p in peers.values()
                if p.get("DNSName", "").rstrip(".") == host]
    if len(matching) != 1 or ip not in matching[0].get("TailscaleIPs", []):
        raise SystemExit("Pinned address does not match Tailscale peer identity; no changes made.")
    # Tailnet packets carry Mullvad's split-tunnel mark (vpn-firewall-setup.sh
    # tailscale-routes), so check the route a marked packet takes.
    route = run("ip", "-4", "route", "get", ip, "mark", "0x6d6f6c65").stdout.split()
    if "dev" not in route or route[route.index("dev") + 1] != "tailscale0":
        raise SystemExit("Destination is not routed through tailscale0; no changes made.")
    rules = ruleset(ip)
    run("nft", "--check", "--file", "-", stdin=rules)
    run("nft", "--file", "-", stdin=rules)
    if not any(host in line.split("#", 1)[0].split()[1:]
               for line in original.splitlines()):
        with HOSTS.open("a") as out:
            out.write(("" if not original or original.endswith("\n") else "\n")
                      + entry(host, ip) + "\n")
    print("Applied OpenClaw-only rule and hostname mapping. Firewall rule expires at reboot.")
    run("getent", "ahostsv4", host)
    result = run("curl", "--noproxy", "*", "--max-time", "20", "--silent",
                 "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}",
                 f"https://{host}/")
    print("HTTPS status:", result.stdout)
    if result.stdout != "200":
        raise SystemExit("HTTPS verification failed; configuration remains available for diagnosis/removal.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr.strip() or str(error))
