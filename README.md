# vpn-kis

A strict VPN kill-switch for Linux that supports **Mullvad**, **AirVPN/Eddie**, and **Tailscale** running concurrently. Built on UFW + ipset + nftables.

If your VPN tunnel drops, packets stop. No DNS leak, no fallback to clearnet, no opportunistic IPv6 escape. Reconnect, or run `sudo ./vpn-firewall-setup.sh unlock` to roll back.

## What you get

- **Strict mode** locks egress on the physical interface to a union of provider endpoint IPs. Pre-tunnel traffic that isn't to a whitelisted relay/DERP/bridge is dropped.
- **Permissive mode** opens DNS + 443 + standard VPN ports to any host on the physical interface. Useful when you can't enumerate endpoints.
- **Provider profiles** auto-fetch endpoint IPs:
  - `mullvad` — pulled from `api.mullvad.net` (WireGuard + OpenVPN + bridge relays).
  - `airvpn` — parsed from `.ovpn` and WireGuard `.conf` files in `/etc/openvpn` and Eddie config dirs.
  - `tailscale` — DERP relays from `derpmap/default` + hardcoded bootstrap DNS list + control plane hosts.
- **Tailscale + Mullvad coexistence** without manual `mullvad-exclude` juggling. Installs `ip rule` entries at priority 5200 (above Mullvad's fwmark default at 5209) so traffic to Tailscale CGNAT (`100.64.0.0/10`) and advertised RFC1918 subnets actually exits `tailscale0`. Persisted via a systemd oneshot.
- **FORWARD chain rules** so containers, VMs, and netns traffic can egress through VPN interfaces. Without these, Docker containers' tunnel-bound traffic dies silently at `FORWARD` policy `DROP`.
- **NetworkManager dispatcher hook** that retargets the kill-switch when the physical interface changes (wifi ↔ ethernet, dock, etc.) — with safety guards that refuse to retarget the DROP rule onto a VPN interface.
- **Emergency `panic`** subcommand: drops all firewall rules, destroys ipsets, removes the dispatcher hook, re-enables IPv6 at runtime, resets `/etc/resolv.conf` to public resolvers, restarts `systemd-resolved` + `NetworkManager` + `tailscaled`, runs a connectivity probe. Use from a local TTY when you've locked yourself out.
- **`unlock`** for the non-destructive rollback path: restores UFW from the snapshot taken at install time.

## Install

```bash
sudo apt install ipset jq ufw   # required
git clone https://github.com/<you>/vpn-kis
cd vpn-kis
chmod +x vpn-firewall-setup.sh
```

## Common workflows

```bash
# Permissive: works with any VPN, hostname-based configs OK
sudo ./vpn-firewall-setup.sh

# Strict, single provider:
sudo ./vpn-firewall-setup.sh fetch mullvad
sudo ./vpn-firewall-setup.sh providers mullvad

# Strict, multiple providers (union of endpoint IPs):
sudo ./vpn-firewall-setup.sh fetch mullvad airvpn tailscale
sudo ./vpn-firewall-setup.sh providers mullvad airvpn tailscale

# Auto-detect from currently-active tunnel:
sudo ./vpn-firewall-setup.sh auto

# Verify (non-disruptive):
sudo ./vpn-firewall-setup.sh test

# Verify (active leak test — drops VPN, checks for leak, reconnects):
sudo FORCE=1 ./vpn-firewall-setup.sh test active

# Rollback to pre-install snapshot:
sudo ./vpn-firewall-setup.sh unlock

# EMERGENCY (locked out, run from local TTY):
sudo ./vpn-firewall-setup.sh panic
```

## Modes

| Mode | When | Pre-tunnel surface |
|---|---|---|
| **PERMISSIVE** (default `setup`) | Hostname-based configs, frequently-rotating providers, exploratory use | DNS + 443 + standard VPN ports open to any host on the physical interface |
| **STRICT** (`auto` / `providers` / `VPN_ENDPOINTS=`) | Production, paranoid, fixed providers | Only whitelisted endpoint IPs reachable on the physical interface |

Strict mode requires periodic `fetch` runs as providers rotate IPs. Mullvad rotates rarely; AirVPN almost never; Tailscale DERP IPs only when servers move.

## Custom providers

Drop a list of IPs into `/etc/vpn-killswitch/providers/<name>.ips` (one per line, `#` comments allowed):

```
# /etc/vpn-killswitch/providers/myvpn.ips
198.51.100.10
198.51.100.11
```

Then:

```bash
sudo ./vpn-firewall-setup.sh providers myvpn
```

Or implement a `fetch_myvpn()` function in the script for auto-refresh from your provider's API.

## Per-domain split tunneling

Run an auxiliary OpenVPN tunnel for a specific set of domains (e.g. an IP-allowlisted SaaS or a private corporate app) while the rest of egress stays on Mullvad / AirVPN / clearnet. The mechanism: dnsmasq tags DNS replies for the listed domains into an ipset, an iptables `mangle` rule marks packets to those IPs, an `ip rule` matches that mark and looks up a dedicated route table, and the auxiliary tunnel's `--up` hook installs `default dev <tun> table <N>` into that table.

### Prerequisites

- `dnsmasq` reachable as the system resolver. The `ipset=` directive is dnsmasq-specific. `systemd-resolved` alone is **not enough** — either install dnsmasq standalone or enable NetworkManager's dnsmasq plugin (`[main] dns=dnsmasq` in `/etc/NetworkManager/NetworkManager.conf`).
- An OpenVPN config with a stable `--dev` name (so the up/down hooks target the right interface). The launcher pins `--dev` for you.

### Config

Drop a file at `/etc/vpn-killswitch/split/<name>.conf` (local — not git-tracked):

```ini
# /etc/vpn-killswitch/split/example.conf
DOMAINS="*.example.com app.example.org"
DEV=tun-example
TABLE=142
MARK=0x42
PRIORITY=auto                       # 'auto' = below Tailscale's priority, or a number
OVPN_CONFIG=/etc/openvpn/example.ovpn
```

### Use

```bash
sudo ./vpn-firewall-setup.sh split add example         # install ipset+mangle+ip rule+dnsmasq+systemd unit
sudo ./vpn-firewall-setup.sh split list                # show all splits
sudo ./vpn-firewall-setup.sh split status example      # ipset entries, route table, unit state
sudo ./vpn-firewall-setup.sh split connect example     # launch openvpn with split-tunnel flags
sudo ./vpn-firewall-setup.sh split rm example          # tear down (config left in place)
```

`split connect` wraps the launcher with `mullvad-exclude` when Mullvad is active, so the OpenVPN handshake bypasses Mullvad's fwmark default route. The launcher always sets `--route-nopull` and `pull-filter ignore "redirect-gateway"` so the auxiliary tunnel cannot hijack the main route.

### What gets installed

- ipset `vpnkis_split_<name>_dst` (hash:ip, 1h timeout — dnsmasq refreshes on each query)
- iptables mangle rule in chain `VPNKIS-SPLIT`: `match-set <set> dst -j MARK --set-mark <MARK>`
- `ip rule` at `PRIORITY`: `fwmark <MARK> lookup <TABLE>`
- dnsmasq drop-in `/etc/dnsmasq.d/vpn-kis-split-<name>.conf`
- systemd oneshot `vpn-killswitch-split-<name>.service` for boot persistence
- openvpn up/down scripts at `/etc/vpn-killswitch/split/<name>.{up,down}.sh`

`unlock` and `panic` clean all of the above.

### Coexistence

Split rules sit ~10 below the Tailscale rule priority (auto-detected from Mullvad's fwmark rule), so the precedence is:

```
<split>      fwmark 0x42  lookup 142   (priority ~5089)
<tailscale>  to CGNAT/RFC1918 lookup 52 (priority ~5099)
<mullvad>    fwmark 0x6d6f6c65 lookup … (priority ~5099)
<main>       0/0 default                (priority 32766)
```

Set an explicit `PRIORITY=<N>` in the conf if you need a different ordering.

## Tailscale + Mullvad coexistence

When both are active, Mullvad's `inet mullvad` nftables table installs `forward` policy `DROP` and a final `reject` rule — only `oif wg0-mullvad` is permitted. Tailscale CGNAT (`100.64.0.0/10`) gets rejected; tailnet RFC1918 subnets get hijacked by Mullvad's fwmark default route (priority 5209) and dropped at the exit.

This script handles both:

1. **`mullvad lan set allow`** (you run this once) — opens RFC1918 + link-local in Mullvad's chains. Required for the next step to work.
2. **`install_tailscale_route_rules`** (the script runs this) — adds `ip rule` entries at priority **5200** for Tailscale CGNAT and discovered RFC1918 subnets, lookup table 52. These beat Mullvad's rule 5209, so traffic to those CIDRs actually exits `tailscale0`. Persisted via `vpn-killswitch-tailscale-routes.service`.

For Kubernetes via a Tailscale subnet router, this means `kubectl` can target the cluster's kube-apiserver ClusterIP (`10.96.0.1` on a default service CIDR) directly — no per-node tailnet whitelist needed.

## Recovery

If you lock yourself out:

1. **Switch to a TTY** (Ctrl+Alt+F2). Don't try to fix it from a window manager that depends on the network.
2. `sudo ./vpn-firewall-setup.sh panic` — the nuclear option. Drops everything, restores DNS, restarts the network stack.
3. If panic fails, the file `/etc/ufw/backup-<timestamp>/` has snapshots of everything modified.

## Persistence

- UFW rules persist via `ufw.service` (enabled at install).
- `vpn_endpoints` ipset persists via `/etc/ipset.conf` + `/etc/ufw/before.init` hook (loads before UFW applies rules).
- Tailscale ip rules persist via `/etc/systemd/system/vpn-killswitch-tailscale-routes.service`.
- IPv6 is disabled at sysctl + modprobe + GRUB level (full disable requires reboot).

## Requirements

- Ubuntu / Debian (uses UFW + apt). Other distros need adaptation of the UFW glue.
- `ipset`, `jq`, `ufw`.
- Root.
- For provider auto-fetch: outbound HTTPS at install time (or use cached `/etc/vpn-killswitch/providers/*.ips`).

## Caveats

- IPv6 is disabled wholesale. The script targets IPv4-only setups; IPv6 leaks are too easy to introduce by accident.
- Tailscale strict mode forces peer-to-peer traffic through DERP relays (direct UDP requires whitelisting per-peer endpoints, which we cannot enumerate ahead of time). Slower, still works.
- The NetworkManager dispatcher hook assumes one physical interface is "the" uplink at a time.
- Active leak test (`test active`) actually disconnects your VPN. Don't run it on a connection you can't afford to drop.

## License

MIT — see [LICENSE](LICENSE).
