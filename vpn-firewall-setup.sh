#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# VPN Kill-Switch Firewall — AirVPN (Eddie) + Mullvad
# Strictest mode: no LAN, no IPv6, VPN-only outbound
#
# FIXES from v1:
#   - DNS allowed on physical IF (needed to resolve VPN hosts)
#   - Eddie HTTPS allowed on physical IF (client auth/API)
#   - UFW is sole rule manager (no conflicting manual iptables)
#   - Kill-switch via /etc/ufw/before.rules so UFW owns it all
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf "${GREEN}[+]${NC} %s\n" "$*" >&2; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*" >&2; }
error() { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

VPN_INTERFACES="${VPN_IFACES:-tun+ wg+ Eddie ppp+ tailscale0}"
# 1194 OpenVPN, 443 OpenVPN-TCP-fallback, 53 AirVPN-DNS-tunnel, 51820 WireGuard,
# 1300-1302 AirVPN OpenVPN alts, 1637 AirVPN WireGuard,
# 41641 Tailscale direct, 3478 STUN (Tailscale NAT traversal)
VPN_PORTS_UDP="1194 443 53 51820 1300 1301 1302 1637 41641 3478"
VPN_PORTS_TCP="443"
PHYSICAL_IF=""

# Optional: lock pre-VPN rules to specific server IPs.
# Set via env: VPN_ENDPOINTS="1.2.3.4 5.6.7.8" ./vpn-firewall-setup.sh
# When set, VPN ports + HTTPS auth only allowed to these IPs (strict mode).
VPN_ENDPOINTS="${VPN_ENDPOINTS:-}"

# Optional: LAN CIDRs allowed to bypass the kill-switch on the physical IF.
# Off by default — opt in per run. Use for management traffic to local
# infra that shouldn't transit the VPN, e.g. Talos cluster apid (:50000)
# on the cluster LAN, NAS, printer. Bidirectional ESTABLISHED is already
# covered by conntrack; this opens NEW outbound to those CIDRs *and*
# inbound from those CIDRs (so LAN devices can also initiate).
#
# Set via CLI flag (recommended):
#   sudo ./vpn-firewall-setup.sh --lan 192.168.100.0/24 providers mullvad
# Or via env var:
#   sudo LAN_ALLOW_CIDRS="192.168.100.0/24 10.0.5.0/24" ./vpn-firewall-setup.sh ...
# Multiple CIDRs: space-separated, quote the whole value.
#
# SECURITY: enabling this exposes your machine to LAN-initiated connections
# on those CIDRs. Acceptable for a wired home LAN of known devices; risky
# on shared/coworking/dorm LANs.
LAN_ALLOW_CIDRS="${LAN_ALLOW_CIDRS:-}"

BACKUP_DIR="/etc/ufw/backup-$(date +%Y%m%d-%H%M%S)"
PROVIDERS_DIR="/etc/vpn-killswitch/providers"

# Public resolvers added to the endpoint ipset in strict mode so 'refresh'
# can re-resolve provider hostnames even while the VPN is down (53/udp is in
# VPN_PORTS_UDP, so strict rules allow DNS to ipset members only).
# Trade-off: DNS to these resolvers is visible to the ISP when the VPN is
# down. Opt out with DNS_BOOTSTRAP_IPS="" in env.
DNS_BOOTSTRAP_IPS="${DNS_BOOTSTRAP_IPS-1.1.1.1 8.8.8.8 9.9.9.9}"

# Provider names from the last 'providers' run — consumed by 'refresh' so
# the timer knows what to re-fetch without re-stating the list.
PROVIDERS_ACTIVE_FILE="/etc/vpn-killswitch/providers.active"
REFRESH_SERVICE=/etc/systemd/system/vpn-killswitch-refresh.service
REFRESH_TIMER=/etc/systemd/system/vpn-killswitch-refresh.timer

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Run as root or with sudo"
    fi
}

# Read-only iptables view. Returns the first backend that can render the
# request; prints nothing and returns 1 if none can.
# READ ONLY — rule *writes* must keep using the bare `iptables` alternatives
# default, the same backend UFW restores into.
ipt_ro() {
    local cand
    for cand in iptables iptables-nft iptables-legacy; do
        command -v "$cand" >/dev/null 2>&1 || continue
        command "$cand" "$@" 2>/dev/null && return 0
    done
    return 1
}

# Print up to 20 lines of a filter-table chain, or explain why it can't be
# rendered. Never fails the caller.
show_filter_chain() {
    local chain="$1" out
    if out=$(ipt_ro -L "$chain" -n -v) && [[ -n "$out" ]]; then
        printf '%s\n' "$out" | head -20
        return 0
    fi
    warn "No iptables backend can render filter/$chain."
    warn "Mixed legacy+nft tables, or a native nft ruleset owns the table."
    warn "Inspect with: nft list chain ip filter $chain"
    nft list chain ip filter "$chain" 2>/dev/null | head -20 || true
}

# ---------- Provider fetchers ----------
# Each fetch_<name> prints IPv4 addrs, one per line, to stdout.
# Add new providers by defining another fetch_<name> function.

fetch_mullvad() {
    # Mullvad needs three IP categories for reliable reconnect:
    #   1. WireGuard + OpenVPN relay IPs (the tunnel endpoints)
    #   2. Bridge IPs (Shadowsocks bridges used by Udp2Tcp / obfuscation modes)
    #   3. api.mullvad.net IPs — required PRE-tunnel for Quantum Resistance
    #      PSK exchange and for the app to fetch fresh relay lists on reconnect
    command -v jq >/dev/null 2>&1 || { warn "jq required (apt install jq)"; return 1; }

    local relay_ips api_ips=""
    relay_ips=$(curl -fsSL --max-time 30 https://api.mullvad.net/app/v1/relays 2>/dev/null \
        | jq -r '[
            .wireguard.relays[]?.ipv4_addr_in,
            .openvpn.relays[]?.ipv4_addr_in,
            .bridge.relays[]?.ipv4_addr_in
          ] | .[] | select(. != null and . != "")' 2>/dev/null \
        | sort -u)

    # Resolve Mullvad control plane / API hosts (needed for QR handshake + reconnect)
    local api_hosts="api.mullvad.net"
    local target r h
    for target in $api_hosts; do
        for r in 1 2 3; do
            if command -v dig >/dev/null 2>&1; then
                h=$(dig +short +time=2 +tries=1 "$target" A 2>/dev/null \
                    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
            else
                h=$(getent ahosts "$target" 2>/dev/null \
                    | awk '/STREAM/ {print $1}' | grep -E '^[0-9]+\.' || true)
            fi
            api_ips="$api_ips $h"
        done
    done

    echo "$relay_ips $api_ips" | tr ' ' '\n' | sort -u | grep -vE '^\s*$'
}

fetch_airvpn() {
    # Scan Eddie/OpenVPN/user config dirs for `remote <host-or-ip>` directives.
    # AirVPN ships hostname-only cluster configs (e.g. earth3.vpn.airdns.org) that
    # DNS-round-robin over its server pool — so we collect both literal IPs and
    # resolve hostnames. Rotation means not all servers appear in one run; merge
    # with existing cache and refresh via cron to grow coverage over time.
    local user_home
    user_home=$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)
    [[ -z "$user_home" ]] && user_home="$HOME"

    local dirs=(
        /etc/openvpn /etc/openvpn/airvpn /etc/AirVPN /etc/eddie /opt/AirVPN
        "$user_home" "$user_home/Downloads" "$user_home/.airvpn" "$user_home/AirVPN"
    )

    local remotes=""
    local dir
    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        local files ovpn_remotes wg_remotes
        files=$(find "$dir" -maxdepth 2 \( -name '*.ovpn' -o -name '*.conf' \) 2>/dev/null)
        [[ -z "$files" ]] && continue

        # OpenVPN: `remote <host> [port]`
        ovpn_remotes=$(echo "$files" | xargs -r grep -hE '^\s*remote\s+\S+' 2>/dev/null \
                       | awk '{print $2}' || true)

        # WireGuard: `Endpoint = host:port`  (AirVPN ships WG configs as .conf)
        wg_remotes=$(echo "$files" | xargs -r grep -hE '^\s*Endpoint\s*=\s*\S+' 2>/dev/null \
                     | awk -F'=' '{print $2}' | awk -F: '{print $1}' | tr -d ' ' || true)

        remotes="$remotes $ovpn_remotes $wg_remotes"
    done

    remotes=$(echo "$remotes" | tr ' ' '\n' | sort -u | grep -vE '^\s*$')
    [[ -z "$remotes" ]] && {
        warn "No AirVPN configs found. Download from airvpn.org/generator and place in ~/Downloads or /etc/openvpn/."
        return 1
    }

    local ips=""
    local target
    for target in $remotes; do
        if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ips="$ips $target"
            continue
        fi
        # hostname → DNS resolve. Multiple rounds catch rotation.
        local r host_ips
        for r in 1 2 3 4 5; do
            if command -v dig >/dev/null 2>&1; then
                host_ips=$(dig +short +time=2 +tries=1 "$target" A 2>/dev/null \
                          | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
            else
                host_ips=$(getent ahosts "$target" 2>/dev/null \
                          | awk '/STREAM/ {print $1}' | grep -E '^[0-9]+\.[0-9]+\.' || true)
            fi
            ips="$ips $host_ips"
        done
    done

    # Merge with previous cache so we accumulate over repeated runs.
    local prev="$PROVIDERS_DIR/airvpn.ips"
    local prev_ips=""
    [[ -f "$prev" ]] && prev_ips=$(grep -vE '^\s*(#|$)' "$prev" 2>/dev/null || true)

    echo "$ips $prev_ips" | tr ' ' '\n' | sort -u | grep -vE '^\s*$'
}

fetch_tailscale() {
    # Tailscale needs: DERP relay IPs + control plane (login/controlplane/log)
    # + bootstrap-DNS fallback DERPs hardcoded in the binary.
    # Direct peer-to-peer (UDP 41641) goes to dynamic peer IPs we cannot enumerate;
    # in strict mode peers fall back to DERP relay automatically. Slower, still works.
    command -v jq >/dev/null 2>&1 || { warn "jq required (apt install jq)"; return 1; }

    local ips=""
    local derp_targets
    derp_targets=$(curl -fsSL --max-time 30 https://login.tailscale.com/derpmap/default 2>/dev/null \
        | jq -r '.Regions[]?.Nodes[]? | (.IPv4, .HostName) | select(. != null and . != "")' 2>/dev/null || true)

    # Hardcoded bootstrap-DNS servers compiled into tailscaled. Used at startup
    # before the DERP map is fetched. Without these, tailscaled cannot resolve
    # controlplane.tailscale.com under strict killswitch and never logs in.
    # Source: tailscale/net/dnsfallback/dns-fallback-servers.json
    local bootstrap_ips="\
        134.122.74.153 176.58.93.248 102.67.165.90 208.111.34.178 \
        192.73.252.4 199.38.181.92 192.73.252.51 192.73.252.52 \
        198.244.226.197 192.241.144.189 96.30.103.51 199.38.183.124 \
        148.79.39.83 169.150.246.180 5.180.146.4 195.201.197.155"
    ips="$ips $bootstrap_ips"

    local control_hosts="login.tailscale.com controlplane.tailscale.com log.tailscale.io"

    local target host_ips r
    for target in $derp_targets $control_hosts; do
        if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ips="$ips $target"
            continue
        fi
        for r in 1 2 3; do
            if command -v dig >/dev/null 2>&1; then
                host_ips=$(dig +short +time=2 +tries=1 "$target" A 2>/dev/null \
                          | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
            else
                host_ips=$(getent ahosts "$target" 2>/dev/null \
                          | awk '/STREAM/ {print $1}' | grep -E '^[0-9]+\.[0-9]+\.' || true)
            fi
            ips="$ips $host_ips"
        done
    done

    # Merge with previous cache (DERP map is stable; control IPs may rotate)
    local prev="$PROVIDERS_DIR/tailscale.ips"
    local prev_ips=""
    [[ -f "$prev" ]] && prev_ips=$(grep -vE '^\s*(#|$)' "$prev" 2>/dev/null || true)

    echo "$ips $prev_ips" | tr ' ' '\n' | sort -u | grep -vE '^\s*$'
}

# Generic fetcher for custom providers backed by a split-tunnel config:
# reads OVPN_CONFIG from /etc/vpn-killswitch/split/<name>.conf (or
# <name>-vpn.conf), extracts `remote <host>` directives and resolves them.
# Hostnames behind dynamic IPs (DDNS) get re-resolved on every fetch — pair
# with 'refresh install' so the ipset tracks IP changes automatically.
# Merges with the cached list: old IPs stay allowed during DNS propagation.
fetch_split_remotes() {
    local name="$1" conf="" c
    for c in "$SPLIT_CONF_DIR/${name}.conf" "$SPLIT_CONF_DIR/${name}-vpn.conf" "$SPLIT_CONF_DIR/vpn-${name}.conf"; do
        [[ -f "$c" ]] && { conf="$c"; break; }
    done
    [[ -n "$conf" ]] || return 1

    local ovpn
    ovpn=$(awk -F'=' '/^[[:space:]]*OVPN_CONFIG[[:space:]]*=/ {
        v=$2; gsub(/^[[:space:]"\047]+|[[:space:]"\047]+$/, "", v); print v; exit }' "$conf")
    [[ -n "$ovpn" && -f "$ovpn" ]] || { warn "$conf: no readable OVPN_CONFIG"; return 1; }

    local remotes
    remotes=$(grep -hE '^\s*remote\s+\S+' "$ovpn" 2>/dev/null | awk '{print $2}' | sort -u)
    [[ -n "$remotes" ]] || { warn "no 'remote' directives in $ovpn"; return 1; }

    local ips="" target host_ips r
    for target in $remotes; do
        if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ips="$ips $target"
            continue
        fi
        # System resolver first (works when VPN/dnsmasq up); direct public
        # resolvers as fallback — they are in the endpoint ipset (see
        # DNS_BOOTSTRAP_IPS) so this works even with the VPN down.
        for r in "" "@1.1.1.1" "@8.8.8.8"; do
            if command -v dig >/dev/null 2>&1; then
                host_ips=$(dig +short +time=2 +tries=1 $r "$target" A 2>/dev/null \
                          | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
            else
                host_ips=$(getent ahosts "$target" 2>/dev/null \
                          | awk '/STREAM/ {print $1}' | grep -E '^[0-9]+\.' || true)
                ips="$ips $host_ips"
                break   # getent has no @server form — one shot only
            fi
            [[ -n "$host_ips" ]] && { ips="$ips $host_ips"; break; }
        done
    done

    local prev="$PROVIDERS_DIR/${name}.ips" prev_ips=""
    [[ -f "$prev" ]] && prev_ips=$(grep -vE '^\s*(#|$)' "$prev" 2>/dev/null || true)

    echo "$ips $prev_ips" | tr ' ' '\n' | sort -u | grep -vE '^\s*$'
}

fetch_provider() {
    local name="$1"
    local fn="fetch_$name"
    info "Fetching $name server IPs..."
    local ips
    if declare -F "$fn" >/dev/null 2>&1; then
        ips=$("$fn") || { warn "Fetch failed for $name"; return 1; }
    elif ips=$(fetch_split_remotes "$name"); then
        info "$name: resolved from split config remotes"
    elif [[ -f "$PROVIDERS_DIR/$name.ips" ]]; then
        # Static hand-maintained list — nothing to fetch, cache stays as-is.
        warn "$name: no fetcher and no split config — keeping static $PROVIDERS_DIR/$name.ips"
        return 0
    else
        error "Unknown provider: $name. Known: $(declare -F | awk '/fetch_[a-z]/ {sub(/fetch_/,"",$3); print $3}' | grep -v '^provider$' | xargs). Custom: drop IPs into $PROVIDERS_DIR/$name.ips, or create a split config with OVPN_CONFIG."
    fi
    [[ -z "${ips// }" ]] && { warn "No IPs returned for $name"; return 1; }

    mkdir -p "$PROVIDERS_DIR"
    local out="$PROVIDERS_DIR/$name.ips"
    {
        echo "# $name server IPs"
        echo "# Fetched: $(date -Iseconds)"
        echo "$ips"
    } > "$out"
    local count
    count=$(grep -cvE '^\s*(#|$)' "$out")
    info "Wrote $count IPs to $out"
}

load_providers() {
    # Args: provider names. Prints union of their cached IP lists.
    local ips=""
    local name
    for name in "$@"; do
        local f="$PROVIDERS_DIR/$name.ips"
        if [[ ! -f "$f" ]]; then
            warn "No cached list for '$name' ($f). Run: $0 fetch $name"
            continue
        fi
        local list
        list=$(grep -vE '^\s*(#|$)' "$f" | tr '\n' ' ')
        ips="$ips $list"
    done
    echo "$ips" | tr ' ' '\n' | sort -u | grep -vE '^$' | tr '\n' ' '
}

backup_existing() {
    info "Backing up current UFW config to $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/ufw/user.rules       "$BACKUP_DIR/" 2>/dev/null || true
    cp -a /etc/ufw/user6.rules      "$BACKUP_DIR/" 2>/dev/null || true
    cp -a /etc/ufw/before.rules     "$BACKUP_DIR/" 2>/dev/null || true
    cp -a /etc/ufw/before6.rules    "$BACKUP_DIR/" 2>/dev/null || true
    cp -a /etc/ufw/after.rules      "$BACKUP_DIR/" 2>/dev/null || true
    cp -a /etc/default/ufw          "$BACKUP_DIR/" 2>/dev/null || true
    ufw status verbose > "$BACKUP_DIR/ufw-status.txt" 2>/dev/null || true
    iptables-save   > "$BACKUP_DIR/iptables.v4" 2>/dev/null || true
    ip6tables-save  > "$BACKUP_DIR/iptables.v6" 2>/dev/null || true
    info "Backup done. Restore: cp $BACKUP_DIR/*.rules /etc/ufw/ && ufw reload"
}

# Auto-detect active VPN server IPs from running VPN clients.
# Sources: wg show endpoints, openvpn status/process, ip route via tun/wg.
# Prints space-separated IPs to stdout. Empty = none detected.
detect_vpn_endpoints() {
    local ips=""

    # WireGuard peers
    if command -v wg >/dev/null 2>&1; then
        local wg_ips
        wg_ips=$(wg show all endpoints 2>/dev/null | awk '{print $2}' | awk -F: '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
        ips="$ips $wg_ips"
    fi

    # OpenVPN: parse active UDP/TCP sockets to remote peers on known VPN ports
    # (handles running openvpn process without status file)
    if pgrep -x openvpn >/dev/null 2>&1; then
        local ovpn_ips
        ovpn_ips=$(ss -tunp 2>/dev/null | grep -E 'users:\(\("openvpn"' \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' \
            | awk -F: '{print $1}' \
            | grep -vE '^(127\.|0\.0\.0\.0$)' || true)
        ips="$ips $ovpn_ips"
    fi

    # Eddie (AirVPN client) runs openvpn under the hood, covered above.
    # Fallback: look at current tun/wg interface peer via `ip route`
    local peer_ips
    peer_ips=$(ip route | awk '/dev (tun|wg)/ && /via/ {print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    ips="$ips $peer_ips"

    # Dedupe
    echo "$ips" | tr ' ' '\n' | sort -u | grep -vE '^$' | tr '\n' ' '
}

# Emergency recovery. Run when locked out: drops all firewall rules, resets
# DNS, re-enables IPv6 at runtime, restarts network stack. Pure local — no
# network/apt deps, works with empty resolv.conf and no internet.
# Usage from TTY: sudo /path/to/vpn-firewall-setup.sh panic
panic_recover() {
    printf '\n=== VPN-KILLSWITCH PANIC RECOVERY ===\n\n'

    # 1. Stop UFW (best effort — even if binary missing, raw iptables flush below covers it)
    if command -v ufw >/dev/null 2>&1; then
        echo "[*] Disabling UFW..."
        ufw --force disable 2>/dev/null || true
        systemctl stop ufw 2>/dev/null || true
    fi

    # 2. Set ACCEPT policy + flush every chain in every iptables table
    echo "[*] Flushing iptables (filter/nat/mangle/raw)..."
    for tbl in filter nat mangle raw; do
        iptables  -t "$tbl" -F 2>/dev/null || true
        iptables  -t "$tbl" -X 2>/dev/null || true
        ip6tables -t "$tbl" -F 2>/dev/null || true
        ip6tables -t "$tbl" -X 2>/dev/null || true
    done
    for chain in INPUT OUTPUT FORWARD; do
        iptables  -P "$chain" ACCEPT 2>/dev/null || true
        ip6tables -P "$chain" ACCEPT 2>/dev/null || true
    done

    # 3. Destroy ipset(s) referenced by killswitch
    if command -v ipset >/dev/null 2>&1; then
        echo "[*] Destroying ipsets..."
        ipset destroy vpn_endpoints 2>/dev/null || true
        ipset flush 2>/dev/null || true
    fi

    # 4. Remove dispatcher hook so it doesn't re-corrupt rules on next iface event
    echo "[*] Removing NetworkManager dispatcher hook..."
    rm -f /etc/NetworkManager/dispatcher.d/90-vpn-killswitch 2>/dev/null || true
    rm -f /etc/ufw/before.init 2>/dev/null || true

    remove_tailscale_web
    # 4b. Remove tailscale route rules + boot-persistence unit
    echo "[*] Removing Tailscale routing rules..."
    if [ -f /etc/systemd/system/vpn-killswitch-tailscale-routes.service ]; then
        systemctl disable --now vpn-killswitch-tailscale-routes.service 2>/dev/null || true
        rm -f /etc/systemd/system/vpn-killswitch-tailscale-routes.service
        systemctl daemon-reload 2>/dev/null || true
    fi
    while ip rule del priority 5200 2>/dev/null; do :; done
    remove_tailscale_nft
    remove_tailscaled_dropin

    # 4c. Remove split-tunnel units + ip rules + ipsets
    echo "[*] Removing split-tunnel rules..."
    if [ -d /etc/systemd/system ]; then
        for u in /etc/systemd/system/vpn-killswitch-split-*.service; do
            [ -f "$u" ] || continue
            systemctl disable --now "$(basename "$u")" 2>/dev/null || true
            rm -f "$u"
        done
        systemctl daemon-reload 2>/dev/null || true
    fi
    if command -v ipset >/dev/null 2>&1; then
        ipset list -name 2>/dev/null | grep '^vpnkis_split_' | while read -r s; do
            ipset destroy "$s" 2>/dev/null || true
        done
    fi
    iptables -t mangle -F "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -D OUTPUT     -j "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -D PREROUTING -j "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -X "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
    rm -f /etc/dnsmasq.d/vpn-kis-split-*.conf 2>/dev/null || true

    # 4c-bis. Remove cgroup-based VPN-exclude routing + unit + cgroup
    echo "[*] Removing VPN-exclude rules..."
    if [ -f "$EXCLUDE_UNIT" ]; then
        systemctl disable --now vpn-killswitch-exclude.service 2>/dev/null || true
        rm -f "$EXCLUDE_UNIT"
        systemctl daemon-reload 2>/dev/null || true
    fi
    while ip rule del priority "$EXCLUDE_PRIO" 2>/dev/null; do :; done
    ip route flush table "$EXCLUDE_TABLE" 2>/dev/null || true
    iptables -t mangle -F "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -D OUTPUT -j "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -X "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$EXCLUDE_NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -j "$EXCLUDE_NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$EXCLUDE_NAT_CHAIN" 2>/dev/null || true
    rmdir "$EXCLUDE_CGROUP" 2>/dev/null || true

    # 4d. Remove endpoint-refresh timer
    echo "[*] Removing endpoint-refresh timer..."
    systemctl disable --now vpn-killswitch-refresh.timer 2>/dev/null || true
    rm -f /etc/systemd/system/vpn-killswitch-refresh.timer \
          /etc/systemd/system/vpn-killswitch-refresh.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # 5. Re-enable IPv6 at runtime (sysctl files persist across reboot — see end)
    echo "[*] Re-enabling IPv6 (runtime only)..."
    for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        echo 0 > "$f" 2>/dev/null || true
    done

    # 6. Reset DNS — write a minimal resolv.conf with public resolvers.
    #    If systemd-resolved manages /etc/resolv.conf via symlink, write to its
    #    real target file instead (or break the symlink and write static).
    echo "[*] Restoring DNS resolvers..."
    if [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi
    cat > /etc/resolv.conf <<'EOF'
# Emergency DNS — restored by vpn-firewall-setup.sh panic
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
options timeout:2 attempts:2
EOF
    chmod 644 /etc/resolv.conf

    # 7. Restart network stack
    echo "[*] Restarting systemd-resolved + NetworkManager..."
    systemctl restart systemd-resolved 2>/dev/null || true
    systemctl restart NetworkManager 2>/dev/null || true

    # 8. Tailscale: bring it back up if installed (was likely down during panic)
    if command -v tailscale >/dev/null 2>&1; then
        echo "[*] Restarting tailscaled..."
        systemctl restart tailscaled 2>/dev/null || true
    fi

    # 9. Connectivity probe (uses IP literal — no DNS needed for first hop)
    echo ""
    echo "[*] Connectivity probe..."
    if ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
        echo "    [OK] ICMP to 1.1.1.1 succeeded"
    else
        echo "    [FAIL] No reply from 1.1.1.1 — check physical link / wifi"
    fi
    if getent ahosts cloudflare.com >/dev/null 2>&1; then
        echo "    [OK] DNS resolution working"
    else
        echo "    [FAIL] DNS still broken — try: sudo systemctl restart NetworkManager"
    fi

    # 10. Show final firewall state for sanity
    echo ""
    echo "[*] Current iptables OUTPUT policy:"
    ipt_ro -L OUTPUT -n | head -3 || echo "    (iptables unreadable)"

    cat <<'NOTE'

=== RECOVERY DONE ===

What was reverted (runtime only):
  - UFW disabled
  - iptables/ip6tables flushed, default ACCEPT
  - ipset 'vpn_endpoints' destroyed
  - NetworkManager dispatcher hook removed
  - IPv6 re-enabled in /proc
  - /etc/resolv.conf reset to public resolvers
  - NetworkManager + systemd-resolved restarted
  - tailscaled restarted (if present)

What is NOT reverted (persists across reboot):
  - /etc/sysctl.d/99-disable-ipv6.conf  (IPv6 will disable again on boot)
  - /etc/modprobe.d/disable-ipv6.conf
  - /etc/default/grub  (ipv6.disable=1 kernel arg)
  - UFW rule files in /etc/ufw/  (UFW disabled but rules remain)

To fully revert IPv6 disable:
  sudo rm /etc/sysctl.d/99-disable-ipv6.conf /etc/modprobe.d/disable-ipv6.conf
  sudo sed -i 's/ipv6.disable=1 //' /etc/default/grub
  sudo update-grub
  sudo reboot

To restore UFW from snapshot backup (less invasive than panic):
  sudo /path/to/vpn-firewall-setup.sh unlock

NOTE
}

unlock_firewall() {
    info "Rolling back VPN kill-switch..."
    local latest
    latest=$(ls -1dt /etc/ufw/backup-*/ 2>/dev/null | head -1)
    [[ -z "$latest" ]] && error "No backup found in /etc/ufw/backup-*. Manual recovery needed."
    info "Restoring from: $latest"

    for f in user.rules user6.rules before.rules before6.rules after.rules; do
        [[ -f "$latest/$f" ]] && cp -a "$latest/$f" "/etc/ufw/$f"
    done
    [[ -f "$latest/ufw" ]] && cp -a "$latest/ufw" /etc/default/ufw

    rm -f /etc/NetworkManager/dispatcher.d/90-vpn-killswitch 2>/dev/null || true
    rm -f /etc/ufw/before.init /etc/ipset.conf 2>/dev/null || true

    remove_tailscale_route_rules
    remove_refresh_timer
    split_remove_all
    exclude_remove_all

    ufw reload || warn "ufw reload failed"

    # Drop ipset after rules no longer reference it
    ipset destroy vpn_endpoints 2>/dev/null || true
    info "Firewall restored from $latest."
    info "IPv6 disable (sysctl/modprobe/GRUB) NOT reverted — remove manually if desired:"
    info "  rm /etc/sysctl.d/99-disable-ipv6.conf /etc/modprobe.d/disable-ipv6.conf"
    info "  edit /etc/default/grub to drop ipv6.disable=1, then update-grub"
}

# ---------- Test suite ----------

PASS=0
FAIL=0
pass() { printf "${GREEN}[PASS]${NC} %s\n" "$*"; PASS=$((PASS+1)); }
fail() { printf "${RED}[FAIL]${NC} %s\n" "$*"; FAIL=$((FAIL+1)); }
skip() { printf "${YELLOW}[SKIP]${NC} %s\n" "$*"; }

detect_vpn_iface() {
    # Match tun0, wg0, wg0-mullvad (Mullvad's naming), Eddie (AirVPN),
    # tailscale0, ppp0. Kernel iptables wildcards (wg+, tun+) cover prefix
    # matching at the firewall layer, but `ip link` shows full iface names
    # so this regex must accept the suffix Mullvad/etc append.
    ip -o link show up 2>/dev/null \
        | awk -F': ' '{print $2}' \
        | grep -E '^(tun[0-9]+|wg[0-9]+([-_].+)?|tailscale[0-9]+|Eddie|ppp[0-9]+)$' \
        | head -1
}

test_passive() {
    info "========== PASSIVE TESTS (non-disruptive) =========="
    echo ""

    # 1. UFW active?
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        pass "UFW active"
    else
        fail "UFW not active — killswitch off"
    fi

    # 2. Default policies deny?
    local out_policy
    out_policy=$(ufw status verbose 2>/dev/null | grep -oE 'Default:.*outgoing' | grep -oE 'deny|allow' | head -1)
    if [[ "$out_policy" == "deny" ]]; then
        pass "Default outgoing policy: deny"
    else
        fail "Default outgoing policy: $out_policy (should be deny)"
    fi

    # 3. Kill-switch DROP rule on physical IF present?
    detect_physical_if >/dev/null 2>&1 || true
    if ipt_ro -S ufw-before-output | grep -qE -- "-o $PHYSICAL_IF .*-j DROP"; then
        pass "Physical IF DROP rule present ($PHYSICAL_IF)"
    else
        fail "No DROP rule on $PHYSICAL_IF in ufw-before-output — killswitch will NOT fire"
    fi

    # 4. VPN iface allowed?
    local allowed_vifs
    allowed_vifs=$(ipt_ro -S ufw-before-output | grep -oE -- "-o \S+ -j ACCEPT" | awk '{print $2}' | sort -u | tr '\n' ' ' || true)
    if [[ -n "$allowed_vifs" ]]; then
        pass "VPN interfaces ACCEPT: $allowed_vifs"
    else
        fail "No iface ACCEPT rules in ufw-before-output"
    fi

    # 5. IPv6 disabled?
    if [[ ! -e /proc/sys/net/ipv6 ]]; then
        pass "IPv6 stack absent (module never loaded)"
    elif [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" == "1" ]]; then
        pass "IPv6 disabled"
    else
        fail "IPv6 still enabled (reboot may be required)"
    fi

    # 6. IPv6 firewall also DROP?
    if ip6tables -S ufw6-before-output 2>/dev/null | grep -q -- "-j DROP"; then
        pass "IPv6 DROP rule present"
    else
        skip "IPv6 DROP rule check (may be skipped if ip6tables unavailable)"
    fi

    # 7. Strict mode check (are endpoint IPs locked via -d or ipset?)
    local strict_rules ipset_count ipset_ok=0
    strict_rules=$(ipt_ro -S ufw-before-output | grep -cE -- "-d [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*ACCEPT" || true)
    if ipt_ro -S ufw-before-output | grep -q "match-set vpn_endpoints"; then
        ipset_count=$(ipset list vpn_endpoints 2>/dev/null | awk '/Number of entries:/ {print $NF}')
        if [[ -n "$ipset_count" && "$ipset_count" -gt 0 ]]; then
            pass "Strict mode active: ipset 'vpn_endpoints' with $ipset_count IPs"
            ipset_ok=1
        else
            fail "ipset referenced in rules but empty/missing — rules won't match"
        fi
    fi
    if [[ "$strict_rules" -gt 0 ]]; then
        pass "Strict mode active: $strict_rules IP-locked rules (-d form)"
        ipset_ok=1
    fi
    if [[ "$ipset_ok" -eq 0 ]]; then
        skip "Permissive mode (no ipset/no -d rules) — pre-VPN HTTPS/DNS open, full leak test will fail by design"
    fi

    # 8. Current public IP reachable via VPN?
    local pub_ip vpn_if
    vpn_if=$(detect_vpn_iface)
    if [[ -n "$vpn_if" ]]; then
        pub_ip=$(curl --max-time 5 -s https://ifconfig.me 2>/dev/null || echo "")
        if [[ -n "$pub_ip" ]]; then
            pass "VPN up ($vpn_if), public IP: $pub_ip"
        else
            fail "VPN iface $vpn_if up but no internet (rules too tight?)"
        fi
    else
        skip "No active VPN interface detected"
    fi

    echo ""
    summary
}

# Bring VPN down, check for leak, bring back up.
test_active() {
    info "========== ACTIVE LEAK TEST (disruptive) =========="
    echo ""
    warn "This will DROP your VPN connection to test the killswitch."
    warn "Any active downloads/SSH/streams will be interrupted."
    if [[ "${FORCE:-0}" != "1" ]]; then
        read -rp "Continue? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] || { info "Aborted."; return 0; }
    fi

    local vpn_if
    vpn_if=$(detect_vpn_iface)
    [[ -z "$vpn_if" ]] && { warn "No VPN interface up — cannot test drop."; return 1; }

    local baseline
    baseline=$(curl --max-time 5 -s https://ifconfig.me 2>/dev/null || echo "")
    info "Baseline public IP (VPN up): ${baseline:-<unreachable>}"
    [[ -z "$baseline" ]] && { warn "No internet even with VPN up — aborting."; return 1; }

    info "Dropping VPN interface: $vpn_if"
    local vpn_cmd_restore=""
    if [[ "$vpn_if" =~ ^wg ]]; then
        wg-quick down "$vpn_if" >/dev/null 2>&1 && vpn_cmd_restore="wg-quick up $vpn_if" \
            || { ip link set "$vpn_if" down; vpn_cmd_restore="ip link set $vpn_if up"; }
    else
        # OpenVPN/Eddie: link-down is less invasive than pkill; Eddie may auto-reconnect
        ip link set "$vpn_if" down
        vpn_cmd_restore="ip link set $vpn_if up (then reconnect via Eddie/openvpn client)"
    fi

    sleep 2

    info "Testing leak with VPN DOWN..."
    local leak=0
    local leaked_ip
    leaked_ip=$(curl --max-time 5 -s https://ifconfig.me 2>/dev/null || echo "")
    if [[ -n "$leaked_ip" ]]; then
        fail "curl ifconfig.me returned: $leaked_ip (LEAK — killswitch failed)"
        leak=1
    else
        pass "curl ifconfig.me timed out (no leak)"
    fi

    local leaked_cf
    leaked_cf=$(curl --max-time 5 -s https://1.1.1.1 2>/dev/null | head -c 20 || echo "")
    if [[ -n "$leaked_cf" ]]; then
        fail "curl 1.1.1.1 returned data (LEAK)"
        leak=1
    else
        pass "curl 1.1.1.1 timed out (no leak)"
    fi

    if ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
        fail "ping 8.8.8.8 succeeded (LEAK)"
        leak=1
    else
        pass "ping 8.8.8.8 blocked"
    fi

    if dig +time=3 +tries=1 google.com @8.8.8.8 +short >/dev/null 2>&1; then
        # permissive mode allows DNS → not a leak per se but noted
        if ipt_ro -S ufw-before-output | grep -qE -- "--dport 53.*ACCEPT"; then
            skip "DNS @8.8.8.8 reached (permissive mode allows DNS to any host)"
        else
            fail "DNS @8.8.8.8 resolved (LEAK — DNS rule shouldn't allow this)"
            leak=1
        fi
    else
        pass "DNS @8.8.8.8 blocked"
    fi

    echo ""
    info "Restoring VPN: $vpn_cmd_restore"
    eval "$vpn_cmd_restore" >/dev/null 2>&1 || warn "Restore command failed — reconnect VPN manually"
    sleep 3
    local restored_ip
    restored_ip=$(curl --max-time 10 -s https://ifconfig.me 2>/dev/null || echo "")
    if [[ -n "$restored_ip" && "$restored_ip" != "$baseline" ]]; then
        pass "VPN restored, public IP: $restored_ip"
    else
        warn "VPN not restored automatically — reconnect via your VPN client"
    fi

    echo ""
    if [[ $leak -eq 0 ]]; then
        info "KILLSWITCH VERIFIED — no leak detected"
    else
        fail "KILLSWITCH FAILED — $leak leak vector(s) detected"
    fi
    echo ""
    summary
}

summary() {
    echo ""
    info "Test summary: $PASS passed, $FAIL failed"
    [[ $FAIL -eq 0 ]] || exit 1
}

detect_physical_if() {
    PHYSICAL_IF=$(ip -4 route ls | grep -m1 default | awk '{print $5}')
    if [[ -z "$PHYSICAL_IF" ]]; then
        PHYSICAL_IF=$(ls /sys/class/net/ | grep -v -E '^lo$|^tun|^wg|^docker|^virbr|^veth|^br-' | head -1)
    fi
    [[ -z "$PHYSICAL_IF" ]] && error "Cannot detect physical interface. Set PHYSICAL_IF manually."
    info "Physical interface: $PHYSICAL_IF"
}

disable_ipv6() {
    info "Disabling IPv6..."

    cat > /etc/sysctl.d/99-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
EOF

    # Whole tree is absent when the ipv6 module never loaded (ipv6.disable=1
    # already on the kernel cmdline); the glob then stays literal.
    for iface in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        [[ -w "$iface" ]] || continue
        echo 1 > "$iface" 2>/dev/null || true
    done
    sysctl --system > /dev/null 2>&1

    cat > /etc/modprobe.d/disable-ipv6.conf <<'EOF'
install ipv6 /bin/true
blacklist ipv6
alias net-pf-10 off
alias sit0 off
EOF

    if [[ -f /etc/default/grub ]] && ! grep -q 'ipv6.disable=1' /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/\0ipv6.disable=1 /' /etc/default/grub
        update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || true
        warn "GRUB updated. Reboot to fully apply IPv6 disable."
    fi

    info "IPv6 disabled via sysctl + modprobe."
}

# Create/populate kernel ipset of VPN endpoint IPs, persist for reboot.
# Uses ipset restore for bulk load — thousands of IPs in <1s.
setup_endpoint_ipset() {
    command -v ipset >/dev/null 2>&1 || {
        warn "ipset not installed — installing..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y ipset 2>/dev/null \
            || error "Cannot install ipset. Run: sudo apt install ipset"
    }

    info "Building ipset 'vpn_endpoints' with $(echo "$VPN_ENDPOINTS" | wc -w) IPs..."

    # Destroy stale set (ignore errors if referenced — handled after rules flush)
    ipset destroy vpn_endpoints 2>/dev/null || true

    # Bulk load via restore (single syscall batch)
    # DNS_BOOTSTRAP_IPS included so 'refresh' can resolve provider hostnames
    # while the VPN is down (strict mode allows 53/udp to set members only).
    {
        echo "create vpn_endpoints hash:ip family inet hashsize 2048 maxelem 65536"
        for ip in $VPN_ENDPOINTS $DNS_BOOTSTRAP_IPS; do
            [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { warn "Skipping non-IPv4 endpoint: $ip"; continue; }
            echo "add vpn_endpoints $ip"
        done
    } | ipset restore -exist

    # Persist: save to /etc/ipset.conf, load via UFW's before.init hook
    mkdir -p /etc
    ipset save vpn_endpoints > /etc/ipset.conf

    # UFW before.init runs pre-rules on boot — ideal place to rehydrate ipset
    cat > /etc/ufw/before.init <<'INIT'
#!/bin/sh
# Hook: rehydrate vpn_endpoints ipset before UFW loads rules (which reference it).
case "$1" in
    start)
        if [ -f /etc/ipset.conf ] && command -v ipset >/dev/null 2>&1; then
            ipset restore -exist < /etc/ipset.conf 2>/dev/null || true
        fi
        ;;
    stop|status|flush-all)
        ;;
esac
INIT
    chmod 755 /etc/ufw/before.init

    local actual
    actual=$(ipset list vpn_endpoints 2>/dev/null | grep "Number of entries:" | awk '{print $NF}')
    info "ipset loaded: $actual entries. Persisted to /etc/ipset.conf + before.init hook."
}

setup_ufw() {
    info "Configuring UFW (sole firewall manager)..."

    ufw --force reset

    ufw default deny incoming
    ufw default deny outgoing
    ufw default deny routed

    ufw allow in on lo
    ufw allow out on lo

    # --- DNS on physical interface ---
    # REQUIRED unless VPN_ENDPOINTS set: VPN client must resolve hostnames pre-tunnel.
    # Trade-off: DNS queries leak to ISP until VPN up.
    if [[ -z "$VPN_ENDPOINTS" ]]; then
        ufw allow out on "$PHYSICAL_IF" to any port 53 proto udp comment "DNS-UDP-pre-VPN"
        ufw allow out on "$PHYSICAL_IF" to any port 53 proto tcp comment "DNS-TCP-pre-VPN"
    else
        info "VPN_ENDPOINTS set — skipping DNS rules (strict mode, no DNS leak)."
    fi

    # --- DHCP ---
    ufw allow out on "$PHYSICAL_IF" to any port 67 proto udp comment "DHCP"

    # --- NTP (time sync for cert validation) ---
    ufw allow out on "$PHYSICAL_IF" to any port 123 proto udp comment "NTP"

    # --- VPN tunnel ports + Eddie HTTPS auth ---
    if [[ -n "$VPN_ENDPOINTS" ]]; then
        # Strict mode: endpoint matching handled via ipset in before.rules.
        # No per-IP UFW user rules — would invoke ufw reload per call, ~1/sec.
        # Thousands of IPs would take hours. ipset handles it in one kernel lookup.
        info "Strict mode: endpoint rules live in before.rules via ipset (fast)"
    else
        # Permissive: any host on VPN ports + 443 (Eddie API)
        ufw allow out on "$PHYSICAL_IF" to any port 443 proto tcp comment "Eddie-HTTPS-auth"
        for port in $VPN_PORTS_UDP; do
            ufw allow out on "$PHYSICAL_IF" to any port "$port" proto udp comment "VPN-UDP-$port"
        done
        for port in $VPN_PORTS_TCP; do
            [[ -n "$port" ]] && ufw allow out on "$PHYSICAL_IF" to any port "$port" proto tcp comment "VPN-TCP-$port"
        done
    fi

    # --- Allow all through VPN interfaces (wildcards + known names) ---
    for vif in $VPN_INTERFACES; do
        ufw allow in  on "$vif" || warn "ufw reject iface pattern: $vif"
        ufw allow out on "$vif" || true
    done

    ufw --force enable

    info "UFW enabled with VPN-only rules + DNS/Eddie pre-connect exceptions."
}

add_killswitch_before_rules() {
    info "Hardening: adding iptables kill-switch to UFW before.rules..."

    cat > /etc/ufw/before.rules <<BEFORE
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]

# --- Loopback ---
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# --- Established/related ---
-A ufw-before-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- DHCP ---
-A ufw-before-output -o $PHYSICAL_IF -p udp --dport 67 -j ACCEPT

# --- NTP ---
-A ufw-before-output -o $PHYSICAL_IF -p udp --dport 123 -j ACCEPT

BEFORE

    # --- LAN CIDR exceptions (e.g. cluster apid, NAS) ---
    # These must precede the kill-switch DROP at the bottom of this file.
    # Conntrack ESTABLISHED,RELATED is already accepted above, so return
    # traffic for outbound flows works without an explicit input rule —
    # we still emit the input rule to permit NEW inbound from same LAN
    # (probes, mDNS, etc.) which the kill-switch would otherwise drop.
    if [[ -n "$LAN_ALLOW_CIDRS" ]]; then
        echo "# --- LAN allow-list ($LAN_ALLOW_CIDRS) ---" >> /etc/ufw/before.rules
        for cidr in $LAN_ALLOW_CIDRS; do
            echo "-A ufw-before-output -o $PHYSICAL_IF -d $cidr -j ACCEPT" >> /etc/ufw/before.rules
            echo "-A ufw-before-input  -i $PHYSICAL_IF -s $cidr -j ACCEPT" >> /etc/ufw/before.rules
        done
        echo "" >> /etc/ufw/before.rules
    fi

    if [[ -z "$VPN_ENDPOINTS" ]]; then
        cat >> /etc/ufw/before.rules <<BEFORE_DNS
# --- DNS on physical IF (resolve VPN hosts) ---
-A ufw-before-output -o $PHYSICAL_IF -p udp --dport 53 -j ACCEPT
-A ufw-before-output -o $PHYSICAL_IF -p tcp --dport 53 -j ACCEPT

# --- Eddie HTTPS auth ---
-A ufw-before-output -o $PHYSICAL_IF -p tcp --dport 443 -j ACCEPT

# --- VPN tunnel ports (any host) ---
BEFORE_DNS
        for port in $VPN_PORTS_UDP; do
            echo "-A ufw-before-output -o $PHYSICAL_IF -p udp --dport $port -j ACCEPT" >> /etc/ufw/before.rules
        done
        for port in $VPN_PORTS_TCP; do
            [[ -n "$port" ]] && echo "-A ufw-before-output -o $PHYSICAL_IF -p tcp --dport $port -j ACCEPT" >> /etc/ufw/before.rules
        done
    else
        # Strict mode: use ipset for O(1) endpoint matching regardless of IP count.
        setup_endpoint_ipset
        local ep_count
        ep_count=$(echo "$VPN_ENDPOINTS" | wc -w)
        echo "# --- VPN tunnel ports (locked to ipset vpn_endpoints: $ep_count IPs) ---" >> /etc/ufw/before.rules
        for port in $VPN_PORTS_UDP; do
            echo "-A ufw-before-output -o $PHYSICAL_IF -p udp --dport $port -m set --match-set vpn_endpoints dst -j ACCEPT" >> /etc/ufw/before.rules
        done
        for port in $VPN_PORTS_TCP; do
            [[ -n "$port" ]] && echo "-A ufw-before-output -o $PHYSICAL_IF -p tcp --dport $port -m set --match-set vpn_endpoints dst -j ACCEPT" >> /etc/ufw/before.rules
        done
    fi

    echo "" >> /etc/ufw/before.rules
    echo "# --- VPN interfaces: allow all ---" >> /etc/ufw/before.rules
    for vif in $VPN_INTERFACES; do
        echo "-A ufw-before-output -o $vif -j ACCEPT" >> /etc/ufw/before.rules
        echo "-A ufw-before-input  -i $vif -j ACCEPT" >> /etc/ufw/before.rules
    done

    # Forward chain: containers / VMs / namespaces routing through VPN ifaces.
    # Without these, FORWARD policy DROP kills container egress to tailscale0,
    # wg+, etc. Established return path also needed for replies.
    echo "" >> /etc/ufw/before.rules
    echo "# --- VPN interfaces: allow forwarded traffic (containers, VMs) ---" >> /etc/ufw/before.rules
    echo "-A ufw-before-forward -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" >> /etc/ufw/before.rules
    for vif in $VPN_INTERFACES; do
        echo "-A ufw-before-forward -o $vif -j ACCEPT" >> /etc/ufw/before.rules
    done

    # --- Owner-based VPN exclusion: ACCEPT excluded users before the DROP ---
    exclude_emit_before_rules_block "$PHYSICAL_IF" >> /etc/ufw/before.rules

    cat >> /etc/ufw/before.rules <<'BEFORE2'

# --- KILL-SWITCH: drop anything else on physical IF ---
-A ufw-before-output -o {{PHYS_IF}} -j DROP
-A ufw-before-input  -i {{PHYS_IF}} -j DROP

COMMIT
BEFORE2

    sed -i "s/{{PHYS_IF}}/$PHYSICAL_IF/g" /etc/ufw/before.rules

    cat > /etc/ufw/before6.rules <<'EOF'
*filter
:ufw6-before-input - [0:0]
:ufw6-before-output - [0:0]
:ufw6-before-forward - [0:0]
-A ufw6-before-input -j DROP
-A ufw6-before-output -j DROP
-A ufw6-before-forward -j DROP
COMMIT
EOF

    ufw reload

    info "Kill-switch active in before.rules. Non-VPN traffic on $PHYSICAL_IF is DROP'd."
}

make_persistent() {
    # UFW is persistent by default via systemd (ufw.service).
    # Do NOT install iptables-persistent — it fights UFW on boot.
    info "UFW persistence handled by ufw.service (systemctl enable ufw)."
    systemctl enable ufw >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1 || true
}

# ---------- Tailscale subnet routing ----------
#
# When Mullvad is connected, its fwmark default-route rule catches any packet
# without explicit policy. Tailscale's own subnet routes live in table 52 at
# priority 5270 (BELOW Mullvad), so packets to tailnet CGNAT and advertised
# subnets get hijacked by Mullvad and dropped at the exit (RFC1918) or
# rejected by Mullvad's nftables forward chain (CGNAT).
#
# These rules push table-52 lookups for those CIDRs ABOVE Mullvad's rule,
# so host AND container traffic to tailnet destinations exit tailscale0.
#
# Priority is detected at install time: we find Mullvad's fwmark rule
# (mark 0x6d6f6c65 — "mole") and place ours one below. Mullvad app builds
# have used different priorities over time (5199 today, 5209 historically),
# so hardcoding is fragile. Fallback to TAILSCALE_RULE_PRIO_FALLBACK if
# Mullvad isn't running at install time.
TAILSCALE_RULE_PRIO_FALLBACK=5100
TAILSCALE_RULE_PRIO=""   # populated by detect_tailscale_rule_prio
TAILSCALE_ROUTE_TABLE=52
TAILSCALE_ROUTES_UNIT=/etc/systemd/system/vpn-killswitch-tailscale-routes.service
MULLVAD_FWMARK=0x6d6f6c65
MULLVAD_CT_MARK=0x00000f41
TAILSCALE_NFT_TABLE=vpn-killswitch-tailscale
TAILSCALED_DROPIN=/etc/systemd/system/tailscaled.service.d/50-vpn-killswitch-mullvad.conf
TAILSCALE_WEB_ENABLED=/etc/vpn-killswitch/tailscale-web.enabled

tailscale_web_helper() {
    python3 "$(dirname "$(readlink -f "$0")")/lib/tailscale-web/configure.py" "$@"
}

remove_tailscale_web() {
    rm -f "$TAILSCALE_WEB_ENABLED"
    tailscale_web_helper remove || warn "Could not fully remove the OpenClaw client exception."
}

detect_tailscale_rule_prio() {
    # Find Mullvad's fwmark default-route rule and place ours one below.
    # `ip rule show` format: "<prio>:\t<selectors> lookup <table>"
    local mullvad_prio
    mullvad_prio=$(ip rule show 2>/dev/null \
        | awk -v mark="$MULLVAD_FWMARK" '$0 ~ "fwmark " mark { sub(/:/,"",$1); print $1; exit }')

    if [[ -n "$mullvad_prio" && "$mullvad_prio" =~ ^[0-9]+$ && "$mullvad_prio" -gt 1 ]]; then
        TAILSCALE_RULE_PRIO=$((mullvad_prio - 1))
        info "Mullvad fwmark rule at priority $mullvad_prio — placing Tailscale rules at $TAILSCALE_RULE_PRIO"
    else
        TAILSCALE_RULE_PRIO=$TAILSCALE_RULE_PRIO_FALLBACK
        info "Mullvad fwmark rule not found — using fallback priority $TAILSCALE_RULE_PRIO"
    fi
}

discover_tailscale_cidrs() {
    # CGNAT is always relevant if tailscale is in the picture.
    echo "100.64.0.0/10"
    # Plus any RFC1918 subnets currently advertised through tailscale0
    # (k8s pod/service CIDRs from subnet routers, home-lab subnets, etc.).
    # tailscaled.service can be active before it creates table 52. `ip` then
    # exits 2; tolerate that expected early-boot state so `set -e -o pipefail`
    # does not abort the oneshot before it installs the CGNAT fallback rule.
    { ip route show table "$TAILSCALE_ROUTE_TABLE" 2>/dev/null || true; } \
        | awk '$2 == "dev" && $3 ~ /^tailscale/ &&
               $1 ~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {print $1}' \
        | sort -u
}

remove_tailscale_policy_rules() {
    local cidr
    while read -r cidr; do
        [[ -z "$cidr" ]] && continue
        while ip rule del to "$cidr" lookup $TAILSCALE_ROUTE_TABLE 2>/dev/null; do :; done
    done < <(ip rule show 2>/dev/null \
        | awk '$4 == "to" && $6 == "lookup" && $7 == "52" {print $5}')
}

# Routing alone is not enough: Mullvad's `inet mullvad` output chain ends in
# a bare `reject` and only accepts conntrack entries carrying its split-tunnel
# ct mark. Host traffic to the tailnet leaves via tailscale0 and gets an
# instant RST ("connection refused" in 0 ms).
#
# Match on the egress interface rather than a snapshot of table 52: route
# discovery races tailscaled restarts, oifname does not. Only private/CGNAT
# destinations are tagged, so exit-node traffic to the public internet still
# hits Mullvad's reject (fail closed). Same idiom as lib/tailscale-web: filter
# hook after conntrack, ct mark only, routing left to Tailscale's rules.
remove_tailscale_nft() {
    command -v nft >/dev/null 2>&1 || return 0
    nft delete table inet "$TAILSCALE_NFT_TABLE" 2>/dev/null || true
}

apply_tailscale_nft() {
    command -v nft >/dev/null 2>&1 || { warn "nft not found — Mullvad will reject tailnet traffic"; return 0; }
    remove_tailscale_nft
    nft -f - <<NFT
table inet $TAILSCALE_NFT_TABLE {
    chain output {
        type filter hook output priority -10; policy accept;
        oifname "tailscale0" ip daddr { 100.64.0.0/10, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } ct mark set $MULLVAD_CT_MARK comment "tailnet over tailscale0 past Mullvad"
    }
}
NFT
    info "Tailnet traffic on tailscale0 marked as Mullvad-excluded (nft table inet $TAILSCALE_NFT_TABLE)"
}

# tailscaled's own egress (control plane, DERP, WireGuard UDP) must bypass
# Mullvad too, or it is rejected the same way and never logs in. Mullvad
# excludes by PID, so the exclusion dies with every tailscaled restart.
# The drop-in re-adds it on each start; the routes unit (ordered after
# mullvad-daemon) re-checks it as a safety net for boot-order races. On the
# physical IF, tailscaled is still confined to the tailscale ipset by UFW.
exclude_tailscaled_from_mullvad() {
    command -v mullvad >/dev/null 2>&1 || return 0
    local pid
    pid=$(systemctl show -p MainPID --value tailscaled 2>/dev/null || true)
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
    if mullvad split-tunnel list 2>/dev/null | grep -qx "$pid"; then
        return 0
    fi
    if mullvad split-tunnel add "$pid" >/dev/null 2>&1; then
        info "tailscaled (pid $pid) excluded from Mullvad"
    else
        warn "Could not exclude tailscaled (pid $pid) from Mullvad — Tailscale login will fail"
    fi
}

install_tailscaled_dropin() {
    command -v mullvad >/dev/null 2>&1 || return 0
    mkdir -p "$(dirname "$TAILSCALED_DROPIN")"
    cat > "$TAILSCALED_DROPIN" <<'DROPIN'
# Managed by vpn-firewall-setup.sh — re-exclude tailscaled from Mullvad on
# every start (Mullvad split-tunnel is PID-based). '-' keeps tailscaled up
# if mullvad-daemon is absent or not ready yet.
[Unit]
After=mullvad-daemon.service

[Service]
ExecStartPost=-/usr/bin/mullvad split-tunnel add $MAINPID
DROPIN
    systemctl daemon-reload
    info "tailscaled drop-in installed: $TAILSCALED_DROPIN"
}

remove_tailscaled_dropin() {
    [[ -f "$TAILSCALED_DROPIN" ]] || return 0
    rm -f "$TAILSCALED_DROPIN"
    rmdir --ignore-fail-on-non-empty "$(dirname "$TAILSCALED_DROPIN")" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
}

apply_tailscale_route_rules() {
    local cidrs cidr
    cidrs=$(discover_tailscale_cidrs | xargs)
    [[ -z "$cidrs" ]] && return 0

    detect_tailscale_rule_prio
    remove_tailscale_policy_rules

    info "Installing Tailscale routing rules (priority $TAILSCALE_RULE_PRIO → table $TAILSCALE_ROUTE_TABLE):"
    for cidr in $cidrs; do
        ip rule add to "$cidr" lookup $TAILSCALE_ROUTE_TABLE priority $TAILSCALE_RULE_PRIO
        info "  $cidr"
    done
    apply_tailscale_nft
    exclude_tailscaled_from_mullvad
    if [[ -f "$TAILSCALE_WEB_ENABLED" ]]; then
        # Missing peer/route fails closed for OpenClaw without breaking other routes.
        tailscale_web_helper apply || warn "OpenClaw client check failed; inspect output and rerun tailscale-routes apply when Tailscale is ready."
    fi
}

install_tailscale_route_rules() {
    # Skip if tailscale isn't part of this killswitch profile.
    [[ "$VPN_INTERFACES" =~ tailscale ]] || return 0

    # This workstation's OpenClaw profile is enabled with the user's normal
    # combined provider selection; preserve general DNS and browser VPN policy.
    if [[ -f "$PROVIDERS_ACTIVE_FILE" ]] && grep -qw mullvad "$PROVIDERS_ACTIVE_FILE" && grep -qw tailscale "$PROVIDERS_ACTIVE_FILE"; then
        mkdir -p "$(dirname "$TAILSCALE_WEB_ENABLED")"
        touch "$TAILSCALE_WEB_ENABLED"
    elif [[ -f "$TAILSCALE_WEB_ENABLED" ]]; then
        remove_tailscale_web
    fi
    install_tailscaled_dropin
    local script
    script=$(readlink -f "$0")

    cat > "$TAILSCALE_ROUTES_UNIT" <<UNIT
[Unit]
Description=VPN Kill-Switch — dynamic Tailscale subnet route rules
After=network-online.target tailscaled.service mullvad-daemon.service
Wants=network-online.target tailscaled.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$script tailscale-routes _apply

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable vpn-killswitch-tailscale-routes.service >/dev/null 2>&1 || true
    systemctl restart vpn-killswitch-tailscale-routes.service
    info "Boot-persisted via $TAILSCALE_ROUTES_UNIT"
}

remove_tailscale_route_rules() {
    remove_tailscale_web
    if [[ -f "$TAILSCALE_ROUTES_UNIT" ]]; then
        systemctl disable --now vpn-killswitch-tailscale-routes.service 2>/dev/null || true
        rm -f "$TAILSCALE_ROUTES_UNIT"
        systemctl daemon-reload 2>/dev/null || true
    fi
    remove_tailscale_policy_rules
    remove_tailscale_nft
    remove_tailscaled_dropin
}

# ---------- Per-domain split tunneling ----------
#
# Route specific destination domains via a named auxiliary VPN tunnel while
# the rest of egress keeps using whatever default (Mullvad, AirVPN, clearnet
# via the killswitch). Useful for IP-allowlisted SaaS or private apps that
# require a specific egress IP, without forcing all traffic through that VPN.
#
# How it works:
#   1. dnsmasq is configured (drop-in) to tag DNS answers for the chosen
#      domains: the resolved IPs land in an ipset named "vpnkis_split_<n>_dst".
#   2. iptables mangle rule MARKs packets whose dst is in that ipset.
#   3. `ip rule` at SPLIT_RULE_PRIO matches that mark and looks up table
#      SPLIT_TABLE.
#   4. When the auxiliary tunnel comes up, its --up hook installs a default
#      route in table SPLIT_TABLE pointing at the tun device.
#   5. Down hook flushes the table — packets fall through to the main route
#      table (i.e. the default VPN/clearnet path).
#
# Config files (LOCAL, NOT git-tracked):
#   /etc/vpn-killswitch/split/<name>.conf — keys (one per line):
#     DOMAINS="*.example.com other.example.org"
#     DEV=tun-<name>                 # must match the openvpn --dev pin
#     TABLE=142                      # default if unset
#     MARK=0x42                      # default if unset
#     PRIORITY=auto                  # 'auto' = below tailscale, or a number
#     OVPN_CONFIG=/path/to/file.ovpn # used by 'split connect <name>'
#
# Coexistence with Mullvad: the openvpn handshake must bypass Mullvad's
# fwmark default route. `split connect <name>` wraps the launcher with
# `mullvad-exclude` when available.

SPLIT_CONF_DIR="/etc/vpn-killswitch/split"
SPLIT_TABLE_DEFAULT=142
SPLIT_MARK_DEFAULT="0x42"
SPLIT_RULE_PRIO_FALLBACK=5090
SPLIT_MANGLE_CHAIN="VPNKIS-SPLIT"

# Populated by split_load_conf
SPLIT_NAME=""
SPLIT_DOMAINS=""
SPLIT_DEV=""
SPLIT_TABLE=""
SPLIT_MARK=""
SPLIT_PRIORITY=""
SPLIT_OVPN_CONFIG=""

split_ipset_name() { echo "vpnkis_split_${1}_dst"; }
split_unit_name()  { echo "vpn-killswitch-split-${1}.service"; }
split_unit_path()  { echo "/etc/systemd/system/$(split_unit_name "$1")"; }
split_dnsmasq_path() { echo "/etc/dnsmasq.d/vpn-kis-split-${1}.conf"; }
split_up_script()    { echo "$SPLIT_CONF_DIR/${1}.up.sh"; }
split_down_script()  { echo "$SPLIT_CONF_DIR/${1}.down.sh"; }

split_load_conf() {
    local name="$1"
    [[ -n "$name" ]] || error "split: name required"
    [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || error "split: name must match [a-zA-Z0-9_-]+"
    local conf="$SPLIT_CONF_DIR/${name}.conf"
    [[ -f "$conf" ]] || error "split: config not found: $conf"

    # Safe key/value parser — no `source`. Trim whitespace + strip surrounding quotes.
    local k v line
    SPLIT_NAME="$name"
    SPLIT_DOMAINS=""; SPLIT_DEV=""; SPLIT_TABLE=""; SPLIT_MARK=""
    SPLIT_PRIORITY=""; SPLIT_OVPN_CONFIG=""
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        k="${BASH_REMATCH[1]}"
        v="${BASH_REMATCH[2]}"
        v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
        v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
        case "$k" in
            DOMAINS)     SPLIT_DOMAINS="$v" ;;
            DEV)         SPLIT_DEV="$v" ;;
            TABLE)       SPLIT_TABLE="$v" ;;
            MARK)        SPLIT_MARK="$v" ;;
            PRIORITY)    SPLIT_PRIORITY="$v" ;;
            OVPN_CONFIG) SPLIT_OVPN_CONFIG="$v" ;;
        esac
    done < "$conf"

    [[ -n "$SPLIT_DOMAINS" ]] || error "split: DOMAINS empty in $conf"
    [[ -n "$SPLIT_DEV" ]]     || error "split: DEV empty in $conf (must match openvpn --dev)"
    SPLIT_TABLE="${SPLIT_TABLE:-$SPLIT_TABLE_DEFAULT}"
    SPLIT_MARK="${SPLIT_MARK:-$SPLIT_MARK_DEFAULT}"
    SPLIT_PRIORITY="${SPLIT_PRIORITY:-auto}"

    if [[ "$SPLIT_PRIORITY" == "auto" ]]; then
        if [[ -z "${TAILSCALE_RULE_PRIO:-}" ]]; then
            detect_tailscale_rule_prio
        fi
        if [[ -n "$TAILSCALE_RULE_PRIO" && "$TAILSCALE_RULE_PRIO" -gt 11 ]]; then
            SPLIT_PRIORITY=$((TAILSCALE_RULE_PRIO - 10))
        else
            SPLIT_PRIORITY=$SPLIT_RULE_PRIO_FALLBACK
        fi
    fi
    [[ "$SPLIT_PRIORITY" =~ ^[0-9]+$ ]] || error "split: PRIORITY must be 'auto' or integer"
}

split_require_dnsmasq() {
    [[ -d /etc/dnsmasq.d ]] || error "split: /etc/dnsmasq.d missing (apt install dnsmasq, or enable NM dnsmasq plugin)"
    if systemctl is-active --quiet systemd-resolved 2>/dev/null \
        && [[ ! -f /etc/NetworkManager/conf.d/dnsmasq.conf ]] \
        && ! systemctl is-active --quiet dnsmasq 2>/dev/null; then
        warn "split: systemd-resolved is the active resolver but no dnsmasq instance was detected."
        warn "split: dnsmasq must front DNS for the ipset= directive to work. See README."
    fi
}

split_install_ipset() {
    command -v ipset >/dev/null 2>&1 || error "ipset required"
    local set
    set=$(split_ipset_name "$SPLIT_NAME")
    ipset create "$set" hash:ip family inet hashsize 1024 maxelem 65536 timeout 3600 -exist
}

split_install_mangle() {
    local set
    set=$(split_ipset_name "$SPLIT_NAME")
    # Use a single shared chain; per-split rules are individual append entries.
    iptables -t mangle -N "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -C OUTPUT     -j "$SPLIT_MANGLE_CHAIN" 2>/dev/null \
        || iptables -t mangle -A OUTPUT     -j "$SPLIT_MANGLE_CHAIN"
    iptables -t mangle -C PREROUTING -j "$SPLIT_MANGLE_CHAIN" 2>/dev/null \
        || iptables -t mangle -A PREROUTING -j "$SPLIT_MANGLE_CHAIN"

    # Idempotent: delete any prior rule for this set, then re-add.
    while iptables -t mangle -D "$SPLIT_MANGLE_CHAIN" -m set --match-set "$set" dst \
        -j MARK --set-mark "$SPLIT_MARK" 2>/dev/null; do :; done
    iptables -t mangle -A "$SPLIT_MANGLE_CHAIN" -m set --match-set "$set" dst \
        -j MARK --set-mark "$SPLIT_MARK"
}

split_install_iprule() {
    # Drop any stale rule at the same priority before adding (idempotent).
    while ip rule del priority "$SPLIT_PRIORITY" 2>/dev/null; do :; done
    ip rule add fwmark "$SPLIT_MARK" lookup "$SPLIT_TABLE" priority "$SPLIT_PRIORITY"
}

split_install_dnsmasq() {
    split_require_dnsmasq
    local set out
    set=$(split_ipset_name "$SPLIT_NAME")
    out=$(split_dnsmasq_path "$SPLIT_NAME")
    {
        echo "# Generated by vpn-firewall-setup.sh split add ${SPLIT_NAME}"
        echo "# Domains routed via auxiliary tunnel ${SPLIT_DEV}"
        local d
        for d in $SPLIT_DOMAINS; do
            echo "ipset=/${d#\*.}/${set}"
        done
    } > "$out"
    # Reload dnsmasq if running. NM-managed dnsmasq reloads on SIGHUP.
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        systemctl reload dnsmasq 2>/dev/null || systemctl restart dnsmasq
    elif pgrep -x dnsmasq >/dev/null 2>&1; then
        pkill -HUP -x dnsmasq 2>/dev/null || true
    fi
}

split_write_updown_scripts() {
    local up down
    up=$(split_up_script "$SPLIT_NAME")
    down=$(split_down_script "$SPLIT_NAME")
    cat > "$up" <<UP
#!/bin/sh
# openvpn --up hook for split '${SPLIT_NAME}'.
# Args from openvpn: \$1=dev \$2=tun_mtu \$3=link_mtu \$4=ifconfig_local \$5=ifconfig_remote
set -eu
DEV="\${1:-${SPLIT_DEV}}"
ip route replace default dev "\$DEV" table ${SPLIT_TABLE}
logger -t vpn-kis-split "[${SPLIT_NAME}] route table ${SPLIT_TABLE} → \$DEV"
UP
    cat > "$down" <<DOWN
#!/bin/sh
# openvpn --down hook for split '${SPLIT_NAME}'.
set -eu
ip route flush table ${SPLIT_TABLE} 2>/dev/null || true
logger -t vpn-kis-split "[${SPLIT_NAME}] route table ${SPLIT_TABLE} flushed"
DOWN
    chmod 755 "$up" "$down"
}

split_install_systemd() {
    # Boot-persists the ip rule and mangle hookup (ipset is rehydrated by
    # /etc/ufw/before.init from /etc/ipset.conf — we add this set there too).
    local unit set
    unit=$(split_unit_path "$SPLIT_NAME")
    set=$(split_ipset_name "$SPLIT_NAME")
    cat > "$unit" <<UNIT
[Unit]
Description=VPN Kill-Switch — split '${SPLIT_NAME}' (mark ${SPLIT_MARK} → table ${SPLIT_TABLE})
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ipset create ${set} hash:ip family inet hashsize 1024 maxelem 65536 timeout 3600 -exist
ExecStart=-/sbin/iptables -t mangle -N ${SPLIT_MANGLE_CHAIN}
ExecStart=-/sbin/iptables -t mangle -C OUTPUT -j ${SPLIT_MANGLE_CHAIN}
ExecStart=/bin/sh -c '/sbin/iptables -t mangle -C OUTPUT -j ${SPLIT_MANGLE_CHAIN} 2>/dev/null || /sbin/iptables -t mangle -A OUTPUT -j ${SPLIT_MANGLE_CHAIN}'
ExecStart=/bin/sh -c '/sbin/iptables -t mangle -C PREROUTING -j ${SPLIT_MANGLE_CHAIN} 2>/dev/null || /sbin/iptables -t mangle -A PREROUTING -j ${SPLIT_MANGLE_CHAIN}'
ExecStart=/bin/sh -c 'while /sbin/iptables -t mangle -D ${SPLIT_MANGLE_CHAIN} -m set --match-set ${set} dst -j MARK --set-mark ${SPLIT_MARK} 2>/dev/null; do :; done'
ExecStart=/sbin/iptables -t mangle -A ${SPLIT_MANGLE_CHAIN} -m set --match-set ${set} dst -j MARK --set-mark ${SPLIT_MARK}
ExecStart=/bin/sh -c 'while /sbin/ip rule del priority ${SPLIT_PRIORITY} 2>/dev/null; do :; done'
ExecStart=/sbin/ip rule add fwmark ${SPLIT_MARK} lookup ${SPLIT_TABLE} priority ${SPLIT_PRIORITY}
ExecStop=/bin/sh -c 'while /sbin/ip rule del priority ${SPLIT_PRIORITY} 2>/dev/null; do :; done'
ExecStop=-/sbin/iptables -t mangle -D ${SPLIT_MANGLE_CHAIN} -m set --match-set ${set} dst -j MARK --set-mark ${SPLIT_MARK}
ExecStop=-/sbin/ip route flush table ${SPLIT_TABLE}

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$(split_unit_name "$SPLIT_NAME")" >/dev/null 2>&1 || true
}

split_install() {
    require_root
    split_load_conf "$1"
    info "Installing split '$SPLIT_NAME': domains=[$SPLIT_DOMAINS] dev=$SPLIT_DEV table=$SPLIT_TABLE mark=$SPLIT_MARK priority=$SPLIT_PRIORITY"
    split_install_ipset
    split_install_mangle
    split_install_iprule
    split_install_dnsmasq
    split_write_updown_scripts
    split_install_systemd
    info "Split '$SPLIT_NAME' installed. Bring the tunnel up with:"
    info "  sudo $0 split connect $SPLIT_NAME"
}

split_remove() {
    require_root
    local name="$1"
    [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || error "split: invalid name"
    local set conf unit dns up down
    set=$(split_ipset_name "$name")
    conf="$SPLIT_CONF_DIR/${name}.conf"
    unit=$(split_unit_path "$name")
    dns=$(split_dnsmasq_path "$name")
    up=$(split_up_script "$name")
    down=$(split_down_script "$name")

    # Discover this split's priority+mark from its unit file before we destroy it,
    # so we can flush the rule even if the conf is gone.
    local prio="" mark=""
    if [[ -f "$unit" ]]; then
        prio=$(awk '/ExecStart=.*ip rule add/ { for(i=1;i<=NF;i++) if($i=="priority"){print $(i+1);exit} }' "$unit")
        mark=$(awk '/ExecStart=.*ip rule add/ { for(i=1;i<=NF;i++) if($i=="fwmark"){print $(i+1);exit} }' "$unit")
        systemctl disable --now "$(split_unit_name "$name")" 2>/dev/null || true
        rm -f "$unit"
        systemctl daemon-reload 2>/dev/null || true
    fi

    if [[ -n "$prio" ]]; then
        while ip rule del priority "$prio" 2>/dev/null; do :; done
    fi
    if [[ -n "$mark" ]]; then
        while iptables -t mangle -D "$SPLIT_MANGLE_CHAIN" \
            -m set --match-set "$set" dst -j MARK --set-mark "$mark" 2>/dev/null; do :; done
    fi
    ipset destroy "$set" 2>/dev/null || true
    rm -f "$dns" "$up" "$down"

    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        systemctl reload dnsmasq 2>/dev/null || systemctl restart dnsmasq
    elif pgrep -x dnsmasq >/dev/null 2>&1; then
        pkill -HUP -x dnsmasq 2>/dev/null || true
    fi

    info "Split '$name' removed. Config left at $conf (delete manually if no longer needed)."
}

split_remove_all() {
    [[ -d "$SPLIT_CONF_DIR" ]] || return 0
    local f name
    for f in "$SPLIT_CONF_DIR"/*.conf; do
        [[ -f "$f" ]] || continue
        name=$(basename "$f" .conf)
        split_remove "$name" || true
    done
    # Tear down the shared chain itself when the last split goes away.
    if ! ls "$SPLIT_CONF_DIR"/*.conf >/dev/null 2>&1; then
        iptables -t mangle -D OUTPUT     -j "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
        iptables -t mangle -D PREROUTING -j "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
        iptables -t mangle -F "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
        iptables -t mangle -X "$SPLIT_MANGLE_CHAIN" 2>/dev/null || true
    fi
}

split_list() {
    if [[ ! -d "$SPLIT_CONF_DIR" ]] || ! ls "$SPLIT_CONF_DIR"/*.conf >/dev/null 2>&1; then
        info "No splits configured. Drop a config at $SPLIT_CONF_DIR/<name>.conf — see README."
        return 0
    fi
    local f name
    for f in "$SPLIT_CONF_DIR"/*.conf; do
        name=$(basename "$f" .conf)
        if [[ -f "$(split_unit_path "$name")" ]]; then
            printf "  %-20s  installed (unit: %s)\n" "$name" "$(split_unit_name "$name")"
        else
            printf "  %-20s  configured (run: %s split add %s)\n" "$name" "$0" "$name"
        fi
    done
}

split_status() {
    local name="$1"
    [[ -n "$name" ]] || { split_list; return 0; }
    split_load_conf "$name"
    local set
    set=$(split_ipset_name "$name")
    info "Split '$name':"
    info "  domains   : $SPLIT_DOMAINS"
    info "  dev       : $SPLIT_DEV"
    info "  table     : $SPLIT_TABLE"
    info "  mark      : $SPLIT_MARK"
    info "  priority  : $SPLIT_PRIORITY"
    info "  ovpn      : ${SPLIT_OVPN_CONFIG:-(unset)}"
    echo ""
    info "ipset $set:"
    ipset list "$set" 2>/dev/null | sed 's/^/  /' || warn "  ipset $set not present"
    echo ""
    info "ip rule:"
    ip rule show priority "$SPLIT_PRIORITY" 2>/dev/null | sed 's/^/  /' || true
    echo ""
    info "route table $SPLIT_TABLE:"
    ip route show table "$SPLIT_TABLE" 2>/dev/null | sed 's/^/  /' || true
    echo ""
    info "systemd unit:"
    systemctl is-enabled "$(split_unit_name "$name")" 2>&1 | sed 's/^/  enabled: /'
    systemctl is-active  "$(split_unit_name "$name")" 2>&1 | sed 's/^/  active : /'
}

split_connect() {
    require_root
    split_load_conf "$1"
    [[ -n "$SPLIT_OVPN_CONFIG" ]] || error "split connect: OVPN_CONFIG not set in $SPLIT_CONF_DIR/${SPLIT_NAME}.conf"
    [[ -f "$SPLIT_OVPN_CONFIG" ]] || error "split connect: OVPN_CONFIG not found: $SPLIT_OVPN_CONFIG"
    command -v openvpn >/dev/null 2>&1 || error "openvpn not installed"

    local launcher=()
    if command -v mullvad-exclude >/dev/null 2>&1 \
        && mullvad status 2>/dev/null | grep -qi connected; then
        info "Mullvad active — wrapping with mullvad-exclude"
        launcher=(mullvad-exclude)
    fi

    info "Connecting split '$SPLIT_NAME' (dev=$SPLIT_DEV, config=$SPLIT_OVPN_CONFIG)"
    info "Default route will NOT be hijacked (route-nopull). Route table $SPLIT_TABLE handles split traffic."

    exec "${launcher[@]}" openvpn \
        --config "$SPLIT_OVPN_CONFIG" \
        --dev "$SPLIT_DEV" \
        --pull-filter ignore "redirect-gateway" \
        --pull-filter ignore "dhcp-option DNS" \
        --route-nopull \
        --script-security 2 \
        --up "$(split_up_script "$SPLIT_NAME")" \
        --down "$(split_down_script "$SPLIT_NAME")"
}

# ---------- cgroup-based VPN exclusion ----------
#
# "split by destination" (above) routes chosen DOMAINS through an auxiliary
# tunnel. This section runs an arbitrary COMMAND whose traffic BYPASSES the VPN
# entirely and egresses the physical IF — the classic `mullvad-exclude`, but
# VPN-agnostic and, crucially, punched through THIS killswitch (mullvad-exclude
# alone is still DROP'd by our `-o $PHYS -j DROP` rule).
#
# Keyed on a dedicated cgroup v2 (EXCLUDE_CGROUP), NOT a user — so a *root*
# command (apt, package managers) can be excluded just as easily as an
# unprivileged one. `exclude run` drops the launched process into the cgroup;
# everything it spawns inherits membership.
#
# Three coupled pieces:
#   1. Mark — mangle OUTPUT matches the cgroup (`-m cgroup --path`) and sets
#      fwmark, but RETURNs first for loopback/LAN/link-local/multicast so the
#      local resolver, LAN and VPN-DNS keep working (only real internet diverts).
#   2. Route + SNAT — fwmark → table EXCLUDE_TABLE (default via the PHYSICAL
#      gateway, overriding the VPN default because ip-rules precede the main
#      table) and MASQUERADE to the physical IP (sockets bind the tunnel source
#      at connect(), before our reroute — without SNAT the reply never returns).
#   3. Firewall — because mangle OUTPUT (prio -150) runs before filter OUTPUT,
#      excluded packets already carry the mark at the killswitch; a single
#      mark-match ACCEPT in before.rules (before the DROP) covers them all.
#
# Routing is (re)applied at boot / IF-change by a systemd unit; the before.rules
# ACCEPT persists because add_killswitch_before_rules() re-emits it on every
# setup and exclude_sync_before_rules() live-patches it in between.
EXCLUDE_USERS_FILE="/etc/vpn-killswitch/exclude.users"   # legacy (uid mode); removed on enable
EXCLUDE_MARK="0x51"
EXCLUDE_TABLE=151
EXCLUDE_PRIO=5080          # < Mullvad fwmark rule (~5199) and < main table (32766)
EXCLUDE_MANGLE_CHAIN="VPNKIS-EXCLUDE"
EXCLUDE_NAT_CHAIN="VPNKIS-EXCLUDE-NAT"
EXCLUDE_UNIT=/etc/systemd/system/vpn-killswitch-exclude.service
EXCLUDE_CGROUP="/sys/fs/cgroup/vpnkis-exclude"           # cgroup v2 dir (we own it)
EXCLUDE_CGROUP_REL="vpnkis-exclude"                       # same, relative — for -m cgroup --path
EXCLUDE_BEGIN="# --- BEGIN vpn-kis exclude (mark ${EXCLUDE_MARK} via cgroup ${EXCLUDE_CGROUP_REL}) ---"
EXCLUDE_END="# --- END vpn-kis exclude ---"
# Stable prefixes so exclude_sync_before_rules strips blocks written by older
# versions (e.g. the owner-based one) regardless of the descriptive suffix.
EXCLUDE_BEGIN_PREFIX="# --- BEGIN vpn-kis exclude"
EXCLUDE_END_PREFIX="# --- END vpn-kis exclude"

# The physical IF the killswitch guards — read authoritatively from the DROP
# rule (same source the NM dispatcher uses, so we auto-follow its rewrites).
exclude_phys() {
    local p
    p=$(grep -oP '(?<=-o )[A-Za-z0-9_.-]+(?= -j DROP)' /etc/ufw/before.rules 2>/dev/null | head -1)
    if [[ -z "$p" ]]; then detect_physical_if >/dev/null 2>&1 || true; p="$PHYSICAL_IF"; fi
    echo "$p"
}

# Exclusion is "enabled" once the systemd unit exists (persistent marker).
exclude_enabled() { [[ -f "$EXCLUDE_UNIT" ]]; }

# Create the cgroup v2 directory we drop excluded processes into. It must exist
# before the `-m cgroup --path` rule is added (the match resolves the path at
# insertion time). We own it — systemd doesn't manage it.
exclude_ensure_cgroup() {
    [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" == "cgroup2fs" ]] \
        || { warn "exclude: /sys/fs/cgroup is not cgroup v2 — cgroup exclusion unavailable"; return 1; }
    [[ -d "$EXCLUDE_CGROUP" ]] || mkdir "$EXCLUDE_CGROUP" 2>/dev/null \
        || { warn "exclude: cannot create cgroup $EXCLUDE_CGROUP"; return 1; }
}

# Print the before.rules ACCEPT block (marker-wrapped). Single mark-match rule,
# emitted only while exclusion is enabled. Empty otherwise.
exclude_emit_before_rules_block() {
    local phys="${1:-$PHYSICAL_IF}"
    exclude_enabled || return 0
    echo ""
    echo "$EXCLUDE_BEGIN"
    echo "-A ufw-before-output -o $phys -m mark --mark $EXCLUDE_MARK -j ACCEPT"
    echo "$EXCLUDE_END"
}

# Live-patch /etc/ufw/before.rules: strip any prior exclude block (matched by
# stable marker prefix, so old owner-based blocks are cleaned too), re-insert
# the current one immediately before the physical-IF DROP, then reload.
exclude_sync_before_rules() {
    local rules=/etc/ufw/before.rules phys tmp block
    [[ -f "$rules" ]] || error "no $rules — install the killswitch first (sudo $0 setup ...)"
    phys=$(exclude_phys)
    block=$(exclude_emit_before_rules_block "$phys")
    tmp=$(mktemp)
    awk -v beginp="$EXCLUDE_BEGIN_PREFIX" -v endp="$EXCLUDE_END_PREFIX" \
        -v phys="$phys" -v block="$block" '
        index($0, beginp) == 1 { inblk=1; next }
        inblk && index($0, endp) == 1 { inblk=0; next }
        inblk { next }
        $0 ~ ("^-A ufw-before-output -o " phys " -j DROP") && block != "" { print block }
        { print }
    ' "$rules" > "$tmp" && cat "$tmp" > "$rules"
    rm -f "$tmp"
    ufw reload >/dev/null 2>&1 || warn "ufw reload failed — check 'ufw status'"
}

# Apply mark + policy routing + SNAT for the excluded cgroup. Idempotent (flushes
# then rebuilds). Also invoked by the systemd unit (ExecStart) at boot/IF-change.
exclude_apply_routing() {
    local phys gw
    if ! exclude_enabled; then
        exclude_teardown_routing
        return 0
    fi
    exclude_ensure_cgroup || return 1
    phys=$(exclude_phys)
    gw=$(ip route show dev "$phys" 2>/dev/null | awk '/^default via/{print $3; exit}')
    [[ -n "$gw" ]] || gw=$(ip route show dev "$phys" 2>/dev/null | awk '/ via /{print $3; exit}')
    [[ -n "$gw" ]] || { warn "exclude: cannot determine physical gateway on $phys — routing not applied"; return 1; }

    # mangle: mark the excluded cgroup's outbound packets
    iptables -t mangle -N "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -C OUTPUT -j "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null \
        || iptables -t mangle -A OUTPUT -j "$EXCLUDE_MANGLE_CHAIN"
    iptables -t mangle -F "$EXCLUDE_MANGLE_CHAIN"

    # Only divert REAL internet traffic. Loopback, LAN, link-local and multicast
    # destinations must keep using the main table — otherwise table
    # $EXCLUDE_TABLE (which holds only a default route) would force e.g. DNS to
    # the local resolver (127.0.0.53), LAN hosts, or a VPN DNS (10.x) out the
    # physical gateway, where the kernel drops them as martians (breaks name
    # resolution — only literal IPs would work).
    local skipnet
    for skipnet in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
                   169.254.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        iptables -t mangle -A "$EXCLUDE_MANGLE_CHAIN" -d "$skipnet" -j RETURN
    done
    iptables -t mangle -A "$EXCLUDE_MANGLE_CHAIN" \
        -m cgroup --path "$EXCLUDE_CGROUP_REL" -j MARK --set-mark "$EXCLUDE_MARK" \
        || warn "exclude: cgroup mark rule failed (xt_cgroup missing, or cgroup absent)"

    # policy routing: marked traffic uses a table whose default is the physical gw
    ip route replace default via "$gw" dev "$phys" table "$EXCLUDE_TABLE"
    while ip rule del priority "$EXCLUDE_PRIO" 2>/dev/null; do :; done
    ip rule add fwmark "$EXCLUDE_MARK" lookup "$EXCLUDE_TABLE" priority "$EXCLUDE_PRIO"

    # nat: source-NAT marked traffic to the physical IP (see header note 2).
    iptables -t nat -N "$EXCLUDE_NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -C POSTROUTING -j "$EXCLUDE_NAT_CHAIN" 2>/dev/null \
        || iptables -t nat -A POSTROUTING -j "$EXCLUDE_NAT_CHAIN"
    iptables -t nat -F "$EXCLUDE_NAT_CHAIN"
    iptables -t nat -A "$EXCLUDE_NAT_CHAIN" -m mark --mark "$EXCLUDE_MARK" -o "$phys" -j MASQUERADE

    info "exclude: active (cgroup $EXCLUDE_CGROUP_REL → $phys via $gw, mark $EXCLUDE_MARK table $EXCLUDE_TABLE, SNAT→$phys)"
}

exclude_teardown_routing() {
    while ip rule del priority "$EXCLUDE_PRIO" 2>/dev/null; do :; done
    ip route flush table "$EXCLUDE_TABLE" 2>/dev/null || true
    iptables -t mangle -F "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -D OUTPUT -j "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t mangle -X "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$EXCLUDE_NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -j "$EXCLUDE_NAT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$EXCLUDE_NAT_CHAIN" 2>/dev/null || true
}

exclude_install_unit() {
    local script
    script=$(readlink -f "$0")
    cat > "$EXCLUDE_UNIT" <<UNIT
[Unit]
Description=VPN Kill-Switch — cgroup-based VPN exclusion (mark + route excluded cgroup)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$script exclude _apply
ExecStop=$script exclude _teardown

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable vpn-killswitch-exclude.service >/dev/null 2>&1 || true
}

exclude_remove_unit() {
    systemctl disable --now vpn-killswitch-exclude.service 2>/dev/null || true
    rm -f "$EXCLUDE_UNIT"
    systemctl daemon-reload 2>/dev/null || true
}

# Full teardown for unlock/panic: routing, unit, cgroup, legacy state.
exclude_remove_all() {
    rm -f "$EXCLUDE_USERS_FILE"
    exclude_teardown_routing
    exclude_remove_unit
    rmdir "$EXCLUDE_CGROUP" 2>/dev/null || true
}

# Enable persistent exclusion: unit + routing + before.rules. Idempotent.
exclude_enable() {
    require_root
    rm -f "$EXCLUDE_USERS_FILE" 2>/dev/null || true   # drop legacy uid-mode state
    exclude_install_unit
    exclude_ensure_cgroup || error "exclude: cgroup v2 unavailable — cannot enable"
    exclude_apply_routing
    exclude_sync_before_rules
}

exclude_disable() {
    require_root
    exclude_remove_unit          # clears the 'enabled' marker so sync emits nothing
    exclude_teardown_routing
    rmdir "$EXCLUDE_CGROUP" 2>/dev/null || true
    exclude_sync_before_rules
    info "exclude: disabled — routing, unit, cgroup and before.rules ACCEPT removed."
}

exclude_status() {
    if ! exclude_enabled; then
        info "exclude: disabled. Enable + run in one step: sudo $0 exclude run -- <command>"
        return 0
    fi
    local phys
    phys=$(exclude_phys)
    info "exclude: ENABLED (cgroup $EXCLUDE_CGROUP → $phys, mark $EXCLUDE_MARK table $EXCLUDE_TABLE)"
    info "  members (PIDs in cgroup):"; sed 's/^/    /' "$EXCLUDE_CGROUP/cgroup.procs" 2>/dev/null || echo "    (none / cgroup absent)"
    echo ""
    info "ip rule (prio $EXCLUDE_PRIO):"; ip rule show priority "$EXCLUDE_PRIO" 2>/dev/null | sed 's/^/  /'
    info "route table $EXCLUDE_TABLE:";   ip route show table "$EXCLUDE_TABLE" 2>/dev/null | sed 's/^/  /'
    info "mangle chain:";                 iptables -t mangle -S "$EXCLUDE_MANGLE_CHAIN" 2>/dev/null | sed 's/^/  /' || true
    info "nat chain:";                    iptables -t nat -S "$EXCLUDE_NAT_CHAIN" 2>/dev/null | sed 's/^/  /' || true
    info "before.rules ACCEPT:";          grep -- "--mark $EXCLUDE_MARK" /etc/ufw/before.rules 2>/dev/null | sed 's/^/  /' || true
    info "unit:"; systemctl is-active vpn-killswitch-exclude.service 2>&1 | sed 's/^/  active : /'
}

# Run a command with its traffic excluded from the VPN.
#   exclude run [--as USER] -- <command...>
# Default runs as root (so root commands like apt work). --as drops privileges
# AFTER joining the cgroup (membership is inherited regardless of uid).
exclude_run() {
    require_root
    local as=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --as)   as="${2:-}"; [[ -n "$as" ]] || error "exclude run: --as needs a username"; shift 2 ;;
            --as=*) as="${1#*=}"; shift ;;
            --)     shift; break ;;
            --*)    error "exclude run: unknown flag '$1'" ;;
            *)      break ;;
        esac
    done
    # Back-compat with the old `run USER -- cmd` form → treat USER as --as.
    if [[ -z "$as" && $# -ge 2 && "${2:-}" == "--" ]] && id "$1" >/dev/null 2>&1; then
        as="$1"; shift 2
    fi
    [[ $# -ge 1 ]] || error "exclude run: usage: sudo $0 exclude run [--as USER] -- <command>"
    if [[ -n "$as" ]]; then
        id "$as" >/dev/null 2>&1 || error "exclude run: user '$as' does not exist"
        command -v runuser >/dev/null 2>&1 || error "exclude run: 'runuser' (util-linux) needed for --as"
    fi

    exclude_enabled || { info "exclude: enabling on first use…"; exclude_enable; }
    # Re-assert rules so a fresh/valid cgroup ref is in the mark rule (the cgroup
    # can be GC'd while empty; re-apply guarantees the running command is caught).
    exclude_apply_routing || error "exclude run: could not apply exclusion rules"
    # Self-heal: ensure the killswitch actually permits marked traffic. Missing
    # when migrating from an older (owner-based) install, or if before.rules was
    # regenerated without the ACCEPT. Sync once (reloads ufw) only when absent.
    grep -q -- "--mark $EXCLUDE_MARK -j ACCEPT" /etc/ufw/before.rules 2>/dev/null \
        || exclude_sync_before_rules

    # Join the cgroup (as root), then exec — optionally dropping to --as USER.
    if [[ -n "$as" ]]; then
        exec sh -c 'echo $$ > "$1/cgroup.procs" || { echo "exclude: cannot join cgroup $1" >&2; exit 1; }; \
                    u=$2; shift 2; exec runuser -u "$u" -- "$@"' \
            sh "$EXCLUDE_CGROUP" "$as" "$@"
    else
        exec sh -c 'echo $$ > "$1/cgroup.procs" || { echo "exclude: cannot join cgroup $1" >&2; exit 1; }; \
                    shift; exec "$@"' \
            sh "$EXCLUDE_CGROUP" "$@"
    fi
}

# ---------- Endpoint auto-refresh ----------
#
# Re-fetch provider IPs and atomically rebuild the vpn_endpoints ipset
# WITHOUT touching UFW rules. Safe to run from a timer while connected:
# the new set is built aside and swapped in one kernel op, so there is no
# window where the killswitch has an empty whitelist. This is what keeps
# dynamic-IP providers (DDNS `remote` hosts) working in strict mode.
refresh_endpoints() {
    local names=("$@")
    if [[ ${#names[@]} -eq 0 ]]; then
        [[ -f "$PROVIDERS_ACTIVE_FILE" ]] \
            || error "refresh: no providers given and $PROVIDERS_ACTIVE_FILE missing. Run '$0 refresh <names>' once to seed it."
        read -ra names < "$PROVIDERS_ACTIVE_FILE"
    else
        # Explicit list becomes the new active set — the timer picks it up.
        mkdir -p "$(dirname "$PROVIDERS_ACTIVE_FILE")"
        echo "${names[*]}" > "$PROVIDERS_ACTIVE_FILE"
    fi
    [[ ${#names[@]} -gt 0 ]] || error "refresh: empty provider list"

    local p
    for p in "${names[@]}"; do
        fetch_provider "$p" || warn "refresh: fetch failed for $p — keeping cached list"
    done

    local ips
    ips="$(load_providers "${names[@]}") $DNS_BOOTSTRAP_IPS"
    [[ -n "${ips// }" ]] || error "refresh: no IPs to load — aborting (current ipset left untouched)"

    ipset create vpn_endpoints hash:ip family inet hashsize 2048 maxelem 65536 -exist
    ipset create vpn_endpoints_new hash:ip family inet hashsize 2048 maxelem 65536 -exist
    ipset flush vpn_endpoints_new
    {
        for p in $ips; do echo "add vpn_endpoints_new $p"; done
    } | ipset restore -exist
    ipset swap vpn_endpoints_new vpn_endpoints
    ipset destroy vpn_endpoints_new
    ipset save vpn_endpoints > /etc/ipset.conf

    local count
    count=$(ipset list vpn_endpoints 2>/dev/null | awk '/Number of entries:/ {print $NF}')
    info "refresh: vpn_endpoints now has $count IPs (providers: ${names[*]})"
}

install_refresh_timer() {
    local interval="${1:-15min}"
    local script
    script=$(readlink -f "$0")
    [[ -f "$PROVIDERS_ACTIVE_FILE" ]] \
        || warn "No $PROVIDERS_ACTIVE_FILE yet — timer will fail until you run '$0 providers <names>' once."

    cat > "$REFRESH_SERVICE" <<UNIT
[Unit]
Description=VPN Kill-Switch — refresh endpoint ipset from provider lists
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$script refresh
UNIT

    cat > "$REFRESH_TIMER" <<UNIT
[Unit]
Description=VPN Kill-Switch — periodic endpoint refresh

[Timer]
OnBootSec=2min
OnUnitActiveSec=$interval
RandomizedDelaySec=30
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    systemctl daemon-reload
    systemctl enable --now vpn-killswitch-refresh.timer
    info "Refresh timer active: every $interval (vpn-killswitch-refresh.timer)"
    info "Provider list read from $PROVIDERS_ACTIVE_FILE (set by 'providers <names>')."
}

remove_refresh_timer() {
    systemctl disable --now vpn-killswitch-refresh.timer 2>/dev/null || true
    rm -f "$REFRESH_TIMER" "$REFRESH_SERVICE"
    systemctl daemon-reload 2>/dev/null || true
}

install_nm_dispatcher() {
    # Re-apply firewall when physical IF changes (wifi↔ethernet, dock, etc.)
    if [[ ! -d /etc/NetworkManager/dispatcher.d ]]; then
        warn "NetworkManager not present — skipping IF-change hook."
        return
    fi
    info "Installing NetworkManager dispatcher hook..."
    cat > /etc/NetworkManager/dispatcher.d/90-vpn-killswitch <<'HOOK'
#!/usr/bin/env bash
# Reapply VPN killswitch DROP rule when the underlying PHYSICAL interface
# changes (dock/undock, wifi↔ethernet). Never follow the default route onto
# a VPN tunnel — doing so would rewrite DROP rule to target the VPN iface
# and lock the host out (this is the v3 lockout bug being patched here).
set -u

IFACE="${1:-}"
ACTION="${2:-}"
LOG_TAG="vpn-killswitch"
RULES=/etc/ufw/before.rules
LOCK=/var/lock/vpn-killswitch.nm.lock
BAK="$RULES.nm-bak"

log() { logger -t "$LOG_TAG" -- "$*"; }

refresh_tailscale_routes() {
    systemctl is-enabled --quiet vpn-killswitch-tailscale-routes.service 2>/dev/null || return 0
    systemctl restart vpn-killswitch-tailscale-routes.service 2>/dev/null \
        || log "failed to refresh Tailscale policy routes"
}

# Pattern of ifaces we must NEVER pin the killswitch DROP rule onto.
is_virtual() {
    case "$1" in
        lo|tun*|wg*|tailscale*|Eddie|ppp*|docker*|veth*|virbr*|br-*|zt*) return 0 ;;
    esac
    return 1
}

# Only react to relevant NM events
case "$ACTION" in
    up|down|vpn-up|vpn-down|connectivity-change) ;;
    *) exit 0 ;;
esac

# Ignore the hook when triggered BY a VPN/virtual iface coming up — those
# events fire NEW_IF detection at the wrong moment (tunnel = default route).
if [ -n "$IFACE" ] && is_virtual "$IFACE"; then
    case "$IFACE" in
        wg*|tailscale*) refresh_tailscale_routes ;;
    esac
    exit 0
fi

# Single-flight: rapid up/down storms would race the sed and corrupt rules
exec 9>"$LOCK" 2>/dev/null || exit 0
command -v flock >/dev/null 2>&1 && { flock -n 9 || { log "lock held, skip"; exit 0; }; }

# Find a real physical iface. Prefer default route, but skip VPN/virtual.
NEW_IF=""
while read -r dev; do
    is_virtual "$dev" && continue
    [ -d "/sys/class/net/$dev" ] || continue
    NEW_IF="$dev"
    break
done < <(ip -4 route ls 2>/dev/null | awk '/^default/ {print $5}')

# Fallback: first UP non-virtual iface holding an IPv4 address
if [ -z "$NEW_IF" ]; then
    for d in /sys/class/net/*; do
        n=$(basename "$d")
        is_virtual "$n" && continue
        ip -4 addr show "$n" 2>/dev/null | grep -q 'inet ' || continue
        NEW_IF="$n"
        break
    done
fi

[ -z "$NEW_IF" ] && { log "no physical IF candidate, skip"; exit 0; }

# Extract current pinned IF from the DROP rule
CURRENT=$(grep -oP '(?<=-o )[A-Za-z0-9_.-]+(?= -j DROP)' "$RULES" 2>/dev/null | head -1)
if [ -z "$CURRENT" ]; then
    log "cannot parse current IF from $RULES, skip (manual fix needed)"
    exit 0
fi

# Defense in depth: never auto-rewrite if either side resembles a VPN iface
if is_virtual "$CURRENT"; then
    log "current IF '$CURRENT' looks virtual/VPN — refusing rewrite (rules may be corrupted)"
    exit 0
fi
if is_virtual "$NEW_IF"; then
    log "candidate '$NEW_IF' is virtual/VPN — refusing rewrite"
    exit 0
fi

[ "$NEW_IF" = "$CURRENT" ] && { refresh_tailscale_routes; exit 0; }

log "physical IF changed: $CURRENT -> $NEW_IF, reapplying"

# Backup, mutate, validate. Restore on any failure.
cp -a "$RULES" "$BAK" || { log "backup failed, abort"; exit 0; }

if ! sed -i "s/-o ${CURRENT} /-o ${NEW_IF} /g; s/-i ${CURRENT} /-i ${NEW_IF} /g" "$RULES"; then
    log "sed failed, restoring backup"
    cp -a "$BAK" "$RULES"
    exit 0
fi

# Confirm new DROP rule actually points at NEW_IF before reload
if ! grep -qE -- "-o ${NEW_IF} -j DROP" "$RULES"; then
    log "post-sed validation failed (no DROP rule for $NEW_IF), restoring"
    cp -a "$BAK" "$RULES"
    exit 0
fi

if ! ufw reload >/dev/null 2>&1; then
    log "ufw reload failed, restoring backup"
    cp -a "$BAK" "$RULES"
    ufw reload >/dev/null 2>&1 || log "restore reload also failed — MANUAL INTERVENTION NEEDED"
    exit 0
fi

log "killswitch retargeted: $CURRENT -> $NEW_IF"

# Re-apply owner-based VPN-exclude routing for the new physical IF (its route
# table + gateway are IF-specific; the before.rules ACCEPTs were already
# sed-rewritten above alongside the DROP rule).
systemctl restart vpn-killswitch-exclude.service 2>/dev/null || true
refresh_tailscale_routes

exit 0
HOOK
    chmod 755 /etc/NetworkManager/dispatcher.d/90-vpn-killswitch
    info "Hook installed: /etc/NetworkManager/dispatcher.d/90-vpn-killswitch"
}

verify() {
    echo ""
    info "========== VERIFICATION =========="
    echo ""

    info "UFW status:"
    ufw status numbered

    echo ""
    info "iptables OUTPUT chain:"
    show_filter_chain OUTPUT

    echo ""
    info "Physical IF kill-switch (should see DROP at end):"
    local kill_rules
    kill_rules=$(ipt_ro -S ufw-before-output | grep -E 'DROP|ACCEPT' | tail -5 || true)
    if [[ -n "$kill_rules" ]]; then
        printf '%s\n' "$kill_rules"
    else
        warn "ufw-before-output unreadable or empty — KILL-SWITCH NOT CONFIRMED."
        warn "Inspect with: nft list chain ip filter ufw-before-output"
    fi

    echo ""
    info "IPv6 status:"
    if [[ ! -e /proc/sys/net/ipv6 ]]; then
        info "IPv6: ABSENT — stack not loaded (best)"
    elif [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)" == "1" ]]; then
        info "IPv6: DISABLED (good)"
    else
        warn "IPv6: still enabled — reboot required"
    fi

    echo ""
    info "Active interfaces:"
    ip -4 addr show | grep -E 'inet ' | awk '{print "  " $NF ": " $2}'

    echo ""
    info "Default route:"
    ip route show default

    echo ""
    info "=================================="
    echo ""
    warn "LEAK TEST: Disconnect VPN, then run:"
    warn "  curl --max-time 5 ifconfig.me"
    warn "Must TIMEOUT. If it returns your real IP, the kill-switch failed."
}

usage() {
    cat <<USAGE
VPN Kill-Switch Firewall v4

Usage:
  $0 [setup]                       Install kill-switch (permissive: any host on VPN ports)
  $0 auto                          Auto-detect live VPN peer IPs, strict-lock to them
  $0 providers <name> [name ...]   Strict-lock to union of provider profiles
                                   (e.g. '$0 providers mullvad airvpn')
  $0 fetch [name ...]              Refresh provider IP lists (default: all known)
  $0 refresh [name ...]            Re-fetch providers + atomically rebuild the
                                   vpn_endpoints ipset (no UFW reload, no leak
                                   window). Default: providers from last
                                   'providers' run. Use after a server IP
                                   rotates and OpenVPN logs EPERM writes.
  $0 refresh install [interval]    Systemd timer running 'refresh' periodically
                                   (default: 15min). Keeps dynamic-IP/DDNS
                                   endpoints unblocked automatically.
  $0 refresh uninstall             Remove the refresh timer
  $0 tailscale-web [apply|remove]  OpenClaw HTTPS-only Mullvad exception + local hostname
                                   Runtime firewall rule; preserves general DNS/VPN policy.
  $0 detect                        Print detected VPN endpoints, exit
  $0 test [passive|active]         Run killswitch self-tests (default: passive)
                                   passive = non-disruptive rule checks
                                   active  = drops VPN, checks for leak, reconnects
                                   FORCE=1 skips confirm prompt
  $0 split add <name>              Install per-domain split tunnel
                                   (reads $SPLIT_CONF_DIR/<name>.conf)
  $0 split rm <name>               Remove split (ip rule, mangle, dnsmasq drop-in, unit)
  $0 split list                    List configured/installed splits
  $0 split status [name]           Show ipset, route table, unit state
  $0 split connect <name>          Launch openvpn with split-tunnel flags
                                   (route-nopull, --dev pin, up/down hooks,
                                   wraps with mullvad-exclude if Mullvad up)
  $0 exclude run [--as U] -- <cmd> Run <cmd> with its traffic BYPASSING the VPN
                                   (out the physical IF, punched through the
                                   killswitch). Runs as root by default so root
                                   commands work; --as U drops to user U.
                                   Auto-enables on first use. Keyed on a cgroup,
                                   so root commands (apt, etc.) work too.
                                   e.g. sudo $0 exclude run -- apt-get update
                                        sudo $0 exclude run --as $USER -- curl ifconfig.me
  $0 exclude on                    Enable exclusion infra explicitly (unit +
                                   routing + before.rules ACCEPT). Persists
                                   across reboot + ufw reload.
  $0 exclude off                   Disable + tear everything down
  $0 exclude status                Show state (cgroup members, routing, fw)
  $0 unlock                        Restore UFW from latest backup
  $0 panic                         EMERGENCY: drop all firewall rules, reset
                                   DNS, re-enable IPv6, restart network stack.
                                   Run from local TTY when locked out.
                                   Aliases: rescue, emergency
  $0 help                          Show this message

Global flags (before the subcommand):
  --lan <cidrs>                    Allow LAN traffic to/from these CIDRs to
                                   bypass the killswitch on the physical IF.
                                   Quote multi-value: --lan "192.168.100.0/24 10.0.5.0/24"
                                   Use for cluster LAN, NAS, printer, etc.
                                   SECURITY: opens machine to LAN-initiated
                                   connections — wired-home OK, coworking risky.

Env:
  VPN_ENDPOINTS="1.2.3.4 5.6.7.8"   Manual strict mode (overrides auto/providers)
  LAN_ALLOW_CIDRS="192.168.100.0/24"   Same as --lan, env-var form.

Providers:
  mullvad   — fetched from api.mullvad.net (needs jq + network)
  airvpn    — scanned from /etc/openvpn + Eddie config dirs
  tailscale — DERP relays + control plane (login.tailscale.com derpmap)
              Strict mode forces peer traffic via DERP relay (no direct UDP).
  <custom>  — drop IPs (one per line) into $PROVIDERS_DIR/<name>.ips, OR
              create $SPLIT_CONF_DIR/<name>.conf with OVPN_CONFIG= — fetch
              then resolves the .ovpn 'remote' hosts (DDNS-friendly).

Modes:
  PERMISSIVE  Default. DNS + 443 + VPN ports open to any host on physical IF.
              Works with any provider, hostname-based configs. Some leak surface.
  STRICT      IP-locked. No DNS/443 pre-holes. Lock via 'auto', 'providers', or
              VPN_ENDPOINTS env var. Zero pre-tunnel leak but fails if server
              IP not in whitelist — refresh with 'fetch' when providers rotate.

Example workflows:
  # One-shot per session, exact peer:
  sudo $0 auto

  # Always-on both providers:
  sudo $0 fetch mullvad airvpn
  sudo $0 providers mullvad airvpn

  # Cluster-LAN management exception (Talos apid :50000, kubelet, etc.):
  sudo $0 --lan 192.168.100.0/24 providers mullvad tailscale airvpn

  # Custom dynamic-IP provider (corporate OpenVPN behind DDNS) that never
  # goes stale: lock once, then auto-refresh every 15 min:
  sudo $0 providers mullvad airvpn tailscale funeraria
  sudo $0 refresh install 15min

  # Rollback:
  sudo $0 unlock
USAGE
}

list_known_providers() {
    declare -F | awk '/fetch_[a-z]/ {sub(/fetch_/,"",$3); print $3}' | grep -v '^provider$'
}

main() {
    local cmd="${1:-setup}"
    shift || true

    case "$cmd" in
         help|-h|--help)
            usage; exit 0 ;;
        detect)
            require_root
            local found
            found=$(detect_vpn_endpoints)
            if [[ -z "${found// }" ]]; then
                warn "No active VPN endpoints detected. Connect VPN first."
                exit 1
            fi
            info "Detected VPN endpoints: $found"
            exit 0 ;;
        unlock)
            require_root
            unlock_firewall
            exit 0 ;;
        refresh)
            require_root
            local sub="${1:-}"
            case "$sub" in
                install|timer)
                    shift || true
                    install_refresh_timer "${1:-}" ;;
                uninstall|remove)
                    remove_refresh_timer
                    info "Refresh timer removed." ;;
                *)
                    refresh_endpoints "$@" ;;
            esac
            exit 0 ;;
        panic|rescue|emergency)
            require_root
            panic_recover
            exit 0 ;;
        tailscale-web)
            require_root
            if [[ "${1:-apply}" == "remove" ]]; then
                remove_tailscale_web
            else
                tailscale_web_helper "${1:-apply}"
            fi
            exit 0 ;;
        tailscale-routes)
            require_root
            local sub="${1:-_apply}"
            case "$sub" in
                _apply|apply) apply_tailscale_route_rules ;;
                install)      install_tailscale_route_rules; install_nm_dispatcher ;;
                remove|rm)    remove_tailscale_route_rules ;;
                *) error "tailscale-routes: unknown subcommand '$sub'. Try: apply|install|remove" ;;
            esac
            exit 0 ;;
        split)
            local sub="${1:-list}"
            shift || true
            case "$sub" in
                add|install)
                    [[ $# -ge 1 ]] || error "split add: name required"
                    split_install "$1" ;;
                rm|remove|del|delete)
                    require_root
                    [[ $# -ge 1 ]] || error "split rm: name required"
                    split_remove "$1" ;;
                ls|list)
                    split_list ;;
                status)
                    split_status "${1:-}" ;;
                connect|up)
                    [[ $# -ge 1 ]] || error "split connect: name required"
                    split_connect "$1" ;;
                *)
                    error "split: unknown subcommand '$sub'. Try: add|rm|list|status|connect" ;;
            esac
            exit 0 ;;
        exclude)
            local sub="${1:-status}"
            shift || true
            case "$sub" in
                run|exec)              exclude_run "$@" ;;
                on|enable|add|install) exclude_enable
                                       info "exclude: enabled. Run: sudo $0 exclude run -- <command>  (add --as USER to drop root)" ;;
                off|disable|rm|remove|del|delete) exclude_disable ;;
                status|ls|list|show)   exclude_status ;;
                _apply)                require_root; exclude_apply_routing ;;
                _teardown)             require_root; exclude_teardown_routing ;;
                *) error "exclude: unknown subcommand '$sub'. Try: run|on|off|status" ;;
            esac
            exit 0 ;;
        test)
            require_root
            local mode="${1:-passive}"
            case "$mode" in
                passive) test_passive ;;
                active)  test_active ;;
                *) error "test mode must be 'passive' or 'active'" ;;
            esac
            exit 0 ;;
        fetch)
            require_root
            local targets=("$@")
            if [[ ${#targets[@]} -eq 0 ]]; then
                mapfile -t targets < <(list_known_providers)
            fi
            local p fail=0
            for p in "${targets[@]}"; do
                fetch_provider "$p" || fail=$((fail+1))
            done
            [[ $fail -eq 0 ]] || warn "$fail provider(s) failed"
            exit $fail ;;
        providers)
            require_root
            [[ $# -eq 0 ]] && error "providers: specify at least one provider name. Known: $(list_known_providers | xargs)"
            info "Loading provider profiles: $*"
            VPN_ENDPOINTS=$(load_providers "$@")
            if [[ -z "${VPN_ENDPOINTS// }" ]]; then
                error "No IPs loaded. Run: $0 fetch $*"
            fi
            local count
            count=$(echo "$VPN_ENDPOINTS" | wc -w)
            info "Locking to $count endpoints from: $*"
            mkdir -p "$(dirname "$PROVIDERS_ACTIVE_FILE")"
            echo "$*" > "$PROVIDERS_ACTIVE_FILE"
            ;;
        auto)
            require_root
            info "Auto-detecting VPN endpoints..."
            VPN_ENDPOINTS=$(detect_vpn_endpoints)
            if [[ -z "${VPN_ENDPOINTS// }" ]]; then
                error "No active VPN detected. Connect VPN first, then rerun with 'auto'. Or use 'setup' for permissive mode, or set VPN_ENDPOINTS=... manually."
            fi
            info "Locking to endpoints: $VPN_ENDPOINTS"
            ;;
        setup|"")
            require_root ;;
        *)
            usage; error "Unknown command: $cmd" ;;
    esac

    echo ""
    info "VPN Kill-Switch Firewall v3"
    if [[ -n "$VPN_ENDPOINTS" ]]; then
        info "Mode: STRICT (endpoint-locked, no DNS/443 pre-holes)"
        info "Endpoints: $VPN_ENDPOINTS"
    else
        info "Mode: PERMISSIVE (DNS/443/VPN ports open pre-tunnel)"
    fi
    info "VPNs: AirVPN/Eddie + Mullvad + generic OpenVPN/WireGuard"
    echo ""

    detect_physical_if
    backup_existing
    disable_ipv6
    setup_ufw
    add_killswitch_before_rules
    install_tailscale_route_rules
    make_persistent
    install_nm_dispatcher
    verify

    echo ""
    info "Done. Reboot for full IPv6 disable."
    info "Rollback: sudo $0 unlock"
}

# --- Global flags (consumed before subcommand dispatch) ---
# Currently: --lan / --lan-allow <cidrs>
# Quote multi-CIDR values:  --lan "192.168.100.0/24 10.0.5.0/24"
_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --lan|--lan-allow)
            [[ $# -ge 2 ]] || error "$1 requires a CIDR (or quoted, space-separated CIDRs)"
            LAN_ALLOW_CIDRS="$2"; shift 2 ;;
        --lan=*|--lan-allow=*)
            LAN_ALLOW_CIDRS="${1#*=}"; shift ;;
        *)
            _args+=("$1"); shift ;;
    esac
done
set -- ${_args[@]+"${_args[@]}"}

main "$@"
