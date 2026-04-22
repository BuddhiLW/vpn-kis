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

info()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
error() { printf "${RED}[-]${NC} %s\n" "$*"; exit 1; }

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

BACKUP_DIR="/etc/ufw/backup-$(date +%Y%m%d-%H%M%S)"
PROVIDERS_DIR="/etc/vpn-killswitch/providers"

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Run as root or with sudo"
    fi
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

fetch_provider() {
    local name="$1"
    local fn="fetch_$name"
    if ! declare -F "$fn" >/dev/null 2>&1; then
        error "Unknown provider: $name. Known: $(declare -F | awk '/fetch_[a-z]/ {sub(/fetch_/,"",$3); print $3}' | grep -v '^provider$' | xargs)"
    fi
    info "Fetching $name server IPs..."
    local ips
    ips=$("$fn") || { warn "Fetch failed for $name"; return 1; }
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

    # 4b. Remove tailscale route rules + boot-persistence unit
    echo "[*] Removing Tailscale routing rules..."
    if [ -f /etc/systemd/system/vpn-killswitch-tailscale-routes.service ]; then
        systemctl disable --now vpn-killswitch-tailscale-routes.service 2>/dev/null || true
        rm -f /etc/systemd/system/vpn-killswitch-tailscale-routes.service
        systemctl daemon-reload 2>/dev/null || true
    fi
    while ip rule del priority 5200 2>/dev/null; do :; done

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
    iptables -L OUTPUT -n | head -3 2>/dev/null || echo "    (iptables unreadable)"

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
    if iptables -S ufw-before-output 2>/dev/null | grep -qE -- "-o $PHYSICAL_IF .*-j DROP"; then
        pass "Physical IF DROP rule present ($PHYSICAL_IF)"
    else
        fail "No DROP rule on $PHYSICAL_IF in ufw-before-output — killswitch will NOT fire"
    fi

    # 4. VPN iface allowed?
    local allowed_vifs
    allowed_vifs=$(iptables -S ufw-before-output 2>/dev/null | grep -oE -- "-o \S+ -j ACCEPT" | awk '{print $2}' | sort -u | tr '\n' ' ')
    if [[ -n "$allowed_vifs" ]]; then
        pass "VPN interfaces ACCEPT: $allowed_vifs"
    else
        fail "No iface ACCEPT rules in ufw-before-output"
    fi

    # 5. IPv6 disabled?
    if [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" == "1" ]]; then
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
    strict_rules=$(iptables -S ufw-before-output 2>/dev/null | grep -cE -- "-d [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*ACCEPT" || true)
    if iptables -S ufw-before-output 2>/dev/null | grep -q "match-set vpn_endpoints"; then
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
        if iptables -S ufw-before-output | grep -qE -- "--dport 53.*ACCEPT"; then
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

    for iface in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
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
    {
        echo "create vpn_endpoints hash:ip family inet hashsize 2048 maxelem 65536"
        for ip in $VPN_ENDPOINTS; do
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
# When Mullvad is connected, its fwmark default-route rule (priority 5209)
# catches any packet without explicit policy. Tailscale's own subnet routes
# live in table 52 at priority 5270 (BELOW Mullvad), so packets to tailnet
# CGNAT and advertised subnets get hijacked by Mullvad and dropped at the
# exit (RFC1918) or rejected by Mullvad's nftables forward chain (CGNAT).
#
# These rules push table-52 lookups for those CIDRs ABOVE Mullvad's rule,
# so host AND container traffic to tailnet destinations exit tailscale0.
TAILSCALE_RULE_PRIO=5200
TAILSCALE_ROUTE_TABLE=52
TAILSCALE_ROUTES_UNIT=/etc/systemd/system/vpn-killswitch-tailscale-routes.service

discover_tailscale_cidrs() {
    # CGNAT is always relevant if tailscale is in the picture.
    echo "100.64.0.0/10"
    # Plus any RFC1918 subnets currently advertised through tailscale0
    # (k8s pod/service CIDRs from subnet routers, home-lab subnets, etc.).
    ip route show table $TAILSCALE_ROUTE_TABLE 2>/dev/null \
        | awk '/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*\/[0-9]+ dev tailscale/ {print $1}' \
        | sort -u
}

install_tailscale_route_rules() {
    # Skip if tailscale isn't part of this killswitch profile.
    [[ "$VPN_INTERFACES" =~ tailscale ]] || return 0

    local cidrs cidr
    cidrs=$(discover_tailscale_cidrs | xargs)
    [[ -z "$cidrs" ]] && return 0

    info "Installing Tailscale routing rules (priority $TAILSCALE_RULE_PRIO → table $TAILSCALE_ROUTE_TABLE):"
    for cidr in $cidrs; do
        ip rule del to "$cidr" lookup $TAILSCALE_ROUTE_TABLE priority $TAILSCALE_RULE_PRIO 2>/dev/null || true
        ip rule add to "$cidr" lookup $TAILSCALE_ROUTE_TABLE priority $TAILSCALE_RULE_PRIO
        info "  $cidr"
    done

    # Persist via systemd oneshot. Re-applies at boot independent of UFW order.
    # The CIDR list is baked in at install time — re-run the script (providers /
    # auto / setup) to re-discover after adding tailnet subnet routers.
    local exec_lines=""
    for cidr in $cidrs; do
        exec_lines+="ExecStart=-/sbin/ip rule del to $cidr lookup $TAILSCALE_ROUTE_TABLE priority $TAILSCALE_RULE_PRIO"$'\n'
        exec_lines+="ExecStart=/sbin/ip rule add to $cidr lookup $TAILSCALE_ROUTE_TABLE priority $TAILSCALE_RULE_PRIO"$'\n'
    done

    cat > "$TAILSCALE_ROUTES_UNIT" <<UNIT
[Unit]
Description=VPN Kill-Switch — Tailscale subnet route rules
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
${exec_lines}ExecStop=/bin/sh -c 'while /sbin/ip rule del priority $TAILSCALE_RULE_PRIO 2>/dev/null; do :; done'

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable vpn-killswitch-tailscale-routes.service >/dev/null 2>&1 || true
    info "Boot-persisted via $TAILSCALE_ROUTES_UNIT"
}

remove_tailscale_route_rules() {
    if [[ -f "$TAILSCALE_ROUTES_UNIT" ]]; then
        systemctl disable --now vpn-killswitch-tailscale-routes.service 2>/dev/null || true
        rm -f "$TAILSCALE_ROUTES_UNIT"
        systemctl daemon-reload 2>/dev/null || true
    fi
    # Flush any rules still installed at our priority (covers stale CIDRs).
    while ip rule del priority $TAILSCALE_RULE_PRIO 2>/dev/null; do :; done
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

# Pattern of ifaces we must NEVER pin the killswitch DROP rule onto.
is_virtual() {
    case "$1" in
        lo|tun*|wg*|tailscale*|Eddie|ppp*|docker*|veth*|virbr*|br-*|zt*) return 0 ;;
    esac
    return 1
}

# Only react to relevant NM events
case "$ACTION" in
    up|down|connectivity-change) ;;
    *) exit 0 ;;
esac

# Ignore the hook when triggered BY a VPN/virtual iface coming up — those
# events fire NEW_IF detection at the wrong moment (tunnel = default route).
if [ -n "$IFACE" ] && is_virtual "$IFACE"; then
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

[ "$NEW_IF" = "$CURRENT" ] && exit 0

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
    iptables -L OUTPUT -n -v | head -20

    echo ""
    info "Physical IF kill-switch (should see DROP at end):"
    iptables -L ufw-before-output -n | grep -E 'DROP|ACCEPT' | tail -5

    echo ""
    info "IPv6 status:"
    val=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
    [[ "$val" == "1" ]] && info "IPv6: DISABLED (good)" || warn "IPv6: still enabled — reboot required"

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
  $0 detect                        Print detected VPN endpoints, exit
  $0 test [passive|active]         Run killswitch self-tests (default: passive)
                                   passive = non-disruptive rule checks
                                   active  = drops VPN, checks for leak, reconnects
                                   FORCE=1 skips confirm prompt
  $0 unlock                        Restore UFW from latest backup
  $0 panic                         EMERGENCY: drop all firewall rules, reset
                                   DNS, re-enable IPv6, restart network stack.
                                   Run from local TTY when locked out.
                                   Aliases: rescue, emergency
  $0 help                          Show this message

Env:
  VPN_ENDPOINTS="1.2.3.4 5.6.7.8"   Manual strict mode (overrides auto/providers)

Providers:
  mullvad   — fetched from api.mullvad.net (needs jq + network)
  airvpn    — scanned from /etc/openvpn + Eddie config dirs
  tailscale — DERP relays + control plane (login.tailscale.com derpmap)
              Strict mode forces peer traffic via DERP relay (no direct UDP).
  <custom>  — drop IPs (one per line) into $PROVIDERS_DIR/<name>.ips

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
        panic|rescue|emergency)
            require_root
            panic_recover
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

main "$@"
