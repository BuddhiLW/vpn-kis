#!/usr/bin/env bash
# Stub harness for the legacy bash implementation
# (lib/legacy/vpn-firewall-setup.bash, run with VPN_KIS_LEGACY=1): runs its
# functions under the script's own `set -euo pipefail` with every privileged
# binary faked (stub.sh) and /etc redirected into a temp root. No root, no
# network.
#
#   tests/bash/run.sh [path/to/vpn-firewall-setup.bash]
#
# Scenarios cover the Mullvad + Tailscale coexistence (mark-based bypass,
# idempotent re-apply, tailscaled restart), panic under failing commands,
# strict-mode rules and the NM hook triggers.
set -uo pipefail
H=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$(readlink -f "${1:-$H/../../lib/legacy/vpn-firewall-setup.bash}")
PASS=0; FAIL=0
ROOTS=()
trap 'rm -rf "${ROOTS[@]}"' EXIT
ok()   { echo "PASS $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL $*"; FAIL=$((FAIL+1)); }
check() {
    if eval "$2"; then ok "$1"; else
        bad "$1"
        [[ -f "${ROOT:-}/out" ]] && sed 's/^/      | /' "$ROOT/out" | tail -6
    fi
}

new_env() {
    ROOT=$(mktemp -d "${TMPDIR:-/tmp}/vpnkis-harness.XXXXXX"); ROOTS+=("$ROOT")
    export ROOT STATE="$ROOT/state" LOG="$ROOT/log"
    mkdir -p "$STATE" "$ROOT/bin" "$ROOT/etc/vpn-killswitch" "$ROOT/etc/ufw" \
             "$ROOT/etc/systemd/system" "$ROOT/etc/NetworkManager/dispatcher.d"
    : > "$LOG"
    local n
    for n in ip nft mullvad systemctl ufw ipset iptables ip6tables iptables-save \
             ip6tables-save iptables-nft iptables-legacy sysctl update-grub \
             grub-mkconfig logger ping getent curl dig wg-quick; do
        cp "$H/stub.sh" "$ROOT/bin/$n"
    done
    chmod +x "$ROOT/bin/"*
    # Live-like state: Mullvad above our legacy rules (the outage we saw).
    cat > "$STATE/ip-rules" <<'EOF'
0:	from all lookup local
5094:	from all lookup main suppress_prefixlength 0
5095:	not from all fwmark 0x6d6f6c65 lookup 1836018789
5096:	from all to 100.64.0.0/10 lookup 52
5096:	from all to 10.244.0.0/16 lookup 52
5096:	from all to 10.96.0.0/12 lookup 52
5096:	from all to 192.168.100.133 lookup 52
5096:	from all to 192.168.100.134 lookup 52
5096:	from all to 192.168.100.137 lookup 52
5096:	from all to 192.168.100.9 lookup 52
5270:	from all lookup 52
32766:	from all lookup main
EOF
    cat > "$STATE/table52" <<'EOF'
10.96.0.0/12 dev tailscale0
10.244.0.0/16 dev tailscale0
100.101.12.99 dev tailscale0
192.168.100.9 dev tailscale0
192.168.100.133 dev tailscale0
192.168.100.134 dev tailscale0
192.168.100.137 dev tailscale0
EOF
    printf 'Excluded PIDs:\n    4242\n' > "$STATE/mullvad-split"
    echo 4242 > "$STATE/tailscaled-pid"
    # A copy of the script with absolute system paths moved under $ROOT and
    # `main "$@"` removed, so it can be sourced.
    sed -e "s#/etc/#$ROOT/etc/#g" -e '$d' "$SCRIPT" > "$ROOT/script.sh"
}

run_fn() {  # run_fn <shell code> ; stdout+stderr -> $ROOT/out ; rc -> $RC
    ( export PATH="$ROOT/bin:$PATH"; source "$ROOT/script.sh"; eval "$*" ) > "$ROOT/out" 2>&1
    RC=$?
}

calls() { grep -c -- "$1" "$LOG" || true; }

# ---------------------------------------------------------------- scenario 1
new_env
run_fn apply_tailscale_route_rules
check "migrate: apply exits 0 under set -euo pipefail (rc=$RC)" '[[ $RC -eq 0 ]]'
check "migrate: nft table loaded once" '[[ $(calls "^nft -f -") -eq 1 ]]'
check "migrate: set holds CGNAT + all table-52 subnets" \
  'grep -q "elements = { 100.64.0.0/10, 10.244.0.0/16, 10.96.0.0/12, 192.168.100.133, 192.168.100.134, 192.168.100.137, 192.168.100.9 }" "$STATE/nft-last"'
check "migrate: never marks all of 10/8 (Mullvad DNS 10.64.0.1 stays in tunnel)" '! grep -q "10.0.0.0/8" "$STATE/nft-last"'
check "migrate: route chain sets both Mullvad marks" \
  'grep -q "ip daddr @tailnet meta mark set 0x6d6f6c65 ct mark set 0x00000f41" "$STATE/nft-last"'
check "migrate: masquerade on tailscale0" 'grep -q "oifname \"tailscale0\" ct mark 0x00000f41 masquerade" "$STATE/nft-last"'
check "migrate: atomic replace (create, delete, recreate in one batch)" \
  '[[ $(head -2 "$STATE/nft-last" | tr "\n" "|") == "table inet vpn-killswitch-tailscale|delete table inet vpn-killswitch-tailscale|" ]]'
check "migrate: legacy lookup-52 rules all removed" '! grep -q " to .* lookup 52" "$STATE/ip-rules"'
check "migrate: tailscale own 5270 rule untouched" 'grep -q "^5270:" "$STATE/ip-rules"'
check "migrate: mark applied BEFORE legacy rules removed (make-before-break)" \
  '[[ $(grep -n "^nft -f -" "$LOG" | cut -d: -f1 | head -1) -lt $(grep -n "^ip rule del" "$LOG" | cut -d: -f1 | head -1) ]]'
check "migrate: indented PID recognised, no re-add" '[[ $(calls "split-tunnel add") -eq 0 ]]'
check "migrate: destinations persisted" '[[ $(wc -l < "$ROOT/etc/vpn-killswitch/tailnet.cidrs") -eq 7 ]]'

# ---------------------------------------------------------------- scenario 2
: > "$LOG"
run_fn apply_tailscale_route_rules
check "reapply: exits 0 (rc=$RC)" '[[ $RC -eq 0 ]]'
check "reapply: no nft reload (idempotent)" '[[ $(calls "^nft -f -") -eq 0 ]]'
check "reapply: no ip rule changes" '[[ $(calls "^ip rule add") -eq 0 && $(calls "^ip rule del") -eq 0 ]]'

# ---------------------------------------------------------------- scenario 3
: > "$LOG"; : > "$STATE/table52"   # tailscaled restarting: table 52 empty
run_fn apply_tailscale_route_rules
check "tailscaled restart: exits 0 (rc=$RC)" '[[ $RC -eq 0 ]]'
check "tailscaled restart: set NOT shrunk (no reload)" '[[ $(calls "^nft -f -") -eq 0 ]]'

# ---------------------------------------------------------------- scenario 4
: > "$LOG"; echo 777 > "$STATE/tailscaled-pid"   # tailscaled came back, new PID
cp /dev/null "$STATE/table52"
printf '10.96.0.0/12 dev tailscale0\n100.101.12.99 dev tailscale0\n' > "$STATE/table52"
run_fn apply_tailscale_route_rules
check "subnet withdrawn + new pid: exits 0 (rc=$RC)" '[[ $RC -eq 0 ]]'
check "subnet withdrawn: set reloaded with the new destinations" \
  'grep -q "elements = { 100.64.0.0/10, 10.96.0.0/12 }" "$STATE/nft-last"'
check "new tailscaled pid excluded from Mullvad" '[[ $(calls "split-tunnel add 777") -eq 1 ]]'

# ---------------------------------------------------------------- scenario 5
new_env
touch "$STATE/fail-all"   # every stubbed command fails (worst case)
run_fn panic_recover
check "panic: runs to completion despite failures (rc=$RC)" 'grep -q "RECOVERY DONE" "$ROOT/out"'
check "panic: keeps the tailnet bypass table" '[[ $(calls "delete table inet vpn-killswitch-tailscale") -eq 0 ]]'
check "panic: no blanket 'ip rule del priority 5200'" '[[ $(calls "rule del priority 5200") -eq 0 ]]'
check "panic: still restarts tailscaled" '[[ $(calls "systemctl restart tailscaled") -eq 1 ]]'
rm -f "$STATE/fail-all"
run_fn panic_recover
check "panic (normal): completes (rc=$RC)" '[[ $RC -eq 0 ]] && grep -q "RECOVERY DONE" "$ROOT/out"'

# ---------------------------------------------------------------- scenario 6
new_env
run_fn 'PHYSICAL_IF=wlp0; VPN_ENDPOINTS="1.2.3.4 5.6.7.8"; add_killswitch_before_rules'
check "strict rules: exits 0 (rc=$RC)" '[[ $RC -eq 0 ]]'
check "strict rules: single any-port set match to endpoints" \
  'grep -qx -- "-A ufw-before-output -o wlp0 -m set --match-set vpn_endpoints dst -j ACCEPT" "$ROOT/etc/ufw/before.rules"'
check "strict rules: no per-port lock by default" '! grep -q -- "--dport 51820 -m set" "$ROOT/etc/ufw/before.rules"'
check "strict rules: killswitch DROP still last" \
  '[[ $(grep -c -- "-o wlp0 -j DROP" "$ROOT/etc/ufw/before.rules") -eq 1 ]]'
run_fn 'PHYSICAL_IF=wlp0; VPN_ENDPOINTS="1.2.3.4"; STRICT_PORTS=1 add_killswitch_before_rules'
check "STRICT_PORTS=1 keeps the legacy port lock" \
  'grep -q -- "-p udp --dport 51820 -m set --match-set vpn_endpoints dst -j ACCEPT" "$ROOT/etc/ufw/before.rules"'

# ---------------------------------------------------------------- scenario 7
new_env
printf 'not json' > "$STATE/curl-body"
run_fn fetch_mullvad
check "fetch_mullvad: fails (keeps cache) when relay list is bad (rc=$RC)" '[[ $RC -ne 0 ]]'
printf '{"wireguard":{"relays":[{"ipv4_addr_in":"1.1.1.2"}]},"bridge":{"relays":[{"ipv4_addr_in":"3.3.3.3"}]}}' > "$STATE/curl-body"
run_fn fetch_mullvad
check "fetch_mullvad: relays + builtin API IP (rc=$RC)" \
  '[[ $RC -eq 0 ]] && grep -qx 1.1.1.2 "$ROOT/out" && grep -qx 3.3.3.3 "$ROOT/out" && grep -qx 45.83.223.196 "$ROOT/out"'

# ---------------------------------------------------------------- dispatcher
new_env
# shellcheck disable=SC2034  # read by the eval'd check expressions below
hook=$(sed -n '/^install_nm_dispatcher()/,/^HOOK$/p' "$SCRIPT")
check "hook: Mullvad wg* events no longer trigger a refresh" '! grep -q "wg\*|tailscale\*) refresh_tailscale_routes" <<<"$hook"'
check "hook: tailscale* events still refresh" 'grep -q "tailscale\*) refresh_tailscale_routes" <<<"$hook"'
check "hook: same-IF connectivity events are a no-op" 'grep -qF "[ \"\$NEW_IF\" = \"\$CURRENT\" ] && exit 0" <<<"$hook"'

echo
echo "harness: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
