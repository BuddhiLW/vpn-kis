#!/bin/sh
# vpn-firewall-setup.sh: the vpn-kis entry point, kept for muscle memory.
#
# The kill-switch itself now lives in vpn-kis-bb (Clojure, run natively via
# ClojureWasm); this shim finds its launcher and passes every argument on.
#
#   VPN_KIS_BB_HOME   checkout of vpn-kis-bb (default: ../vpn-kis-bb next to
#                     this repo, else `vpn-kis` on PATH)
#   VPN_KIS_LEGACY=1  run the previous bash implementation instead
#                     (lib/legacy/vpn-firewall-setup.bash)
#
# Under sudo, pass these as `sudo VPN_KIS_LEGACY=1 ./vpn-firewall-setup.sh ...`.
set -u

here=$(CDPATH='' cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)

if [ "${VPN_KIS_LEGACY:-}" = "1" ]; then
    exec bash "$here/lib/legacy/vpn-firewall-setup.bash" "$@"
fi

launcher=""
for cand in "${VPN_KIS_BB_HOME:-}/bin/vpn-kis" "$here/../vpn-kis-bb/bin/vpn-kis"; do
    if [ -x "$cand" ]; then
        launcher=$cand
        break
    fi
done
if [ -z "$launcher" ]; then
    launcher=$(command -v vpn-kis 2>/dev/null || true)
fi
if [ -z "$launcher" ]; then
    echo "vpn-firewall-setup.sh: vpn-kis-bb not found." >&2
    echo "  Clone it next to this repo, set VPN_KIS_BB_HOME, or run the bash" >&2
    echo "  version with VPN_KIS_LEGACY=1." >&2
    exit 127
fi

export VPN_KIS_PROG="${VPN_KIS_PROG:-$0}"
exec "$launcher" "$@"
