#!/usr/bin/env bash
# Multiplexing stub: behaviour chosen by the name it is invoked as.
name=$(basename "$0")
echo "$name $*" >> "$LOG"
[[ -f "$STATE/fail-all" ]] && exit 1
case "$name" in
  ip)
    case "$*" in
      "rule show"|"rule show "*) cat "$STATE/ip-rules" ;;
      "rule del to "*)
        cidr=$4
        line=$(grep -n -m1 -E "^[0-9]+:	from all to ${cidr//./\\.} lookup 52\$" "$STATE/ip-rules" | cut -d: -f1)
        [[ -n "$line" ]] || exit 2
        sed -i "${line}d" "$STATE/ip-rules" ;;
      "rule del"*) exit 2 ;;
      "rule add"*) exit 0 ;;
      "route show table 52") [[ -s "$STATE/table52" ]] || exit 2; cat "$STATE/table52" ;;
      "-4 route ls"*) echo "default via 192.168.12.1 dev wlp0 proto dhcp" ;;
      *) exit 0 ;;
    esac ;;
  nft)
    case "$*" in
      "-f -") cat > "$STATE/nft-last"; cp "$STATE/nft-last" "$STATE/nft-live" ;;
      "list table inet vpn-killswitch-tailscale") [[ -f "$STATE/nft-live" ]] || exit 1; cat "$STATE/nft-live" ;;
      "delete table inet vpn-killswitch-tailscale") rm -f "$STATE/nft-live" ;;
      "list table"*) exit 1 ;;
      *) exit 0 ;;
    esac ;;
  mullvad)
    case "$*" in
      "split-tunnel list") cat "$STATE/mullvad-split" ;;
      "split-tunnel add "*) echo "    $3" >> "$STATE/mullvad-split" ;;
      status) echo Connected ;;
      *) exit 0 ;;
    esac ;;
  systemctl)
    case "$*" in
      "show -p MainPID --value tailscaled") cat "$STATE/tailscaled-pid" ;;
      *) exit 0 ;;
    esac ;;
  ipset)
    case "${1:-}" in
      restore) cat > /dev/null ;;
      list) [[ "${2:-}" == -name ]] || printf 'Name: %s\nType: hash:ip\nNumber of entries: 2\nMembers:\n' "${2:-}" ;;
    esac
    exit 0 ;;
  curl) [[ -f "$STATE/curl-body" ]] || exit 22; cat "$STATE/curl-body" ;;
  dig) echo "45.83.223.193" ;;
  *) exit 0 ;;
esac
