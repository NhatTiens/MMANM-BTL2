#!/bin/sh
set -eu
mode=${IPS_MODE:-ids}
case "$mode" in ids|ips) ;; *) echo 'Invalid IPS_MODE' >&2; exit 2;; esac
[ -f /.dockerenv ] || { echo 'Run inside Compose only' >&2; exit 2; }
[ -s /rules/local.rules ] || { echo 'Missing generated.rules; run configure.py' >&2; exit 2; }
if grep -q '@MSSV_HEX@' /rules/local.rules; then echo 'Unrendered MSSV' >&2; exit 2; fi
mkdir -p /logs
python3 /sensor_config.py --mode "$mode"
config=/tmp/btl2-suricata.yaml
suricata -T -c "$config" -S /rules/local.rules -l /logs
if [ "$mode" = ips ]; then
  exec suricata -c "$config" -S /rules/local.rules -l /logs -q 0
fi
# Only external interface; avoid counting forwarded packets twice.
iface=$(ip -o -4 addr show | awk '$4 == "172.28.50.254/24" {print $2}')
[ -n "$iface" ] && [ "$(printf '%s\n' "$iface" | wc -l)" -eq 1 ] || { echo 'Missing/ambiguous external interface' >&2; exit 2; }
exec suricata -c "$config" -S /rules/local.rules -l /logs -i "$iface"
