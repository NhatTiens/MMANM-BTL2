#!/bin/sh
set -eu
rm -f /tmp/gateway-ready
mkdir -p /logs
# Fail closed during startup. Set the filter policies before enabling services.
# This script runs only inside the isolated gateway image.
[ -f /.dockerenv ] && [ -f /lab/firewall/policy.py ] || exit 1
iptables -w 5 -P INPUT DROP
iptables -w 5 -P FORWARD DROP
sh /lab/firewall/rules.sh
if [ "${VPN_ENABLED:-0}" = 1 ]; then sh /lab/vpn/gateway.sh; fi
exec python3 /lab/firewall/counters.py
