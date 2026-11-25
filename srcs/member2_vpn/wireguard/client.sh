#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"
# Prevent ambiguous or injected routes; conform to the MSSV-derived DMZ contract.
python3 - "${DMZ_NET:?DMZ_NET required}" <<'PY'
import ipaddress, sys
try:
    net = ipaddress.IPv4Network(sys.argv[1], strict=True)
    a, b, c, d = net.network_address.packed
    if net.prefixlen != 24 or a != 10 or b >= 200 or c != 1 or d != 0:
        raise ValueError('invalid DMZ')
except ValueError:
    sys.exit('DMZ_NET must be 10.(MSSV mod 200).1.0/24')
PY
validate_pair
new_interface
ip address add 10.77.0.2/24 dev wg0
wg set wg0 private-key /keys/private peer "$(cat /keys/peer)" endpoint 172.28.50.254:51820 allowed-ips "10.77.0.1/32,172.28.60.0/24,$DMZ_NET" persistent-keepalive 25
ip link set wg0 up
ip route replace 172.28.60.0/24 dev wg0
ip route replace "$DMZ_NET" dev wg0
finish_interface
printf '%s\n' 'VPN client ready (split tunnel); traffic will trigger handshake'
exec sleep infinity
