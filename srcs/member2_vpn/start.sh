#!/bin/sh
set -eu
# All routing changes are limited to a single lab container namespace.
python3 - "${ROLE:?ROLE required}" "${ROUTER:?ROUTER required}" "${SERVICE_IP:-}" <<'PY'
import ipaddress, sys
role, router, address = sys.argv[1:]
try:
    gw = ipaddress.IPv4Address(router)
    if role == 'dmz':
        ip = ipaddress.IPv4Address(address)
        a,b,c,d = ip.packed
        ok = a == 10 and b < 200 and c == 1 and d == 10 and int(gw) == int(ip)+244
    else:
        ok = router == {'internal':'172.28.60.254', 'relay':'172.28.60.254', 'client':'172.28.50.254'}.get(role)
    if not ok:
        raise ValueError('invalid endpoint configuration')
except ValueError:
    sys.exit('ROLE/ROUTER/SERVICE_IP do not match the team network contract')
PY
ip route replace default via "$ROUTER"
case "$ROLE" in
    dmz|internal) exec python -u service.py;;
    relay) exec python -u legacy/server.py;;
    client) exec sleep infinity;;
    *) exit 1;;
esac
