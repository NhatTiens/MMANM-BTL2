#!/bin/sh
# Sourced only from the lab's WireGuard startup scripts.
fail() { printf '%s\n' "$*" >&2; exit 1; }
validate_key() {
    # WireGuard keys are canonical base64 encodings of 32 bytes.
    python3 - "$1" <<'PY'
import base64, pathlib, sys
try:
    raw = pathlib.Path(sys.argv[1]).read_bytes().strip()
    key = base64.b64decode(raw, validate=True)
    if len(key) != 32 or base64.b64encode(key) != raw or not any(key):
        raise ValueError('invalid key')
except (OSError, ValueError):
    sys.exit('Missing or invalid WireGuard key file (contents hidden)')
PY
}
validate_pair() {
    validate_key /keys/private
    validate_key /keys/public
    validate_key /keys/peer
    [ "$(wg pubkey < /keys/private)" = "$(cat /keys/public)" ] || fail 'Local public key does not match private key'
    [ "$(cat /keys/public)" != "$(cat /keys/peer)" ] || fail 'Local and peer public keys must differ'
}
# No automatic replacement of an existing interface: never touch an unrelated tunnel.
new_interface() {
    if ip link show dev wg0 >/dev/null 2>&1; then fail 'wg0 already exists; recreate the lab container'; fi
    ip link add wg0 type wireguard
    trap 'ip link del dev wg0 >/dev/null 2>&1 || true' EXIT
    trap 'exit 1' HUP INT TERM
}
finish_interface() { trap - EXIT HUP INT TERM; }
