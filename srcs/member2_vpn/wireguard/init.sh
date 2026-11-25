#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"
umask 077
# Run with both VPN peers stopped; initializer is the sole writer of these volumes.
atomic_public() {
    destination=$1
    temporary=$(mktemp "${destination}.XXXXXX")
    if ! cat > "$temporary" || ! mv -f "$temporary" "$destination"; then
        rm -f "$temporary"; fail 'Could not write public key'
    fi
}
for role in gateway client; do
    dir=/keys/$role
    [ -d "$dir" ] || fail 'VPN key volume missing'
    if [ ! -e "$dir/private" ]; then
        tmp=$(mktemp "$dir/private.XXXXXX")
        if ! wg genkey > "$tmp" || ! validate_key "$tmp"; then
            rm -f "$tmp"; fail 'Could not generate WireGuard key'
        fi
        mv -f "$tmp" "$dir/private"
    fi
    # Never overwrite damaged or empty existing private keys silently.
    validate_key "$dir/private"
    chmod 600 "$dir/private"
    pub=$(wg pubkey < "$dir/private")
    printf '%s\n' "$pub" | atomic_public "$dir/public"
    validate_key "$dir/public"
done
[ "$(cat /keys/gateway/public)" != "$(cat /keys/client/public)" ] || fail 'Peer keys must differ'
atomic_public /keys/client/peer < /keys/gateway/public
atomic_public /keys/gateway/peer < /keys/client/public
printf '%s\n' 'VPN key pairs ready. Existing private keys preserved; no secrets printed.'
