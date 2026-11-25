"""Noninteractive BTL1-compatible encrypted chat demo, only for the team's lab.

Public MSSV-based HMAC and exchanged RSA keys are NOT trusted identity pins.
Demonstrates confidentiality against a passive relay, not active-MITM immunity.
No private keys, session keys or plaintext messages are printed or saved.
"""
import argparse
import base64
import socket
import sys

if __package__:
    from .legacy.crypto_core import CryptoCore as C, OFFICIAL_GROUP_MSSV
    from .legacy.protocol import recv_json, send_json
else:
    from legacy.crypto_core import CryptoCore as C, OFFICIAL_GROUP_MSSV
    from legacy.protocol import recv_json, send_json

HELLO = f"Hello, We are {', '.join(OFFICIAL_GROUP_MSSV)}"
MESSAGE = b'BTL2 VPN chat demonstration'
ACK = b'BTL2 received and verified'


def b64(data):
    return base64.b64encode(data).decode('ascii')


def decoded(data):
    return base64.b64decode(data, validate=True)


def expect(sock, kind):
    data = recv_json(sock)
    if not data or data.get('type') != kind:
        raise ValueError('Unexpected protocol message')
    return data


def send_chat(sock, key, message):
    nonce, ciphertext = C.aes_gcm_encrypt(key, message)
    send_json(sock, {'type': 'CHAT', 'nonce': b64(nonce), 'data': b64(ciphertext)})


def receive_chat(sock, key):
    data = expect(sock, 'CHAT')
    return C.aes_gcm_decrypt(key, decoded(data['nonce']), decoded(data['data']))


def exchange(sock):
    role = expect(sock, 'INIT_START').get('role')
    private, public = C.generate_rsa_keypair()
    public_pem = C.export_public_key_pem(public)
    master = C.derive_kdf_from_mssv()
    if role == 'initiator':
        send_json(sock, {'type': 'HANDSHAKE_HELLO', 'plaintext': HELLO,
                         'hmac': b64(C.compute_hmac(master, HELLO.encode())), 'pubkey': public_pem})
        peer = C.load_public_key_pem(expect(sock, 'HANDSHAKE_REPLY')['pubkey'])
        key = C.generate_aes_key()
        wrapped = C.rsa_encrypt(peer, key)
        send_json(sock, {'type': 'SESSION_KEY_EXCHANGE', 'enc_key': b64(wrapped),
                         'signature': b64(C.rsa_sign(private, wrapped))})
        send_chat(sock, key, MESSAGE)
        if receive_chat(sock, key) != ACK:
            raise ValueError('Incorrect encrypted acknowledgement')
    elif role == 'receiver':
        hello = expect(sock, 'HANDSHAKE_HELLO')
        if hello['plaintext'] != HELLO or not C.verify_hmac(master, HELLO.encode(), decoded(hello['hmac'])):
            raise ValueError('BTL1 handshake mismatch')
        peer = C.load_public_key_pem(hello['pubkey'])
        send_json(sock, {'type': 'HANDSHAKE_REPLY', 'pubkey': public_pem})
        package = expect(sock, 'SESSION_KEY_EXCHANGE')
        wrapped, signature = decoded(package['enc_key']), decoded(package['signature'])
        if not C.rsa_verify(peer, signature, wrapped):
            raise ValueError('Invalid session-key signature')
        key = C.rsa_decrypt(private, wrapped)
        if len(key) != 32 or receive_chat(sock, key) != MESSAGE:
            raise ValueError('Unexpected encrypted message')
        send_chat(sock, key, ACK)
    else:
        raise ValueError('Invalid relay role')
    return role


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', choices=['172.28.60.30', '127.0.0.1'], default='172.28.60.30')
    args = parser.parse_args()
    try:
        with socket.create_connection((args.host, 9999), timeout=25) as sock:
            role = exchange(sock)
        print(f'PASS chat {role}: encrypted message / acknowledgement verified')
        return 0
    except Exception as exc:
        print(f'FAIL chat: {type(exc).__name__}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
