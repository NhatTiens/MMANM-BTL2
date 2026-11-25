"""BTL1-compatible 4-byte big-endian framing, now bounded to 1 MiB."""
import json

MAX_FRAME = 1024 * 1024


def send_frame(sock, payload):
    if not 1 <= len(payload) <= MAX_FRAME:
        raise ValueError('Invalid frame size')
    sock.sendall(len(payload).to_bytes(4, 'big') + payload)


def recv_exact(sock, length):
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            if buf:
                raise EOFError('Truncated frame')
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock):
    header = recv_exact(sock, 4)
    if header is None:
        return None
    size = int.from_bytes(header, 'big')
    if not 1 <= size <= MAX_FRAME:
        raise ValueError('Invalid frame size')
    payload = recv_exact(sock, size)
    if payload is None:
        raise EOFError('Missing frame payload')
    return payload


def send_json(sock, data):
    send_frame(sock, json.dumps(data).encode('utf-8'))


def recv_json(sock):
    payload = recv_frame(sock)
    if payload is None:
        return None
    data = json.loads(payload.decode('utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Expected JSON object')
    return data
