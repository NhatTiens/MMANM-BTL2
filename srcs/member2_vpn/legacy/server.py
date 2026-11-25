"""BTL1-compatible blind relay. One pair at a time, multiple sequential sessions."""
import socket
import threading
import time

if __package__:
    from .protocol import recv_frame, send_frame, send_json
else:
    from protocol import recv_frame, send_frame, send_json

HOST = '0.0.0.0'
PORT = 9999


def stop_pair(pair):
    for conn in pair:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def relay_worker(source, target):
    try:
        while (frame := recv_frame(source)) is not None:
            send_frame(target, frame)
    except (OSError, EOFError, ValueError):
        pass
    finally:
        stop_pair((source, target))


def serve_pair(first, second, idle_timeout=60):
    pair = (first, second)
    try:
        for conn in pair:
            conn.settimeout(idle_timeout)
        send_json(first, {'type': 'INIT_START', 'role': 'initiator'})
        send_json(second, {'type': 'INIT_START', 'role': 'receiver'})
        workers = [threading.Thread(target=relay_worker, args=args) for args in (pair, pair[::-1])]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()
    except (OSError, EOFError, ValueError):
        pass
    finally:
        stop_pair(pair)
        for conn in pair:
            conn.close()


def serve(listener, stop=None, pair_timeout=20, idle_timeout=60):
    listener.settimeout(0.25)
    while stop is None or not stop.is_set():
        try:
            first, _ = listener.accept()
        except TimeoutError:
            continue
        second = None
        try:
            deadline = time.monotonic() + pair_timeout
            while time.monotonic() < deadline and (stop is None or not stop.is_set()):
                try:
                    second, _ = listener.accept()
                    break
                except TimeoutError:
                    continue
            if second is not None:
                print('Relay pair established (blind forwarding)', flush=True)
                serve_pair(first, second, idle_timeout)
                print('Relay pair closed', flush=True)
        finally:
            first.close()
            if second is not None:
                second.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(4)
        print('BTL1 relay ready: TCP 9999', flush=True)
        serve(listener)


if __name__ == '__main__':
    main()
