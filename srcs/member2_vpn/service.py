"""Bounded, non-reflecting HTTP lab fixture and verified TLS service.

The reused BTL1 CA helper issues a fresh lab certificate per service start.
Only the public root certificate crosses the DMZ container boundary.
"""
import http.server
import ipaddress
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
if __package__:
    from .legacy.ca_manager import PrivatePKIManager
else:
    from legacy.ca_manager import PrivatePKIManager

MAX_BODY = 4096


class Handler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 closes connections and avoids persistent request-body ambiguity.
    server_version = 'BTL2-Lab'
    sys_version = ''

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, fmt, *args):
        # Do not log request targets, arbitrary marker payloads or credentials.
        return

    def reply(self, status=200):
        data = json.dumps({'status': 'ok', 'service': self.server.role}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply()

    def do_POST(self):
        if self.headers.get('Transfer-Encoding') is not None:
            self.send_error(400, 'Transfer-Encoding unsupported'); return
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal() or len(lengths[0]) > 10:
            self.send_error(400, 'Invalid Content-Length'); return
        size = int(lengths[0])
        if size > MAX_BODY:
            self.send_error(413); return
        if len(self.rfile.read(size)) != size:
            self.send_error(400, 'Incomplete body'); return
        self.reply()  # Never reflect, execute or store incoming content.


class LabServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, role, context=None):
        self.role = role
        self.context = context
        super().__init__(address, Handler)

    def handle_error(self, request, client_address):
        # Expected TLS rejection / disconnect is not an application traceback.
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)

    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(5)
        if self.context is not None:
            try:
                # Handshake occurs in worker, not in the accept loop.
                conn = self.context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
            except BaseException:
                conn.close()
                raise
        return conn, address


def issue_tls(ip, directory):
    ip = str(ipaddress.IPv4Address(ip))
    path = Path(directory)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Temporary private directory, not a volume and not committed to Git.
    with tempfile.TemporaryDirectory(dir=path) as private:
        manager = PrivatePKIManager(private)
        ca_key, ca_cert = manager.create_root_ca()
        manager.issue_web_server_certificate(ca_key, ca_cert, domain='dmz-web', ip=ip)
        for f in (manager.root_ca_key_path, manager.server_key_path):
            os.chmod(f, 0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(manager.server_cert_path, manager.server_key_path)
        public = Path(manager.root_ca_cert_path).read_bytes()
    # Private files removed; SSLContext retains only its needed server key in memory.
    return ctx, public


def publish_ca(public, directory):
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.root-', dir=path)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(public)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path / 'root_ca.crt')
    finally:
        Path(name).unlink(missing_ok=True)


def main():
    role = os.environ['ROLE']
    if role not in ('dmz', 'internal'):
        raise ValueError('invalid HTTP service role')
    os.umask(0o077)
    http = LabServer(('0.0.0.0', 8080), role)
    tls = None
    thread = None
    try:
        if role == 'dmz':
            ctx, public = issue_tls(os.environ['SERVICE_IP'], '/tmp')
            tls = LabServer(('0.0.0.0', 8443), role, ctx)
            publish_ca(public, '/public-ca')
            thread = threading.Thread(target=tls.serve_forever, daemon=True)
            thread.start()
        print(f'{role} service ready: HTTP 8080' + (' / TLS 8443' if tls else ''), flush=True)
        http.serve_forever()
    finally:
        http.server_close()
        if tls:
            if thread and thread.is_alive():
                tls.shutdown()
                thread.join(timeout=5)
            tls.server_close()


if __name__ == '__main__':
    main()
