import concurrent.futures
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from cryptography.exceptions import InvalidTag
from srcs.member2_vpn import service, chat_demo
from srcs.member2_vpn.legacy import protocol, server
from srcs.member2_vpn.legacy.crypto_core import CryptoCore


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        path = Path(cls.temp.name)
        ctx, cls.public = service.issue_tls('127.0.0.1', path / 'private')
        service.publish_ca(cls.public, path / 'public')
        cls.ca = str(path / 'public' / 'root_ca.crt')
        cls.http = service.LabServer(('127.0.0.1', 0), 'dmz')
        cls.tls = service.LabServer(('127.0.0.1', 0), 'dmz', ctx)
        for obj in (cls.http, cls.tls):
            threading.Thread(target=obj.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for obj in (cls.http, cls.tls):
            obj.shutdown()
            obj.server_close()
        cls.temp.cleanup()

    def request(self, method='GET', body=None, headers=None, context=None, host='127.0.0.1', tls=False):
        conn = http.client.HTTPSConnection(host, self.tls.server_port, context=context, timeout=3) if tls else http.client.HTTPConnection(host, self.http.server_port, timeout=3)
        try:
            conn.request(method, '/', body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_http(self):
        status, raw = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {'status':'ok', 'service':'dmz'})

    def test_marker_not_reflected(self):
        status, raw = self.request('POST', b'LAB_MARKER')
        self.assertEqual(status, 200)
        self.assertNotIn(b'LAB_MARKER', raw)

    def test_body_boundary(self):
        self.assertEqual(self.request('POST', b'x'*4096)[0], 200)
        self.assertEqual(self.request('POST', b'x'*4097)[0], 413)

    def test_invalid_length_and_transfer_encoding(self):
        self.assertEqual(self.request('POST', b'', {'Content-Length':'-1'})[0], 400)
        self.assertEqual(self.request('POST', b'', {'Transfer-Encoding':'chunked'})[0], 400)
        self.assertEqual(self.request('POST', b'', {'Content-Length':'9999999999999999999999'})[0], 400)

    def test_duplicate_length(self):
        with socket.create_connection(('127.0.0.1', self.http.server_port), timeout=3) as sock:
            sock.sendall(b'POST / HTTP/1.0\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n')
            self.assertIn(b'400', sock.recv(1024).split(b'\r\n')[0])

    def test_tls_verified(self):
        context = ssl.create_default_context(cafile=self.ca)
        self.assertEqual(self.request(tls=True, context=context)[0], 200)

    def test_tls_untrusted(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request(tls=True, context=ssl.create_default_context())

    def test_tls_wrong_hostname(self):
        context = ssl.create_default_context(cafile=self.ca)
        with socket.create_connection(('127.0.0.1', self.tls.server_port), timeout=3) as sock:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(sock, server_hostname='wrong.lab')

    def test_tls_dns_san(self):
        ctx = ssl.create_default_context(cafile=self.ca)
        with socket.create_connection(('127.0.0.1', self.tls.server_port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname='dmz-web') as conn:
                self.assertIn(conn.version(), ('TLSv1.2', 'TLSv1.3'))

    def test_private_files_removed(self):
        path = Path(self.temp.name)
        self.assertEqual(list((path / 'private').iterdir()), [])
        self.assertEqual([p.name for p in (path / 'public').iterdir()], ['root_ca.crt'])
        self.assertNotIn(b'PRIVATE KEY', Path(self.ca).read_bytes())

    def test_atomic_ca_replacement(self):
        with tempfile.TemporaryDirectory() as path:
            service.publish_ca(self.public, path)
            _, another = service.issue_tls('127.0.0.1', Path(path)/'private')
            service.publish_ca(another, path)
            self.assertNotEqual(self.public, another)
            self.assertEqual((Path(path)/'root_ca.crt').read_bytes(), another)
            self.assertFalse(list(Path(path).glob('.root-*')))


class ProtocolTests(unittest.TestCase):
    def test_frame_limit(self):
        a, b = socket.socketpair()
        with a,b:
            with self.assertRaises(ValueError):
                protocol.send_frame(a, b'x'*(protocol.MAX_FRAME+1))
            a.sendall((protocol.MAX_FRAME+1).to_bytes(4, 'big'))
            with self.assertRaises(ValueError):
                protocol.recv_frame(b)

    def test_truncated_frame(self):
        a,b = socket.socketpair()
        with a,b:
            a.sendall(b'\0\0\0\x05ab'); a.shutdown(socket.SHUT_WR)
            with self.assertRaises(EOFError):
                protocol.recv_frame(b)

    def test_bad_json_type(self):
        a,b = socket.socketpair()
        with a,b:
            protocol.send_frame(a,b'[]')
            with self.assertRaises(ValueError):
                protocol.recv_json(b)

    def test_aead_tamper_rejected(self):
        key = CryptoCore.generate_aes_key()
        nonce,cipher = CryptoCore.aes_gcm_encrypt(key,b'lab')
        with self.assertRaises(InvalidTag):
            CryptoCore.aes_gcm_decrypt(key,nonce,cipher[:-1]+bytes([cipher[-1]^1]))

    def test_two_real_tcp_chat_sessions(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); listener.listen(4)
            address = listener.getsockname(); stop = threading.Event()
            worker = threading.Thread(target=server.serve,args=(listener,stop,2,5),daemon=True); worker.start()
            def peer():
                with socket.create_connection(address,timeout=5) as conn:
                    return chat_demo.exchange(conn)
            try:
                for _ in range(2):
                    with concurrent.futures.ThreadPoolExecutor(2) as pool:
                        a,b = pool.submit(peer),pool.submit(peer)
                        self.assertEqual({a.result(timeout=8),b.result(timeout=8)}, {'initiator','receiver'})
            finally:
                stop.set(); worker.join(timeout=6)
                self.assertFalse(worker.is_alive())

    def test_relay_forwards_opaque_bytes(self):
        a,b=socket.socketpair(); c,d=socket.socketpair()
        with a,b,c,d:
            t=threading.Thread(target=server.serve_pair,args=(b,c,2),daemon=True); t.start()
            self.assertEqual(protocol.recv_json(a)['role'],'initiator')
            self.assertEqual(protocol.recv_json(d)['role'],'receiver')
            protocol.send_frame(a,b'\xff\x00ciphertext')
            self.assertEqual(protocol.recv_frame(d),b'\xff\x00ciphertext')
            a.shutdown(socket.SHUT_RDWR); t.join(timeout=3)
            self.assertFalse(t.is_alive())


if __name__=='__main__': unittest.main()
