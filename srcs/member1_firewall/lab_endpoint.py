"""Fixed local lab services; no external target or public listener mapping."""
import http.server
import os
import subprocess
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status": "ok"}\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    subprocess.run(['ip', 'route', 'replace', 'default', 'via', os.environ['ROUTER']], check=True)
    servers = [http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler) for port in (8080, 8443, 9090)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    while True:
        time.sleep(60)


if __name__ == '__main__':
    main()
