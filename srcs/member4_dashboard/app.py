"""Read-only, bounded SOC dashboard for the isolated BTL2 lab."""
import csv
import io
import json
import math
import os
import time
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

IDS = Path(os.environ.get('IDS_LOG_PATH', '/data/ids/eve.json'))
FW = Path(os.environ.get('FW_LOG_PATH', '/data/firewall/counters.json'))
LIMIT = 512 * 1024
MAX_ALERTS = 500
ASSETS = {'/': ('index.html', 'text/html; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'), '/dashboard.js': ('dashboard.js', 'text/javascript; charset=utf-8')}


def scalar(value):
    if isinstance(value, str):
        return value[:1024]
    if type(value) is int:
        return value if abs(value) <= 2**53-1 else str(value)
    return None


def epoch(value):
    try:
        if type(value) in (int, float):
            return float(value) if math.isfinite(value) else None
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.timestamp() if dt.tzinfo else None
    except (ValueError, TypeError, AttributeError, OverflowError, OSError):
        return None


def metadata(updated, now, *, threshold):
    age = max(0, now-updated) if updated is not None else None
    return {'updated_at': updated, 'age_seconds': round(age, 1) if age is not None else None,
            'stale': age > threshold if age is not None else None}


def tail(path, limit=LIMIT):
    with path.open('rb') as f:
        end = f.seek(0, 2)
        start = max(0, end-limit)
        if start:
            f.seek(start-1)
            boundary = f.read(1) == b'\n'
        else:
            boundary = True
        f.seek(start)
        raw = f.read(end-start)
        mtime = os.fstat(f.fileno()).st_mtime
    lines = raw.split(b'\n')
    if not boundary:
        lines = lines[1:]
    # Writer may still be appending last record; process only complete lines.
    return lines[:-1], start > 0, mtime


def snapshot(ids=IDS, fw=FW, *, now=None, mode=None):
    now = time.time() if now is None else now
    states = {'ids': 'waiting', 'firewall': 'waiting'}
    info = {'ids': {}, 'firewall': {}}
    alerts = []
    malformed = 0
    truncated = False
    try:
        lines, truncated, updated = tail(Path(ids))
        for line in lines:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError('not object')
                if obj.get('event_type') != 'alert':
                    continue
                a = obj.get('alert')
                if not isinstance(a, dict):
                    raise ValueError('not alert')
                severity = a.get('severity')
                alerts.append({'time': scalar(obj.get('timestamp')), 'src': scalar(obj.get('src_ip')),
                    'dst': scalar(obj.get('dest_ip')), 'signature': scalar(a.get('signature')),
                    'sid': scalar(a.get('signature_id')), 'action': scalar(a.get('action')),
                    'severity': severity if type(severity) is int and 1 <= severity <= 4 else None,
                    'category': scalar(a.get('category')), 'proto': scalar(obj.get('proto'))})
            except (ValueError, UnicodeError, RecursionError):
                malformed += 1
        states['ids'] = 'available'
        info['ids'] = metadata(updated, now, threshold=60)
    except FileNotFoundError:
        pass
    except OSError:
        states['ids'] = 'error'
    counters = {'rules': []}
    try:
        with Path(fw).open('rb') as f:
            raw = f.read(LIMIT+1)
        if len(raw) > LIMIT:
            raise ValueError('counter file too large')
        obj = json.loads(raw)
        if not isinstance(obj, dict) or not isinstance(obj.get('rules'), list):
            raise ValueError('invalid counter format')
        rules = []
        for r in obj['rules']:
            if not isinstance(r, dict) or any(type(r.get(k, 0)) is not int or r.get(k, 0) < 0 for k in ('packets','bytes')):
                raise ValueError('invalid counter row')
            rules.append({k: scalar(v) for k, v in r.items() if k in ('rule','packets','bytes')})
        counters = {'rules': rules}
        if 'timestamp' in obj:
            counters['timestamp'] = epoch(obj['timestamp'])
        states['firewall'] = 'available'
        info['firewall'] = metadata(epoch(obj.get('timestamp')), now, threshold=10)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError, RecursionError):
        states['firewall'] = 'error'
    timeline = Counter()
    for a in alerts:
        t = epoch(a['time'])
        if t is not None:
            try:
                timeline[datetime.fromtimestamp(t-t%60, timezone.utc).isoformat()] += 1
            except (OverflowError, OSError, ValueError):
                pass
    counts = Counter(a['action'] or 'unknown' for a in alerts)
    return {'status': states, 'sources': info, 'generated_at': now,
            'mode': mode or os.environ.get('DASHBOARD_MODE', 'live'),
            'window': {'bytes': LIMIT, 'truncated': truncated, 'malformed_lines': malformed, 'returned': min(len(alerts),MAX_ALERTS)},
            'recent_alert_count': len(alerts), 'by_signature': dict(Counter(str(a['signature']) for a in alerts)),
            'by_source': dict(Counter(a['src'] or 'unknown' for a in alerts).most_common(10)),
            'by_action': dict(counts), 'by_severity': dict(Counter(str(a['severity'] or 'unknown') for a in alerts)),
            'timeline': [{'minute': k, 'count': v} for k,v in sorted(timeline.items())[-60:]],
            'alerts': alerts[-MAX_ALERTS:][::-1], 'firewall': counters}


def safe_cell(v):
    # Spreadsheet formula injection prevention, including leading whitespace.
    s = '' if v is None else str(v)
    return "'"+s if s.lstrip().startswith(('=', '+', '-', '@')) or s.startswith(('\t','\r','\n')) else s


def export_csv(snap):
    out = io.StringIO(newline='')
    fields = ('time','src','dst','signature','sid','action','severity','category','proto')
    writer = csv.writer(out)
    writer.writerow(('data_mode',*fields))
    for a in snap['alerts']:
        writer.writerow([safe_cell(snap['mode']),*(safe_cell(a.get(k)) for k in fields)])
    return out.getvalue().encode('utf-8-sig')


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        extra = {}
        if path == '/api/snapshot':
            data = json.dumps(snapshot(), ensure_ascii=False, allow_nan=False).encode(); ctype = 'application/json; charset=utf-8'
        elif path == '/api/alerts.csv':
            data = export_csv(snapshot()); ctype = 'text/csv; charset=utf-8'; extra['Content-Disposition'] = 'attachment; filename="soc-alerts.csv"'
        elif path == '/healthz':
            data = b'{"status":"ok"}'; ctype = 'application/json'
        elif path in ASSETS:
            file, ctype = ASSETS[path]; data = Path(__file__).with_name(file).read_bytes()
        else:
            self.send_error(404); return
        self.send_response(200)
        for k,v in {'Content-Type': ctype,'Content-Length':str(len(data)), 'Cache-Control':'no-store',
                    'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
                    'Content-Security-Policy':"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", **extra}.items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(data)


if __name__ == '__main__':
    ThreadingHTTPServer((os.environ.get('DASHBOARD_BIND','0.0.0.0'),int(os.environ.get('DASHBOARD_PORT','8501'))),Handler).serve_forever()
