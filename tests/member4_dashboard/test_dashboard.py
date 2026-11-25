import csv, io, json, os, tempfile, threading, unittest, urllib.request, urllib.error
from pathlib import Path
from unittest.mock import patch
from srcs.member4_dashboard import app

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.eve=Path(self.tmp.name)/'eve.json'; self.fw=Path(self.tmp.name)/'counters.json'
    def event(self, **kwargs):
        return {'event_type':'alert','timestamp':'2026-01-01T00:00:00Z','src_ip':'192.0.2.1','dest_ip':'192.0.2.2','alert':{'signature':'synthetic','signature_id':1000001,'action':'allowed','severity':2,**kwargs}}
    def write(self, *records):
        self.eve.write_text(''.join(json.dumps(x)+'\n' for x in records))
    def snap(self, **kwargs): return app.snapshot(self.eve,self.fw,**kwargs)
    def test_no_files(self): self.assertEqual(self.snap()['status'],{'ids':'waiting','firewall':'waiting'})
    def test_malformed_and_partial(self):
        self.write(self.event(),[],{'event_type':'flow'}, {'event_type':'alert','alert':[]});
        with self.eve.open('a') as f: f.write('{"event_type":')
        s=self.snap(); self.assertEqual(s['recent_alert_count'],1); self.assertEqual(s['window']['malformed_lines'],2)
    def test_bounded_tail(self):
        self.eve.write_bytes(b'x'*(app.LIMIT+100)+b'\n'+json.dumps(self.event()).encode()+b'\n'); s=self.snap(); self.assertTrue(s['window']['truncated']); self.assertEqual(s['recent_alert_count'],1)
    def test_exact_boundary(self):
        self.eve.write_bytes(b'xx\n'+b'abc\n'); self.assertEqual(app.tail(self.eve,4)[0],[b'abc'])
    def test_aggregation(self):
        self.write(self.event(),self.event(action='blocked',severity=1)); s=self.snap(); self.assertEqual(s['by_action'],{'allowed':1,'blocked':1}); self.assertEqual(s['by_severity'],{'2':1,'1':1}); self.assertEqual(s['timeline'][0]['count'],2); self.assertEqual(s['by_source'],{'192.0.2.1':2})
    def test_alert_limit(self):
        self.write(*[self.event(signature_id=i) for i in range(600)]); s=self.snap(); self.assertEqual(s['recent_alert_count'],600); self.assertEqual(len(s['alerts']),500); self.assertEqual(s['alerts'][0]['sid'],599)
    def test_counter_stale(self):
        self.fw.write_text(json.dumps({'timestamp':100,'rules':[{'rule':'A','packets':1,'bytes':2}]})); self.assertTrue(self.snap(now=120)['sources']['firewall']['stale']); self.assertFalse(self.snap(now=105)['sources']['firewall']['stale'])
    def test_counter_corrupt(self):
        self.fw.write_text('{'); self.assertEqual(self.snap()['status']['firewall'],'error')
    def test_counter_negative(self):
        self.fw.write_text('{"rules":[{"packets":-1}]}'); self.assertEqual(self.snap()['firewall'],{'rules':[]})
    def test_counter_oversize(self):
        self.fw.write_bytes(b' '*(app.LIMIT+1)); self.assertEqual(self.snap()['status']['firewall'],'error')
    def test_nonfinite_time(self):
        self.fw.write_text('{"timestamp":NaN,"rules":[]}'); json.dumps(self.snap(),allow_nan=False)
    def test_csv_formula(self):
        self.write(self.event(signature='  =1+1')); s=self.snap(mode='fixture'); rows=list(csv.DictReader(io.StringIO(app.export_csv(s).decode('utf-8-sig')))); self.assertEqual(rows[0]['data_mode'],'fixture'); self.assertTrue(rows[0]['signature'].startswith("'"))
    def test_invalid_types(self):
        self.write(self.event(signature={'x':1},severity=True)); s=self.snap(); self.assertIsNone(s['alerts'][0]['signature']); self.assertIsNone(s['alerts'][0]['severity'])
    def test_rotation(self):
        self.write(self.event()); self.assertEqual(self.snap()['recent_alert_count'],1); self.eve.rename(self.eve.with_suffix('.old')); self.write(); self.assertEqual(self.snap()['recent_alert_count'],0)
    def test_http(self):
        server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler); th=threading.Thread(target=server.serve_forever,daemon=True); th.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            for path in ('/','/style.css','/dashboard.js','/api/snapshot','/api/alerts.csv','/healthz'):
                with urllib.request.urlopen(base+path,timeout=3) as r: self.assertEqual(r.status,200); self.assertEqual(r.headers['X-Content-Type-Options'],'nosniff'); self.assertTrue(r.read())
            with self.assertRaises(urllib.error.HTTPError) as err: urllib.request.urlopen(base+'/not-found')
            self.assertEqual(err.exception.code,404)
        finally: server.shutdown(); server.server_close(); th.join(2)
