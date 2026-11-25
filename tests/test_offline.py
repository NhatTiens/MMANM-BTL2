import unittest, sys, json, tempfile, importlib.util, socket, threading, ssl
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
cfg=load('cfg','scripts/configure.py'); dash=load('dash','srcs/member4_dashboard/app.py')
ca=load('ca','srcs/member2_vpn/legacy/ca_manager.py'); proto=load('proto','srcs/member2_vpn/legacy/protocol.py')
class Offline(unittest.TestCase):
    def test_subnet(self):
        env,h=cfg.values('2012345'); self.assertEqual(env['DMZ_NET'],'10.145.1.0/24'); self.assertEqual(h,'32 30 31 32 33 34 35')
    def test_first_example(self): self.assertEqual(cfg.values('2213444')[0]['DMZ_NET'],'10.44.1.0/24')
    def test_invalid(self):
        for x in ['abc','１２３４５','123','12345\nINJECT=x']:
            with self.assertRaises(ValueError): cfg.values(x)
    def test_rule_template(self):
        text=(ROOT/'srcs/member3_ids/local.rules.in').read_text(); self.assertEqual(text.count('@MSSV_HEX@'),1); self.assertIn('sid:1000001;',text); self.assertIn('drop tcp',text)
    def test_missing_logs(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'missing'; snap=dash.snapshot(f,f); self.assertEqual(snap['status'],{'ids':'waiting','firewall':'waiting'}); self.assertEqual(snap['alerts'],[])
    def test_log_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            e=Path(d)/'eve'; f=Path(d)/'fw'; a={'event_type':'alert','alert':{'signature':'test','signature_id':1000001},'src_ip':'172.28.50.10'}
            e.write_text('invalid\n'+json.dumps(a)+'\n'+json.dumps({'event_type':'flow'})+'\n'); f.write_text(json.dumps({'rules':[{'packets':3}]})); s=dash.snapshot(e,f); self.assertEqual(s['recent_alert_count'],1); self.assertEqual(s['alerts'][0]['sid'],1000001); self.assertEqual(s['firewall']['rules'][0]['packets'],3)
    def test_corrupt_counters(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'bad'; f.write_text('{'); self.assertEqual(dash.snapshot(f,f)['firewall'],{'rules':[]})
    def test_ca_issues_fresh_cert(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import padding
        from ipaddress import ip_address
        with tempfile.TemporaryDirectory() as d:
            m=ca.PrivatePKIManager(d); k,c=m.create_root_ca(); _,s=m.issue_web_server_certificate(k,c,domain='dmz-web',ip='10.44.1.10'); c.public_key().verify(s.signature,s.tbs_certificate_bytes,padding.PKCS1v15(),s.signature_hash_algorithm); self.assertIn(ip_address('10.44.1.10'),s.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress))
    def test_reused_framing(self):
        a,b=socket.socketpair()
        with a,b: proto.send_frame(a,b'lab'); self.assertEqual(proto.recv_frame(b),b'lab')
if __name__=='__main__': unittest.main()
