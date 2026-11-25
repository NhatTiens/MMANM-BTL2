import json
from pathlib import Path
import re
import struct
import tempfile
import unittest
from .pcap_cases import checksum,packet,cases,generate
from srcs.member3_ids.eve_tools import alerts,read,summarize
from srcs.member3_ids.sensor_config import configure
from scripts.configure import values
ROOT=Path(__file__).resolve().parents[2]
RULES=(ROOT/'srcs/member3_ids/local.rules.in').read_text()


class TestIDS(unittest.TestCase):
    def test_unique_sids(self):
        sids=re.findall(r'\bsid:(\d+);',RULES)
        self.assertEqual(len(sids),len(set(sids))); self.assertEqual(len(sids),13)
    def test_shared_sids(self):
        self.assertTrue(all(f'sid:{sid};' in RULES for sid in range(1000001,1000008)))
    def test_mssv_hex(self):
        _,hex_mssv=values('0012345'); text=RULES.replace('@MSSV_HEX@',hex_mssv)
        self.assertIn('content:"|30 30 31 32 33 34 35|"',text); self.assertNotIn('@MSSV_HEX@',text)
    def test_block_only_marker(self):
        drops=[line for line in RULES.splitlines() if line.startswith('drop ')]; self.assertEqual(len(drops),1); self.assertIn('sid:1000007;',drops[0])
    def test_config_modes(self):
        self.assertEqual(configure({},'ids')['stream']['inline'],'no'); self.assertEqual(configure({},'ips')['stream']['inline'],'yes'); self.assertEqual(configure({},'offline')['stream']['inline'],'no')
        with self.assertRaises(ValueError): configure({},'bad')
    def test_config_privacy(self):
        d=configure({},'ips'); a=d['outputs'][0]['eve-log']['types'][0]['alert']; self.assertFalse(a['payload']); self.assertFalse(a['packet']); self.assertFalse(a['metadata']); self.assertFalse(d['nfq']['fail-open'])
    def test_checksum(self):
        p=packet('192.0.2.20','198.51.100.10',40000,8080,100,0,2,b'abc'); ip=p[14:34]; tcp=p[34:]
        self.assertEqual(checksum(ip),0); self.assertEqual(checksum(ip[12:20]+struct.pack('!BBH',0,6,len(tcp))+tcp),0)
    def test_pcap_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            m=generate(tmp,'2213444'); self.assertEqual(len(m),18); self.assertEqual(json.loads((Path(tmp)/'manifest.json').read_text()),m)
            for c in m:
                p=(Path(tmp)/c['pcap']).read_bytes(); self.assertEqual(p[:4],b'\xd4\xc3\xb2\xa1'); pos=24; n=0
                while pos<len(p):
                    _,_,size,orig=struct.unpack_from('<IIII',p,pos); self.assertEqual(size,orig); pos+=16+size; n+=1
                self.assertEqual(pos,len(p)); self.assertEqual(n,c['packets'])
    def test_pcap_reproducible(self):
        self.assertEqual(cases('0012345'),cases('0012345'))
        with self.assertRaises(ValueError): cases('x')
    def test_pcap_all_rules_covered(self):
        all_sids={s for _,labels,_ in cases('2213444') for s in labels}; self.assertEqual(all_sids,{int(x) for x in re.findall(r'\bsid:(\d+);',RULES)})
    def test_eve_tolerant(self):
        rows=['bad','[]','{"event_type":"flow"}','{"event_type":"alert","alert":null}','{"event_type":"alert","alert":{"signature_id":true}}',json.dumps({'event_type':'alert','alert':{'signature_id':1000007,'action':'blocked'},'src_ip':'192.0.2.20'})]
        result=list(alerts(rows)); self.assertEqual(len(result),1); self.assertEqual(result[0]['sid'],1000007); self.assertEqual(result[0]['action'],'blocked')
    def test_eve_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError): read(Path(tmp)/'missing')
    def test_metrics(self):
        r=summarize([{'case':str(i),'expected':a,'seen':b} for i,(a,b) in enumerate([([1],[1]),([1],[]),([],[2]),([],[])])]); self.assertEqual(r['counts'],dict(TP=1,FP=1,TN=1,FN=1)); self.assertEqual(r['precision'],0.5); self.assertEqual(r['recall'],0.5); self.assertEqual(r['exact_pass'],2)
    def test_metrics_wrong_sid(self):
        r=summarize([{'case':'x','expected':[1],'seen':[2]}]); self.assertEqual(r['counts']['TP'],1); self.assertEqual(r['exact_pass'],0); self.assertEqual(r['cases'][0]['missing'],[1]); self.assertEqual(r['cases'][0]['unexpected'],[2]); self.assertIsNone(r['false_positive_rate'])
    def test_empty_metrics(self):
        self.assertIsNone(summarize([])['accuracy'])
