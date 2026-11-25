"""Exercise real POSIX startup scripts with fake wg/ip binaries and temporary keys.
No network changes or root required. This is NOT a WireGuard kernel test.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'srcs/member2_vpn/wireguard'


@unittest.skipUnless(os.name == 'posix' and shutil.which('sh'), 'POSIX shell required')
class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keys = self.root / 'keys'
        self.scripts = self.root / 'scripts'
        self.scripts.mkdir(); self.keys.mkdir()
        for role in ('gateway','client'):
            (self.keys / role).mkdir()
        # Seed synthetic key pairs directly for startup tests. The initializer
        # test removes them and exercises actual shell generation separately.
        for role, byte in (('gateway', b'g'), ('client', b'c')):
            raw = byte * 32
            (self.keys/role/'private').write_bytes(base64.b64encode(raw)+b'\n')
            (self.keys/role/'private').chmod(0o600)
            (self.keys/role/'public').write_bytes(base64.b64encode(hashlib.sha256(raw).digest())+b'\n')
        for role, other in (('gateway','client'),('client','gateway')):
            shutil.copyfile(self.keys/other/'public',self.keys/role/'peer')
        self.bin = self.root/'bin'; self.bin.mkdir()
        self.log = self.root/'commands.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'], MOCK_LOG=str(self.log), DMZ_NET='10.44.1.0/24')
        # Stubs emulate command behavior only. No real wg or ip is called.
        wg = '''import sys, os, hashlib, base64, json
args=sys.argv[1:]
if args==['genkey']: print(base64.b64encode(os.urandom(32)).decode())
elif args==['pubkey']: print(base64.b64encode(hashlib.sha256(base64.b64decode(sys.stdin.read())).digest()).decode())
elif args and args[0]=='set':
    # Redact peer keys even though these are synthetic fixtures.
    if 'peer' in args: args[args.index('peer')+1]='<public>'
    with open(os.environ['MOCK_LOG'],'a') as f: f.write(json.dumps(['wg']+args)+'\\n')
    sys.exit(int(os.environ.get('MOCK_WG_FAIL','0')))
else: sys.exit(2)
'''
        ip = '''import sys, os, json
args=sys.argv[1:]
with open(os.environ['MOCK_LOG'],'a') as f: f.write(json.dumps(['ip']+args)+'\\n')
if args[:3]==['link','show','dev']: sys.exit(int(os.environ.get('MOCK_NO_INTERFACE','1')))
if args[:2]==['route','replace'] and os.environ.get('MOCK_ROUTE_FAIL'): sys.exit(1)
'''
        for name, code in [('wg',wg),('ip',ip),('sleep','pass')]:
            file=self.bin/name; file.write_text('#!'+sys.executable+'\n'+code); file.chmod(0o755)
        (self.bin/'python3').symlink_to(sys.executable)
        for source in SCRIPTS.glob('*.sh'):
            # Test-only replacement redirects fixed container paths to temp dirs.
            (self.scripts/source.name).write_text(source.read_text().replace('/keys',str(self.keys)))

    def run_script(self,name,**extra):
        return subprocess.run(['sh',str(self.scripts/name)],env=dict(self.env,**extra),capture_output=True,text=True,timeout=60)

    def init(self):
        r=self.run_script('init.sh'); self.assertEqual(r.returncode,0,r.stderr)

    def switch_keys(self,role):
        for name in ('private','public','peer'):
            shutil.copyfile(self.keys/role/name,self.keys/name)

    def commands(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_init_idempotent_separate_private_keys(self):
        for role in ('gateway','client'):
            for file in (self.keys/role).iterdir(): file.unlink()
        self.init()
        a=self.keys/'gateway/private'; b=self.keys/'client/private'
        original=(a.read_bytes(),b.read_bytes())
        self.assertNotEqual(*original)
        self.assertEqual(a.stat().st_mode & 0o777,0o600)
        self.assertEqual((self.keys/'gateway/peer').read_bytes(),(self.keys/'client/public').read_bytes())
        self.assertEqual((self.keys/'client/peer').read_bytes(),(self.keys/'gateway/public').read_bytes())
        self.init(); self.assertEqual(original,(a.read_bytes(),b.read_bytes()))

    def test_corrupt_key_not_overwritten(self):
        p=self.keys/'gateway/private'; p.write_bytes(b'broken')
        r=self.run_script('init.sh'); self.assertNotEqual(r.returncode,0); self.assertEqual(p.read_bytes(),b'broken')
        self.assertNotIn('broken',r.stderr)

    def test_gateway_config_contract(self):
        self.switch_keys('gateway')
        r=self.run_script('gateway.sh'); self.assertEqual(r.returncode,0,r.stderr)
        commands=self.commands(); self.assertIn(['ip','address','add','10.77.0.1/24','dev','wg0'],commands)
        cmd=next(x for x in commands if x[:2]==['wg','set']); self.assertIn('51820',cmd); self.assertIn('10.77.0.2/32',cmd)
        self.assertFalse(any(x[:3]==['ip','link','del'] for x in commands))

    def test_split_tunnel_no_default_route(self):
        self.switch_keys('client')
        r=self.run_script('client.sh'); self.assertEqual(r.returncode,0,r.stderr)
        commands=self.commands(); routes=[x for x in commands if x[:3]==['ip','route','replace']]
        self.assertEqual(routes,[['ip','route','replace','172.28.60.0/24','dev','wg0'],['ip','route','replace','10.44.1.0/24','dev','wg0']])
        cmd=next(x for x in commands if x[:2]==['wg','set']); self.assertIn('172.28.50.254:51820',cmd); self.assertIn('10.77.0.1/32,172.28.60.0/24,10.44.1.0/24',cmd)

    def test_invalid_dmz_fails_before_network_changes(self):
        self.switch_keys('client')
        for dmz in ('0.0.0.0/0','10.200.1.0/24','10.44.1.2/24','10.44.1.0/24;bad'):
            self.assertNotEqual(self.run_script('client.sh',DMZ_NET=dmz).returncode,0)
        self.assertEqual(self.commands(),[])

    def test_wrong_public_key_fails_before_network_changes(self):
        self.switch_keys('gateway'); (self.keys/'public').write_bytes((self.keys/'client/public').read_bytes())
        self.assertNotEqual(self.run_script('gateway.sh').returncode,0); self.assertEqual(self.commands(),[])

    def test_existing_interface_preserved(self):
        self.switch_keys('gateway')
        self.assertNotEqual(self.run_script('gateway.sh',MOCK_NO_INTERFACE='0').returncode,0)
        self.assertEqual(self.commands(),[['ip','link','show','dev','wg0']])

    def test_partial_setup_rolled_back(self):
        self.switch_keys('client')
        self.assertNotEqual(self.run_script('client.sh',MOCK_ROUTE_FAIL='1').returncode,0)
        self.assertEqual(self.commands()[-1],['ip','link','del','dev','wg0'])

    def test_failed_wg_set_rolls_back(self):
        self.switch_keys('gateway')
        self.assertNotEqual(self.run_script('gateway.sh',MOCK_WG_FAIL='1').returncode,0)
        self.assertEqual(self.commands()[-1],['ip','link','del','dev','wg0'])


if __name__=='__main__': unittest.main()
