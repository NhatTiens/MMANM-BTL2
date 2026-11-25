import importlib.util
from pathlib import Path
import tempfile
import unittest
import json

ROOT = Path(__file__).resolve().parents[2]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'srcs/member1_firewall'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

policy, counters = load('policy'), load('counters')
ENV = dict(DMZ_NET='10.44.1.0/24', DMZ_GW='10.44.1.254', DMZ_WEB='10.44.1.10', VPN_ENABLED='1', IPS_MODE='ids')
IFACE = dict(ext='eth2', dmz='eth0', internal='eth1')

def addresses():
    return [{'ifname': n, 'addr_info': [{'family': 'inet', 'local': ip, 'prefixlen': 24}]}
            for n, ip in [('eth0', ENV['DMZ_GW']), ('eth1', policy.INT_GW), ('eth2', policy.EXT_GW)]]

class FirewallTests(unittest.TestCase):
    def render(self, **kwargs):
        return policy.render(policy.configuration(dict(ENV, **kwargs)), IFACE)

    def test_config_boundaries(self):
        for n in (0, 199):
            p = f'10.{n}.1.'
            self.assertEqual(policy.configuration(dict(ENV, DMZ_NET=p+'0/24', DMZ_GW=p+'254', DMZ_WEB=p+'10'))['net'], p+'0/24')

    def test_bad_config(self):
        for change in [dict(DMZ_NET='10.200.1.0/24'), dict(DMZ_NET='10.44.1.1/24'), dict(DMZ_GW='10.44.1.1'), dict(DMZ_WEB='10.44.1.20'), dict(VPN_ENABLED='yes'), dict(IPS_MODE='bypass')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy.configuration(dict(ENV, **change))

    def test_interface_discovery_independent_of_order(self):
        self.assertEqual(policy.interfaces(addresses(), policy.configuration(ENV)), IFACE)

    def test_missing_or_duplicate_interface(self):
        for data in (addresses()[:-1], addresses()+addresses()[:1]):
            with self.assertRaises(ValueError):
                policy.interfaces(data, policy.configuration(ENV))

    def test_default_deny(self):
        text = self.render()
        self.assertIn(':INPUT DROP', text)
        self.assertIn(':FORWARD DROP', text)
        self.assertIn('FW_FWD_DEFAULT -j DROP', text)
        self.assertIn('FW_IN_DEFAULT -j DROP', text)
        self.assertTrue(text.endswith('COMMIT\n'))

    def test_zone_validation_before_state(self):
        text = self.render()
        self.assertLess(text.index('FW_FORWARD_CHECK_ZONE'), text.index('FW_FWD_STATE'))
        self.assertLess(text.index('FW_FORWARD_INVALID'), text.index('FW_FWD_STATE'))
        for iface, net in [('eth2', policy.EXT_NET), ('eth0', ENV['DMZ_NET']), ('eth1', policy.INT_NET), ('wg0','10.77.0.2/32')]:
            self.assertIn(f'-A LAB_INGRESS -i {iface} -s {net}', text)
        self.assertIn('FW_DROP_SPOOF_OR_UNKNOWN -j DROP', text)

    def test_allowlist_new_connections(self):
        rules = [l for l in self.render().splitlines() if l.startswith('-A FORWARD') and '--ctstate NEW' in l]
        self.assertEqual(len(rules), 5)
        self.assertTrue(all('--syn' in l and '-j INSPECT' in l for l in rules))
        self.assertTrue(all(' -o eth0 ' in l for l in rules if 'DMZ_WEB' in l))
        self.assertTrue(all(' -i wg0 ' in l for l in rules if ' -o eth1 ' in l))
        self.assertTrue(any('-d 10.44.1.10/32 -p tcp -m multiport --dports 8080,8443' in l for l in rules))

    def test_vpn_disabled(self):
        text = self.render(VPN_ENABLED='0')
        self.assertNotIn('wg0', text)
        self.assertNotIn('51820', text)
        self.assertNotIn('FW_VPN_', text)

    def test_vpn_narrow_handshake(self):
        self.assertIn('-i eth2 -s 172.28.50.20/32 -d 172.28.50.254/32 -p udp --dport 51820', self.render())

    def test_ips_fail_closed(self):
        self.assertNotIn('NFQUEUE', self.render())
        text = self.render(IPS_MODE='ips')
        self.assertIn('NFQUEUE --queue-num 0', text)
        self.assertNotIn('--queue-bypass', text)
        self.assertLess(text.index('FW_IPS_QUEUE'), text.index('FW_INSPECT_ACCEPT'))
        self.assertIn('FW_FWD_STATE -j INSPECT', text)

    def test_counter_parser_contract(self):
        raw = '*filter\n:INPUT DROP [0:0]\n[7:210] -A FORWARD -m comment --comment FW_FWD_DEFAULT -j DROP\n[2:90] -A LAB_INGRESS -j RETURN\nCOMMIT\n'
        rules = counters.parse(raw)
        self.assertEqual(rules[0], dict(rule='-A FORWARD -m comment --comment FW_FWD_DEFAULT -j DROP', packets=7, bytes=210))
        self.assertEqual(len(rules), 2)
        with self.assertRaises(ValueError): counters.parse('*filter\nCOMMIT\n')

    def test_snapshot_and_delta(self):
        old = [dict(rule='r', packets=2, bytes=100)]
        new = [dict(rule='r', packets=3, bytes=170)]
        self.assertEqual(counters.deltas(old,new), [dict(rule='r',packets_delta=1,bytes_delta=70)])
        self.assertEqual(counters.deltas(new,old), [])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            counters.atomic_snapshot(path, dict(timestamp=10,rules=new))
            self.assertEqual(json.loads((path/'counters.json').read_text())['rules'],new)
            self.assertFalse((path/'counters.tmp').exists())
            for t in (10,11): counters.append_interval(path,t,counters.deltas(old,new),limit=150)
            self.assertTrue((path/'counter_intervals.previous.jsonl').exists())
            self.assertEqual(json.loads((path/'counter_intervals.jsonl').read_text())['timestamp'],11)
