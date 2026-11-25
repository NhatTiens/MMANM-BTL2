import unittest
from scripts.team_guard import policy
class TeamGuardTest(unittest.TestCase):
    def test_own_paths(self):
        self.assertEqual(policy('feature/member1-firewall','develop',['srcs/member1_firewall/rules.sh','tests/member1_firewall/test_policy.py','docs/member1_firewall/result.md','pics/member1_firewall/demo.png']),[])
    def test_other_member(self):
        self.assertEqual(policy('feature/member1-firewall','develop',['srcs/member2_vpn/service.py']),['srcs/member2_vpn/service.py'])
    def test_shared_files(self):
        self.assertEqual(policy('feature/member3-ids-ips','develop',['compose.yaml','.github/workflows/ownership.yml']),['compose.yaml','.github/workflows/ownership.yml'])
    def test_release(self):
        self.assertTrue(policy('feature/member4-dashboard','main',[])); self.assertEqual(policy('develop','main',['compose.yaml']),[])
    def test_integration(self):
        self.assertEqual(policy('integration/config','develop',['compose.yaml']),[])
    def test_unknown(self):
        self.assertTrue(policy('random','develop',[])); self.assertTrue(policy('develop','feature/test',[]))
