"""Bounded, fixed-target integration smoke. No external target parameters."""
import argparse, subprocess, json, time, urllib.request
from pathlib import Path
from configure import values, ROOT

def run(service,*args):
    return subprocess.run(['docker','compose','exec','-T',service,*args],cwd=ROOT,capture_output=True,text=True,timeout=20)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--vpn',action='store_true'); opt=ap.parse_args()
    env=dict(line.split('=',1) for line in (ROOT/'.env').read_text().splitlines() if '=' in line); expected,_=values(env['LEADER_MSSV']); assert all(env[k]==v for k,v in expected.items()); dmz=expected['DMZ_WEB']; mode=env['IPS_MODE']; assert mode in ('ids','ips')
    fails=0
    def case(name,service,args,allow):
        nonlocal fails
        r=run(service,*args); ok=(r.returncode==0 and '"status": "ok"' in r.stdout) if allow else r.returncode in (7,28,52,56)
        # Not treating arbitrary compose/configuration errors as expected block.
        print(('PASS' if ok else 'FAIL'),name,'exit=',r.returncode, (r.stderr.strip()[:200] if not ok else '')); fails+=not ok
    def curl(url,*extra): return ['curl','-fsS','--connect-timeout','3','--max-time','5',*extra,url]
    web='http://'+dmz+':8080/'
    case('FW-01 external -> DMZ','external-client',curl(web),True)
    case('FW-02 external -> internal','external-client',curl('http://172.28.60.10:8080/'),False)
    case('FW-03 DMZ -> internal','dmz-web',curl('http://172.28.60.10:8080/'),False)
    case('TLS-01 verified CA','external-client',curl('https://'+dmz+':8443/','--cacert','/public-ca/root_ca.crt'),True)
    if opt.vpn: case('VPN-01 internal via tunnel','vpn-client',curl('http://172.28.60.10:8080/'),True)
    baseline=set()
    def events():
        r=run('suricata','tail','-n','1000','/logs/eve.json'); out=[]
        if r.returncode!=0:return out
        for line in r.stdout.splitlines():
            try:
                a=json.loads(line)
                if a.get('event_type')=='alert': out.append(a)
            except ValueError: pass
        return out
    def identity(e): return (e.get('timestamp'),e.get('flow_id'),e.get('alert',{}).get('signature_id'))
    baseline={identity(e) for e in events()}
    for label,marker in [('MSSV',env['LEADER_MSSV']),('SQLi marker','LAB_SQLI'),('XSS marker','LAB_XSS'),('C2 marker','LAB_C2')]:
        case('HTTP '+label,'external-client',curl(web,'--data-binary',marker),True)
    case('IPS-01 block marker','external-client',curl(web,'--data-binary','LAB_BLOCK'),mode=='ids')
    seen=set()
    for _ in range(10):
        seen={e.get('alert',{}).get('signature_id') for e in events() if identity(e) not in baseline}
        if {1000001,1000002,1000003,1000004,1000007}<=seen: break
        time.sleep(1)
    ok={1000001,1000002,1000003,1000004,1000007}<=seen; print(('PASS' if ok else 'FAIL'),'new marker SIDs',sorted(x for x in seen if isinstance(x,int))); fails+=not ok
    case('FW-04 clean request after marker','external-client',curl(web),True)
    try:
        with urllib.request.urlopen('http://127.0.0.1:8502/api/snapshot',timeout=4) as r: snap=json.load(r)
        ok=snap['status']=={'ids':'available','firewall':'available'}
    except (OSError,ValueError,KeyError):ok=False
    print(('PASS' if ok else 'FAIL'),'dashboard data sources'); fails+=not ok
    print('Smoke failures:',fails); return int(bool(fails))
if __name__=='__main__': raise SystemExit(main())

