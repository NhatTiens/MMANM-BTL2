"""Bounded live acceptance; benign markers only, fixed isolated lab targets.
No scanning, traffic flood, exploit execution, or external target argument.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from srcs.member3_ids.eve_tools import alerts
from scripts.configure import values
BASE=['docker','compose','-p','mmanm-tv3-lab','--env-file',str(ROOT/'.env'),'-f',str(ROOT/'compose.yaml')]


def command(*args):
    return subprocess.run(BASE+list(args),cwd=ROOT,text=True,capture_output=True,timeout=30)


def output(*args):
    r=command(*args)
    if r.returncode: raise RuntimeError(f'Compose command failed: {args[0:3]} ({r.returncode})')
    return r.stdout


def events():
    return list(alerts(output('exec','-T','suricata','tail','-n','2000','/logs/eve.json').splitlines()))


def key(e): return (e['time'],e['flow'],e['sid'],e['src'],e['dst'],e['action'])


def curl(url,marker=None):
    args=['exec','-T','external-client','curl','--noproxy','*','-fsS','--connect-timeout','2','--max-time','5']
    if marker is not None: args+=['--data-binary',marker]
    return command(*args,url)


def allowed(r):
    try: return r.returncode==0 and json.loads(r.stdout)=={'status':'ok','service':'dmz'}
    except ValueError: return False


def blocked(r):
    # Docker/Compose errors are not treated as blocks.
    return r.returncode in (7,28,52,56) and 'curl:' in r.stderr


def poll(before,sid,action,dmz):
    for _ in range(12):
        if any(e['sid']==sid and e['action']==action and e['src']=='172.28.50.10' and e['dst']==dmz and key(e) not in before for e in events()): return True
        time.sleep(0.5)
    return False


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--fail-closed',action='store_true'); a=ap.parse_args()
    env=dict(line.split('=',1) for line in (ROOT/'.env').read_text().splitlines() if '=' in line)
    expected,_=values(env['LEADER_MSSV'])
    if any(env.get(k)!=v for k,v in expected.items()) or env.get('VPN_ENABLED')!='0' or env.get('IPS_MODE') not in ('ids','ips'):
        raise SystemExit('Run configure.py with correct MSSV, --no-vpn and mode ids/ips')
    mode=env['IPS_MODE']; dmz=expected['DMZ_WEB']; url=f'http://{dmz}:8080/'
    if a.fail_closed and mode!='ips': raise SystemExit('--fail-closed needs IPS mode')
    # Verify runtime mode and isolation rather than assuming .env equals running container.
    for s in ('gateway','suricata'):
        if output('exec','-T',s,'printenv','IPS_MODE').strip()!=mode: raise RuntimeError('Recreate containers for current mode')
    fw=output('exec','-T','gateway','iptables-save','-t','filter')
    queue=[line for line in fw.splitlines() if '-j NFQUEUE' in line]
    correct_queue=(len(queue)==1 and '--queue-num 0' in queue[0] and '--queue-bypass' not in queue[0]) if mode=='ips' else not queue
    results=[]
    def check(name,ok):
        results.append(bool(ok)); print('PASS' if ok else 'FAIL',name,flush=True)
    check('runtime queue policy',correct_queue)
    check('normal request baseline',allowed(curl(url)))
    for marker,sid in [(env['LEADER_MSSV'],1000001),('LAB_SQLI',1000002),('LAB_XSS',1000003),('LAB_C2',1000004),('LAB_BLOCK',1000007)]:
        before={key(e) for e in events()}; r=curl(url,marker)
        deny=mode=='ips' and sid==1000007
        check(f'{sid} HTTP behavior',blocked(r) if deny else allowed(r))
        check(f'{sid} fresh EVE action',poll(before,sid,'blocked' if deny else 'allowed',dmz))
    check('normal request after marker',allowed(curl(url)))
    if a.fail_closed:
        output('stop','suricata')
        try: check('fail closed without sensor',blocked(curl(url)))
        finally: output('up','-d','--wait','--wait-timeout','60','suricata')
        check('recovery after sensor restart',allowed(curl(url)))
    print(f'Acceptance: {sum(results)}/{len(results)} PASS'); return int(not all(results))


if __name__=='__main__': raise SystemExit(main())
