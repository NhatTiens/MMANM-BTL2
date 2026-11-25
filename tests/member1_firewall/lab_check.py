"""Run against TV1's isolated lab only. Checks fixed routes, live services, rule counters."""
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import ipaddress

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ['docker','compose','--env-file',str(ROOT/'.env'),'-f',str(ROOT/'srcs/member1_firewall/compose.lab.yaml')]

def execute(service,*args):
    return subprocess.run(COMPOSE+['exec','-T',service,*args],cwd=ROOT,text=True,capture_output=True,timeout=20)

def checked(service,*args):
    r = execute(service,*args)
    if r.returncode: raise RuntimeError(f'{service}: {r.stderr.strip()}')
    return r.stdout

def counter(label):
    raw = checked('gateway','iptables-save','-c','-t','filter')
    matches = [int(m.group(1)) for line in raw.splitlines() if re.search(r'--comment "?'+re.escape(label)+r'"?(?: |$)',line) and (m:=re.match(r'\[(\d+):\d+\]',line))]
    if len(matches)!=1: raise RuntimeError('Missing or duplicate counter '+label)
    return matches[0]

def curl(service,ip,port):
    return execute(service,'curl','--noproxy','*','-fsS','--connect-timeout','2','--max-time','4',f'http://{ip}:{port}/')

def healthy(r):
    return r.returncode==0 and '"status": "ok"' in r.stdout

def main():
    env=dict(line.split('=',1) for line in (ROOT/'.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
    dmz=str(ipaddress.IPv4Address(env['DMZ_WEB'])); gw=str(ipaddress.IPv4Address(env['DMZ_GW']))
    # Confirm active listeners, including deliberately blocked ports.
    for service in ('dmz-web','internal-app','external-client'):
        for port in (8080,8443,9090):
            for attempt in range(15):
                if healthy(curl(service,'127.0.0.1',port)): break
                time.sleep(1)
            else: raise RuntimeError(f'Preflight: {service}:{port} not listening')
    for service,target,router in [('external-client',dmz,'172.28.50.254'),('external-client','172.28.60.10','172.28.50.254'),('dmz-web','172.28.60.10',gw),('internal-app',dmz,'172.28.60.254')]:
        route=checked(service,'ip','-4','route','get',target)
        if f'via {router} ' not in route: raise RuntimeError(f'Wrong route: {service} {route}')
    print('PASS preflight: listeners and gateway routes',flush=True)
    cases=[('FW01','external-client',dmz,8080,True,'FW_EXT_DMZ_WEB'),('FW02','external-client',dmz,8443,True,'FW_EXT_DMZ_WEB'),('FW03','external-client',dmz,9090,False,'FW_FWD_DEFAULT'),('FW04','external-client','172.28.60.10',8080,False,'FW_FWD_DEFAULT'),('FW05','dmz-web','172.28.60.10',8080,False,'FW_FWD_DEFAULT'),('FW06','internal-app',dmz,8080,True,'FW_INT_DMZ_WEB'),('FW07','internal-app','172.28.50.10',8080,False,'FW_FWD_DEFAULT')]
    failed=0
    for name,service,ip,port,allow,label in cases:
        before=counter(label); state=counter('FW_FWD_STATE')
        result=curl(service,ip,port)
        delta=counter(label)-before
        ok=(healthy(result) and counter('FW_FWD_STATE')>state if allow else result.returncode==28) and delta>0
        print(f'{"PASS" if ok else "FAIL"} {name}: {service} -> {ip}:{port}; curl={result.returncode}; {label} +{delta}',flush=True)
        failed+=not ok
    snap=json.loads(checked('gateway','cat','/logs/counters.json'))
    ok=bool(snap['rules']) and 0<=time.time()-snap['timestamp']<15
    print('PASS snapshot fresh' if ok else 'FAIL snapshot stale')
    return int(bool(failed or not ok))

if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired) as e:
        print('FAIL lab:',e,file=sys.stderr); raise SystemExit(1)
