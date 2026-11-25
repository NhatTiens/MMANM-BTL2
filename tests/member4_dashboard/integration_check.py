"""Verify shared lab smoke plus fresh dashboard evidence. Fixed loopback and lab services only."""
import argparse, json, subprocess, sys, time, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def get(path='/api/snapshot'):
    with urllib.request.urlopen('http://127.0.0.1:8502'+path,timeout=5) as response:
        return json.load(response) if path.endswith('snapshot') else response.read()

def main():
    p=argparse.ArgumentParser(); p.add_argument('--vpn',action='store_true'); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    report={'started_at':time.time(),'cases':{},'status':'FAIL'}
    def check(name,result):
        report['cases'][name]=bool(result); print('PASS' if result else 'FAIL',name,flush=True)
    try:
        env=dict(line.split('=',1) for line in (ROOT/'.env').read_text().splitlines() if '=' in line)
        before=get(); check('live mode',before['mode']=='live')
        if before['mode']!='live': raise RuntimeError('Fixture is not runtime evidence')
        check('both sources before smoke',before['status']=={'ids':'available','firewall':'available'})
        command=[sys.executable,str(ROOT/'scripts/smoke.py')]+(['--vpn'] if a.vpn else [])
        r=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=180)
        (a.output/'smoke.txt').write_text(r.stdout+'\n'+r.stderr,encoding='utf-8'); print(r.stdout); check('shared smoke',r.returncode==0)
        old={(x['time'],x['sid'],x['src'],x['dst'],x['action']) for x in before['alerts']}
        def fresh(s): return [x for x in s['alerts'] if (x['time'],x['sid'],x['src'],x['dst'],x['action']) not in old and x['src']=='172.28.50.10' and x['dst']==env['DMZ_WEB']]
        expected={1000001,1000002,1000003,1000004,1000007}
        for _ in range(12):
            after=get(); new=fresh(after)
            if expected<={x['sid'] for x in new} and (after['firewall'].get('timestamp') or 0)>(before['firewall'].get('timestamp') or 0): break
            time.sleep(1)
        check('fresh SIDs in dashboard',expected<={x['sid'] for x in new})
        check('expected IPS/IDS action',any(x['sid']==1000007 and x['action']==('blocked' if env['IPS_MODE']=='ips' else 'allowed') for x in new))
        old_rules={x.get('rule'):x.get('packets',0) for x in before['firewall']['rules']}
        check('firewall deny counter increased',any('FW_FWD_DEFAULT' in (x.get('rule') or '') and int(x.get('packets',0))>int(old_rules.get(x.get('rule'),0)) for x in after['firewall']['rules']))
        check('fresh firewall snapshot',after['status']['firewall']=='available' and after['sources']['firewall'].get('stale') is False)
        check('CSV endpoint',get('/api/alerts.csv').startswith(b'\xef\xbb\xbfdata_mode,'))
        (a.output/'snapshot.json').write_text(json.dumps(after,ensure_ascii=False,indent=2),encoding='utf-8')
        report['status']='PASS' if all(report['cases'].values()) else 'FAIL'
    except Exception as exc:
        report['error']=str(exc); print('FAIL',exc,file=sys.stderr)
    finally:
        report['finished_at']=time.time(); (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return int(report['status']!='PASS')
if __name__=='__main__': raise SystemExit(main())

