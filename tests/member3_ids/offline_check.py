"""Offline Suricata replay, no network traffic. Docker image must be built first."""
import argparse
import json
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from pcap_cases import generate
from srcs.member3_ids.eve_tools import read,summarize
from scripts.configure import values


def run(args):
    subprocess.run(args,check=True,timeout=90)


def main():
    p=argparse.ArgumentParser(); p.add_argument('--leader',required=True); p.add_argument('--output',type=Path,required=True); p.add_argument('--image',default='mmanm-btl2-tv3:local'); a=p.parse_args()
    _,hex_mssv=values(a.leader)
    root=a.output.resolve(); root.mkdir(parents=True,exist_ok=False)
    template=(ROOT/'srcs/member3_ids/local.rules.in').read_text()
    (root/'local.rules').write_text(template.replace('@MSSV_HEX@',hex_mssv))
    manifest=generate(root,a.leader)
    # Offline engine container has no network; the only writable mount is this fresh directory.
    base=['docker','run','--rm','--network','none','--cap-drop','ALL','--mount',f'type=bind,source={root},target=/work','--entrypoint','sh',a.image,'-ec']
    prefix='python3 /sensor_config.py --mode offline; '
    flags='-c /tmp/btl2-suricata.yaml -S /work/local.rules'
    run(base+[prefix+'suricata -T '+flags+' -l /work'])
    rows=[]
    for c in manifest:
        out=root/c['case']; out.mkdir()
        run(base+[prefix+'exec suricata --runmode single -r "/work/$1" '+flags+' -l "/work/$2"','sh',c['pcap'],c['case']])
        log=out/'eve.json'
        if not log.is_file(): raise RuntimeError('missing engine output '+str(log))
        rows.append({**c,'seen':sorted({e['sid'] for e in read(log)})})
    report=summarize(rows); (root/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    for row in report['cases']: print('PASS' if row['pass'] else 'FAIL',row['case'],row['seen'])
    print(f"Exact: {report['exact_pass']}/{report['total']}",report['counts'])
    return int(report['exact_pass']!=report['total'])


if __name__=='__main__': raise SystemExit(main())
