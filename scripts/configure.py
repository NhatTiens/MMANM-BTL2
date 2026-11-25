"""Generate local Compose env + MSSV signature. Does not touch shared template."""
import argparse
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def values(mssv):
    if not (mssv.isascii() and mssv.isdecimal() and 5 <= len(mssv) <= 12):
        raise ValueError('MSSV must contain 5–12 ASCII digits')
    prefix = f'10.{int(mssv)%200}.1'
    return {'LEADER_MSSV':mssv, 'DMZ_NET':prefix+'.0/24', 'DMZ_GW':prefix+'.254', 'DMZ_WEB':prefix+'.10'}, ' '.join(f'{b:02X}' for b in mssv.encode('ascii'))
def configure(mssv, mode='ids', vpn=True):
    env, hex_mssv = values(mssv)
    env.update(IPS_MODE=mode, VPN_ENABLED=str(int(vpn)))
    template=(ROOT/'srcs/member3_ids/local.rules.in').read_text(encoding='utf-8')
    (ROOT/'srcs/member3_ids/generated.rules').write_text(template.replace('@MSSV_HEX@',hex_mssv),encoding='utf-8')
    (ROOT/'.env').write_text('\n'.join(f'{k}={v}' for k,v in env.items())+'\n',encoding='utf-8')
    return env
if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--leader',required=True); ap.add_argument('--mode',choices=['ids','ips'],default='ids'); ap.add_argument('--no-vpn',action='store_true'); args=ap.parse_args()
    try: print(configure(args.leader,args.mode,not args.no_vpn))
    except ValueError as e: ap.error(str(e))
