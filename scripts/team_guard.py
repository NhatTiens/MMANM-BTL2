"""Check file ownership in a feature PR (or staged local changes). No external dependencies."""
import argparse
import subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OWNERS = {
    'feature/member1-firewall': 'member1_firewall',
    'feature/member2-vpn': 'member2_vpn',
    'feature/member3-ids-ips': 'member3_ids',
    'feature/member4-dashboard': 'member4_dashboard',
}
def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode('utf-8',errors='surrogateescape')
def allowed(branch, paths):
    if branch not in OWNERS:
        return list(paths)
    module = OWNERS[branch]
    prefixes = tuple(f'{folder}/{module}/' for folder in ('srcs','tests','docs','pics'))
    return [path for path in paths if not path.startswith(prefixes)]
def policy(branch,target,paths):
    if target == 'main':
        return [] if branch == 'develop' else ['Only develop may target main']
    if target != 'develop':
        return ['PR must target develop or main']
    if branch.startswith('integration/'):
        return [] # group lead review mandatory; CI cannot verify identity
    if branch not in OWNERS:
        return ['Unknown branch: '+branch]
    return allowed(branch, paths)
def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--base'); parser.add_argument('--head'); parser.add_argument('--branch'); parser.add_argument('--target',default='develop'); parser.add_argument('--staged',action='store_true'); args=parser.parse_args()
    if args.staged:
        branch=args.branch or git('branch','--show-current').strip()
        diff=git('diff','--cached','--no-renames','--name-only','-z')
    else:
        if not all((args.base,args.head,args.branch)):
            parser.error('PR check requires --base --head --branch')
        branch=args.branch
        diff=git('diff','--no-renames','--name-only','-z',args.base+'...'+args.head)
    problems=policy(branch,args.target,[x for x in diff.split('\0') if x])
    if problems:
        print('FAIL: outside assigned scope or invalid PR target:'); print('\n'.join(problems)); return 1
    print('PASS: branch scope and target'); return 0
if __name__=='__main__': raise SystemExit(main())
