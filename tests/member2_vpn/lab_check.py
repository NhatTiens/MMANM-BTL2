"""Acceptance tests for TV2's isolated Compose lab. Fixed lab destinations only."""
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
# The separate project uses the same IPs as shared Compose: stop other lab first.
BASE = ['docker', 'compose', '--env-file', str(ROOT / '.env'), '-f',
        str(ROOT / 'srcs/member2_vpn/compose.lab.yaml')]


def exec_in(service, *args, timeout=15):
    return subprocess.run(BASE + ['exec', '-T', service, *args], cwd=ROOT,
                          text=True, capture_output=True, timeout=timeout)


def output(service, *args):
    result = exec_in(service, *args)
    if result.returncode:
        raise RuntimeError(f'{service}: command failed ({result.returncode})')
    return result.stdout


def counters():
    data = output('gateway', 'iptables-save', '-c', '-t', 'filter')
    return {m.group(2): int(m.group(1)) for line in data.splitlines()
            if (m := re.search(r'^\[(\d+):\d+\].*--comment "?(FW_[A-Z_]+)"?', line))}


def curl(service, url, *options):
    return exec_in(service, 'curl', '--noproxy', '*', '-fsS', '--connect-timeout', '3', '--max-time', '7', *options, url)


def expect_http(result, role):
    if result.returncode:
        return False
    try:
        return json.loads(result.stdout) == {'status': 'ok', 'service': role}
    except ValueError:
        return False


def fresh_handshake(service):
    rows = output(service, 'wg', 'show', 'wg0', 'latest-handshakes').splitlines()
    return len(rows) == 1 and 0 <= time.time() - int(rows[0].split()[1]) <= 180


def traffic(service):
    rows = output(service, 'wg', 'show', 'wg0', 'transfer').splitlines()
    if len(rows) != 1:
        raise ValueError('Expected a single WireGuard peer')
    return tuple(map(int, rows[0].split()[1:]))


def route(service, addr):
    return json.loads(output(service, 'ip', '-j', '-4', 'route', 'get', addr))[0]


def run_chat():
    # First initiator and second receiver; both must exit successfully.
    cmd = ['python', '/lab/chat_demo.py']
    first = subprocess.Popen(BASE + ['exec', '-T', 'vpn-client', *cmd], cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        second = exec_in('internal-app', *cmd, timeout=35)
        first_out, _ = first.communicate(timeout=35)
        return first.returncode == second.returncode == 0 and 'PASS chat' in first_out and 'PASS chat' in second.stdout
    finally:
        if first.poll() is None:
            first.kill()
        first.communicate()


def main():
    sys.path.insert(0, str(ROOT / 'scripts'))
    from configure import values
    env = dict(line.split('=', 1) for line in (ROOT / '.env').read_text().splitlines() if '=' in line)
    derived, _ = values(env['LEADER_MSSV'])
    if any(env.get(k) != v for k, v in derived.items()):
        raise ValueError('Inconsistent .env; run scripts/configure.py')
    dmz = derived['DMZ_WEB']
    web, tls = f'http://{dmz}:8080/', f'https://{dmz}:8443/'
    internal = 'http://172.28.60.10:8080/'
    failures = []

    def case(name, fn):
        try:
            ok = bool(fn())
        except (OSError, ValueError, RuntimeError, KeyError, IndexError, subprocess.TimeoutExpired) as exc:
            print(f'  {type(exc).__name__}: {exc}')
            ok = False
        print(('PASS' if ok else 'FAIL'), name, flush=True)
        if not ok:
            failures.append(name)

    def blocked(service, target, label='FW_FWD_DEFAULT'):
        before = counters().get(label, -1)
        result = curl(service, target)
        after = counters().get(label, -1)
        return before >= 0 and after > before and result.returncode in (7, 28, 52, 56)

    case('VPN01 routes use wg0, endpoint stays external', lambda:
         route('vpn-client', '172.28.60.10').get('dev') == 'wg0' and
         route('vpn-client', dmz).get('dev') == 'wg0' and
         route('vpn-client', '172.28.50.254').get('dev') != 'wg0')
    case('VPN02 external -> DMZ HTTP', lambda: expect_http(curl('external-client', web), 'dmz'))
    case('VPN03 external -> internal denied (counter)', lambda: blocked('external-client', internal))
    case('VPN04 DMZ -> internal denied (counter)', lambda: blocked('dmz-web', internal))
    def encrypted_request():
        before = traffic('vpn-client')
        ok = expect_http(curl('vpn-client', internal), 'internal')
        after = traffic('vpn-client')
        return ok and all(b > a for a, b in zip(before, after)) and fresh_handshake('vpn-client') and fresh_handshake('gateway')
    case('VPN05 VPN -> internal, recent handshake on both ends, transfer increases', encrypted_request)
    case('VPN06 VPN -> DMZ HTTP', lambda: expect_http(curl('vpn-client', web), 'dmz'))
    case('VPN07 VPN -> unauthorized port denied (counter)', lambda: blocked('vpn-client', 'http://172.28.60.10:8081/'))
    case('TLS01 verified CA and IP SAN (external)', lambda: expect_http(curl('external-client', tls, '--cacert', '/public-ca/root_ca.crt'), 'dmz'))
    case('TLS02 verified CA and IP SAN (VPN)', lambda: expect_http(curl('vpn-client', tls, '--cacert', '/public-ca/root_ca.crt'), 'dmz'))
    case('TLS03 no trust -> curl rejects certificate', lambda: curl('external-client', tls).returncode == 60)
    case('TLS04 wrong hostname -> curl rejects certificate', lambda: curl('external-client', 'https://wrong.lab:8443/', '--cacert', '/public-ca/root_ca.crt', '--resolve', f'wrong.lab:8443:{dmz}').returncode == 60)
    case('HTTP01 marker accepted without reflection', lambda: expect_http(curl('external-client', web, '--data-binary', 'LAB_MARKER'), 'dmz'))
    case('CHAT01 encrypted chat via VPN + internal client', run_chat)
    case('CHAT02 second independent relay session', run_chat)
    print(f'Acceptance: {14-len(failures)}/14 PASS')
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())
