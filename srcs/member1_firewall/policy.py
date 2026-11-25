"""IPv4 policy for the isolated Compose gateway; never run on the host."""
import ipaddress
import json
import os
import re
import subprocess
import sys

EXT_NET = '172.28.50.0/24'
INT_NET = '172.28.60.0/24'
EXT_GW = '172.28.50.254'
INT_GW = '172.28.60.254'


def configuration(env):
    net = ipaddress.IPv4Network(env['DMZ_NET'], strict=True)
    a, b, c, d = net.network_address.packed
    if net.prefixlen != 24 or (a, c, d) != (10, 1, 0) or b >= 200:
        raise ValueError('DMZ must be 10.(MSSV mod 200).1.0/24')
    gw, web = str(net[254]), str(net[10])
    if env['DMZ_GW'] != gw or env['DMZ_WEB'] != web:
        raise ValueError('DMZ gateway/web must be .254/.10')
    mode, vpn = env.get('IPS_MODE', 'ids'), env.get('VPN_ENABLED', '0')
    if mode not in ('ids', 'ips') or vpn not in ('0', '1'):
        raise ValueError('Invalid IPS_MODE or VPN_ENABLED')
    return dict(net=str(net), gw=gw, web=web, mode=mode, vpn=vpn == '1')


def interfaces(addresses, cfg):
    found = {}
    for role, addr in [('ext', EXT_GW), ('dmz', cfg['gw']), ('internal', INT_GW)]:
        matches = [x['ifname'] for x in addresses for info in x.get('addr_info', [])
                   if info.get('family') == 'inet' and info.get('local') == addr and info.get('prefixlen') == 24]
        if len(matches) != 1 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', matches[0]):
            raise ValueError(f'Missing/ambiguous interface for {role}: {addr}/24')
        found[role] = matches[0]
    if len(set(found.values())) != 3 or set(found.values()) & {'lo', 'wg0'}:
        raise ValueError('Zones must have distinct interfaces')
    return found


def render(cfg, iface):
    ext, dmz, internal = (iface[x] for x in ('ext', 'dmz', 'internal'))
    lines = ['*filter', ':INPUT DROP [0:0]', ':FORWARD DROP [0:0]', ':OUTPUT ACCEPT [0:0]',
             ':LAB_INGRESS - [0:0]', ':INSPECT - [0:0]']
    def add(chain, match, label, target):
        lines.append(f'-A {chain} {match} -m comment --comment {label} -j {target}'.replace('  ', ' '))
    add('INPUT', '-i lo', 'FW_IN_LOOPBACK', 'ACCEPT')
    for chain in ('INPUT', 'FORWARD'):
        add(chain, '-m conntrack --ctstate INVALID', f'FW_{chain}_INVALID', 'DROP')
        add(chain, '', f'FW_{chain}_CHECK_ZONE', 'LAB_INGRESS')
    for name, dev, net in [('EXT', ext, EXT_NET), ('DMZ', dmz, cfg['net']), ('INT', internal, INT_NET)]:
        add('LAB_INGRESS', f'-i {dev} -s {net}', f'FW_ZONE_{name}', 'RETURN')
    if cfg['vpn']:
        add('LAB_INGRESS', '-i wg0 -s 10.77.0.2/32', 'FW_ZONE_VPN', 'RETURN')
    add('LAB_INGRESS', '', 'FW_DROP_SPOOF_OR_UNKNOWN', 'DROP')
    add('INPUT', '-m conntrack --ctstate ESTABLISHED,RELATED', 'FW_IN_STATE', 'ACCEPT')
    if cfg['vpn']:
        add('INPUT', f'-i {ext} -s 172.28.50.20/32 -d {EXT_GW}/32 -p udp --dport 51820 -m conntrack --ctstate NEW', 'FW_VPN_HANDSHAKE', 'ACCEPT')
    add('INPUT', '', 'FW_IN_DEFAULT', 'DROP')
    add('FORWARD', '-m conntrack --ctstate ESTABLISHED,RELATED', 'FW_FWD_STATE', 'INSPECT')
    def web_rule(src_if, source, label):
        add('FORWARD', f'-i {src_if} -o {dmz} -s {source} -d {cfg["web"]}/32 -p tcp -m multiport --dports 8080,8443 --syn -m conntrack --ctstate NEW', label, 'INSPECT')
    web_rule(ext, EXT_NET, 'FW_EXT_DMZ_WEB')
    web_rule(internal, INT_NET, 'FW_INT_DMZ_WEB')
    if cfg['vpn']:
        for ip, port, label in [('172.28.60.10', 8080, 'FW_VPN_APP'), ('172.28.60.30', 9999, 'FW_VPN_CHAT')]:
            add('FORWARD', f'-i wg0 -o {internal} -s 10.77.0.2/32 -d {ip}/32 -p tcp --dport {port} --syn -m conntrack --ctstate NEW', label, 'INSPECT')
        web_rule('wg0', '10.77.0.2/32', 'FW_VPN_DMZ_WEB')
    add('FORWARD', '', 'FW_FWD_DEFAULT', 'DROP')
    if cfg['mode'] == 'ips':
        add('INSPECT', '', 'FW_IPS_QUEUE', 'NFQUEUE --queue-num 0')
    add('INSPECT', '', 'FW_INSPECT_ACCEPT', 'ACCEPT')
    return '\n'.join(lines + ['COMMIT', ''])


def main():
    # Refuse accidental execution outside the gateway container.
    if not os.path.isfile('/.dockerenv') or not os.path.isfile('/lab/firewall/policy.py'):
        raise SystemExit('Run only inside the dedicated Compose gateway container')
    cfg = configuration(os.environ)
    addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show'], text=True))
    iface = interfaces(addresses, cfg)
    if open('/proc/sys/net/ipv4/ip_forward').read().strip() != '1':
        raise SystemExit('IPv4 forwarding is not enabled in gateway namespace')
    # The project uses IPv4 only. Refuse routable IPv6 addresses or forwarding.
    v6 = json.loads(subprocess.check_output(['ip', '-j', '-6', 'addr', 'show'], text=True))
    if any(a.get('scope') == 'global' for dev in v6 for a in dev.get('addr_info', [])):
        raise SystemExit('IPv6 global addressing is outside this lab policy')
    if os.path.exists('/proc/sys/net/ipv6/conf/all/forwarding') and open('/proc/sys/net/ipv6/conf/all/forwarding').read().strip() != '0':
        raise SystemExit('IPv6 forwarding is outside this lab policy')
    policy = render(cfg, iface)
    subprocess.run(['iptables-restore', '-w', '5', '--test'], input=policy, text=True, check=True)
    subprocess.run(['iptables-restore', '-w', '5'], input=policy, text=True, check=True)
    print('IPv4 policy installed:', cfg['net'], iface, cfg['mode'], 'VPN:', cfg['vpn'], flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print(f'Firewall initialization failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
