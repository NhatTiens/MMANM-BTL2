"""Prepare an explicit EVE-only configuration from the packaged Suricata YAML."""
import argparse
from pathlib import Path


def configure(data, mode):
    if mode not in ('ids', 'ips', 'offline'):
        raise ValueError('invalid mode')
    data['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular',
        'filename': 'eve.json', 'types': [{'alert': {'payload': False,
        'payload-printable': False, 'packet': False, 'metadata': False}}]}}]
    data.setdefault('stream', {})['inline'] = 'yes' if mode == 'ips' else 'no'
    data['nfq'] = {'mode': 'accept', 'fail-open': False}
    # HTTP body is bounded by the TV2 service (4096 bytes); allow inspection of that range.
    htp = data.setdefault('app-layer', {}).setdefault('protocols', {}).setdefault('http', {}).setdefault('libhtp', {})
    htp.setdefault('default-config', {})['request-body-limit'] = 8192
    return data


def main():
    import yaml
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['ids','ips','offline'], required=True)
    p.add_argument('--source', type=Path, default=Path('/etc/suricata/suricata.yaml'))
    p.add_argument('--output', type=Path, default=Path('/tmp/btl2-suricata.yaml'))
    a = p.parse_args()
    with a.source.open() as f:
        data = yaml.safe_load(f)
    a.output.write_text('%YAML 1.1\n---\n' + yaml.safe_dump(configure(data,a.mode), sort_keys=False), encoding='utf-8')


if __name__ == '__main__':
    main()
