"""Atomic snapshots for TV4 and bounded aggregate change history (not per-packet logs)."""
import json
import os
from pathlib import Path
import re
import subprocess
import time

COUNTER = re.compile(r'^\[(\d+):(\d+)\] (-A (?:FORWARD|INPUT|INSPECT|LAB_INGRESS) .+)$')


def parse(raw):
    rules = []
    for line in raw.splitlines():
        match = COUNTER.match(line)
        if match:
            packets, octets, rule = match.groups()
            rules.append(dict(rule=rule, packets=int(packets), bytes=int(octets)))
    if not rules:
        raise ValueError('No filter counters found')
    return rules


def atomic_snapshot(directory, data):
    temp = directory / 'counters.tmp'
    temp.write_text(json.dumps(data), encoding='utf-8')
    os.replace(temp, directory / 'counters.json')


def deltas(previous, current):
    old = {x['rule']: x for x in previous}
    out = []
    for item in current:
        before = old.get(item['rule'])
        if before is None or item['packets'] < before['packets'] or item['bytes'] < before['bytes']:
            continue  # New rule or reset: no fabricated increase.
        p, b = item['packets'] - before['packets'], item['bytes'] - before['bytes']
        if p or b:
            out.append(dict(rule=item['rule'], packets_delta=p, bytes_delta=b))
    return out


def append_interval(directory, timestamp, changes, limit=1024*1024):
    if not changes:
        return
    path = directory / 'counter_intervals.jsonl'
    line = json.dumps(dict(timestamp=timestamp, kind='counter_delta', changes=changes)) + '\n'
    if path.exists() and path.stat().st_size + len(line.encode()) > limit:
        os.replace(path, directory / 'counter_intervals.previous.jsonl')
    with path.open('a', encoding='utf-8') as out:
        out.write(line)


def main():
    directory = Path('/logs')
    previous = []
    while True:
        rules = parse(subprocess.check_output(['iptables-save', '-c', '-t', 'filter'], text=True))
        now = time.time()
        atomic_snapshot(directory, dict(timestamp=now, rules=rules))
        append_interval(directory, now, deltas(previous, rules))
        previous = rules
        Path('/tmp/gateway-ready').touch()
        time.sleep(2)


if __name__ == '__main__':
    main()
