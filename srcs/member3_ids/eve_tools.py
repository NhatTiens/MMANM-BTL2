"""Read EVE JSON Lines without retaining payloads; score labeled offline cases."""
import json
from collections import Counter
from pathlib import Path


def alerts(lines):
    for line in lines:
        try: event=json.loads(line)
        except (ValueError,UnicodeError,TypeError): continue
        if not isinstance(event,dict) or event.get('event_type')!='alert': continue
        a=event.get('alert')
        if not isinstance(a,dict) or type(a.get('signature_id')) is not int: continue
        yield {'sid':a['signature_id'],'action':a.get('action'),'signature':a.get('signature'),
               'src':event.get('src_ip'),'dst':event.get('dest_ip'),'time':event.get('timestamp'),
               'flow':event.get('flow_id')}


def read(path):
    with Path(path).open('rb') as f: return list(alerts(f))


def summarize(cases):
    # Case-level classification + exact rule match; not packet-level accuracy.
    counts=Counter(dict(TP=0,FP=0,TN=0,FN=0)); rows=[]
    for c in cases:
        expected=set(c['expected']); seen=set(c['seen'])
        label='TP' if expected and seen else 'FN' if expected else 'FP' if seen else 'TN'
        counts[label]+=1
        rows.append({'case':c['case'],'expected':sorted(expected),'seen':sorted(seen),
                     'missing':sorted(expected-seen),'unexpected':sorted(seen-expected),
                     'classification':label,'pass':expected==seen})
    tp,fp,tn,fn=(counts[k] for k in ('TP','FP','TN','FN'))
    ratio=lambda n,d:n/d if d else None
    return {'counts':dict(counts),'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),
            'false_positive_rate':ratio(fp,fp+tn),'accuracy':ratio(tp+tn,len(rows)),
            'exact_pass':sum(x['pass'] for x in rows),'total':len(rows),'cases':rows}
