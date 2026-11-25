"""Generate small, deterministic *offline* PCAP fixtures. No network I/O.
All addresses are RFC 5737 documentation ranges; no executable payloads.
"""
import ipaddress
import json
import struct
from pathlib import Path

SRC='192.0.2.20'; DST='198.51.100.10'
EPOCH=1700000000


def checksum(data):
    if len(data)%2: data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16: total=(total&65535)+(total>>16)
    return (~total)&65535


def packet(src,dst,sport,dport,seq,ack,flags,body=b''):
    a=ipaddress.IPv4Address(src).packed; b=ipaddress.IPv4Address(dst).packed
    tcp=struct.pack('!HHIIBBHHH',sport,dport,seq,ack,0x50,flags,65535,0,0)
    check=checksum(a+b+struct.pack('!BBH',0,6,len(tcp)+len(body))+tcp+body)
    tcp=tcp[:16]+struct.pack('!H',check)+tcp[18:]
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp)+len(body),1,0x4000,64,6,0,a,b)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'+ip+tcp+body


def http(body=b'',uri='/',host='dmz-web',port=40000):
    # Proper bidirectional handshake, data, response and ACK; no connection is sent.
    request=(f'POST {uri} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()+body
    response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
    c=lambda s,a,f,p=b'':packet(SRC,DST,port,8080,s,a,f,p)
    d=lambda s,a,f,p=b'':packet(DST,SRC,8080,port,s,a,f,p)
    return [c(100,0,2),d(500,101,18),c(101,501,16),c(101,501,24,request),d(501,101+len(request),24,response),c(101+len(request),501+len(response),16)]


def cases(mssv):
    if not (mssv.isascii() and mssv.isdecimal() and 5<=len(mssv)<=12): raise ValueError('invalid MSSV')
    # The signatures are defensive indicators. The content is inert text, not executed.
    return [
        ('normal_http',[],http(b'hello classroom')),
        ('normal_keywords',[],http(b'union membership; script documentation')),
        ('normal_beacon_path',[],http(uri='/beacon',host='dmz-web')),
        ('normal_c2_host_other_path',[],http(uri='/health',host='c2-demo.invalid')),
        ('mssv',[1000001],http(mssv.encode())),
        ('marker_sqli',[1000002],http(b'LAB_SQLI')),
        ('marker_xss',[1000003],http(b'LAB_XSS')),
        ('marker_c2',[1000004],http(b'LAB_C2')),
        ('marker_block',[1000007],http(b'LAB_BLOCK')),
        ('sqli_body',[1000014],http(b'UNION SELECT')),
        ('sqli_uri',[1000010],http(uri='/lab?example=UNION%20SELECT')),
        ('xss_body',[1000011],http(b'<script>classroom text</script>')),
        ('xss_uri',[1000015],http(uri='/lab?example=%3Cscript%3E')),
        ('c2_simulated',[1000012],http(uri='/beacon',host='c2-demo.invalid')),
        ('scan_heuristic',[1000005],[packet(SRC,DST,41000+i,9000+i,100,0,2) for i in range(6)]),
        ('aggregate_syn_heuristic',[1000013],[packet(f'192.0.2.{20+i}',DST,42000+i,8080,100,0,2) for i in range(13)]),
        ('normal_low_syn',[],[packet(SRC,DST,43000+i,8080,100,0,2) for i in range(3)]),
        ('marker_rate',[1000005,1000006],[p for i in range(5) for p in http(b'LAB_RATE',port=44000+i)]),
    ]


def write_pcap(path,packets):
    with Path(path).open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for i,p in enumerate(packets):
            sec,usec=divmod(i*10000,1000000)
            f.write(struct.pack('<IIII',EPOCH+sec,usec,len(p),len(p))+p)


def generate(directory,mssv):
    root=Path(directory); root.mkdir(parents=True,exist_ok=True)
    manifest=[]
    for name,expected,packets in cases(mssv):
        file=name+'.pcap'; write_pcap(root/file,packets)
        manifest.append({'case':name,'pcap':file,'expected':expected,'packets':len(packets)})
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest
