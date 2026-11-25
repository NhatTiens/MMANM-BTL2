# Validation — bản tích hợp 4 thành viên

Actual: `python -m unittest discover -s tests -v` ran 83 tests successfully (15 nền, 12 TV1, 26 TV2, 15 TV3, 15 TV4). Python local HTTP API and Node syntax checked. Git TV4 scope check passed. Browser attempt blocked by Chromium ERR_BLOCKED_BY_ADMINISTRATOR; no UI acceptance claim. Docker, WireGuard and Suricata executables unavailable; no Docker config/build, real handshake, packet forwarding, rule compilation, PCAP replay or NFQUEUE verdict acceptance executed. Read evidence log outside repository in delivery ZIP.

Pending: TV1 7 cases, TV2 14 cases, TV3 18 PCAP + 13 IDS + 15 IPS cases, TV4 common integration IDS/IPS with real logs, browser acceptance, CPU/RAM/throughput and report evidence. Unit tests include synthetic/mocked command cases; they do not prove runtime. Use module README and report chapter 3 to fill actual results. Do not invent numbers.
