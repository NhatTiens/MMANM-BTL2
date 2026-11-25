# TV2 tests

Root repository: `python -m unittest discover -s tests/member2_vpn -v` hoặc `python -m unittest discover -s tests -v`.
`test_services.py` kiểm thử HTTP, HTTPS/TLS thật trên localhost, framing và relay Chat thật trên TCP loopback. `test_wireguard.py` kiểm thử shell với wg/ip giả lập, không cần root, POSIX (Windows không có sh thì skip; dùng WSL/Linux để chạy). Không dùng key thật.
Sau khi merge TV1, chạy lab theo srcs/member2_vpn/README.md rồi `python tests/member2_vpn/lab_check.py`. 14 ca này cần Docker runtime; không suy ra VPN thật từ mock test. Test targets là IP lab cố định.
