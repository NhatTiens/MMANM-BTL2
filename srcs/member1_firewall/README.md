# Thành viên 1 — Network & Stateful Firewall

Module chạy trong gateway Docker riêng, không sửa firewall của Windows/Linux host. Nhánh `feature/member1-firewall`; chỉ thay đổi thư mục thuộc TV1. Giữ nguyên compose.yaml chung và contract với TV2/TV3/TV4. Không chạy script `rules.sh` hoặc `start.sh` trực tiếp trên host.

## 1. Lab độc lập (không cần TV2/3/4 chạy dịch vụ)

Yêu cầu: Docker Desktop Linux containers hoặc Linux Docker Engine + Compose v2, Python 3.10+, kernel hỗ trợ iptables/conntrack. Không chạy đồng thời lab riêng và compose chung vì dùng cùng các subnet.

Từ thư mục gốc repository:

```powershell
python scripts/configure.py --leader 2213444 --no-vpn
python -m unittest discover -s tests -v
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml config
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml up -d --build
python tests/member1_firewall/lab_check.py
```

Thay 2213444 bằng MSSV nhóm trưởng đã xác nhận. Script configure của nhóm sinh .env và generated.rules, hai file không commit. Lab riêng cố định VPN=0 và IPS_MODE=ids, chỉ để nghiệm thu routing/firewall. Lab dùng các endpoint HTTP giả lập cục bộ, **8080, 8443 và 9090 đều là HTTP**, không phải TLS; HTTPS thật do TV2 nghiệm thu ở compose chung.

Lấy minh chứng (chạy từ root):

```powershell
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml ps
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml exec gateway ip -br -4 addr
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml exec gateway ip route
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml exec gateway iptables -nvL FORWARD
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml exec gateway iptables -nvL LAB_INGRESS
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml exec gateway cat /logs/counters.json
```

Dừng lab riêng trước khi chạy compose chung:

```powershell
docker compose --env-file .env -f srcs/member1_firewall/compose.lab.yaml down
```

## 2. Tích hợp chung (sau khi TV2/TV3 sẵn sàng)

Dùng `compose.yaml` hiện có. Chế độ VPN và IPS cần được kiểm tra chung, không sửa module thành viên khác. Thực hiện theo README chính và docs/INTEGRATION.md. Sinh lại `.env` với `python scripts/configure.py --leader MSSV_THAT` (thay placeholder bằng số), khởi tạo VPN theo README chung, sau đó chạy `docker compose --profile vpn up -d --build` và `python scripts/smoke.py --vpn`. Kiểm tra chế độ IPS riêng khi TV3 đã cấu hình Suricata queue 0. Không bật queue bypass.

## 3. Contract

- 3 zone IPv4: external 172.28.50.0/24, internal 172.28.60.0/24, DMZ 10.(MSSV mod 200).1.0/24. Gateway mỗi zone .254, DMZ web .10, internal app .10, relay .30.
- Stateful filter: INPUT/FORWARD mặc định DROP; OUTPUT ACCEPT cho gateway. Kiểm tra INVALID và nguồn IP đúng subnet/interface trước khi xét trạng thái ESTABLISHED,RELATED. Chỉ cho phép TCP NEW có SYN tới các dịch vụ trong ma trận. Kiểm tra source prefix không xác thực danh tính từng host trong cùng subnet.
- IDS mode: INSPECT ACCEPT. IPS mode: NFQUEUE 0, fail-closed nếu không có listener; cần xác minh trên kernel thật.
- `/logs/counters.json` giữ nguyên schema `{timestamp, rules:[{rule,packets,bytes}]}`; cập nhật atomic mỗi 2 giây; gateway-ready chỉ tạo sau snapshot đầu tiên. Comment ổn định FW_* giúp đối chiếu rule.
- `/logs/counter_intervals.jsonl` là tổng delta counter mỗi khoảng lấy mẫu, không phải log từng packet, không chứa payload. Giữ file hiện tại và một file previous (~1 MiB mỗi file). TV4 không bắt buộc đọc file mới.
- IPv4 lab; từ chối IPv6 global address/IPv6 forwarding. Không phải giải pháp firewall production, không kiểm soát traffic cùng một subnet hoặc endpoint có quyền quản trị mạng. Không publish port của lab riêng ra host.

## 4. Test

`python -m unittest discover -s tests -v`: unit test offline, không dùng Docker. `python tests/member1_firewall/lab_check.py`: 7 kịch bản allow/drop + preflight listener, route và stateful counter + snapshot. Kết quả runtime phải ghi theo thực tế; chưa chạy Docker trong môi trường tạo patch.

Xem `docs/member1_firewall/REPORT.md` và `docs/member1_firewall/PROGRESS.md` để bổ sung minh chứng.
