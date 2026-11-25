# MMANM-BTL2 | Enterprise Network Security Lab

Môn Mật mã và An ninh mạng — HK261. Bản tích hợp 4 module, phạm vi 2.1 Firewall/VPN + 2.2 IDS/IPS (nhóm trưởng cần xác nhận phạm vi với giảng viên). Mã nguồn đã kiểm thử offline; **chưa nghiệm thu Docker/Suricata/WireGuard thật**. Không dùng ngoài lab cô lập, không có bảo chứng production.

## 1. Thành viên và cấu trúc
| TV | Branch | Module | Dữ liệu / chức năng |
|---|---|---|---|
| 1 | feature/member1-firewall | srcs/member1_firewall | Gateway, IPv4 routing, Stateful Firewall, counters.json |
| 2 | feature/member2-vpn | srcs/member2_vpn | WireGuard, HTTP/HTTPS, Chat relay tùy chọn |
| 3 | feature/member3-ids-ips | srcs/member3_ids | Suricata, 13 SID, EVE JSON |
| 4 | feature/member4-dashboard | srcs/member4_dashboard | SOC Dashboard, CSV, kiểm thử tích hợp |

Mỗi module có tests/, docs/, pics/ tương ứng. `compose.yaml` và `scripts/configure.py` do nhóm trưởng quản lý. `docs/GIT_WORKFLOW.md` mô tả PR về develop, sau nghiệm thu release develop → main. Không ghi đè repository bằng ZIP; áp dụng các patch đúng nhánh nếu chưa có.

## 2. Chuẩn bị
Git, Python >=3.10, Docker Desktop Linux containers/WSL2 hoặc Linux VM, Docker Compose v2. Kernel cần hỗ trợ WireGuard và NFQUEUE. Không dùng privileged hoặc host network để lách lỗi. Dừng các lab cùng subnet trước. Chạy lệnh tại root repository, PowerShell.

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```
Linux: 83 test đã PASS trong môi trường tạo dự án; trên Windows một số test Shell có thể skip. `2213444` dưới đây là ví dụ, thay bằng MSSV nhóm trưởng đã xác nhận. Không commit .env, generated.rules, private key hay log thật.

## 3. Chạy Dashboard bằng dữ liệu giả lập (không Docker)
```powershell
python tests/member4_dashboard/fixture_server.py
```
Mở http://127.0.0.1:8501. Giao diện có banner DỮ LIỆU GIẢ LẬP. Kiểm tra filter, severity, action, biểu đồ, CSV; ảnh fixture không phải bằng chứng lab. Dừng Ctrl+C trước khi chạy Docker.

## 4. Chạy toàn hệ thống IDS + VPN
```powershell
python scripts/configure.py --leader 2213444 --mode ids
docker compose config --quiet
docker compose run --build --rm vpn-init
docker compose --profile vpn up -d --build --wait --wait-timeout 120
docker compose --profile vpn ps
python tests/member4_dashboard/integration_check.py --vpn --output evidence-ids
```
Dashboard: http://127.0.0.1:8501. Output evidence-ids phải chưa tồn tại. Script gọi smoke chung (HTTP, TLS, VPN, marker) và kiểm tra SID mới, action, counter deny tăng, snapshot mới và CSV. Không coi smoke đơn lẻ là nghiệm thu toàn bộ. Nếu VPN chưa hỗ trợ kernel, dừng trước, configure `--no-vpn`, bỏ `--profile vpn` khi up và bỏ `--vpn` khi test; sau đó cần nghiệm thu VPN trên máy hỗ trợ.

## 5. Chạy IPS + VPN
```powershell
docker compose --profile vpn --profile legacy down
python scripts/configure.py --leader 2213444 --mode ips
docker compose --profile vpn up -d --build --wait --wait-timeout 120
python tests/member4_dashboard/integration_check.py --vpn --output evidence-ips
```
NFQUEUE 0 không bypass; nếu sensor chưa hoạt động, traffic qua queue có thể bị chặn. Chờ healthcheck. Dùng `docker compose logs --tail 100 gateway suricata dashboard` để chẩn đoán. Không dùng `down -v` nếu chưa sao lưu bằng chứng và khóa; `down` giữ volumes. Log cũ có thể còn tồn tại; test kiểm tra sự kiện mới, không xóa log tự động.

## 6. Kiểm thử module chuyên sâu (chạy lần lượt, không trùng subnet)
- TV1: `srcs/member1_firewall/README.md`, 7 ca FW riêng.
- TV2: `srcs/member2_vpn/README.md`, 14 ca lab, handshake hai đầu, TLS và Chat. Demo Chat trên Compose chung dùng overlay `srcs/member2_vpn/compose.chat.yaml` và profile legacy; các lệnh chi tiết nằm trong README TV2.
- TV3: `srcs/member3_ids/README.md`, 18 PCAP offline có nhãn, 13 ca IDS, 15 ca IPS. Lab live TV3 dùng project riêng `mmanm-tv3-lab` và `--no-vpn`; dừng Compose chung trước.
- TV4: `srcs/member4_dashboard/README.md`, 15 unit/API test; browser test tùy chọn cần Playwright/Chromium. `integration_check.py` dùng project Compose chung, lưu result.json, smoke.txt, snapshot.json. Kết quả runtime phải điền từ dữ liệu thật.

## 7. Kiến trúc, hợp đồng dữ liệu
External 172.28.50.0/24 (.10 client, .20 VPN); Internal 172.28.60.0/24 (.10 app:8080, .30 relay:9999); DMZ 10.(MSSV mod 200).1.0/24 (.10 web:8080/8443); gateway .254 mỗi zone; VPN 10.77.0.1/.2, UDP 51820. Firewall default deny; IDS capture External; IPS NFQUEUE 0 sau policy allow. Dashboard mạng management riêng, port localhost 8501.

`counters.json`: timestamp Unix + rules[{rule,packets,bytes}]. Counter từng rule, không phải tổng packet. `eve.json`: JSONL alert, metadata và verdict. API `/api/snapshot` tương thích trường cũ, thêm nguồn/độ mới, action/severity, timeline, top source; đọc 512 KiB cuối, tối đa 500 alert trả về; `/api/alerts.csv` xuất cửa sổ mới, không phải toàn lịch sử hay kết quả lọc. Không có API thay policy. IDS không có log mới không đồng nghĩa sensor dừng. TLS/E2EE hạn chế khả năng nhìn payload.

## 8. Trạng thái và nộp bài
83 unit test PASS; JS syntax PASS; Python HTTP local PASS. Chromium bị chính sách môi trường chặn localhost, chưa nghiệm thu UI thật. Docker Engine và Suricata không có trong môi trường tạo dự án; toàn bộ ca runtime/PCAP engine chưa chạy. Các rule mẫu/heuristic không chứng minh khả năng phát hiện mọi tấn công. Chat cũ không xác thực danh tính độc lập; không tuyên bố chống MitM chủ động. Dashboard nhẹ tự viết thay cho ELK/Wazuh; nếu giảng viên bắt buộc stack cụ thể cần bổ sung.

Theo đề trang 2–3: README.doc, srcs/, refs/, báo cáo 20–30 trang Word/PDF, 4 chương; đóng gói Assigment2.zip sau tuần 14. Báo cáo dự thảo có sẵn; điền tên/MSSV/nhóm trưởng, kết quả Docker/PCAP, ảnh/video thật, phiên bản và nguồn đã dùng trước khi nộp. Không đưa private key, log nhạy cảm hoặc dữ liệu giả lập không gắn nhãn vào bài nộp.
