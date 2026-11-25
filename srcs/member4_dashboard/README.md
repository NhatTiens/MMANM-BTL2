# TV4 – SOC Dashboard & Integration Testing

Branch `feature/member4-dashboard`. Module đọc log qua hai volume read-only; không sửa Firewall, VPN hoặc IDS. API giữ các trường cũ, bổ sung metadata nguồn, severity, timeline UTC, top source, action và CSV. Cửa sổ IDS 512 KiB cuối, chỉ đọc JSONL hoàn chỉnh; tối đa 500 cảnh báo trả về, 25/dòng trang; thống kê trên cả cửa sổ. Firewall snapshot tối đa 512 KiB, counter từng rule, không cộng thành tổng packet. IDS không ghi log mới không đồng nghĩa sensor dừng. Không xác nhận VPN handshake qua log Dashboard. Chỉ sử dụng local lab, không có auth/TLS quản trị production.

## Chạy độc lập (không Docker)
```powershell
python tests/member4_dashboard/fixture_server.py
```
Mở http://127.0.0.1:8501. Banner DỮ LIỆU GIẢ LẬP, không dùng ảnh này làm minh chứng lab thật. Dừng Ctrl+C trước khi chạy Compose.

## Chạy hệ thống thực
Từ root dùng README.md chung. Dashboard publish localhost:8501, đọc `/data/ids/eve.json` và `/data/firewall/counters.json`. Chờ nguồn log sẵn sàng. CSV xuất tối đa 500 alert tại thời điểm tải, không phải kết quả lọc hiện tại. Chuỗi có nguy cơ spreadsheet formula injection được thêm dấu nháy đơn. UI hiển thị textContent thay vì innerHTML; CSP chỉ cho asset cùng origin. Không gửi payload thô, khóa hoặc thay đổi policy.

## Test
```powershell
python -m unittest discover -s tests/member4_dashboard -v
python -m unittest discover -s tests -v
node --check srcs/member4_dashboard/dashboard.js
# Optional browser test, port 8501 phải rảnh
python -m pip install playwright
python -m playwright install chromium
python tests/member4_dashboard/browser_check.py --output browser-evidence
# Runtime, sau khi khởi động Compose thật với profile vpn
python tests/member4_dashboard/integration_check.py --vpn --output evidence-ids
```
Không chạy hai lab cùng subnet. `integration_check.py` dùng smoke chung + đối chiếu SID mới, action, counter deny tăng, độ mới snapshot, CSV. Kết quả lưu result.json, smoke.txt và snapshot.json. Chỉ chạy trên project Compose chung, không nhận đích ngoài lab. Với IPS, dừng Compose, configure mode ips, khởi động lại và dùng thư mục evidence-ips mới. Bỏ --vpn nếu cấu hình --no-vpn. Không coi fixture hoặc unit test là chứng minh runtime. Xem docs/member4_dashboard/VALIDATION.md.
