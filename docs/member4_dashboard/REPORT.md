# Báo cáo kỹ thuật TV4 – SOC Dashboard và tích hợp

## Phân tích và thiết kế
TV4 đọc hai nguồn dữ liệu từ TV1 và TV3 qua volume chỉ đọc. `eve.json` là JSON Lines; `counters.json` là snapshot atomic, timestamp Unix. API giữ status, recent_alert_count, by_signature, alerts, firewall; mở rộng metadata sources, generated_at, mode, window, by_source, by_action, by_severity và timeline. Giới hạn 512 KiB cuối của EVE, tối đa 500 alert trả về; thống kê toàn cửa sổ đọc, không phải tổng lịch sử. Không cộng counter qua các chain vì một gói có thể khớp nhiều rule.

## Hiện thực
`app.py` dùng Python HTTP server, chỉ GET asset/API, đọc log hữu hạn, bỏ dòng không hoàn chỉnh hoặc sai định dạng, nhận file mới khi rotation. Snapshot Firewall cũ sau 10 giây; log IDS không ghi mới sau 60 giây chỉ là thông tin độ mới, không kết luận sensor dừng. UI tách HTML/CSS/JS, cập nhật mỗi 3 giây, có lọc từ khóa, action, severity, phân trang 25 alert, biểu đồ và CSV. CSV đánh dấu nguồn fixture/live, chống chuỗi công thức; UI dùng textContent, CSP same origin. Không có API đổi rule hoặc quản trị từ xa. Dashboard không đo trạng thái handshake VPN.

## Kiểm thử
15 unit/API test TV4, tổng hợp 83 unit test toàn repository PASS trên môi trường tạo dự án. Node kiểm tra cú pháp JS PASS. Browser Playwright đã thử nhưng bị chính sách môi trường chặn truy cập localhost; chưa nghiệm thu tương tác UI qua trình duyệt. Docker không có nên integration_check.py chưa chạy. Script đối chiếu smoke, SID mới, action, counter deny tăng, snapshot và CSV; lưu evidence JSON. Nghiệm thu cả IDS/IPS với VPN thật, chạy lại module labs và PCAP. Không tạo kết quả giả.

## Giới hạn
Không phải ELK/Wazuh, không có retention/index/search toàn lịch sử, không có auth/TLS quản trị, không có thông tin peer VPN trong snapshot, không đo performance runtime. Chỉ phù hợp SOC lab local. Cần kiểm tra quyền đọc volume, render trình duyệt và kết quả tích hợp thật trước khi nộp.
