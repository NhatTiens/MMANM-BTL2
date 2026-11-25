# Tiến độ TV1 — Network & Firewall
- [x] Đọc hợp đồng tích hợp và yêu cầu BTL 2.1.
- [x] Hiện thực cấu hình DMZ, phát hiện interface, Stateful Firewall, default deny, anti-spoof theo subnet.
- [x] Giữ contract counters.json; bổ sung thống kê delta có giới hạn.
- [x] Lab riêng và kịch bản kiểm thử allow/drop, state, route, snapshot.
- [x] Unit test 12/12 TV1, 27/27 toàn repo; kiểm tra phạm vi Git.
- [ ] Xác nhận MSSV nhóm trưởng.
- [ ] Chạy Docker lab, lưu log thật của 7 case và ảnh minh chứng.
- [ ] Kiểm thử HTTPS/VPN/IPS chung với TV2/TV3.
- [ ] Tạo PR vào develop, review và merge sau khi test thật đạt.

Không có Docker Engine/iptables-restore trong môi trường tạo patch. Chưa nghiệm thu runtime. Xem REPORT.md.
