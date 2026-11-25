# Validation — TV2

Môi trường tạo patch: Linux x86_64, Python 3.13.5, cryptography 46.0.4; không có Docker Engine hoặc `wg` binary. Không thay đổi network host. Các test Shell gọi ip/wg giả lập trong thư mục tạm; không chứng minh kernel WireGuard chạy thật.

| Kiểm tra | Kết quả |
|---|---|
| Test dịch vụ/protocol TV2 | 17/17 PASS (HTTP, TLS, TCP relay thật qua loopback, frame bounds, AEAD tag) |
| Test startup shell TV2 | 9/9 PASS (mock wg/ip) |
| Toàn bộ branch TV2, chưa có TV1 patch | 41/41 PASS (32.340 s) |
| Bản clone sạch áp dụng TV1 patch rồi TV2 patch | 53/53 PASS (30.837 s) |
| Git scope guard cho TV2 | PASS |
| Compose chung và code TV1/TV3/TV4 không đổi bởi TV2 | PASS |
| Shell syntax (`sh -n`), Python compile, YAML parse | PASS |
| So sánh IP/network giữa lab và compose chung | PASS |
| Docker Compose config/build/runtime | Chưa chạy |
| 14 ca acceptance lab (handshake, counters, TLS, chat qua tunnel thật) | Chưa chạy |
| Suricata IPS tích hợp / dashboard thật | Chưa chạy (module khác) |

Test log kèm ZIP là stdout/stderr thực tế. Thời gian test chỉ là thời lượng chạy test trong môi trường tạo patch, không phải benchmark mạng. Windows native sẽ skip 9 ca shell nếu không chạy qua WSL/Linux; kết quả 53 trên Linux gồm cả 12 test mới TV1 và 15 test nền. Không có số liệu mạng bịa đặt. Sau khi chạy Docker lab, cập nhật REPORT.md với kết quả, phiên bản Docker/kernel và ảnh đã che thông tin khóa.
