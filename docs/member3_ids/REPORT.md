# Báo cáo kỹ thuật TV3 – Hệ thống phát hiện/ngăn chặn xâm nhập

## 1. Yêu cầu
Theo đề BTL2 mục 2.2: hệ thống IDS/IPS, tập luật tùy chỉnh cho port scanning, DoS/DDoS, SQL Injection/XSS qua HTTP, Malware C2, nhật ký và kịch bản diễn tập. Ít nhất một rule kiểm tra chuỗi hex của MSSV nhóm trưởng. TV3 xây dựng Suricata trong lab Docker của nhóm, không sử dụng đích ngoài lab.

## 2. Phân tích và thiết kế
TV1 phân vùng External/DMZ/Internal, Firewall kiểm tra source và trạng thái kết nối. TV2 cung cấp HTTP/HTTPS và VPN. IDS chạy capture External trong network namespace Gateway; IPS kiểm tra FORWARD được Firewall cho phép qua NFQUEUE 0. Sensor không sửa policy TV1. EVE JSON alert-only được chia sẻ qua volume `ids_logs`; TV4 đọc volume read-only. Dữ liệu không chứa packet dump hay plaintext payload trực tiếp. Để phát hiện chữ ký ứng dụng phải có plaintext; TLS và E2EE làm giới hạn nội dung nhìn thấy.

## 3. Hiện thực
| SID | Mục đích | Action | Giới hạn |
|---|---|---|---|
| 1000001 | MSSV ASCII chuyển hex, TCP 8080 established | alert | Không chứng minh tấn công |
| 1000002–4 | Marker SQLi/XSS/C2 tương thích smoke | alert | Marker không phải chữ ký thực tế |
| 1000005 | SYN nhiều lần theo nguồn | alert | Không phân biệt số cổng, có thể nhầm retry |
| 1000006 | Marker lặp theo nguồn | alert | Chỉ lab |
| 1000007 | Marker chặn inline | drop | Chỉ lab, IDS thụ động không chặn |
| 1000010, 1000014 | Mẫu UNION SELECT trong URI/body HTTP | alert | Không bao phủ mọi SQLi, có thể báo nhầm tài liệu |
| 1000011, 1000015 | Mẫu script tag trong body/URI HTTP | alert | Không bao phủ mọi XSS, không chứng minh thực thi |
| 1000012 | Host giả lập `.invalid` và path beacon | alert | Không phải IOC malware thật |
| 1000013 | SYN aggregate theo đích | alert | Heuristic, không chứng minh DDoS |

Rule template dùng `@MSSV_HEX@`; script configure chung thay bằng ASCII hex từng byte; giữ nguyên SID tích hợp. Sensor đọc YAML package, cấu hình EVE, stream.inline, NFQ fail-open false; `-T` phải thành công mới khởi động. Cấu hình mode khớp với Gateway. Firewall không bypass queue khi không có listener; giới hạn fail-closed khi quá tải cần nghiệm thu riêng.

## 4. Đánh giá
Tạo 18 PCAP nhỏ có nhãn bằng dữ liệu hoàn toàn tổng hợp, IP dành cho tài liệu; mỗi ca chạy Suricata offline riêng và không có mạng. So sánh SID kỳ vọng với SID thực tế. Có 5 ca âm tính và 13 ca dương tính dự kiến, bao gồm từ khóa bình thường, host/path riêng lẻ và SYN ít. Cần phân biệt metrics nhị phân (có/không alert) với exact SID matching (đúng loại); không suy diễn độ chính xác trên dữ liệu mạng thật. TP/(TP+FP), TP/(TP+FN), FP/(FP+TN), (TP+TN)/N; mẫu số 0 biểu diễn null.

| Hạng mục | Kỳ vọng | Kết quả thực tế |
|---|---|---|
| Offline replay 18 ca | SID đúng, không extra/missing | Chưa chạy engine |
| IDS 13 ca live | Marker cảnh báo nhưng vẫn HTTP OK | Chưa chạy Docker |
| IPS 15 ca live | Marker block, clean OK, sensor stop fail closed | Chưa chạy Docker |
| Dashboard | Nhận đúng SID/action EVE | Chưa chạy Compose |

Kết quả unit test được cung cấp riêng. Khi có log thật, đính kèm results.json, phiên bản Suricata, ảnh EVE và Dashboard; bổ sung precision/recall/FPR từ output thực, không dùng kỳ vọng làm số liệu. Chưa đo throughput, packet loss hay mức sử dụng CPU/RAM.

## 5. Kết luận
Đã hiện thực source, rule template, cấu hình sensor và công cụ đánh giá. Chưa khẳng định hệ thống đạt hiệu quả phòng vệ thực tế cho đủ 5 nhóm tấn công. Hướng phát triển: rule từ nguồn threat intel được phép, dataset độc lập có nhãn, phân tích distinct ports theo flow, tuning theo lưu lượng nền, kiểm thử hiệu năng và quản lý log dài hạn, xác thực TLS ở endpoint. Không chặn tự động heuristic chưa được đánh giá.

## Tài liệu tham khảo
- https://docs.suricata.io/en/suricata-6.0.20/rules/http-keywords.html
- https://docs.suricata.io/en/suricata-6.0.20/configuration/global-thresholds.html
- https://docs.suricata.io/en/suricata-6.0.20/setting-up-ipsinline-for-linux.html
- https://docs.suricata.io/en/suricata-6.0.20/output/eve/eve-json-output.html
- https://docs.suricata.io/en/suricata-6.0.20/command-line-options.html
