# Kịch bản demo / nghiệm thu
Chỉ chạy trong mạng mô phỏng Compose. Không có đích tùy ý trong smoke.py; địa chỉ lấy từ cấu hình MSSV và kiểm tra lại. Không chạy tấn công thật, không dùng malware, không flood.

| Case | Mong đợi | Thực tế | Bằng chứng |
|---|---|---|---|
| FW-01 External → DMZ HTTP | 200 | TODO | |
| FW-02 External → Internal | timeout/blocked | TODO | |
| FW-03 DMZ → Internal | timeout/blocked | TODO | |
| TLS-01 verify CA | 200 | TODO | |
| VPN-01 VPN → Internal | 200 + handshake | TODO | |
| IDS-01 MSSV payload | SID 1000001 | TODO | |
| IDS-02 marker SQLi/XSS/C2 | SIDs 1000002–4 | TODO | |
| IDS-03 normal request | Không có marker alert tương ứng | TODO | |
| IPS-01 LAB_BLOCK | IDS: 200; IPS: blocked | TODO | |
| DET-01..05 | 5 nhóm rule thực tế theo đề | TODO | |
| UI-01 | log thật + bộ đếm | TODO | |

Chạy `python scripts/smoke.py --vpn` (bỏ --vpn nếu VPN chưa triển khai). Smoke chỉ kiểm tra kết nối, marker, alert và inline; không phải bộ test tấn công đầy đủ. Từng nhóm tự hoàn thiện DET-01..05 bằng fixture/PCAP hoặc traffic lab hợp pháp, có ground truth. Đo trước/sau chính sách, số gói/latency, false positive/negative. Video: trình bày sơ đồ, show kết nối hợp lệ, blocked, VPN, alert MSSV, IDS vs IPS, dashboard, hạn chế.
