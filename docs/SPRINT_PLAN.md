# Kế hoạch triển khai (7 ngày làm việc đề xuất, không phải hạn chính thức)
| Mốc | TV1 | TV2 | TV3 | TV4 | Nhóm trưởng |
|---|---|---|---|---|---|
| Ngày 1 | Đọc policy, chạy test | Đọc VPN/service | Đọc rules/schema | Đọc schema, chạy fixture | Tạo repo, mời team, xác nhận MSSV/phạm vi |
| Ngày 2–3 | Routing, allow/deny, counter | TLS, WireGuard, dịch vụ nội bộ | Rule MSSV và tuning offline | UI, API, log fixture và test | Review PR nhỏ, chốt interface |
| Ngày 4 | Test firewall | Test VPN/TLS | Test IDS trong lab | Test API/hiển thị | Merge M1/M2, nghiệm thu kết nối |
| Ngày 5 | Phối hợp IPS | Test đường truyền | Test IDS/IPS | Tích hợp log thật | Merge M3/M4, chạy smoke |
| Ngày 6 | Đánh giá firewall | Đánh giá VPN | Đánh giá detection | Tổng hợp test/demo | Sửa lỗi tích hợp, chạy lại |
| Ngày 7 | Viết phần báo cáo | Viết phần báo cáo | Viết phần báo cáo | Tổng hợp báo cáo/video | Release PR, đóng gói theo đề |

Checklist nghiệm thu chi tiết: docs/TEAM_WORK.md. Mỗi PR có kết quả thật, thời gian và hạn chế; không ghi PASS nếu chưa chạy. Hạn thực tế do nhóm thống nhất với giảng viên (đề: sau 14 tuần học).
