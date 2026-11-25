# Team work – 4 thành viên
Nhóm trưởng xác nhận người nào nhận module nào; không suy đoán MSSV nhóm trưởng từ thứ tự BTL1. Mỗi thành viên tự ghi tiến độ và bằng chứng thực nghiệm ở PR.

| ID | Chủ sở hữu | Hạng mục | Phụ thuộc | Done khi |
|---|---|---|---|---|
| M1-01 | 1 | Kiểm tra subnet, routing, default-deny | config | External không vào Internal; DMZ không vào Internal |
| M1-02 | 1 | Hoàn thiện policy, counter và log sự kiện | M1-01 | Ma trận allow/drop có kết quả thực |
| M1-03 | 1 | Đánh giá stateful + NFQUEUE | 3 | Kết nối trả lời hợp lệ và fail closed được chứng minh |
| M2-01 | 2 | WireGuard key, tunnel, route | 1 | VPN handshake + truy cập Internal |
| M2-02 | 2 | TLS, BTL1 relay và client | 1 | TLS verify đúng CA; 2 client demo được chat |
| M2-03 | 2 | Quyền truy cập VPN, đánh giá | 1 | Client không VPN bị chặn, VPN đúng peer được phép |
| M3-01 | 3 | Suricata + rules MSSV | 1 | SID 1000001 alert trên log thật |
| M3-02 | 3 | Rule 5 nhóm tấn công & tuning trong lab | 1,2 | Có test dương/âm, thống kê FP/FN; marker riêng |
| M3-03 | 3 | Inline IPS | 1 | Marker LAB_BLOCK bị drop, request sạch vẫn qua |
| M4-01 | 4 | Dashboard + API, lọc và thống kê | 1,3 | Dữ liệu thật, xử lý log thiếu/garbled |
| M4-02 | 4 | Kịch bản kiểm thử tích hợp, video | 1,2,3 | Ma trận test có thời gian và minh chứng |
| M4-03 | 4 | Tổng hợp đánh giá và báo cáo | all | Chương 3, bảng kết quả không dùng số giả |

## Milestones
- M0: nhóm trưởng tạo repo, xác nhận phạm vi 2.1 + 2.2 và MSSV, tạo 4 branches/issues. Tất cả chạy unit test.
- M1: 1 dựng routing/policy; 2 tích hợp dịch vụ/VPN song song; 3 hoàn thiện rule template + test offline; 4 làm dashboard với fixture synthetic có nhãn rõ ràng.
- M2: merge firewall/services trước, rồi IDS/IPS và dashboard; cùng chạy smoke trong lab.
- M3: tinh chỉnh 5 nhóm detection, đo chỉ số, demo và nộp report. Không coi smoke marker là đầy đủ 2.2.

## Quy tắc PR
Tên PR `[M3-02] ...`; mô tả What/Why, file thay đổi, cách chạy, test expected/actual, hạn chế. Một reviewer khác module. Không merge nếu chưa test; không sửa interface chung tùy tiện. Nhóm trưởng ưu tiên merge M1/M2 sau đó M3/M4; interface đã chốt cho phép làm song song.

Cập nhật Git workflow: feature -> develop -> main; xem docs/GIT_WORKFLOW.md.
