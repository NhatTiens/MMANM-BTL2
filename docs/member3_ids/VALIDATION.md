# Validation TV3

- 15 unit tests riêng: cấu trúc SID, Hex MSSV, giới hạn drop, mode, cấu hình EVE, checksum PCAP, manifest, replay fixtures coverage, JSON parsing, metrics.
- Unit tests không chạy Suricata và không chứng minh rule syntax được engine chấp nhận.
- Docker Engine / Suricata binary không có ở môi trường tạo source. Chưa chạy `suricata -T`, replay 18 PCAP, live IDS/IPS, NFQUEUE, Dashboard.
- Replay: `offline_check.py` chạy trong Docker `--network none`, expected labels là mục tiêu kiểm thử. Chỉ điền kết quả thật từ `results.json`.
- Live: `lab_check.py` 13 ca IDS và 15 ca IPS (với `--fail-closed`), chỉ dùng marker lành tính. Kiểm tra log mới có action đúng, HTTP behavior, clean baseline, chính sách queue và recovery.
- Phải nghiệm thu trên Linux kernel có NFQUEUE. Không tắt firewall để chữa lỗi. Log EVE không rotation trong starter; dừng lab và lưu/xóa có chủ ý sau khi chạy.
