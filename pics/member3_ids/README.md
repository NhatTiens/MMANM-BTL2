# Ảnh minh chứng cần bổ sung sau khi nghiệm thu
1. Suricata version và `-T` thành công.
2. Offline results.json (che MSSV nếu công bố).
3. IDS marker: HTTP OK, EVE allowed.
4. IPS marker: HTTP bị chặn, EVE blocked; clean request vẫn thành công.
5. Fail-closed và recovery khi sensor restart.
6. Dashboard hiển thị cảnh báo thật.
Không tạo ảnh/log giả làm bằng chứng. Không commit PCAP hoặc log chứa thông tin nhóm.
