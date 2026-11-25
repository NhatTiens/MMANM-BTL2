# Test TV3
- `python -m unittest discover -s tests -v`: test Python, không cần Docker.
- `offline_check.py`: tạo và replay PCAP nhỏ, không phát network traffic; dùng Docker image TV3; xem README module.
- `lab_check.py`: Compose project mmanm-tv3-lab, target cố định DMZ, chỉ benign markers. Chạy hai mode riêng. Không cho phép target ngoài lab.
- `pcap_cases.py`: generator fixtures có nhãn, TCP/IP checksum, không gửi socket.
- `test_ids.py`: 15 unit tests. Không nhầm với các ca engine/runtime chưa chạy.
