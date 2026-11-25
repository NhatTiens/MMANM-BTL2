# Test TV1

- `python -m unittest discover -s tests -v` chạy offline 12 test mới của TV1 và test nhóm.
- `python tests/member1_firewall/lab_check.py` chạy sau khi đã dựng compose.lab.yaml. Không chạy test runtime khi lab chưa sẵn sàng.
- Kết quả timeout chỉ PASS khi rule DROP tương ứng tăng counter và listener đã được kiểm tra trước; các trường hợp allow phải có HTTP thành công và state counter tăng.
