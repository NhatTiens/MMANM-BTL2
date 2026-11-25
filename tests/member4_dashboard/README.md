# TV4 test
- `test_dashboard.py`: 15 ca unit/API chạy localhost, dữ liệu tổng hợp.
- `fixture_server.py`: UI độc lập, banner fixture.
- `browser_check.py`: kiểm tra UI bằng Playwright, lưu ảnh và CSV fixture; tùy chọn `--chromium PATH`.
- `integration_check.py`: gọi smoke chung và kiểm tra bằng chứng mới trong Dashboard khi Compose thật đang chạy; lưu artifact, không thay policy.
Các thư mục output phải chưa tồn tại. Không sử dụng fixture như bằng chứng runtime.
