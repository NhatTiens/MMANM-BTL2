# Bắt đầu — nhóm trưởng (Windows PowerShell)
Gói ZIP có source để xem trước và Git bundle chứa đủ 6 nhánh. Dùng bundle để publish, không git init lại source. Không có GitHub remote thật cho đến khi nhóm trưởng tạo repository.

1. Tạo repository **Private** rỗng tên MMANM-BTL2 tại https://github.com/new (không chọn README, gitignore, license).
2. Mở PowerShell ở thư mục đã giải nén (nơi chứa MMANM-BTL2.bundle). Thay YOUR_GITHUB bằng tài khoản thật, thực hiện:

```powershell
git clone --bare .\MMANM-BTL2.bundle MMANM-BTL2.git
git -C MMANM-BTL2.git push --all https://github.com/YOUR_GITHUB/MMANM-BTL2.git
```

Kiểm tra GitHub có 6 nhánh và default main. Đăng nhập GitHub khi Git yêu cầu; không đưa token vào lệnh hoặc gửi cho người khác. Thêm 3 collaborator trong Settings. Dùng merge commit, không tự xóa feature branch. Cấu hình bảo vệ develop/main nếu gói hỗ trợ (xem docs/GIT_WORKFLOW.md).

3. Mỗi người clone **URL GitHub**, không dùng thư mục source preview chung. Ví dụ TV4:

```powershell
git clone https://github.com/YOUR_GITHUB/MMANM-BTL2.git
cd MMANM-BTL2
git switch --track origin/feature/member4-dashboard
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

Nếu đã clone từ trước, `git fetch origin` rồi `git switch --track origin/feature/member4-dashboard` (nếu đã có local branch, `git switch feature/member4-dashboard`). Mỗi thành viên sửa srcs/tests/docs/pics trong module mình, commit/push riêng và mở PR về develop. Trưởng nhóm merge develop vào main sau khi nghiệm thu.

Nếu muốn chạy Docker, xác nhận MSSV nhóm trưởng và làm theo README.md. Docker runtime chưa được xác minh trong môi trường tạo gói này. Kế hoạch 7 ngày là đề xuất; điều chỉnh theo hạn thực tế. Không sử dụng log synthetic làm minh chứng. Git CI không khóa quyền push theo người dùng; cần quy tắc review/bảo vệ nhánh và kiểm tra trên GitHub thật.
