# Quy trình Git — 4 thành viên
## Nhánh và quyền
`main`: bản ổn định; `develop`: tích hợp. 4 nhánh feature lâu dài (không xóa sau merge); nhóm trưởng tạo thêm `integration/<task>` cho thay đổi chung. Các nhánh feature chỉ PR về develop; develop PR về main. Không squash/rebase merge các nhánh lâu dài; dùng Create a merge commit để giữ ancestry. Không force push. CI kiểm tra đường dẫn, không phải cơ chế phân quyền theo người dùng. Trưởng nhóm duyệt PR integration, không tự nhận mọi PR là an toàn chỉ vì CI xanh.

| Nhánh | Thư mục sở hữu (trong srcs/, tests/, docs/, pics/) |
|---|---|
| feature/member1-firewall | member1_firewall/ |
| feature/member2-vpn | member2_vpn/ |
| feature/member3-ids-ips | member3_ids/ |
| feature/member4-dashboard | member4_dashboard/ |

Shared: compose.yaml, .github/, scripts/, tests/test_offline.py, README, docs/INTEGRATION.md, requirements-dev.txt, refs/. Chủ sở hữu thay đổi chung: nhóm trưởng qua integration PR có review từ module liên quan. Không đổi port, subnet, SID, API schema, log schema nếu chưa thống nhất. Module có dependency runtime nhưng không cần sửa source của người khác.

## Clone và làm việc (PowerShell)
Thay URL bằng URL thật, chọn đúng nhánh:
```powershell
git clone URL_REPO
cd MMANM-BTL2
git switch --track origin/feature/member1-firewall
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```
Mỗi lần trước khi code (working tree sạch):
```powershell
git pull --ff-only
git fetch origin
git merge origin/develop
```
Sau khi code: `git status`, stage đúng các thư mục mình sửa (không dùng git add .), `python scripts/team_guard.py --staged`, test, commit, push. Mở PR base develop, compare feature của mình. Không xóa branch sau merge. Nếu conflict: dừng, `git status`, thống nhất với chủ file; `git merge --abort` nếu chưa sẵn sàng giải quyết. Không dùng reset --hard hay force push để giải quyết conflict.

## Trưởng nhóm
Tạo repo private rỗng, publish bundle theo START_HERE.md. Mời collaborator, kiểm tra CI Actions, bật merge commits. Nếu gói GitHub hỗ trợ bảo vệ nhánh private, yêu cầu PR và tối thiểu 1 review, required checks (Offline tests / offline và Team ownership / ownership theo tên hiển thị thực tế) cho develop/main, không force push/delete; kiểm tra ruleset thực sự active. Nếu không hỗ trợ, đây chỉ là quy ước review + CI, không phải khóa push cưỡng chế. Tránh bật auto-delete branches cho feature dài hạn. Trình tự: PR M1/M2 -> M3 -> M4; mỗi PR merge commit khi check pass, sau đó chạy integration smoke trên develop. Release PR develop -> main chỉ khi nghiệm thu thật. Không cần đợi cả 4 người xong mới PR; chia PR nhỏ.

## Làm việc độc lập
Mỗi người clone vào máy riêng. Nếu nhiều người chạy lab trên cùng một Docker daemon, subnet tĩnh có thể xung đột kể cả khi đổi tên project; dùng VM/daemon riêng, không chạy song song trên cùng daemon nếu chưa quy hoạch lại subnet và port. Dashboard fixture ở `tests/member4_dashboard/fixtures` là dữ liệu synthetic, không phải minh chứng thực. IDS/Firewall/VPN cần Docker Linux hoặc Linux VM để nghiệm thu. Không chạy lab trên mạng bên ngoài.
