# Thành viên 2 — WireGuard VPN & dịch vụ bảo mật

Branch `feature/member2-vpn`. Chỉ sửa `srcs/member2_vpn/`, `tests/member2_vpn/`, `docs/member2_vpn/`, `pics/member2_vpn/`. Không thay đổi Compose chung, TV1, TV3, TV4. Phần này dùng kết quả TV1 đã hoàn thiện (patch `TV1-Network-Firewall.patch`), không yêu cầu TV3/TV4 chạy để nghiệm thu lab riêng.

## Hợp đồng tích hợp

- Gateway External `172.28.50.254`, client VPN bên ngoài `172.28.50.20`, UDP `51820`.
- `wg0`: gateway `10.77.0.1/24`; client `10.77.0.2/24`. Gateway chỉ chấp nhận peer `10.77.0.2/32`.
- Split tunnel: `172.28.60.0/24` và `DMZ_NET` (10.(MSSV nhóm trưởng mod 200).1.0/24), không đổi default route của VPN client, không NAT tunnel. Firewall TV1 quyết định dịch vụ nào được truy cập.
- Internal HTTP `172.28.60.10:8080`; relay BTL1 `172.28.60.30:9999`; DMZ `.10` TCP 8080/8443. External không được truy cập Internal.
- HTTP fixture trả đúng JSON `{"status": "ok", "service": "dmz"}` hoặc `internal`; marker POST tối đa 4096 byte, không phản chiếu, không có database hay thực thi. HTTPS dùng CA mới, SAN IP DMZ và DNS `dmz-web`; CA công khai ở `/public-ca/root_ca.crt`.
- Hai private key WireGuard ở hai volume riêng, peer chỉ chứa public key đối tác. Không commit khóa. Không dùng `wg showconf` / `wg show all dump` để chụp ảnh vì có thể lộ khóa. `wg show wg0 latest-handshakes` và `wg show wg0 transfer` an toàn hơn.

## Chạy lab riêng (PowerShell tại root repository)

Yêu cầu Git, Python 3.10+, Docker Desktop Linux containers/WSL2 hoặc Linux có kernel WireGuard; Docker Compose v2 hỗ trợ `--wait`. Không cài WireGuard trên Windows host để chạy lab này. Dừng lab TV1/Compose chung nếu đang dùng cùng subnet (không dùng `down -v` tùy tiện). Cần áp dụng TV1 patch hoặc cập nhật `develop` đã merge TV1 trước. Nếu chưa có, nhóm trưởng merge TV1 trước khi test lab; không cherry-pick TV1 thành commit riêng trên branch TV2.

```powershell
python scripts/configure.py --leader 2213444 --mode ids
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
$lab = 'srcs/member2_vpn/compose.lab.yaml'
docker compose --env-file .env -f $lab config --quiet
docker compose --env-file .env -f $lab run --build --rm vpn-init
docker compose --env-file .env -f $lab up -d --build --wait --wait-timeout 120
docker compose --env-file .env -f $lab ps
python tests/member2_vpn/lab_check.py
```
`2213444` chỉ là ví dụ lấy từ danh sách BTL1, xác nhận MSSV nhóm trưởng thật. Lab ép VPN bật và IDS mode (không khởi chạy IDS); cấu hình chung vẫn đọc `.env`. Lab không mở port ra host/Internet. Nếu WireGuard kernel không hỗ trợ, không chuyển sang `privileged` hay `network_mode: host`; chạy trên Linux VM có hỗ trợ kernel WireGuard, ví dụ Ubuntu 22.04/24.04.

### Kiểm tra thủ công

```powershell
docker compose --env-file .env -f $lab exec vpn-client ip -4 route
docker compose --env-file .env -f $lab exec vpn-client curl --noproxy '*' -fsS --max-time 7 http://172.28.60.10:8080/
docker compose --env-file .env -f $lab exec vpn-client wg show wg0 latest-handshakes
docker compose --env-file .env -f $lab exec gateway wg show wg0 latest-handshakes
docker compose --env-file .env -f $lab exec vpn-client wg show wg0 transfer
```
Với MSSV ví dụ DMZ là `10.44.1.10`; thay IP nếu MSSV khác:
```powershell
docker compose --env-file .env -f $lab exec external-client curl --noproxy '*' -fsS --cacert /public-ca/root_ca.crt https://10.44.1.10:8443/
docker compose --env-file .env -f $lab exec external-client curl --noproxy '*' -fsS --max-time 7 http://172.28.60.10:8080/
```
Lệnh thứ hai phải thất bại; đối chiếu counter Firewall, không chỉ dựa vào timeout. `lab_check.py` tự kiểm tra cả 14 ca. Cần traffic trước khi kiểm tra handshake. Dùng `docker compose --env-file .env -f $lab logs gateway vpn-client dmz-web legacy-chat` khi gặp lỗi.

### Chat qua VPN
Hai cửa sổ PowerShell (cùng root và khai báo `$lab` ở mỗi cửa sổ):
```powershell
# Terminal A
 docker compose --env-file .env -f $lab exec -T vpn-client python /lab/chat_demo.py
# Terminal B (trong vòng 20 giây)
 docker compose --env-file .env -f $lab exec -T internal-app python /lab/chat_demo.py
```
Relay phân vai theo thứ tự kết nối; cả hai phải báo `PASS chat ...`. Demo gửi nội dung cố định đã mã hóa và nhận ACK mã hóa, không in khóa. Relay hỗ trợ nhiều phiên tuần tự, mỗi lần chỉ hai client; tối đa 1 MiB/frame, giới hạn chờ ghép cặp và idle. Client CLI BTL1 cũ được giữ nguyên để tham khảo, KHÔNG dùng để bảo mật dữ liệu thật vì in khóa và tính năng nhận file cũ chưa được kiểm định. Demo mới chỉ kiểm tra Chat, không kiểm thử truyền file. HMAC từ MSSV công khai không xác thực danh tính; RSA key trao đổi không có pin/cert. Vì vậy chỉ kết luận bảo mật nội dung với relay thụ động trong lab; WireGuard/TLS là lớp xác thực khóa riêng. Không tuyên bố miễn nhiễm MitM ở ứng dụng Chat.

### Tích hợp Compose chung
Dừng lab riêng trước bằng `docker compose --env-file .env -f $lab down` (giữ volume). Từ root:
```powershell
python scripts/configure.py --leader 2213444 --mode ids
docker compose run --build --rm vpn-init
docker compose --profile vpn up -d --build
python scripts/smoke.py --vpn
```
Compose chung mặc định vpn-client dùng image TV1 (có curl, wg; không có crypto Python). Để chạy demo Chat qua VPN, thêm overlay **của TV2** và profile legacy vào mọi lệnh Compose liên quan:
```powershell
docker compose -f compose.yaml -f srcs/member2_vpn/compose.chat.yaml --profile vpn --profile legacy up -d --build
docker compose -f compose.yaml -f srcs/member2_vpn/compose.chat.yaml exec -T vpn-client python /lab/chat_demo.py
# terminal khác:
docker compose -f compose.yaml -f srcs/member2_vpn/compose.chat.yaml exec -T internal-app python /lab/chat_demo.py
```
Shared smoke còn phụ thuộc TV3/TV4; không đánh đồng TV2 lab PASS với cả hệ thống PASS.

## Vòng đời khóa & giới hạn
- `vpn-init` chạy khi hai peer đã dừng. Sinh khóa nếu chưa tồn tại, bảo toàn private key hợp lệ, từ chối key hỏng; không tự sửa/ghi đè key hỏng. Muốn xoay khóa: dừng hệ thống, nhóm trưởng sao lưu an toàn nếu cần, xóa đúng 2 volume VPN của đúng project rồi chạy initializer; không xóa log/CA tùy tiện. Không đồng thời chạy nhiều initializer.
- Khóa WireGuard dùng quyền file 0600. Volume peer mount read-only lúc chạy. Máy có quyền Docker/root vẫn có thể đọc volume, không phải HSM.
- CA và server key mới mỗi lần process DMZ khởi động. Private file nằm trong thư mục tạm 0700, bị xóa sau khi nạp SSLContext; chỉ root certificate công khai được publish atomic. CA rotate khi restart; client cần dùng CA mới. Đây là fixture CA trong DMZ, không phải PKI sản xuất, không có kiểm tra CRL/OCSP runtime. Không cài root CA vào trust store toàn hệ thống.
- HTTP mở trong lab để IDS đọc payload; HTTPS và WireGuard mã hóa nên IDS ngoài tunnel không đọc trực tiếp payload. Suricata TV3 có thể quan sát lưu lượng sau giải mã tại gateway tùy interface/chế độ; cần nghiệm thu riêng.
- Không có VPN nhiều người, không có remote Internet thực, không có management API công khai, không có NAT hay default route qua VPN. Tất cả mạng mô phỏng cô lập.
