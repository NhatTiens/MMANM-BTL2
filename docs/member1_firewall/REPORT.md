# Nội dung báo cáo kỹ thuật — Thành viên 1

## 2. Phân tích và thiết kế

### 2.1 Yêu cầu

Theo đề BTL 2.1, xây dựng mô hình mạng doanh nghiệp phân vùng Internal, DMZ, External; thiết kế Stateful Firewall; phối hợp TV2 cung cấp VPN. DMZ phải tính từ MSSV nhóm trưởng theo `10.(MSSV mod 200).1.0/24`. Đây là phần đóng góp của TV1; không thay thế phần VPN của TV2.

### 2.2 Sơ đồ mạng

```mermaid
flowchart LR
 E[External client 172.28.50.10] --- X[External 172.28.50.0/24]
 V[VPN peer 172.28.50.20] --- X
 X --- G[Gateway: IPv4 routing + Stateful Firewall]
 G --- D[DMZ 10.x.1.0/24]
 G --- I[Internal 172.28.60.0/24]
 D --- W[Web .10: TCP 8080/8443]
 I --- A[App .10: TCP 8080]
 I --- C[Chat .30: TCP 9999]
 G -. INSPECT / NFQUEUE 0 .- S[TV3 Suricata]
 G -. counters.json .-> T[TV4 Dashboard]
```

| Vùng | Subnet | Gateway | Host |
|---|---|---|---|
| External | 172.28.50.0/24 | 172.28.50.254 | .10 client; .20 VPN peer |
| DMZ | 10.x.1.0/24 | 10.x.1.254 | .10 web |
| Internal | 172.28.60.0/24 | 172.28.60.254 | .10 app; .30 chat |
| VPN tunnel | 10.77.0.0/24 | 10.77.0.1 | .2 peer |

x = MSSV nhóm trưởng mod 200; ví dụ 2213444 cho x=44 (chưa xác nhận MSSV chính thức). Ba bridge tách biệt; endpoint đặt default route qua gateway cùng subnet. Không NAT giữa các zone, giữ IP nguồn phục vụ IDS. Docker network internal và không public các cổng của lab riêng.

### 2.3 Ma trận luật

| ID | Nguồn → đích | Điều kiện | Hành động |
|---|---|---|---|
| FW_*_INVALID | INPUT/FORWARD | conntrack INVALID | DROP |
| FW_DROP_SPOOF_OR_UNKNOWN | Mỗi zone | Nguồn ngoài prefix hoặc interface không được phép | DROP |
| FW_IN_STATE | Tới gateway | ESTABLISHED,RELATED | ACCEPT |
| FW_VPN_HANDSHAKE | External .20 → gateway .254 | UDP 51820, VPN bật | ACCEPT |
| FW_FWD_STATE | Qua gateway | ESTABLISHED,RELATED, nguồn hợp lệ | INSPECT |
| FW_EXT_DMZ_WEB | External → DMZ web | TCP NEW SYN 8080,8443 | INSPECT |
| FW_INT_DMZ_WEB | Internal → DMZ web | TCP NEW SYN 8080,8443 | INSPECT |
| FW_VPN_APP | VPN peer → Internal .10 | TCP NEW SYN 8080 | INSPECT |
| FW_VPN_CHAT | VPN peer → Internal .30 | TCP NEW SYN 9999 | INSPECT |
| FW_VPN_DMZ_WEB | VPN peer → DMZ .10 | TCP NEW SYN 8080,8443 | INSPECT |
| FW_IN_DEFAULT / FW_FWD_DEFAULT | Các kết nối còn lại | Không khớp allowlist | DROP |

INPUT loopback được phép, OUTPUT mặc định ACCEPT. INSPECT nhận kết nối hợp lệ; IDS thụ động không chặn; IPS chuyển gói qua NFQUEUE 0, không bypass. Rule ESTABLISHED,RELATED cho phép phản hồi hợp lệ và lưu lượng liên quan; conntrack không xác thực nội dung ứng dụng. Không cho DMZ chủ động khởi tạo kết nối Internal hay External trực tiếp truy cập Internal.

## 3. Hiện thực và đánh giá

### 3.1 Hiện thực

`policy.py` xác minh cấu hình, tìm interface theo IP (không giả định eth0/eth1), sinh filter table và yêu cầu `iptables-restore --test` trước khi apply một lần. `start.sh` đặt policy mặc định DROP, áp dụng luật rồi mới khởi tạo VPN nếu bật. `counters.py` lưu snapshot atomic và thống kê delta có giới hạn dung lượng. `compose.lab.yaml` tạo môi trường kiểm thử độc lập; không sửa compose chung. `lab_endpoint.py` giả lập dịch vụ HTTP cho phép xác định chính xác lỗi bị firewall chặn thay vì dịch vụ không chạy.

### 3.2 Kịch bản nghiệm thu độc lập

| ID | Nguồn | Đích | Kỳ vọng | Kết quả runtime |
|---|---|---|---|---|
| FW01 | External | DMZ:8080 | HTTP 200, allow + state counter tăng | Chưa chạy |
| FW02 | External | DMZ:8443 | HTTP 200, allow + state counter tăng | Chưa chạy |
| FW03 | External | DMZ:9090 | Timeout, drop counter tăng | Chưa chạy |
| FW04 | External | Internal:8080 | Timeout, drop counter tăng | Chưa chạy |
| FW05 | DMZ | Internal:8080 | Timeout, drop counter tăng | Chưa chạy |
| FW06 | Internal | DMZ:8080 | HTTP 200, allow + state counter tăng | Chưa chạy |
| FW07 | Internal | External:8080 | Timeout, drop counter tăng | Chưa chạy |

Preflight kiểm tra listener trên từng endpoint và đường định tuyến. Snapshot phải mới và chứa danh sách rule. `lab_check.py` không nhận đích tùy ý; chỉ kiểm thử các dịch vụ của lab. HTTP giả lập tại 8443 không phải kiểm thử TLS. Cần TV2 kiểm tra TLS thật, VPN handshake và quyền truy cập; TV3 kiểm tra NFQUEUE fail-closed và verdict. Test spoofing hiện mới kiểm tra cấu trúc policy, chưa kiểm thử gói thực tế.

### 3.3 Kết quả và giới hạn

Tại thời điểm tạo patch: 12/12 unit test mới TV1, 27/27 toàn repository; kiểm tra cú pháp shell và Python đạt. Docker Engine/iptables-restore runtime không có trong môi trường tạo patch, nên chưa xác nhận policy được kernel chấp nhận hay lưu lượng đi xuyên qua bridge Docker. Cần lưu output test thật, ảnh route, rule counter, cấu hình Docker Compose và phiên bản kernel vào `pics/member1_firewall/`. Không điền kết quả runtime giả.

Nếu gặp lỗi bridge isolation hoặc subnet trùng trên máy thật, ghi lại cấu hình và phối hợp nhóm trưởng sửa hạ tầng chung bằng PR integration riêng. Endpoint trong lab có NET_ADMIN để thiết lập route: không xem đây là môi trường chống lại container có quyền quản trị. Mô hình không bảo vệ lưu lượng giữa hai host trên cùng bridge. Không dùng ngoài lab hoặc áp dụng trực tiếp lên host thật.

## 4. Kết luận phần TV1

Đã hiện thực bộ luật phân vùng IPv4, theo dõi trạng thái kết nối, giới hạn nguồn theo zone, điểm kết nối IDS/IPS và thống kê counters. Đã cung cấp lab và kịch bản đánh giá độc lập. Điều kiện hoàn thành cuối: nghiệm thu Docker runtime, sau đó tích hợp TV2/TV3/TV4 và lưu kết quả thực tế.
