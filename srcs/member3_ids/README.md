# Thành viên 3 – IDS/IPS Suricata

Branch: `feature/member3-ids-ips`. Phụ thuộc hạ tầng đã tích hợp TV1 + TV2 khi chạy live; offline độc lập. Chỉ sửa các thư mục `srcs/member3_ids`, `tests/member3_ids`, `docs/member3_ids`, `pics/member3_ids`.

## 1. Chức năng và giới hạn
- IDS quan sát interface External của Gateway (tìm theo 172.28.50.254/24); IPS dùng NFQUEUE 0 trong cùng network namespace. Không sửa iptables từ module TV3.
- TV1 chỉ đưa lưu lượng được Firewall cho phép vào queue. Port đã bị Firewall chặn không qua IPS. IDS thụ động không quan sát đầy đủ VPN đã giải mã hay lưu lượng giữa DMZ và Internal. IPS có thể thấy plaintext sau VPN nếu lưu lượng đi qua queue; không đọc được TLS/E2EE payload.
- Rule MSSV 1000001, marker 1000002–1000007 tương thích smoke test cũ; HTTP pattern 1000010–1000012, 1000014–1000015; aggregate SYN 1000013. Chỉ marker 1000007 dùng action drop. Các rule nghi ngờ còn lại alert để đánh giá false positives trước khi thay đổi chính sách.
- C2 dùng hostname `.invalid` và path lab, không có malware hoặc kết nối C2 thật. SYN count không đếm cổng riêng biệt và không chứng minh DoS/DDoS; ngưỡng nhỏ chỉ cho PCAP giáo dục. Không tạo scan/flood trên mạng thật. HTTP server TV2 không thực thi input, không phải server dễ tổn thương.
- EVE JSON ghi `/logs/eve.json` (alert-only, không ghi raw packet/payload); giữ schema cho TV4. Log không tự rotate; chỉ dùng lab ngắn hạn, dừng và lưu log trước khi xóa volume. Không commit log/PCAP chứa MSSV.

## 2. Kiểm tra offline (không cần TV1/TV2 chạy)
Từ repo root, PowerShell hoặc Linux; cài Docker Desktop Linux containers. `--leader` là MSSV nhóm trưởng thực tế (2213444 chỉ ví dụ).

```powershell
python -m unittest discover -s tests -v
docker build -f srcs/member3_ids/Dockerfile -t mmanm-btl2-tv3:local .
python tests/member3_ids/offline_check.py --leader 2213444 --output "$env:TEMP/tv3-eval-01"
```
Linux dùng `--output /tmp/tv3-eval-01` hoặc đường dẫn mới. Output phải chưa tồn tại. Chương trình sinh 18 PCAP có nhãn (không phát gói ra mạng), validate `suricata -T`, replay mỗi file trong container `--network none`, rồi tạo `results.json` với SID expected/seen, missing/unexpected, TP/FP/TN/FN, precision, recall, FPR, accuracy, exact match. Mỗi ca tách tiến trình để threshold không nhiễu nhau. Không có log EVE hoặc lỗi engine => dừng, không tính TN giả. Không chỉnh expected để che lỗi; phân tích và ghi lại nguyên nhân trước khi sửa rule.

## 3. Lab live TV3 (dùng Compose chung với tên project riêng)
Dừng các lab TV1/TV2/Compose khác trên máy để tránh trùng subnet. Không dùng các lệnh này trên mạng production. Không cần VPN để kiểm tra baseline IDS/IPS.

```powershell
python scripts/configure.py --leader 2213444 --mode ids --no-vpn
docker compose -p mmanm-tv3-lab --env-file .env -f compose.yaml config --quiet
docker compose -p mmanm-tv3-lab --env-file .env -f compose.yaml up -d --build --wait --wait-timeout 120 gateway dmz-web external-client suricata
python tests/member3_ids/lab_check.py
```
13 ca: runtime queue policy, clean baseline, 5 marker * HTTP + EVE action, clean after marker. Nếu `--wait` không hỗ trợ, cập nhật Compose hoặc chạy up -d rồi kiểm tra readiness thủ công.

Đổi sang IPS (cần tái tạo namespace gateway và sensor, không chỉ restart sensor):
```powershell
docker compose -p mmanm-tv3-lab --env-file .env -f compose.yaml down
python scripts/configure.py --leader 2213444 --mode ips --no-vpn
docker compose -p mmanm-tv3-lab --env-file .env -f compose.yaml up -d --build --wait --wait-timeout 120 gateway dmz-web external-client suricata
python tests/member3_ids/lab_check.py --fail-closed
```
15 ca với kiểm tra sensor down và recovery. Cần kernel hỗ trợ NFQUEUE, NET_ADMIN/NET_RAW. Không dùng `--queue-bypass`. Nếu thiếu kernel/module, dùng Linux VM hỗ trợ NFQUEUE thay vì tắt firewall. Dùng `docker compose ... logs suricata` để xem startup validation, `docker compose ... exec suricata tail -n 10 /logs/eve.json` để xem log. `--fail-closed` chỉ dùng lab cô lập: dừng sensor có chủ ý rồi khôi phục trong finally. Không coi lỗi Compose hoặc lỗi kết nối bất kỳ là thành công: test đối chiếu fresh SID/action với nguồn và đích cố định. Chạy trên máy mình rồi lưu log thực tế.

## 4. Dashboard và bàn giao
`docker compose -p mmanm-tv3-lab --env-file .env -f compose.yaml up -d --build dashboard` (đảm bảo port 8501 không bị chiếm). Dashboard đọc volume `ids_logs` ở `/data/ids/eve.json`. Các trường: event_type, timestamp, src_ip, dest_ip, alert.signature, alert.signature_id, alert.action. TV4 đọc theo cửa sổ 512 KiB cuối, không phải lịch sử toàn bộ. Không đổi schema hoặc `compose.yaml` chung. Nếu sửa template, chạy lại configure.py và recreate sensor.

Sau khi lưu bằng chứng, dừng lab với `docker compose -p mmanm-tv3-lab --env-file .env -f compose.yaml down`. `down -v` xóa toàn bộ volume lab, chỉ dùng sau khi sao lưu. Không xóa log của nhóm.

## 5. Tài liệu
`docs/member3_ids/REPORT.md`, `VALIDATION.md`, `PROGRESS.md`; `tests/member3_ids/README.md`. Tham khảo Suricata 6.0.20 docs: rules/HTTP, thresholding, EVE, NFQUEUE. Version package thực tế kiểm tra `docker run --rm --network none --entrypoint suricata mmanm-btl2-tv3:local -V`. Chưa nghiệm thu engine trên môi trường tạo source; các kết quả runtime chỉ là kỳ vọng.
