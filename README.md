# Hệ thống Audit Log với Demo Tấn công RSA PKCS#1 v1.5

**Đồ án môn học: An toàn và Bảo mật Thông tin**

---

## 👥 Danh sách thành viên nhóm

| STT | Họ và Tên | MSSV | Email | Vai trò |
|-----|-----------|------|-------|---------|
| 1 | Vũ Nguyễn Duy Anh | 22810310266 | duyanhsadg@gmail.com | Nhóm trưởng |
| 2 | Trịnh Thị Thu Huyền | 22810310234|  | Thành viên |
| 3 | Nguyễn Nhật Quang | 22810310087 |  | Thành viên |

---

## 📋 Phân chia công việc

| Thành viên | Công việc phụ trách | Tiến độ |
|------------|---------------------|---------|
| Nhật Quang | - Xây dựng module xác thực JWT<br>-Nghiên cứu RSA-PSS<br>- Tích hợp database PostgreSQL | ✅ Hoàn thành |
| Duy Anh | - Thiết kế kiến trúc hệ thống<br>- Nghiên cứu lỗ hổng RSA PKCS#1 v1.5<br>- Xây dựng demo tấn công Bleichenbacher<br>- Viết script demo so sánh | ✅ Hoàn thành |
| Thu Huyền | - Xây dựng API FastAPI<br>- Thiết kế database schema<br>-Nghiên cứu Ed22519<br>- Xây dựng module quản lý khóa | ✅ Hoàn thành |

---

## 📖 Hướng dẫn sử dụng

### 1. Yêu cầu hệ thống

- **Docker Desktop** (Windows/Mac) hoặc Docker Engine (Linux)
- **Docker Compose** v2.0+
- **Python 3.10+** (để chạy các script demo)
- **Git** (để clone repository)

### 2. Cài đặt và khởi chạy

#### Bước 1: Clone repository

```bash
git clone <repository-url>
cd audit-service
```

#### Bước 2: Khởi động các services

```bash
docker compose up -d
```

Đợi khoảng 30 giây để các services khởi động hoàn tất.

#### Bước 3: Kiểm tra trạng thái

```bash
docker compose ps
```

Kết quả mong đợi: tất cả services ở trạng thái `running`.

<img width="1717" height="457" alt="image" src="https://github.com/user-attachments/assets/0dd4f627-9ecf-4b28-8f58-85e9a9d5c9f1" />
> *Hình 2.1: Các services đang chạy*

---

### 3. Demo tấn công RSA PKCS#1 v1.5
#### 3.1. request khai thác lỗ hổng padding 

<img width="1567" height="592" alt="image" src="https://github.com/user-attachments/assets/0d421333-0e22-4efe-9219-624e4a7a00a1" />

> *Hình 3.1: Kết quả phát hiện RSA PKCS#1 v1.5 Padding Oracle*

#### 3.2. mô phỏng tấn cổng sử dung cube root 3

<img width="794" height="408" alt="image" src="https://github.com/user-attachments/assets/46516e61-1f51-4d7f-936c-d66dfa822764" />

>*Hình 3.2 kết quả tấn công thành công với e=3*

-> request đã được gửi thành công đến server

<img width="1557" height="612" alt="image" src="https://github.com/user-attachments/assets/5172cce1-7cde-4e35-8069-6ff67d61e58a" />

>*Hình 3.4 request detail*

#### 3.3. Chạy script so sánh Secure vs Vulnerable

```bash
cd scripts
pip install -r requirements.txt
python test_secure_vs_vulnerable.py
```

Script này sẽ demo:
- ✅ Chữ ký hợp lệ được chấp nhận (cả 2 phiên bản)
- ✅ Chữ ký giả mạo bị từ chối bởi phiên bản **secure**
- ❌ Chữ ký giả mạo được chấp nhận bởi phiên bản **vulnerable**

<img width="786" height="496" alt="image" src="https://github.com/user-attachments/assets/913f95a6-3798-4731-ad9d-fcd3c67be476" />

> *Hình 3.4: Kết quả demo tấn công RSA PKCS#1 v1.5*

#### Giải thích kết quả

| Thuật toán | Chữ ký hợp lệ | Chữ ký giả mạo |
|------------|---------------|----------------|
| `rsa-pkcs1v15` (Secure) | ✅ Accepted | ❌ Rejected |
| `rsa-pkcs1v15-vulnerable` | ✅ Accepted | ⚠️ **Accepted (LỖ HỔNG!)** |

#### 3.4 Chạy script ghi event log sử dụng RSA-PSS

```bash
python log_rsa_pss_service.py
```

#### 3.4 Chạy script ghi event log sử dụng Ed25519

```bash
python log_ed25519_service.py
```

---
### 4. Đăng ký và duyệt khóa công khai

#### 4.1. Tạo cặp khóa RSA

```bash
python scripts/generate_rsa_keys.py
```

#### 4.2. Đăng ký khóa công khai

```bash
python scripts/register_key.py --algorithm rsa-pkcs1v15-vulnerable
```

<img width="525" height="672" alt="image" src="https://github.com/user-attachments/assets/52fb92f1-efa2-40c4-88e4-8c2e3189782f" />

> *Hình 4.1: Đăng ký khóa công khai*

#### 4.3. Duyệt khóa (Admin)

```bash
# Xem danh sách khóa chờ duyệt
python scripts/admin_auth.py

# Duyệt khóa qua API
curl -X POST http://localhost/v1/admin/keys/review \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"key_id": "<key-id>", "action": "approve"}'
```

---

### 6. Gửi và xác minh Audit Event

#### 6.1. Gửi event với chữ ký

```bash
python scripts/send_audit_event.py
```
hoặc sử dụng ui

<img width="526" height="662" alt="image" src="https://github.com/user-attachments/assets/d88c865c-e67b-4001-a7ac-b0369a48acd6" />

> *Hình 4.2: Giao diện gửi audit event với chữ ký số*

#### 6.2. Xem danh sách events

```bash
curl "http://localhost/v1/logs?limit=10"
```

---

### 7. Monitoring với Grafana

#### 7.1. Truy cập Grafana

- **URL:** http://localhost:3000
- **Username:** admin
- **Password:** admin

#### 7.2. Xem Dashboard

Sau khi đăng nhập, vào **Dashboards** > **Audit Log Service**

---

### 8. Sử dụng với Burp Suite (Penetration Testing)

Hệ thống hỗ trợ proxy qua Burp Suite để phân tích traffic:

```bash
# Chạy script với proxy Burp Suite
python scripts/test_secure_vs_vulnerable.py --proxy http://127.0.0.1:8080
```

---

## 🔧 Các lệnh hữu ích

| Lệnh | Mô tả |
|------|-------|
| `docker compose up -d` | Khởi động tất cả services |
| `docker compose down` | Dừng tất cả services |
| `docker compose logs -f api` | Xem logs của API |
| `docker compose build api` | Build lại API sau khi sửa code |
| `docker compose restart api` | Khởi động lại API |

---

## 📄 Giấy phép

Đồ án phục vụ mục đích học tập và nghiên cứu.
