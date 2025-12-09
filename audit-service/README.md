# Hệ thống Audit Log với Demo Tấn công RSA PKCS#1 v1.5

**Đồ án môn học: An toàn và Bảo mật Thông tin**

---

## 👥 Danh sách thành viên nhóm

| STT | Họ và Tên | MSSV | Email | Vai trò |
|-----|-----------|------|-------|---------|
| 1 | [Vũ Nguyễn Duy Anh] | [22810310266] | [dauyanhsadg@gmail.com] | Nhóm trưởng |
| 2 | [Trịnh Thị Thu Huyền] | [22810310234] | [email2@example.com] | Thành viên |
| 3 | [Nguyễn Nhật Quang] | [22810310087] | [email3@example.com] | Thành viên |

---

## 📋 Phân chia công việc

| Thành viên | Công việc phụ trách | Tiến độ |
|------------|---------------------|---------|
| [Nhật Quang] | - Xây dựng module xác thực JWT<br>-Nghiên cứu RSA-PSS<br>- Tích hợp database PostgreSQL | ✅ Hoàn thành |
| [Duy Anh] | - Thiết kế kiến trúc hệ thống<br>- Nghiên cứu lỗ hổng RSA PKCS#1 v1.5<br>- Xây dựng demo tấn công Bleichenbacher<br>- Viết script demo so sánh | ✅ Hoàn thành |
| [Thu Huyền] | - Xây dựng API FastAPI<br>- Thiết kế database schema<br>-Nghiên cứu Ed22519<br>- Xây dựng module quản lý khóa | ✅ Hoàn thành |

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

![Docker Services Running](./docs/images/docker-services.png)
> *Hình 1: Các services đang chạy*

---

### 3. Demo tấn công RSA PKCS#1 v1.5

#### 3.1. Chạy script so sánh Secure vs Vulnerable

```bash
cd scripts
pip install -r requirements.txt
python test_secure_vs_vulnerable.py
```

Script này sẽ demo:
- ✅ Chữ ký hợp lệ được chấp nhận (cả 2 phiên bản)
- ✅ Chữ ký giả mạo bị từ chối bởi phiên bản **secure**
- ❌ Chữ ký giả mạo được chấp nhận bởi phiên bản **vulnerable**

![RSA Attack Demo](./docs/images/rsa-attack-demo.png)
> *Hình 2: Kết quả demo tấn công RSA PKCS#1 v1.5*

#### 3.2. Giải thích kết quả

| Thuật toán | Chữ ký hợp lệ | Chữ ký giả mạo |
|------------|---------------|----------------|
| `rsa-pkcs1v15` (Secure) | ✅ Accepted | ❌ Rejected |
| `rsa-pkcs1v15-vulnerable` | ✅ Accepted | ⚠️ **Accepted (LỖ HỔNG!)** |

---

### 4. Xác thực Admin với JWT

#### 4.1. Đăng nhập lấy token

```bash
python scripts/admin_auth.py
```

Hoặc sử dụng curl:

```bash
curl -X POST http://localhost/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"
```

![JWT Login](./docs/images/jwt-login.png)
> *Hình 3: Đăng nhập thành công và nhận JWT token*

#### 4.2. Thông tin đăng nhập mặc định

| Username | Password | Vai trò |
|----------|----------|---------|
| `admin` | `admin123` | Superadmin |

#### 4.3. Sử dụng token để truy cập API

```bash
# Xem thông tin user
curl http://localhost/v1/auth/me \
  -H "Authorization: Bearer <your-token>"

# Xem danh sách khóa chờ duyệt
curl http://localhost/v1/admin/keys/pending \
  -H "Authorization: Bearer <your-token>"
```

![Admin Endpoints](./docs/images/admin-endpoints.png)
> *Hình 4: Truy cập các endpoint admin với JWT*

---

### 5. Đăng ký và duyệt khóa công khai

#### 5.1. Tạo cặp khóa RSA

```bash
python scripts/generate_rsa_keys.py
```

#### 5.2. Đăng ký khóa công khai

```bash
python scripts/register_key.py --algorithm rsa-pkcs1v15-vulnerable
```

![Key Registration](./docs/images/key-registration.png)
> *Hình 5: Đăng ký khóa công khai*

#### 5.3. Duyệt khóa (Admin)

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

![Send Audit Event](./docs/images/send-audit-event.png)
> *Hình 6: Gửi audit event với chữ ký số*

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

![Grafana Dashboard](./docs/images/grafana-dashboard.png)
> *Hình 7: Dashboard giám sát hệ thống*

---

### 8. Sử dụng với Burp Suite (Penetration Testing)

Hệ thống hỗ trợ proxy qua Burp Suite để phân tích traffic:

```bash
# Chạy script với proxy Burp Suite
python scripts/test_secure_vs_vulnerable.py --proxy http://127.0.0.1:8080
```

![Burp Suite Capture](./docs/images/burp-suite.png)
> *Hình 8: Capture traffic với Burp Suite*

---

## 📸 Hình ảnh Demo

> **Hướng dẫn thêm hình ảnh:**
> 1. Tạo thư mục `docs/images/` trong project
> 2. Chụp màn hình kết quả demo
> 3. Lưu với tên file tương ứng:
>    - `docker-services.png` - Docker containers đang chạy
>    - `rsa-attack-demo.png` - Kết quả demo tấn công RSA
>    - `jwt-login.png` - Đăng nhập JWT thành công
>    - `admin-endpoints.png` - Truy cập admin API
>    - `key-registration.png` - Đăng ký khóa
>    - `send-audit-event.png` - Gửi audit event
>    - `grafana-dashboard.png` - Grafana dashboard
>    - `burp-suite.png` - Burp Suite capture

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

## 📚 Tài liệu tham khảo

1. Bleichenbacher, D. (1998). "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
2. RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2
3. CVE-2006-4339 - OpenSSL RSA Signature Forgery Vulnerability

---

## 📄 Giấy phép

Đồ án phục vụ mục đích học tập và nghiên cứu.
