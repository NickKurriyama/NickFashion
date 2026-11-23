# Nick Fashion — web bán hàng (Node.js + SQLite)

## Chạy
```bash
npm install
cp .env.example .env     # rồi sửa .env (JWT_SECRET, ADMIN_*, SMTP/Twilio)
npm start                # http://localhost:3000
```
Cần Node.js 18+. Lần chạy đầu tự tạo `data.db`, bảng, sản phẩm mẫu, voucher mẫu và tài khoản admin (ADMIN_EMAIL / ADMIN_PASSWORD).

## Gửi OTP thật
- **Email (Gmail):** bật xác minh 2 bước → Tài khoản Google → Mật khẩu ứng dụng → điền `SMTP_USER` (địa chỉ Gmail) và `SMTP_PASS` (mật khẩu ứng dụng).
- **SMS:** điền `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM`. Số 0xxxxxxxxx tự đổi sang +84. Muốn dùng nhà mạng VN (eSMS, SpeedSMS…) thì sửa hàm `deliver()` trong `server.js`.
- Chưa điền thì chạy chế độ DEV: OTP in ra console và hiện trên form (chỉ khi `NODE_ENV=development`).
- Khi triển khai thật: `NODE_ENV=production`, `JWT_SECRET` dài ngẫu nhiên, chạy sau HTTPS.

## Cơ sở dữ liệu
SQLite (`data.db`, cấu trúc ở `schema.sql`): users, otps, products, vouchers, orders, order_items.
Quản lý bằng **DB Browser for SQLite** (giao diện) hoặc `sqlite3 data.db`. Ví dụ:
```sql
UPDATE products SET stock=50 WHERE id=1;
INSERT INTO vouchers(code,type,value,max_off,min_order,expires_at,usage_limit) VALUES('TET100','fix',100000,NULL,800000,'2027-02-28',200);
```
Chuyển sang PostgreSQL/MySQL: giữ schema, đổi lớp truy cập DB trong `server.js`.

## API chính
`POST /api/otp/send|verify`, `/api/register`, `/api/login`, `GET /api/me|products|orders`, `POST /api/orders`, `/api/orders/:id/cancel|return`, `GET /api/vouchers/:code`; admin: `GET /api/admin/orders|vouchers`, `POST /api/admin/orders/:id/advance`.

## Đưa lên Render (chạy lâu dài)
1. Đẩy code lên GitHub (`.env` và `data.db` đã được `.gitignore` loại).
2. Brevo: tạo tài khoản, xác minh email người gửi (Senders), tạo API key → dùng cho `BREVO_API_KEY`, `MAIL_FROM` = email đã xác minh.
3. Render → New → Blueprint → chọn repo (đọc `render.yaml`) → điền `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `BREVO_API_KEY`, `MAIL_FROM` → Apply.
4. `render.yaml` dùng gói trả phí kèm ổ đĩa `/opt/render/project/src/storage` để `data.db` không mất khi deploy/restart.
