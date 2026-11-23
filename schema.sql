CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT UNIQUE, email TEXT UNIQUE, pw_hash TEXT NOT NULL, address TEXT, role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN('customer','admin')), created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS otps(id INTEGER PRIMARY KEY, contact TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, price INTEGER NOT NULL, sizes TEXT NOT NULL, colors TEXT NOT NULL, stock INTEGER NOT NULL DEFAULT 0 CHECK(stock>=0));
CREATE TABLE IF NOT EXISTS vouchers(code TEXT PRIMARY KEY, type TEXT NOT NULL CHECK(type IN('fix','pct')), value INTEGER NOT NULL, max_off INTEGER, min_order INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL, usage_limit INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), address TEXT NOT NULL, subtotal INTEGER NOT NULL, discount INTEGER NOT NULL DEFAULT 0, voucher TEXT, total INTEGER NOT NULL, payment TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id), product_id INTEGER NOT NULL REFERENCES products(id), name TEXT NOT NULL, size TEXT, color TEXT, qty INTEGER NOT NULL, price INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
INSERT OR IGNORE INTO products(id,name,category,price,sizes,colors,stock) VALUES
(1,'Áo sơ mi Oxford','Nam',390000,'["S","M","L","XL"]','["Trắng","Navy"]',20),
(2,'Áo thun cotton basic','Nam',190000,'["S","M","L","XL"]','["Đen","Trắng","Be"]',20),
(3,'Quần tây slim-fit','Nam',450000,'["M","L","XL"]','["Đen","Navy"]',20),
(4,'Váy midi xếp ly','Nữ',520000,'["S","M","L"]','["Navy","Be"]',20),
(5,'Áo blazer dáng suông','Nữ',780000,'["S","M","L"]','["Đen","Be"]',20),
(6,'Giày sneaker tối giản','Giày dép',650000,'["38","40","42"]','["Trắng","Đen"]',20),
(7,'Túi tote da mềm','Phụ kiện',480000,'["Free"]','["Đen","Be"]',20),
(8,'Thắt lưng da','Phụ kiện',250000,'["Free"]','["Đen","Navy"]',20);
INSERT OR IGNORE INTO vouchers(code,type,value,max_off,min_order,expires_at,usage_limit) VALUES
('SUMMER50','fix',50000,NULL,500000,'2026-12-31',100),
('GIAM10','pct',10,100000,300000,'2026-12-31',100);
