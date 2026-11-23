require('dotenv').config();
const express=require('express'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),
crypto=require('crypto'),fs=require('fs'),path=require('path'),nodemailer=require('nodemailer'),rateLimit=require('express-rate-limit');
const{JWT_SECRET,NODE_ENV}=process.env,PORT=process.env.PORT||3000;
if(!JWT_SECRET||JWT_SECRET.length<16){console.error('Thiếu JWT_SECRET (>=16 ký tự) trong .env');process.exit(1)}

/* ---------- Database (SQLite) ---------- */
const db=new Database(process.env.DB_FILE||path.join(__dirname,'data.db'));
db.pragma('journal_mode=WAL');db.pragma('foreign_keys=ON');
db.exec(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));

const norm=v=>{v=String(v||'').trim();return v.includes('@')?v.toLowerCase():v.replace(/[\s.-]/g,'')};
const valid=c=>/^0\d{9}$/.test(c)||/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c);
const find=c=>db.prepare(`SELECT * FROM users WHERE ${c.includes('@')?'email':'phone'}=?`).get(c);
const hash=(code,c)=>crypto.createHash('sha256').update(`${code}:${c}:${JWT_SECRET}`).digest('hex');
const sign=id=>jwt.sign({id},JWT_SECRET,{expiresIn:'7d'});
if(process.env.ADMIN_EMAIL&&process.env.ADMIN_PASSWORD&&!find(process.env.ADMIN_EMAIL.toLowerCase()))
  db.prepare("INSERT INTO users(name,email,pw_hash,address,role) VALUES('Quản trị viên',?,?,'','admin')").run(process.env.ADMIN_EMAIL.toLowerCase(),bcrypt.hashSync(process.env.ADMIN_PASSWORD,10));

/* ---------- Gửi OTP: email (SMTP) hoặc SMS (Twilio) ---------- */
const mailer=process.env.SMTP_USER?nodemailer.createTransport({host:process.env.SMTP_HOST||'smtp.gmail.com',port:+(process.env.SMTP_PORT||465),secure:+(process.env.SMTP_PORT||465)===465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}}):null;
async function deliver(c,msg){
  if(c.includes('@')){
    if(process.env.BREVO_API_KEY){const r=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':process.env.BREVO_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({sender:{name:'Nick Fashion',email:process.env.MAIL_FROM},to:[{email:c}],subject:'Mã xác thực Nick Fashion',textContent:msg})});if(!r.ok)throw new Error('Brevo '+r.status);return true}
    if(mailer){await mailer.sendMail({from:`Nick Fashion <${process.env.SMTP_USER}>`,to:c,subject:'Mã xác thực Nick Fashion',text:msg});return true}}
  else if(process.env.TWILIO_SID){const{TWILIO_SID:s,TWILIO_TOKEN:t,TWILIO_FROM:f}=process.env;
    const r=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${s}/Messages.json`,{method:'POST',headers:{Authorization:'Basic '+Buffer.from(`${s}:${t}`).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({To:'+84'+c.slice(1),From:f,Body:msg})});
    if(!r.ok)throw new Error('SMS provider '+r.status);return true}
  if(NODE_ENV==='production')throw new Error('Chưa cấu hình dịch vụ gửi OTP');
  console.log(`[DEV] OTP cho ${c}: ${msg}`);return false}

/* ---------- App ---------- */
const app=express();app.use(express.json({limit:'50kb'}));app.use(express.static(path.join(__dirname,'public')));
const bad=(res,m,c=400)=>res.status(c).json({error:m});
const lim=(ms,max)=>rateLimit({windowMs:ms,max,standardHeaders:true,legacyHeaders:false,message:{error:'Bạn thao tác quá nhiều lần, hãy thử lại sau'}});
const auth=(req,res,next)=>{try{const t=jwt.verify((req.headers.authorization||'').slice(7),JWT_SECRET);
  const u=db.prepare('SELECT id,name,phone,email,address,role FROM users WHERE id=?').get(t.id);if(!u)throw 0;req.user=u;next()}catch{bad(res,'Vui lòng đăng nhập',401)}};
const admin=(req,res,next)=>req.user.role==='admin'?next():bad(res,'Không có quyền truy cập',403);

/* Đăng ký bằng OTP */
app.post('/api/otp/send',lim(3600e3,10),async(req,res)=>{try{
  const c=norm(req.body.contact);if(!valid(c))return bad(res,'Số điện thoại hoặc email không hợp lệ');
  if(find(c))return bad(res,'Tài khoản đã tồn tại, hãy đăng nhập',409);
  const last=db.prepare('SELECT created_at FROM otps WHERE contact=? ORDER BY id DESC LIMIT 1').get(c);
  if(last&&Date.now()-last.created_at<60000)return bad(res,'Vui lòng đợi 60 giây rồi gửi lại',429);
  const code=String(crypto.randomInt(100000,1000000));
  db.prepare('INSERT INTO otps(contact,code_hash,expires_at,created_at) VALUES(?,?,?,?)').run(c,hash(code,c),Date.now()+300000,Date.now());
  const sent=await deliver(c,`Nick Fashion: mã xác thực của bạn là ${code}. Hiệu lực 5 phút, không chia sẻ mã này.`);
  res.json(sent||NODE_ENV!=='development'?{ok:true}:{ok:true,devCode:code});
}catch(e){console.error(e);bad(res,'Không gửi được mã OTP, hãy thử lại sau',502)}});
app.post('/api/otp/verify',lim(900e3,30),(req,res)=>{
  const c=norm(req.body.contact),code=String(req.body.code||'');
  const o=db.prepare('SELECT * FROM otps WHERE contact=? AND used=0 ORDER BY id DESC LIMIT 1').get(c);
  if(!o||Date.now()>o.expires_at)return bad(res,'Mã OTP đã hết hạn, hãy gửi lại');
  if(o.tries>=5)return bad(res,'Nhập sai quá 5 lần, hãy gửi lại mã');
  if(!crypto.timingSafeEqual(Buffer.from(hash(code,c)),Buffer.from(o.code_hash))){db.prepare('UPDATE otps SET tries=tries+1 WHERE id=?').run(o.id);return bad(res,'Mã OTP không đúng')}
  db.prepare('UPDATE otps SET used=1 WHERE id=?').run(o.id);
  res.json({token:jwt.sign({c,p:'reg'},JWT_SECRET,{expiresIn:'15m'})})});
app.post('/api/register',(req,res)=>{const{token,name,password,address}=req.body;let t;
  try{t=jwt.verify(token,JWT_SECRET);if(t.p!=='reg')throw 0}catch{return bad(res,'Phiên xác thực OTP không hợp lệ, hãy xác thực lại',401)}
  if(!name||String(password||'').length<6||!address)return bad(res,'Điền đủ họ tên, địa chỉ và mật khẩu (từ 6 ký tự)');
  if(find(t.c))return bad(res,'Tài khoản đã tồn tại',409);const em=t.c.includes('@');
  const r=db.prepare('INSERT INTO users(name,phone,email,pw_hash,address) VALUES(?,?,?,?,?)').run(String(name).trim(),em?null:t.c,em?t.c:null,bcrypt.hashSync(String(password),10),String(address).trim());
  res.json({token:sign(r.lastInsertRowid)})});
app.post('/api/login',lim(900e3,20),(req,res)=>{const u=find(norm(req.body.contact));
  if(!u||!bcrypt.compareSync(String(req.body.password||''),u.pw_hash))return bad(res,'Sai tài khoản hoặc mật khẩu',401);res.json({token:sign(u.id)})});
app.get('/api/me',auth,(req,res)=>res.json(req.user));

/* Sản phẩm & voucher */
app.get('/api/products',(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id').all().map(p=>({id:p.id,name:p.name,cat:p.category,price:p.price,sizes:JSON.parse(p.sizes),colors:JSON.parse(p.colors),stock:p.stock}))));
const vOut=v=>({code:v.code,t:v.type,v:v.value,max:v.max_off,min:v.min_order,exp:v.expires_at,lim:v.usage_limit,used:v.used});
app.get('/api/vouchers/:code',(req,res)=>{const v=db.prepare('SELECT * FROM vouchers WHERE code=?').get(req.params.code.toUpperCase());v?res.json(vOut(v)):bad(res,'Mã không tồn tại',404)});
function vcheck(code,sub){const v=db.prepare('SELECT * FROM vouchers WHERE code=?').get(code);
  if(!v)return{err:'Mã không tồn tại'};if(new Date(v.expires_at+'T23:59:59')<new Date())return{err:'Mã đã hết hạn'};
  if(v.used>=v.usage_limit)return{err:'Mã đã hết lượt sử dụng'};if(sub<v.min_order)return{err:'Đơn hàng chưa đạt giá trị tối thiểu '+v.min_order.toLocaleString('vi-VN')+'đ'};
  return{amt:v.type==='fix'?v.value:Math.min(Math.round(sub*v.value/100),v.max_off)}}

/* Đơn hàng */
const mapO=o=>({id:o.id,u:o.name||'',uid:o.user_id,addr:o.address,items:db.prepare('SELECT * FROM order_items WHERE order_id=?').all(o.id).map(l=>({id:l.product_id,name:l.name,size:l.size,color:l.color,q:l.qty,price:l.price})),
  sub:o.subtotal,disc:o.discount,vc:o.voucher||'',total:o.total,pay:o.payment,st:o.status,note:o.note,t:new Date(o.created_at.replace(' ','T')+'Z').toLocaleString('vi-VN',{timeZone:'Asia/Ho_Chi_Minh'})});
const Q='SELECT o.*,u.name FROM orders o JOIN users u ON u.id=o.user_id';
const restock=id=>db.prepare('SELECT product_id,qty FROM order_items WHERE order_id=?').all(id).forEach(l=>db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(l.qty,l.product_id));
const setSt=(id,st,note)=>db.prepare('UPDATE orders SET status=?,note=? WHERE id=?').run(st,note,id);
app.get('/api/orders',auth,(req,res)=>res.json(db.prepare(Q+' WHERE o.user_id=? ORDER BY o.rowid DESC').all(req.user.id).map(mapO)));
app.post('/api/orders',auth,(req,res)=>{const{items,voucher,payment,address,simulateFail}=req.body;
  if(req.user.role==='admin')return bad(res,'Tài khoản quản trị không thể mua hàng',403);
  if(!Array.isArray(items)||!items.length||!address||!['Ngân hàng','Ví điện tử','COD'].includes(payment))return bad(res,'Thông tin đơn hàng không hợp lệ');
  const id='NF'+Date.now().toString(36).toUpperCase()+crypto.randomInt(10,99);
  db.transaction(()=>{let sub=0;const L=[],need={};
    for(const it of items){const p=db.prepare('SELECT * FROM products WHERE id=?').get(it.id),q=Number(it.q);
      if(!p||!Number.isInteger(q)||q<1||!JSON.parse(p.sizes).includes(it.size)||!JSON.parse(p.colors).includes(it.color))throw new Error('Sản phẩm trong giỏ không hợp lệ');
      L.push({p,q,size:it.size,color:it.color});sub+=p.price*q;need[p.id]=(need[p.id]||0)+q}
    for(const l of L)if(need[l.p.id]>l.p.stock)throw new Error(`"${l.p.name}" không đủ hàng`);
    let disc=0,vc='';if(voucher){vc=String(voucher).toUpperCase();const r=vcheck(vc,sub);if(r.err)throw new Error(r.err);disc=r.amt}
    const fail=!!simulateFail&&payment!=='COD'&&NODE_ENV!=='production',st=fail?'Thanh toán lỗi':payment==='COD'?'Chờ xác nhận':'Đã thanh toán';
    db.prepare('INSERT INTO orders(id,user_id,address,subtotal,discount,voucher,total,payment,status,note) VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,req.user.id,String(address).trim(),sub,disc,vc,sub-disc,payment,st,fail?'Giao dịch lỗi nhưng đã ghi nhận trừ tiền: hệ thống đang hoàn tiền cho bạn. Voucher được giữ nguyên.':'');
    for(const l of L)db.prepare('INSERT INTO order_items(order_id,product_id,name,size,color,qty,price) VALUES(?,?,?,?,?,?,?)').run(id,l.p.id,l.p.name,l.size,l.color,l.q,l.p.price);
    if(!fail){for(const k in need)db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(need[k],k);if(vc)db.prepare('UPDATE vouchers SET used=used+1 WHERE code=?').run(vc)}
  })();res.json(mapO(db.prepare(Q+' WHERE o.id=?').get(id)))});
app.post('/api/orders/:id/cancel',auth,(req,res)=>{const o=db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(req.params.id,req.user.id);
  if(!o||!['Chờ xác nhận','Đã thanh toán'].includes(o.status))return bad(res,'Không thể hủy đơn này');
  db.transaction(()=>{restock(o.id);if(o.voucher)db.prepare('UPDATE vouchers SET used=MAX(used-1,0) WHERE code=?').run(o.voucher);
    setSt(o.id,'Đã hủy',o.payment==='COD'?'Đơn đã hủy, voucher được trả lại.':'Đơn đã hủy, tiền được hoàn về phương thức thanh toán ban đầu, voucher được trả lại.')})();res.json({ok:true})});
app.post('/api/orders/:id/return',auth,(req,res)=>{const o=db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(req.params.id,req.user.id);
  if(!o||o.status!=='Đã giao')return bad(res,'Không thể trả đơn này');setSt(o.id,'Yêu cầu trả hàng','Đang chờ shop duyệt yêu cầu trả hàng.');res.json({ok:true})});

/* Quản trị */
app.get('/api/admin/orders',auth,admin,(req,res)=>res.json(db.prepare(Q+' ORDER BY o.rowid DESC').all().map(mapO)));
app.get('/api/admin/vouchers',auth,admin,(req,res)=>res.json(db.prepare('SELECT * FROM vouchers').all().map(vOut)));
app.post('/api/admin/orders/:id/advance',auth,admin,(req,res)=>{const o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);if(!o)return bad(res,'Không tìm thấy đơn',404);
  const nx={'Chờ xác nhận':'Đang giao','Đã thanh toán':'Đang giao','Đang giao':'Đã giao'}[o.status];
  db.transaction(()=>{if(nx)setSt(o.id,nx,o.note);
    else if(o.status==='Yêu cầu trả hàng'){restock(o.id);setSt(o.id,'Đã hoàn tiền','Shop đã hoàn tiền cho đơn này.')}
    else if(o.status==='Thanh toán lỗi')setSt(o.id,'Đã hoàn tiền','Shop đã hoàn tiền cho đơn này.');
    else throw new Error('Đơn không có bước tiếp theo')})();res.json({ok:true})});
/* Quản trị: tồn kho & voucher */
app.post('/api/admin/products/:id/stock',auth,admin,(req,res)=>{
  const n=Number(req.body.stock);
  if(!Number.isInteger(n)||n<0||n>100000)return bad(res,'Số lượng phải là số nguyên từ 0 đến 100000');
  const r=db.prepare('UPDATE products SET stock=? WHERE id=?').run(n,req.params.id);
  r.changes?res.json({ok:true}):bad(res,'Không tìm thấy sản phẩm',404)});

app.post('/api/admin/vouchers/:code/limit',auth,admin,(req,res)=>{
  const n=Number(req.body.limit);
  if(!Number.isInteger(n)||n<0||n>1000000)return bad(res,'Số lượt phải là số nguyên từ 0 trở lên');
  const r=db.prepare('UPDATE vouchers SET usage_limit=? WHERE code=?').run(n,req.params.code.toUpperCase());
  r.changes?res.json({ok:true}):bad(res,'Không tìm thấy voucher',404)});

app.post('/api/admin/vouchers',auth,admin,(req,res)=>{
  const b=req.body,code=String(b.code||'').trim().toUpperCase(),value=Number(b.value),min=Number(b.min||0),limit=Number(b.limit);
  if(!/^[A-Z0-9]{3,20}$/.test(code))return bad(res,'Mã gồm 3-20 ký tự chữ hoặc số, không dấu');
  if(!Number.isInteger(value)||value<1)return bad(res,'Giá trị giảm không hợp lệ');
  if(!Number.isInteger(min)||min<0)return bad(res,'Đơn tối thiểu không hợp lệ');
  if(!Number.isInteger(limit)||limit<1)return bad(res,'Số lượt dùng phải từ 1 trở lên');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(b.exp||''))return bad(res,'Hạn dùng không hợp lệ');
  const fix=b.type==='fix';let max=null,type='fix';
  if(!fix){
    if(value>100)return bad(res,'Giảm % không được quá 100');
    max=Number(b.max);if(!Number.isInteger(max)||max<1)return bad(res,'Nhập mức giảm tối đa cho voucher %');
    type=(db.prepare("SELECT type FROM vouchers WHERE type!='fix' LIMIT 1").get()||{}).type||'pct'}
  try{db.prepare('INSERT INTO vouchers(code,type,value,max_off,min_order,expires_at,usage_limit) VALUES(?,?,?,?,?,?,?)').run(code,type,value,max,min,b.exp,limit)}
  catch(e){return bad(res,'Mã này đã tồn tại',409)}
  res.json({ok:true})});

  
app.use((err,req,res,next)=>{console.error(err);bad(res,err.message||'Lỗi máy chủ',err.status||400)});
app.listen(PORT,()=>console.log('Nick Fashion chạy tại http://localhost:'+PORT));