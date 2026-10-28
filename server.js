require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const secret = process.env.SESSION_SECRET;
if (!secret || secret.length < 32) {
  console.error("Set SESSION_SECRET to a random string at least 32 characters long.");
  process.exit(1);
}
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "khushbu.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','moderator'))
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, size TEXT DEFAULT '',
 price REAL NOT NULL CHECK(price >= 0), cost REAL NOT NULL DEFAULT 0 CHECK(cost >= 0),
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, order_code TEXT UNIQUE NOT NULL,
 customer_name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL,
 items_json TEXT NOT NULL, subtotal REAL NOT NULL, delivery REAL NOT NULL DEFAULT 0,
 discount REAL NOT NULL DEFAULT 0, total REAL NOT NULL, cost_total REAL NOT NULL,
 profit REAL NOT NULL, profit_percent REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','confirmed','processing','shipped','completed','cancelled')),
 note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
function seedUser(username, password, role) {
 if (!username || !password) return;
 const existing = db.prepare("SELECT id FROM users WHERE username=?").get(username);
 if (!existing) {
   const hash = bcrypt.hashSync(password, 12);
   db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(username, hash, role);
   console.log(`Created ${role} login: ${username}`);
 }
}
seedUser(process.env.ADMIN_USERNAME, process.env.ADMIN_PASSWORD, "admin");
seedUser(process.env.MODERATOR_USERNAME, process.env.MODERATOR_PASSWORD, "moderator");
if (db.prepare("SELECT COUNT(*) AS n FROM products").get().n === 0) {
 const add = db.prepare("INSERT INTO products(name,size,price,cost,active) VALUES(?,?,?,?,1)");
 const demo = db.transaction(() => {
   add.run("নমুনা আতর", "৩ মি.লি.", 150, 90);
   add.run("নমুনা আতর", "৬ মি.লি.", 280, 170);
   add.run("নমুনা আতর", "১২ মি.লি.", 500, 310);
 });
 demo();
}
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:"100kb"}));
app.use(express.urlencoded({extended:false,limit:"100kb"}));
app.use(session({
 name:"khushbu.sid", secret, resave:false, saveUninitialized:false,
 cookie:{httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:8*60*60*1000}
}));
app.use(express.static(path.join(__dirname,"public")));
const loginLimiter = rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:true,legacyHeaders:false});
function auth(req,res,next){ if(!req.session.user) return res.status(401).json({error:"লগইন প্রয়োজন"}); next(); }
function roles(...allowed){return (req,res,next)=>{if(!req.session.user)return res.status(401).json({error:"লগইন প্রয়োজন"});if(!allowed.includes(req.session.user.role))return res.status(403).json({error:"এই কাজের অনুমতি নেই"});next();};}
const validText=(v,max=200)=>typeof v==="string"&&v.trim().length>0&&v.trim().length<=max;
app.get("/api/products",(req,res)=>res.json(db.prepare("SELECT id,name,size,price FROM products WHERE active=1 ORDER BY id DESC").all()));
app.post("/api/orders",rateLimit({windowMs:60*60*1000,limit:20,standardHeaders:true,legacyHeaders:false}), (req,res)=>{
 try{
  const {customerName,phone,address,items,note=""}=req.body||{};
  if(!validText(customerName,100)||!validText(phone,30)||!validText(address,500)||!Array.isArray(items)||!items.length||items.length>30)
   return res.status(400).json({error:"নাম, ফোন, ঠিকানা ও পণ্য নির্বাচন সঠিকভাবে দিন।"});
  const chosen=[];let subtotal=0,costTotal=0;
  for(const it of items){
   const id=Number(it.productId),qty=Number(it.quantity);
   if(!Number.isInteger(id)||!Number.isInteger(qty)||qty<1||qty>50) return res.status(400).json({error:"পণ্যের পরিমাণ সঠিক নয়।"});
   const p=db.prepare("SELECT id,name,size,price,cost FROM products WHERE id=? AND active=1").get(id);
   if(!p) return res.status(400).json({error:"একটি পণ্য আর পাওয়া যাচ্ছে না। পেজ রিফ্রেশ করুন।"});
   subtotal+=p.price*qty;costTotal+=p.cost*qty;
   chosen.push({productId:p.id,name:p.name,size:p.size,unitPrice:p.price,quantity:qty,lineTotal:p.price*qty});
  }
  const delivery=0; // Admin can configure this after confirming actual delivery charge.
  const discount=0;
  const total=subtotal+delivery-discount;
  const profit=total-costTotal;
  const profitPercent=total>0?(profit/total)*100:0;
  const orderCode="KH"+Date.now().toString().slice(-8)+Math.floor(Math.random()*90+10);
  db.prepare(`INSERT INTO orders(order_code,customer_name,phone,address,items_json,subtotal,delivery,discount,total,cost_total,profit,profit_percent,note)
  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(orderCode,customerName.trim(),phone.trim(),address.trim(),JSON.stringify(chosen),subtotal,delivery,discount,total,costTotal,profit,profitPercent,String(note).slice(0,500));
  res.status(201).json({message:"অর্ডার গ্রহণ করা হয়েছে",orderCode,total});
 }catch(e){console.error(e);res.status(500).json({error:"অর্ডার সংরক্ষণ করা যায়নি। আবার চেষ্টা করুন।"});}
});
app.post("/api/login",loginLimiter,async(req,res)=>{
 const {username,password}=req.body||{};
 if(!validText(username,100)||typeof password!=="string"||password.length>200) return res.status(400).json({error:"ইউজারনেম ও পাসওয়ার্ড দিন।"});
 const user=db.prepare("SELECT id,username,password_hash,role FROM users WHERE username=?").get(username.trim());
 if(!user||!await bcrypt.compare(password,user.password_hash))return res.status(401).json({error:"লগইন তথ্য সঠিক নয়।"});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:"লগইন করা যায়নি"});req.session.user={id:user.id,username:user.username,role:user.role};res.json({username:user.username,role:user.role});});
});
app.get("/api/me",auth,(req,res)=>res.json(req.session.user));
app.post("/api/logout",auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/admin/products",roles("admin"),(req,res)=>res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all()));
app.post("/api/admin/products",roles("admin"),(req,res)=>{
 const {name,size="",price,cost}=req.body||{};
 if(!validText(name,120)||!Number.isFinite(Number(price))||Number(price)<0||!Number.isFinite(Number(cost))||Number(cost)<0)return res.status(400).json({error:"পণ্যের তথ্য সঠিক নয়।"});
 const result=db.prepare("INSERT INTO products(name,size,price,cost,active) VALUES(?,?,?,?,1)").run(name.trim(),String(size).slice(0,50),Number(price),Number(cost));
 res.status(201).json({id:result.lastInsertRowid});
});
app.patch("/api/admin/products/:id",roles("admin"),(req,res)=>{
 const id=Number(req.params.id),{name,size="",price,cost,active}=req.body||{};
 if(!Number.isInteger(id)||!validText(name,120)||!Number.isFinite(Number(price))||Number(price)<0||!Number.isFinite(Number(cost))||Number(cost)<0)return res.status(400).json({error:"পণ্যের তথ্য সঠিক নয়।"});
 const r=db.prepare("UPDATE products SET name=?,size=?,price=?,cost=?,active=? WHERE id=?").run(name.trim(),String(size).slice(0,50),Number(price),Number(cost),active?1:0,id);
 if(!r.changes)return res.status(404).json({error:"পণ্য পাওয়া যায়নি"});res.json({ok:true});
});
app.get("/api/orders",roles("admin","moderator"),(req,res)=>{
 const rows=db.prepare("SELECT * FROM orders ORDER BY id DESC LIMIT 500").all().map(o=>({...o,items:JSON.parse(o.items_json)}));
 res.json(rows);
});
app.patch("/api/orders/:id/status",roles("admin","moderator"),(req,res)=>{
 const allowed=["new","confirmed","processing","shipped","completed","cancelled"],status=req.body?.status;
 if(!allowed.includes(status))return res.status(400).json({error:"স্ট্যাটাস সঠিক নয়।"});
 const r=db.prepare("UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(status,Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:"অর্ডার পাওয়া যায়নি"});res.json({ok:true});
});
app.get("/api/reports",roles("admin"),(req,res)=>{
 const totals=db.prepare(`SELECT COUNT(*) AS orderCount,COALESCE(SUM(total),0) AS sales,COALESCE(SUM(profit),0) AS profit,
 CASE WHEN COALESCE(SUM(total),0)>0 THEN COALESCE(SUM(profit),0)*100/SUM(total) ELSE 0 END AS profitPercent
 FROM orders WHERE status!='cancelled'`).get();
 res.json(totals);
});
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("/health",(req,res)=>res.json({ok:true}));
app.listen(PORT,()=>console.log(`Khushbu order website running on http://localhost:${PORT}`));
