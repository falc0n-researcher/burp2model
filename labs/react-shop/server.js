// A small but realistic React SPA backend: JWT auth, roles, history routing fallback, REST API.
const express = require('express'), crypto = require('crypto'), path = require('path');
const app = express(); app.use(express.json());
const SECRET = 'react-demo-secret';
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const sign = p => { const h = b64({alg:'HS256',typ:'JWT'}), b = b64(p); return `${h}.${b}.${crypto.createHmac('sha256',SECRET).update(h+'.'+b).digest('base64url')}`; };
const verify = t => { try { const [h,b,s] = t.split('.'); if (crypto.createHmac('sha256',SECRET).update(h+'.'+b).digest('base64url') !== s) return null; return JSON.parse(Buffer.from(b,'base64url')); } catch { return null; } };
const users = [{id:1,email:'alice@shop.test',password:'Passw0rd!',role:'user',name:'Alice'},
               {id:2,email:'root@shop.test',password:'Adm1nPass!',role:'admin',name:'Root'},
               {id:3,email:'bob@shop.test',password:'B0bPass!word',role:'user',name:'Bob'}];
const products = Array.from({length:24},(_,i)=>({id:i+1,name:['Mug','Lamp','Desk','Chair','Pen','Book'][i%6]+' '+(i+1),price:5+i*3,featured:i<4,stock:20-i}));
const reviews = {}; const carts = {}; const orders = [];
const auth = (req,res,next) => { const m = (req.headers.authorization||'').match(/^Bearer (.+)$/); const p = m && verify(m[1]); if (!p) return res.status(401).json({error:'unauthorized'}); req.user = p; next(); };
const admin = (req,res,next) => req.user.role === 'admin' ? next() : res.status(403).json({error:'forbidden'});
app.use((req,res,next)=>{ res.set('X-Request-Id', crypto.randomUUID()); if (!req.headers.cookie) res.cookie('sid', crypto.randomBytes(12).toString('hex'), {httpOnly:true}); next(); });
app.post('/api/auth/login',(req,res)=>{ const u = users.find(x=>x.email===req.body.email&&x.password===req.body.password); if(!u) return res.status(401).json({error:'bad credentials'}); res.json({token: sign({sub:u.id,role:u.role,email:u.email}), user:{id:u.id,name:u.name,role:u.role}}); });
app.post('/api/auth/register',(req,res)=>{ if(!req.body.email||!req.body.password) return res.status(400).json({error:'missing'}); const u={id:users.length+1,email:req.body.email,password:req.body.password,role:'user',name:req.body.name||'New'}; users.push(u); res.status(201).json({id:u.id}); });
app.get('/api/products',(req,res)=>{ let r = products; if(req.query.q) r = r.filter(p=>p.name.toLowerCase().includes(String(req.query.q).toLowerCase())); if(req.query.featured) r = r.filter(p=>p.featured); const page=+req.query.page||1; res.json({items:r.slice((page-1)*12,page*12), total:r.length, page}); });
app.get('/api/products/:id',(req,res)=>{ const p = products.find(x=>x.id===+req.params.id); p?res.json(p):res.status(404).json({error:'not found'}); });
app.get('/api/products/:id/reviews',(req,res)=>res.json(reviews[req.params.id]||[]));
app.post('/api/products/:id/reviews',auth,(req,res)=>{ (reviews[req.params.id] = reviews[req.params.id]||[]).push({by:req.user.email,text:req.body.text}); res.status(201).json({ok:true}); });
app.get('/api/cart',auth,(req,res)=>res.json(carts[req.user.sub]||[]));
app.post('/api/cart/items',auth,(req,res)=>{ (carts[req.user.sub] = carts[req.user.sub]||[]).push({productId:req.body.productId,qty:req.body.qty||1}); res.status(201).json({ok:true}); });
app.delete('/api/cart/items/:pid',auth,(req,res)=>{ carts[req.user.sub]=(carts[req.user.sub]||[]).filter(i=>i.productId!==+req.params.pid); res.json({ok:true}); });
app.post('/api/orders',auth,(req,res)=>{ const o={id:orders.length+1,user:req.user.sub,items:carts[req.user.sub]||[],card:String(req.body.card||'').slice(-4)}; orders.push(o); carts[req.user.sub]=[]; res.status(201).json(o); });
app.get('/api/orders',auth,(req,res)=>res.json(orders.filter(o=>o.user===req.user.sub)));
app.get('/api/orders/:id',auth,(req,res)=>{ const o=orders.find(x=>x.id===+req.params.id); o?res.json(o):res.status(404).json({error:'not found'}); });  // no ownership check: an IDOR on purpose
app.get('/api/me',auth,(req,res)=>{ const u=users.find(x=>x.id===req.user.sub); res.json({id:u.id,email:u.email,name:u.name,role:u.role}); });
app.put('/api/me',auth,(req,res)=>{ const u=users.find(x=>x.id===req.user.sub); u.name=req.body.name||u.name; res.json({ok:true}); });
app.post('/api/me/password',auth,(req,res)=>{ const u=users.find(x=>x.id===req.user.sub); if(u.password!==req.body.current) return res.status(400).json({error:'wrong current'}); u.password=req.body.next; res.json({ok:true}); });
app.get('/api/admin/users',auth,admin,(req,res)=>res.json(users.map(({password,...u})=>u)));
app.get('/api/admin/users/:id',auth,admin,(req,res)=>{ const u=users.find(x=>x.id===+req.params.id); u?res.json({...u,password:undefined}):res.status(404).json({error:'not found'}); });
app.get('/api/admin/stats',auth,admin,(req,res)=>res.json({users:users.length,orders:orders.length}));
app.get('/api/health',(req,res)=>res.json({ok:true,version:'1.4.2'}));
app.use('/static',express.static(path.join(__dirname,'public')));
app.get(/\.(js|map|ico|css)$/,(req,res,next)=>express.static(path.join(__dirname,'public'))(req,res,()=>res.status(404).end()));
app.get(/^(?!\/api).*/,(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));   // history-API fallback
app.listen(3100,'0.0.0.0',()=>console.log('react demo on 3100'));
