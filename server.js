// server.js
const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = jsonServer.bodyParser;
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';


// Middleware
app.use(cors());
app.use(express.json());

server.use(middlewares);
server.use(bodyParser);

// PUT /products/:id - تحديث منتج
server.put('/products/:id', (req, res) => {
  const id = req.params.id;
  const db = router.db;
  const product = db.get('products').find({ id }).assign(req.body).write();
  res.json(product);
});

// POST /orders - إضافة طلب جديد
server.post('/orders', (req, res) => {
  const db = router.db;
  const order = { ...req.body };

  if (!order.created_at) {
    order.created_at = new Date().toISOString();
  }

  const created = db.get('orders').insert(order).write();
  res.status(201).json(created);
});

// POST /products - إضافة منتج جديد
server.post('/products', (req, res) => {
  const db = router.db;
  const product = { ...req.body };
  if (!product.created_at) {
    product.created_at = new Date().toISOString();
  }
  const created = db.get('products').insert(product).write();
  res.status(201).json(created);
});

// PATCH /orders/:id - تعديل حالة الطلب
server.patch('/orders/:id', (req, res) => {
  const id = req.params.id;
  const db = router.db;
  const order = db.get('orders').find({ id }).assign(req.body).write();
  res.json(order);
});

// GET /orders/stats - إحصائيات الطلبات
server.get('/orders/stats', (req, res) => {
  const db = router.db;
  const orders = db.get('orders').value() || [];

  const total = orders.length;
  const counts = orders.reduce((acc, o) => {
    const s = (o.status || '').toLowerCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const inTransit = counts.intransit || counts['in_transit'] || counts['in-transit'] || 0;

  res.json({
    total,
    processing: counts.processing || 0,
    inTransit,
    delivered: counts.delivered || 0,
    canceled: counts.canceled || 0,
  });
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////


// قاعدة بيانات وهمية (في الإنتاج استخدم قاعدة بيانات حقيقية)
let users = [];

// Middleware للتحقق من التوكن
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// تسجيل حساب جديد
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    // التحقق من البيانات المطلوبة
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }
    
    // التحقق من وجود المستخدم
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }
    
    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // إنشاء المستخدم الجديد
    const newUser = {
      id: uuidv4(),
      name,
      email,
      phone: phone || null,
      password: hashedPassword,
      created_at: new Date().toISOString(),
    };
    
    users.push(newUser);
    
    // إنشاء التوكن
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // إرسال الاستجابة (بدون كلمة المرور)
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({
      user: userWithoutPassword,
      token,
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// تسجيل الدخول
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // التحقق من البيانات المطلوبة
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    // البحث عن المستخدم
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // التحقق من كلمة المرور
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // إنشاء التوكن
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // إرسال الاستجابة (بدون كلمة المرور)
    const { password: _, ...userWithoutPassword } = user;
    res.json({
      user: userWithoutPassword,
      token,
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// التحقق من صحة التوكن
app.get('/auth/verify', authenticateToken, (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
    
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// تسجيل الخروج
app.post('/auth/logout', authenticateToken, (req, res) => {
  // في التطبيق الحقيقي، يمكنك إضافة التوكن إلى قائمة سوداء
  res.json({ message: 'Logged out successfully' });
});

// الحصول على جميع المستخدمين (للاختبار فقط)
app.get('/users', authenticateToken, (req, res) => {
  const usersWithoutPasswords = users.map(({ password, ...user }) => user);
  res.json(usersWithoutPasswords);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// باقي الـ routes الافتراضية (GET/DELETE/pagination)
server.use(router);

const port = process.env.PORT || 3000;
server.listen(port, '0.0.0.0', () => {
  console.log(`✅ JSON Server is running on port ${port}`);
});
