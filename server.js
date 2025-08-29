// server.js
const jsonServer = require('json-server');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(middlewares);

// قاعدة بيانات وهمية (في الإنتاج استخدم قاعدة بيانات حقيقية)
let users = [];

// Middleware للتحقق من التوكن
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ✅ Auth Routes
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }
    const existingUser = users.find(u => u.email === email);
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: uuidv4(), name, email, phone: phone || null, password: hashedPassword, created_at: new Date().toISOString() };
    users.push(newUser);

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({ user: userWithoutPassword, token });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword, token });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/auth/verify', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const { password: _, ...userWithoutPassword } = user;
  res.json({ user: userWithoutPassword });
});

app.post('/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/users', authenticateToken, (req, res) => {
  res.json(users.map(({ password, ...u }) => u));
});

// ✅ Routes مخصصة
app.put('/products/:id', (req, res) => {
  const db = router.db;
  const product = db.get('products').find({ id: req.params.id }).assign(req.body).write();
  res.json(product);
});

app.post('/orders', (req, res) => {
  const db = router.db;
  const order = { ...req.body, created_at: new Date().toISOString() };
  const created = db.get('orders').insert(order).write();
  res.status(201).json(created);
});

app.patch('/orders/:id', (req, res) => {
  const db = router.db;
  const order = db.get('orders').find({ id: req.params.id }).assign(req.body).write();
  res.json(order);
});

app.get('/orders/stats', (req, res) => {
  const db = router.db;
  const orders = db.get('orders').value() || [];
  const total = orders.length;
  const counts = orders.reduce((acc, o) => {
    const s = (o.status || '').toLowerCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});
  res.json({
    total,
    processing: counts.processing || 0,
    inTransit: counts.intransit || counts['in_transit'] || counts['in-transit'] || 0,
    delivered: counts.delivered || 0,
    canceled: counts.canceled || 0,
  });
});

// ✅ باقي الـ routes الافتراضية
app.use(router);

// تشغيل السيرفر
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
