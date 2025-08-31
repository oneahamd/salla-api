// server.js
const express = require('express');
const jsonServer = require('json-server');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fs = require('fs');

const app = express();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your-refresh-secret-key';

// -- In-memory stores (استبدل بقاعدة بيانات في الإنتاج)
let users = [];
let refreshTokens = []; // في الإنتاج خزّنها في DB ويفضل أن تكون مُجزّأة أو مؤمنة

// حاول تحميل المستخدمين من db.json إن وُجد قسم users
try {
  const dbRaw = fs.readFileSync('db.json', 'utf8');
  const dbParsed = JSON.parse(dbRaw);
  if (Array.isArray(dbParsed.users)) {
    users = dbParsed.users.map((u) => ({ ...u }));
  }
} catch (e) {
  // إذا ما وُجد db.json أو لم تحتوي على users، نستمر بقيمة افتراضية
  console.log('db.json not loaded for users (ok if fresh).');
}

// -- Middleware أساسي (ضعهم قبل أي route يستخدم req.body أو الحماية)
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(middlewares);

// -- Rate limiter (طبق قبل الـ auth routes)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 10, // عدد المحاولات المسموح بها
  message: { message: 'Too many requests, please try again later.' },
});

app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);

// -- Helpers
const generateAccessToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
const generateRefreshToken = (payload) => jwt.sign(payload, REFRESH_SECRET, { expiresIn: '7d' });

const revokeRefreshToken = (token) => {
  refreshTokens = refreshTokens.filter((t) => t !== token);
};

const revokeAllRefreshTokensForUser = (userId) => {
  refreshTokens = refreshTokens.filter((t) => {
    try {
      const decoded = jwt.verify(t, REFRESH_SECRET);
      return decoded.id !== userId;
    } catch (e) {
      return false;
    }
  });
};

// -- Middleware للتحقق من access token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ------------------- Auth Routes -------------------

// تسجيل
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    if (!name || !password) {
      return res.status(400).json({ message: 'Name and password are required' });
    }

    if (!email && !phone) {
      return res.status(400).json({ message: 'Either email or phone number is required' });
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    if (phone && !/^[+]?[0-9]{10,15}$/.test((phone || '').replace(/\s/g, ''))) {
      return res.status(400).json({ message: 'Invalid phone number format' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }
    if (name.length < 3) {
      return res.status(400).json({ message: 'Name must be at least 3 characters' });
    }

    // التحقق من عدم وجود مستخدم بنفس الإيميل أو الهاتف
    if (email) {
      const existingEmail = users.find((u) => u.email === email);
      if (existingEmail)
        return res.status(400).json({ message: 'User with this email already exists' });
    }

    if (phone) {
      const existingPhone = users.find((u) => u.phone === phone);
      if (existingPhone)
        return res.status(400).json({ message: 'User with this phone already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(),
      name,
      email: email || null,
      phone: phone || null,
      password: hashedPassword,
      created_at: new Date().toISOString(),
    };
    users.push(user);

    const accessToken = generateAccessToken({ id: user.id, email: user.email, phone: user.phone });
    const refreshToken = generateRefreshToken({
      id: user.id,
      email: user.email,
      phone: user.phone,
    });
    refreshTokens.push(refreshToken);

    const { password: pw, ...userWithoutPassword } = user;
    res.status(201).json({ user: userWithoutPassword, accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// تسجيل الدخول
app.post('/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password)
      return res.status(400).json({ message: 'Email/Phone and password required' });

    // البحث عن المستخدم بالإيميل أو الهاتف
    const user = users.find((u) => u.email === identifier || u.phone === identifier);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = generateAccessToken({ id: user.id, email: user.email, phone: user.phone });
    const refreshToken = generateRefreshToken({
      id: user.id,
      email: user.email,
      phone: user.phone,
    });
    refreshTokens.push(refreshToken);

    const { password: pw, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword, accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// تجديد الـ access token
app.post('/auth/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'Refresh token required' });

    if (!refreshTokens.includes(refreshToken))
      return res.status(403).json({ message: 'Invalid refresh token' });

    jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ message: 'Invalid refresh token' });

      const accessToken = generateAccessToken({ id: decoded.id, email: decoded.email });
      const newRefreshToken = generateRefreshToken({ id: decoded.id, email: decoded.email });

      // تدوير التوكن
      revokeRefreshToken(refreshToken);
      refreshTokens.push(newRefreshToken);

      res.json({ accessToken, refreshToken: newRefreshToken });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// تسجيل الخروج: يحذف refresh token من المخزن
app.post('/auth/logout', authenticateToken, (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) revokeRefreshToken(refreshToken);
    // اختياري: revokeAllRefreshTokensForUser(req.user.id);
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// تحقق من التوكن (مثال)
app.get('/auth/verify', authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const { password, ...u } = user;
  res.json({ user: u });
});

// حذف الحساب (يتطلب authentication)
app.delete('/auth/remove', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const idx = users.findIndex((u) => u.id === userId);
    if (idx === -1) return res.status(404).json({ message: 'User not found' });

    users.splice(idx, 1);

    revokeAllRefreshTokensForUser(userId);

    // حذف بيانات مرتبطة في json-server db (إن وُجد)
    const db = router.db;
    if (db) {
      db.get('orders')
        .remove((o) => o.user_id === userId)
        .write();
      db.get('products')
        .remove((p) => p.owner_id === userId)
        .write();
    }

    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// أمثلة routes مخصصة للـ products و orders (تستخدم json-server DB)
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

// قائمة المستخدمين (محمية)
app.get('/users', authenticateToken, (req, res) => {
  res.json(users.map(({ password, ...u }) => u));
});

// أخيراً: ربط json-server router (ضع هذا آخر شيء)
app.use(router);

// تشغيل السيرفر
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
