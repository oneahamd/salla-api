// server.js
/**
 * Server كامل جاهز للاستخدام مع json-server كقاعدة بيانات محلية (db.json).
 * يحسن إدارة refresh tokens عبر تخزين سجل لكل توكن (jti) في جدول منفصل داخل db.json،
 * ويطبّق تدوير (rotation) وإبطال (revocation) للتوكنات لتحسين الأمان.
 *
 * قبل التشغيل:
 * - تأكد أن لديك ملف db.json في نفس المجلد يحتوي على مصفوفات: users, refreshTokens, products, orders, reviews, cart
 *   مثال مبسّط لبدأ التشغيل موجود أدناه في التعليقات داخل الكود.
 * - ضع متغيرات البيئة JWT_SECRET و REFRESH_SECRET و PORT حسب الحاجة (أو سيستخدم القيم الافتراضية).
 *
 * ملاحظات أمان:
 * - هذا إعداد مناسب للتجارب أو بيئات صغيرة؛ للإنتاج استخدم قاعدة بيانات حقيقية (Postgres/Supabase) بدل db.json.
 * - في التطبيق الحقيقي استعمل httpOnly secure cookies للـ refresh token على الويب، وعلى الموبايل خزّنها في SecureStore.
 */

const express = require('express');
const jsonServer = require('json-server');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');

const app = express();
const router = jsonServer.router(path.join(__dirname, 'db.json'));
const middlewares = jsonServer.defaults();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your-refresh-secret-key';

// Ensure db has required collections (safe-init)
function ensureCollection(name) {
  const db = router.db;
  if (!db.has(name).value()) {
    db.set(name, []).write();
  }
}
ensureCollection('users');
ensureCollection('refreshTokens');
ensureCollection('products');
ensureCollection('orders');
ensureCollection('cart');
ensureCollection('reviews');

/**
 * Helpers for DB operations (using lowdb via json-server router.db)
 */
function findUserByEmail(email) {
  return router.db.get('users').find({ email }).value();
}
function findUserByPhone(phone) {
  return router.db.get('users').find({ phone }).value();
}
function findUserById(id) {
  return router.db.get('users').find({ id }).value();
}
function createUserInDB(user) {
  router.db.get('users').push(user).write();
}
function removeUserFromDB(userId) {
  router.db.get('users').remove({ id: userId }).write();
}

/**
 * Refresh token helpers (store records with jti, user_id, expires_at, revoked, replaced_by)
 */
function saveRefreshTokenToDB({ jti, userId, expiresAt }) {
  const db = router.db;
  if (!db.get('refreshTokens').value()) db.set('refreshTokens', []).write();
  db.get('refreshTokens')
    .push({
      jti,
      user_id: userId,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString(),
      revoked: false,
      replaced_by: null,
    })
    .write();
}

function findRefreshTokenByJti(jti) {
  return router.db.get('refreshTokens').find({ jti }).value();
}

function revokeRefreshTokenByJti(jti, replacedByJti = null) {
  const db = router.db;
  const token = db.get('refreshTokens').find({ jti }).value();
  if (!token) return false;
  db.get('refreshTokens')
    .find({ jti })
    .assign({ revoked: true, replaced_by: replacedByJti })
    .write();
  return true;
}

function revokeAllRefreshTokensForUserInDB(userId) {
  const db = router.db;
  const tokens = db.get('refreshTokens').filter({ user_id: userId }).value() || [];
  tokens.forEach((t) => {
    db.get('refreshTokens').find({ jti: t.jti }).assign({ revoked: true }).write();
  });
}

/**
 * JWT helpers
 */
const generateAccessToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
const generateRefreshTokenWithJti = (payload, jti, options = {}) =>
  jwt.sign({ ...payload, jti }, REFRESH_SECRET, { expiresIn: options.expiresIn || '7d' });

/**
 * Basic middleware
 */
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(middlewares);

// Rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { message: 'Too many requests, please try again later.' },
});
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);

/**
 * Authenticate access token middleware
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

/* ------------------- Auth Routes ------------------- */

/**
 * Register
 * Accepts: { name, email?, phone?, password }
 * Requires: name + password, and at least one of email/phone
 * On success: returns { user, accessToken, refreshToken }
 */
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

    // uniqueness checks against DB
    if (email) {
      const existingEmail = findUserByEmail(email);
      if (existingEmail) return res.status(400).json({ message: 'User with this email already exists' });
    }
    if (phone) {
      const existingPhone = findUserByPhone(phone);
      if (existingPhone) return res.status(400).json({ message: 'User with this phone already exists' });
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

    createUserInDB(user);

    // create tokens
    const accessToken = generateAccessToken({ id: user.id, email: user.email, phone: user.phone });
    const jti = uuidv4();
    const refreshToken = generateRefreshTokenWithJti({ id: user.id }, jti, { expiresIn: '7d' });
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    saveRefreshTokenToDB({ jti, userId: user.id, expiresAt });

    const { password: pw, ...userWithoutPassword } = user;
    res.status(201).json({ user: userWithoutPassword, accessToken, refreshToken });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * Login
 * Accepts: { identifier, password } where identifier is email or phone
 * On success: returns { user, accessToken, refreshToken }
 */
app.post('/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ message: 'Email/Phone and password required' });

    const user = router.db.get('users').find((u) => u.email === identifier || u.phone === identifier).value();
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = generateAccessToken({ id: user.id, email: user.email, phone: user.phone });
    const jti = uuidv4();
    const refreshToken = generateRefreshTokenWithJti({ id: user.id }, jti, { expiresIn: '7d' });
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    saveRefreshTokenToDB({ jti, userId: user.id, expiresAt });

    const { password: pw, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword, accessToken, refreshToken });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * Refresh access token with rotation
 * Accepts: { refreshToken }
 * Returns: { accessToken, refreshToken } (new refresh token)
 */
app.post('/auth/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'Refresh token required' });

    jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ message: 'Invalid refresh token' });

      const userId = decoded.id;
      const jti = decoded.jti;
      if (!jti) return res.status(403).json({ message: 'Malformed refresh token' });

      const tokenRecord = findRefreshTokenByJti(jti);
      if (!tokenRecord) return res.status(403).json({ message: 'Refresh token not recognized' });
      if (tokenRecord.revoked) return res.status(403).json({ message: 'Refresh token revoked' });
      if (new Date(tokenRecord.expires_at) < new Date()) return res.status(403).json({ message: 'Refresh token expired' });

      // rotate token: revoke old, create new
      const newJti = uuidv4();
      const newRefreshToken = generateRefreshTokenWithJti({ id: userId }, newJti, { expiresIn: '7d' });
      const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      revokeRefreshTokenByJti(jti, newJti);
      saveRefreshTokenToDB({ jti: newJti, userId, expiresAt: newExpiresAt });

      const accessToken = generateAccessToken({ id: userId });

      res.json({ accessToken, refreshToken: newRefreshToken });
    });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * Logout
 * Accepts: { refreshToken? } — إذا أعطى الريفريش توكن، نلغي سجله؛ وإلا يمكن إلغاء كل توكنات المستخدم
 */
app.post('/auth/logout', authenticateToken, (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      try {
        const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
        const jti = decoded.jti;
        if (jti) revokeRefreshTokenByJti(jti);
      } catch (e) {
        // token invalid — تجاهل
      }
    } else {
      // لو لم يُرسل refresh token، يمكنك إبطال كل توكنات المستخدم (اختياري)
      // revokeAllRefreshTokensForUserInDB(req.user.id);
    }
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * Verify access token (protected)
 */
app.get('/auth/verify', authenticateToken, (req, res) => {
  try {
    const user = findUserById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const { password, ...u } = user;
    res.json({ user: u });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * Delete account (protected)
 */
app.delete('/auth/remove', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const user = findUserById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // remove user from DB
    removeUserFromDB(userId);

    // revoke all refresh tokens
    revokeAllRefreshTokensForUserInDB(userId);

    // remove associated orders/products in db (if applicable)
    const db = router.db;
    db.get('orders').remove((o) => o.user_id === userId).write();
    db.get('products').remove((p) => p.owner_id === userId).write();

    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/* ------------------- Example product/order routes (json-server backed) ------------------- */
/**
 * Note: these routes act as examples that interact with the json-server DB.
 * You can expand/secure them as needed.
 */

app.put('/products/:id', (req, res) => {
  try {
    const db = router.db;
    const product = db.get('products').find({ id: req.params.id }).assign(req.body).write();
    res.json(product);
  } catch (err) {
    console.error('PUT /products/:id error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/orders', (req, res) => {
  try {
    const db = router.db;
    const order = { ...req.body, created_at: new Date().toISOString() };
    const created = db.get('orders').push(order).write();
    // json-server returns whole collection; we will return the created order
    const inserted = db.get('orders').find(order).value();
    res.status(201).json(inserted);
  } catch (err) {
    console.error('POST /orders error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.patch('/orders/:id', (req, res) => {
  try {
    const db = router.db;
    const order = db.get('orders').find({ id: req.params.id }).assign(req.body).write();
    res.json(order);
  } catch (err) {
    console.error('PATCH /orders/:id error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/orders/stats', (req, res) => {
  try {
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
  } catch (err) {
    console.error('GET /orders/stats error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * Protected route: list users (without passwords)
 */
app.get('/users', authenticateToken, (req, res) => {
  try {
    const db = router.db;
    const users = db.get('users').value().map(({ password, ...u }) => u);
    res.json(users);
  } catch (err) {
    console.error('GET /users error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

/* ------------------- Attach json-server router for other CRUD endpoints ------------------- */
app.use(router);

/* ------------------- Start server ------------------- */
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});

/**
 * Minimal example db.json shape (ضعه في ملف db.json إذا لم يوجد)
 *
 * {
 *   "products": [],
 *   "orders": [],
 *   "cart": [],
 *   "users": [],
 *   "refreshTokens": [],
 *   "reviews": []
 * }
 *
 * بعد التشغيل يمكنك إنشاء مستخدم عبر POST /auth/register ثم تفقد db.json لتجد المستخدم وسجل refresh token في refreshTokens.
 */
