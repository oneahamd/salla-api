// server.js
const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = jsonServer.bodyParser;

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

// باقي الـ routes الافتراضية (GET/DELETE/pagination)
server.use(router);

const port = process.env.PORT || 3000;
server.listen(port, '0.0.0.0', () => {
  console.log(`✅ JSON Server is running on port ${port}`);
});
