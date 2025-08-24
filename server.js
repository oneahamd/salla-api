// server.js
const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = jsonServer.bodyParser;

server.use(middlewares);
server.use(bodyParser);

// Helper: safeISO
function toISO(d) {
  try { return new Date(d).toISOString(); } catch (e) { return new Date().toISOString(); }
}

// --- PUT /products/:id handler (merge/assign كما تريد)
server.put('/products/:id', (req, res) => {
  const id = req.params.id;
  const db = router.db; // lowdb instance
  // دمج التعديلات مع المنتج الحالي
  const product = db.get('products').find({ id }).assign(req.body).write();
  res.json(product);
});

// --- POST /orders: أضف created_at تلقائياً إذا مش موجود
server.post('/orders', (req, res, next) => {
  const db = router.db;
  const order = { ...req.body };

  if (!order.created_at) {
    order.created_at = new Date().toISOString();
  }

  // رجاءً لا تولّد id على الكلاينت — خلوه للسيرفر (json-server سيعطي id عند الإدخال)
  const created = db.get('orders').insert(order).write();
  res.status(201).json(created);
});

// --- POST /products: أضف created_at تلقائياً لو حاب
server.post('/products', (req, res, next) => {
  const db = router.db;
  const product = { ...req.body };
  if (!product.created_at) product.created_at = new Date().toISOString();
  const created = db.get('products').insert(product).write();
  res.status(201).json(created);
});

// --- Optional: PATCH /orders/:id (نموذجي)
server.patch('/orders/:id', (req, res) => {
  const id = req.params.id;
  const db = router.db;
  const order = db.get('orders').find({ id }).assign(req.body).write();
  res.json(order);
});

// --- GET /orders/stats : إحصائيات بسيطة حسب الحقول status
server.get('/orders/stats', (req, res) => {
  const db = router.db;
  const orders = db.get('orders').value() || [];

  const total = orders.length;
  const counts = orders.reduce((acc, o) => {
    const s = o.status || 'unknown';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  // دعم تسميات مختلفة: inTransit أو in_transit
  const inTransit = counts.inTransit || counts.in_transit || counts['in-transit'] || 0;

  res.json({
    total,
    processing: counts.processing || 0,
    inTransit,
    delivered: counts.delivered || 0,
    canceled: counts.canceled || 0,
  });
});

// --- استخدم الراوتر الافتراضي لباقي الرouten (GET, DELETE, pagination _page/_limit إلخ)
server.use(router);

const port = process.env.PORT || 3000;
server.listen(port, '0.0.0.0', () => {
  console.log(`JSON Server is running on port ${port}`);
});
