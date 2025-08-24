const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

// إضافة CORS للسماح بالطلبات من التطبيق
server.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

server.use(middlewares);
server.use(jsonServer.bodyParser);

// إضافة endpoint للبحث في المنتجات
server.get('/products/search', (req, res) => {
  const { q, vendor, minPrice, maxPrice } = req.query;
  const db = router.db;
  let products = db.get('products').value();
  
  if (q) {
    products = products.filter(p => 
      p.title.toLowerCase().includes(q.toLowerCase()) ||
      p.description.toLowerCase().includes(q.toLowerCase())
    );
  }
  
  if (vendor) {
    products = products.filter(p => p.vendor === vendor);
  }
  
  if (minPrice) {
    products = products.filter(p => p.price >= parseInt(minPrice));
  }
  
  if (maxPrice) {
    products = products.filter(p => p.price <= parseInt(maxPrice));
  }
  
  res.json(products);
});

// تحديث المنتج مع التحقق من صحة البيانات
server.put('/products/:id', (req, res) => {
  const id = req.params.id;
  const db = router.db;
  
  // التحقق من وجود المنتج
  const existingProduct = db.get('products').find({ id }).value();
  if (!existingProduct) {
    return res.status(404).json({ error: 'Product not found' });
  }
  
  // التحقق من صحة البيانات المطلوبة
  const { title, price, description, vendor } = req.body;
  if (!title || !price || !description || !vendor) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const product = db.get('products')
    .find({ id })
    .assign({
      ...req.body,
      updatedAt: new Date().toISOString()
    })
    .write();
    
  res.json(product);
});

// إضافة endpoint لإدارة المفضلة
server.patch('/products/:id/favorite', (req, res) => {
  const id = req.params.id;
  const { favorite } = req.body;
  const db = router.db;
  
  const product = db.get('products')
    .find({ id })
    .assign({ favorite })
    .write();
    
  res.json(product);
});

server.use(router);
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
