const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(jsonServer.bodyParser);

// إذا بدك تضيف أي تعديل أو تحقق قبل التعديل على المنتجات
server.put('/products/:id', (req, res) => {
  const id = req.params.id;
  const db = router.db; // lowdb instance
  const product = db.get('products').find({ id }).assign(req.body).write();
  res.json(product);
});

server.use(router);
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
