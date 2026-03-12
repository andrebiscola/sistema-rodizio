const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rodizio_secret_2024';
const DB_FILE = path.join(__dirname, 'db.json');

// ===== BANCO JSON =====
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const empty = { users: [], groups: [], people: [], schedules: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(empty, null, 2));
    return empty;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ===== MIDDLEWARES =====
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Token não fornecido.' });
  try {
    req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    next();
  } catch(e) { return res.status(401).json({ error: 'Token inválido.' }); }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso restrito.' });
  next();
}

function uid() { return Math.random().toString(36).substr(2,9) + Date.now().toString(36); }

// ===== AUTH =====
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Campos obrigatórios.' });
  const db = loadDB();
  if (db.users.find(u => u.email === email.toLowerCase())) {
    return res.status(400).json({ error: 'E-mail já cadastrado.' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const id = uid();
  const userRole = role === 'admin' ? 'admin' : 'user';
  const user = { id, name, email: email.toLowerCase(), password: hash, role: userRole, created_at: new Date().toISOString() };
  db.users.push(user);
  saveDB(db);
  const token = jwt.sign({ id, name, email: user.email, role: userRole }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id, name, email: user.email, role: userRole } });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.email === email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Credenciais inválidas.' });
  }
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json(req.user));

// ===== GRUPOS =====
app.get('/api/groups', authMiddleware, (req, res) => {
  const db = loadDB();
  const result = db.groups.map(g => ({
    ...g,
    owner: db.users.find(u => u.id === g.owner_id) || null
  }));
  res.json(result);
});

app.post('/api/groups', authMiddleware, adminMiddleware, (req, res) => {
  const { name, days } = req.body;
  if (!name || !days?.length) return res.status(400).json({ error: 'Nome e dias obrigatórios.' });
  const db = loadDB();
  const group = { id: uid(), owner_id: req.user.id, name, days, created_at: new Date().toISOString() };
  db.groups.push(group);
  saveDB(db);
  res.json(group);
});

app.put('/api/groups/:id', authMiddleware, adminMiddleware, (req, res) => {
  const { name, days } = req.body;
  const db = loadDB();
  const g = db.groups.find(x => x.id === req.params.id);
  if (!g) return res.status(404).json({ error: 'Grupo não encontrado.' });
  g.name = name; g.days = days;
  saveDB(db);
  res.json({ ok: true });
});

app.delete('/api/groups/:id', authMiddleware, adminMiddleware, (req, res) => {
  const db = loadDB();
  db.groups = db.groups.filter(x => x.id !== req.params.id);
  db.people = db.people.filter(x => x.group_id !== req.params.id);
  db.schedules = db.schedules.filter(x => x.group_id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

// ===== PESSOAS =====
app.get('/api/groups/:groupId/people', authMiddleware, (req, res) => {
  const db = loadDB();
  const people = db.people
    .filter(p => p.group_id === req.params.groupId)
    .sort((a, b) => a.order_index - b.order_index);
  res.json(people);
});

app.post('/api/groups/:groupId/people', authMiddleware, (req, res) => {
  const { name, cpf, email, phone, address, role } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório.' });
  const db = loadDB();
  const count = db.people.filter(p => p.group_id === req.params.groupId).length;
  const person = {
    id: uid(), group_id: req.params.groupId, name,
    cpf: cpf||'', email: email||'', phone: phone||'',
    address: address||'', role: role||'Examinadora',
    order_index: count, created_at: new Date().toISOString()
  };
  db.people.push(person);
  saveDB(db);
  res.json(person);
});

app.put('/api/groups/:groupId/people/reorder', authMiddleware, (req, res) => {
  const { order } = req.body;
  const db = loadDB();
  order.forEach((id, index) => {
    const p = db.people.find(x => x.id === id);
    if (p) p.order_index = index;
  });
  saveDB(db);
  res.json({ ok: true });
});

app.put('/api/groups/:groupId/people/:id', authMiddleware, (req, res) => {
  const { name, cpf, email, phone, address, role } = req.body;
  const db = loadDB();
  const p = db.people.find(x => x.id === req.params.id && x.group_id === req.params.groupId);
  if (!p) return res.status(404).json({ error: 'Pessoa não encontrada.' });
  p.name = name; p.cpf = cpf||''; p.email = email||'';
  p.phone = phone||''; p.address = address||''; p.role = role||'Examinadora';
  saveDB(db);
  res.json({ ok: true });
});

app.delete('/api/groups/:groupId/people/:id', authMiddleware, (req, res) => {
  const db = loadDB();
  db.people = db.people.filter(x => !(x.id === req.params.id && x.group_id === req.params.groupId));
  saveDB(db);
  res.json({ ok: true });
});

// ===== ESCALAS =====
app.get('/api/schedules/:groupId/:year/:semester', authMiddleware, (req, res) => {
  const db = loadDB();
  const rows = db.schedules.filter(s =>
    s.group_id === req.params.groupId &&
    s.year === parseInt(req.params.year) &&
    s.semester === parseInt(req.params.semester)
  );
  const schedule = {};
  rows.forEach(r => { schedule[r.date_key] = r.person_name; });
  res.json(schedule);
});

app.post('/api/schedules/:groupId/:year/:semester', authMiddleware, (req, res) => {
  const { groupId, year, semester } = req.params;
  const { schedule } = req.body;
  const db = loadDB();
  db.schedules = db.schedules.filter(s =>
    !(s.group_id === groupId && s.year === parseInt(year) && s.semester === parseInt(semester))
  );
  Object.entries(schedule).forEach(([date_key, person_name]) => {
    db.schedules.push({ id: uid(), group_id: groupId, year: parseInt(year), semester: parseInt(semester), date_key, person_name });
  });
  saveDB(db);
  res.json({ ok: true });
});

app.put('/api/schedules/:groupId/:year/:semester/:dateKey', authMiddleware, (req, res) => {
  const { groupId, year, semester, dateKey } = req.params;
  const db = loadDB();
  const s = db.schedules.find(x =>
    x.group_id === groupId && x.year === parseInt(year) &&
    x.semester === parseInt(semester) && x.date_key === dateKey
  );
  if (s) s.person_name = req.body.personName;
  saveDB(db);
  res.json({ ok: true });
});

// ===== FALLBACK =====
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log('Servidor rodando na porta ' + PORT));