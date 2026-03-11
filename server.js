const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rodizio_secret_2024';

// ===== BANCO =====
const db = new sqlite3.Database('database.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    days TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS people (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cpf TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    role TEXT NOT NULL DEFAULT 'Examinadora',
    order_index INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    year INTEGER NOT NULL,
    semester INTEGER NOT NULL,
    date_key TEXT NOT NULL,
    person_name TEXT NOT NULL
  )`);
});

// ===== HELPERS DB =====
function dbGet(sql, params) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err); else resolve(row);
    });
  });
}

function dbAll(sql, params) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err); else resolve(rows);
    });
  });
}

function dbRun(sql, params) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err); else resolve(this);
    });
  });
}

// ===== MIDDLEWARES =====
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido.' });
  }
  try {
    req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Token inválido.' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  }
  next();
}

function uid() {
  return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}

// ===== AUTH =====
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Nome, e-mail e senha são obrigatórios.' });
    }
    const existing = await dbGet('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing) return res.status(400).json({ error: 'E-mail já cadastrado.' });

    const hash = bcrypt.hashSync(password, 10);
    const id = uid();
    const userRole = role === 'admin' ? 'admin' : 'user';
    await dbRun('INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
      [id, name, email.toLowerCase(), hash, userRole]);

    const token = jwt.sign({ id, name, email: email.toLowerCase(), role: userRole }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id, name, email: email.toLowerCase(), role: userRole } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json(req.user);
});

// ===== GRUPOS =====
app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const groups = await dbAll('SELECT * FROM groups ORDER BY created_at DESC', []);
    const result = await Promise.all(groups.map(async g => {
      const owner = await dbGet('SELECT id, name, email, role FROM users WHERE id = ?', [g.owner_id]);
      return { ...g, days: JSON.parse(g.days), owner };
    }));
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, days } = req.body;
    if (!name || !days || !days.length) {
      return res.status(400).json({ error: 'Nome e dias são obrigatórios.' });
    }
    const id = uid();
    await dbRun('INSERT INTO groups (id, owner_id, name, days) VALUES (?, ?, ?, ?)',
      [id, req.user.id, name, JSON.stringify(days)]);
    res.json({ id, owner_id: req.user.id, name, days });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/groups/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, days } = req.body;
    await dbRun('UPDATE groups SET name = ?, days = ? WHERE id = ?',
      [name, JSON.stringify(days), req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await dbRun('DELETE FROM groups WHERE id = ?', [req.params.id]);
    await dbRun('DELETE FROM people WHERE group_id = ?', [req.params.id]);
    await dbRun('DELETE FROM schedules WHERE group_id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ===== PESSOAS =====
app.get('/api/groups/:groupId/people', authMiddleware, async (req, res) => {
  try {
    const people = await dbAll(
      'SELECT * FROM people WHERE group_id = ? ORDER BY order_index ASC',
      [req.params.groupId]
    );
    res.json(people);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/:groupId/people', authMiddleware, async (req, res) => {
  try {
    const { name, cpf, email, phone, address, role } = req.body;
    if (!name) return res.status(400).json({ error: 'Nome é obrigatório.' });
    const countRow = await dbGet('SELECT COUNT(*) as c FROM people WHERE group_id = ?', [req.params.groupId]);
    const id = uid();
    await dbRun(
      'INSERT INTO people (id, group_id, name, cpf, email, phone, address, role, order_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, req.params.groupId, name, cpf||'', email||'', phone||'', address||'', role||'Examinadora', countRow.c]
    );
    res.json({ id, group_id: req.params.groupId, name, cpf, email, phone, address, role, order_index: countRow.c });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/groups/:groupId/people/reorder', authMiddleware, async (req, res) => {
  try {
    const { order } = req.body;
    await Promise.all(order.map((id, index) =>
      dbRun('UPDATE people SET order_index = ? WHERE id = ?', [index, id])
    ));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/groups/:groupId/people/:id', authMiddleware, async (req, res) => {
  try {
    const { name, cpf, email, phone, address, role } = req.body;
    await dbRun(
      'UPDATE people SET name=?, cpf=?, email=?, phone=?, address=?, role=? WHERE id=? AND group_id=?',
      [name, cpf||'', email||'', phone||'', address||'', role||'Examinadora', req.params.id, req.params.groupId]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/:groupId/people/:id', authMiddleware, async (req, res) => {
  try {
    await dbRun('DELETE FROM people WHERE id = ? AND group_id = ?', [req.params.id, req.params.groupId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ===== ESCALAS =====
app.get('/api/schedules/:groupId/:year/:semester', authMiddleware, async (req, res) => {
  try {
    const rows = await dbAll(
      'SELECT date_key, person_name FROM schedules WHERE group_id=? AND year=? AND semester=?',
      [req.params.groupId, parseInt(req.params.year), parseInt(req.params.semester)]
    );
    const schedule = {};
    rows.forEach(r => { schedule[r.date_key] = r.person_name; });
    res.json(schedule);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/schedules/:groupId/:year/:semester', authMiddleware, async (req, res) => {
  try {
    const { groupId, year, semester } = req.params;
    const { schedule } = req.body;
    await dbRun(
      'DELETE FROM schedules WHERE group_id=? AND year=? AND semester=?',
      [groupId, parseInt(year), parseInt(semester)]
    );
    await Promise.all(Object.entries(schedule).map(([dateKey, personName]) =>
      dbRun(
        'INSERT INTO schedules (id, group_id, year, semester, date_key, person_name) VALUES (?, ?, ?, ?, ?, ?)',
        [uid(), groupId, parseInt(year), parseInt(semester), dateKey, personName]
      )
    ));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/schedules/:groupId/:year/:semester/:dateKey', authMiddleware, async (req, res) => {
  try {
    const { groupId, year, semester, dateKey } = req.params;
    const { personName } = req.body;
    await dbRun(
      'UPDATE schedules SET person_name=? WHERE group_id=? AND year=? AND semester=? AND date_key=?',
      [personName, groupId, parseInt(year), parseInt(semester), dateKey]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ===== FALLBACK =====
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('Servidor rodando na porta ' + PORT);
});