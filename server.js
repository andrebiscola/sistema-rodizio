const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const ExcelJS = require('exceljs');
const PDFDocument = require('pdfkit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rodizio_secret_2024';
const DB_FILE = path.join(__dirname, 'db.json');

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

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

const DAY_NAMES = ['Dom','Seg','Ter','Qua','Qui','Sex','Sáb'];
const MONTH_NAMES = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho',
                     'Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];
const CAT_LABELS = { culto: 'C. Oficial', jovens: 'C. Jovens', meia_hora: 'M. Hora' };

// ===== AUTH =====
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Campos obrigatórios.' });
  const db = loadDB();
  if (db.users.find(u => u.email === email.toLowerCase())) return res.status(400).json({ error: 'E-mail já cadastrado.' });
  const hash = bcrypt.hashSync(password, 10);
  const id = uid();
  const userRole = role === 'admin' ? 'admin' : 'user';
  db.users.push({ id, name, email: email.toLowerCase(), password: hash, role: userRole, created_at: new Date().toISOString() });
  saveDB(db);
  const token = jwt.sign({ id, name, email: email.toLowerCase(), role: userRole }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id, name, email: email.toLowerCase(), role: userRole } });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.email === email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Credenciais inválidas.' });
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json(req.user));

// ===== GRUPOS =====
app.get('/api/groups', authMiddleware, (req, res) => {
  const db = loadDB();
  res.json(db.groups.map(g => ({ ...g, owner: db.users.find(u => u.id === g.owner_id) || null })));
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
  if (!g) return res.status(404).json({ error: 'Não encontrado.' });
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
  res.json(db.people.filter(p => p.group_id === req.params.groupId).sort((a,b) => a.order_index - b.order_index));
});

app.post('/api/groups/:groupId/people', authMiddleware, (req, res) => {
  const { name, cpf, email, phone, address, categories } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório.' });
  const db = loadDB();
  const count = db.people.filter(p => p.group_id === req.params.groupId).length;
  const person = {
    id: uid(), group_id: req.params.groupId, name,
    cpf: cpf||'', email: email||'', phone: phone||'',
    address: address||'', role: 'Organista',
    categories: categories || ['culto','jovens','meia_hora'],
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
  const { name, cpf, email, phone, address, categories } = req.body;
  const db = loadDB();
  const p = db.people.find(x => x.id === req.params.id && x.group_id === req.params.groupId);
  if (!p) return res.status(404).json({ error: 'Não encontrado.' });
  p.name = name; p.cpf = cpf||''; p.email = email||'';
  p.phone = phone||''; p.address = address||'';
  p.categories = categories || ['culto','jovens','meia_hora'];
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
app.get('/api/schedules/:groupId/:year/:semester/:category', authMiddleware, (req, res) => {
  const { groupId, year, semester, category } = req.params;
  const db = loadDB();
  const rows = db.schedules.filter(s =>
    s.group_id === groupId && s.year === parseInt(year) &&
    s.semester === parseInt(semester) && s.category === category
  );
  const schedule = {};
  rows.forEach(r => { schedule[r.date_key] = r.person_name; });
  res.json(schedule);
});

app.post('/api/schedules/:groupId/:year/:semester/:category', authMiddleware, (req, res) => {
  const { groupId, year, semester, category } = req.params;
  const { schedule } = req.body;
  const db = loadDB();
  db.schedules = db.schedules.filter(s =>
    !(s.group_id === groupId && s.year === parseInt(year) &&
      s.semester === parseInt(semester) && s.category === category)
  );
  Object.entries(schedule).forEach(([date_key, person_name]) => {
    db.schedules.push({ id: uid(), group_id: groupId, year: parseInt(year), semester: parseInt(semester), category, date_key, person_name });
  });
  saveDB(db);
  res.json({ ok: true });
});

app.put('/api/schedules/:groupId/:year/:semester/:category/:dateKey', authMiddleware, (req, res) => {
  const { groupId, year, semester, category, dateKey } = req.params;
  const db = loadDB();
  const s = db.schedules.find(x =>
    x.group_id === groupId && x.year === parseInt(year) &&
    x.semester === parseInt(semester) && x.category === category &&
    x.date_key === dateKey
  );
  if (s) s.person_name = req.body.personName;
  saveDB(db);
  res.json({ ok: true });
});

// ===== EXPORTAR XLSX =====
app.get('/api/export/xlsx/:groupId/:year/:semester', authMiddleware, async (req, res) => {
  const { groupId, year, semester } = req.params;
  const db = loadDB();
  const group = db.groups.find(g => g.id === groupId);
  if (!group) return res.status(404).json({ error: 'Grupo não encontrado.' });

  const categories = ['meia_hora', 'culto', 'jovens'];
  const catLabels = { meia_hora: 'M. HORA', culto: 'C. OFICIAL', jovens: 'C. JOVENS' };
  const startMonth = parseInt(semester) === 1 ? 0 : 6;
  const endMonth = parseInt(semester) === 1 ? 5 : 11;

  // Montar mapa de schedules
  const schedMap = {};
  categories.forEach(cat => { schedMap[cat] = {}; });
  db.schedules.filter(s =>
    s.group_id === groupId && s.year === parseInt(year) && s.semester === parseInt(semester)
  ).forEach(s => {
    if (schedMap[s.category]) schedMap[s.category][s.date_key] = s.person_name;
  });

  const workbook = new ExcelJS.Workbook();
  const ws = workbook.addWorksheet('Rodízio');

  // Estilo cabeçalho
  const headerFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1a73e8' } };
  const headerFont = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
  const monthFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0d47a1' } };
  const altFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFe8f0fe' } };
  const border = { style: 'thin', color: { argb: 'FFcccccc' } };
  const allBorders = { top: border, left: border, bottom: border, right: border };

  let currentRow = 1;

  for (let m = startMonth; m <= endMonth; m++) {
    const daysInMonth = new Date(parseInt(year), m + 1, 0).getDate();

    // Cabeçalho do mês
    const monthRow = ws.getRow(currentRow);
    ws.mergeCells(currentRow, 1, currentRow, 6);
    const monthCell = ws.getCell(currentRow, 1);
    monthCell.value = MONTH_NAMES[m].toUpperCase() + ' ' + year;
    monthCell.fill = monthFill;
    monthCell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 13 };
    monthCell.alignment = { horizontal: 'center', vertical: 'middle' };
    monthRow.height = 24;
    currentRow++;

    // Cabeçalho das colunas
    const cols = ['DIA', 'DIA SEM.', 'M. HORA', 'C. OFICIAL', 'C. JOVENS', ''];
    const headerRow = ws.getRow(currentRow);
    cols.forEach((col, i) => {
      const cell = ws.getCell(currentRow, i + 1);
      cell.value = col;
      cell.fill = headerFill;
      cell.font = headerFont;
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
      cell.border = allBorders;
    });
    headerRow.height = 20;
    currentRow++;

    // Dias
    let rowCount = 0;
    for (let d = 1; d <= daysInMonth; d++) {
      const date = new Date(parseInt(year), m, d);
      const dow = date.getDay();
      if (!group.days.includes(dow)) continue;

      const dk = year + '-' + String(m+1).padStart(2,'0') + '-' + String(d).padStart(2,'0');
      const row = ws.getRow(currentRow);
      const isAlt = rowCount % 2 === 1;

      const values = [
        d,
        DAY_NAMES[dow],
        schedMap['meia_hora'][dk] || '',
        schedMap['culto'][dk] || '',
        schedMap['jovens'][dk] || '',
        ''
      ];

      values.forEach((val, i) => {
        const cell = ws.getCell(currentRow, i + 1);
        cell.value = val;
        cell.alignment = { horizontal: 'center', vertical: 'middle' };
        cell.border = allBorders;
        if (isAlt) cell.fill = altFill;
      });

      row.height = 18;
      currentRow++;
      rowCount++;
    }

    currentRow++; // espaço entre meses
  }

  // Largura das colunas
  ws.getColumn(1).width = 8;
  ws.getColumn(2).width = 10;
  ws.getColumn(3).width = 16;
  ws.getColumn(4).width = 16;
  ws.getColumn(5).width = 16;
  ws.getColumn(6).width = 4;

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="rodizio_' + group.name.replace(/\s/g,'_') + '_' + year + '_' + semester + 'sem.xlsx"');
  await workbook.xlsx.write(res);
  res.end();
});

// ===== EXPORTAR PDF =====
app.get('/api/export/pdf/:groupId/:year/:semester', authMiddleware, (req, res) => {
  const { groupId, year, semester } = req.params;
  const db = loadDB();
  const group = db.groups.find(g => g.id === groupId);
  if (!group) return res.status(404).json({ error: 'Grupo não encontrado.' });

  const categories = ['meia_hora', 'culto', 'jovens'];
  const catLabels = { meia_hora: 'M. HORA', culto: 'C. OFICIAL', jovens: 'C. JOVENS' };
  const startMonth = parseInt(semester) === 1 ? 0 : 6;
  const endMonth = parseInt(semester) === 1 ? 5 : 11;

  const schedMap = {};
  categories.forEach(cat => { schedMap[cat] = {}; });
  db.schedules.filter(s =>
    s.group_id === groupId && s.year === parseInt(year) && s.semester === parseInt(semester)
  ).forEach(s => {
    if (schedMap[s.category]) schedMap[s.category][s.date_key] = s.person_name;
  });

  const doc = new PDFDocument({ margin: 30, size: 'A4' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="rodizio_' + group.name.replace(/\s/g,'_') + '_' + year + '_' + semester + 'sem.pdf"');
  doc.pipe(res);

  // Título
  doc.fontSize(16).fillColor('#0d47a1').text('Sistema de Rodízio', { align: 'center' });
  doc.fontSize(13).fillColor('#333').text(group.name + ' — ' + (parseInt(semester) === 1 ? '1º' : '2º') + ' Semestre de ' + year, { align: 'center' });
  doc.moveDown(0.5);

  const colWidths = [35, 40, 110, 110, 110];
  const colHeaders = ['DIA', 'DIA SEM.', 'M. HORA', 'C. OFICIAL', 'C. JOVENS'];
  const tableLeft = 30;
  const rowHeight = 18;

  for (let m = startMonth; m <= endMonth; m++) {
    const daysInMonth = new Date(parseInt(year), m + 1, 0).getDate();

    // Verificar espaço na página
    if (doc.y > 680) doc.addPage();

    // Cabeçalho do mês
    const mY = doc.y;
    const totalW = colWidths.reduce((a,b) => a+b, 0);
    doc.rect(tableLeft, mY, totalW, 22).fill('#0d47a1');
    doc.fontSize(11).fillColor('white')
       .text(MONTH_NAMES[m].toUpperCase() + ' ' + year, tableLeft, mY + 5, { width: totalW, align: 'center' });
    doc.y = mY + 24;

    // Cabeçalho das colunas
    let hY = doc.y;
    doc.rect(tableLeft, hY, totalW, rowHeight).fill('#1a73e8');
    let hX = tableLeft;
    colHeaders.forEach((h, i) => {
      doc.fontSize(8).fillColor('white')
         .text(h, hX + 2, hY + 5, { width: colWidths[i] - 4, align: 'center' });
      hX += colWidths[i];
    });
    doc.y = hY + rowHeight;

    // Linhas
    let rowCount = 0;
    for (let d = 1; d <= daysInMonth; d++) {
      const date = new Date(parseInt(year), m, d);
      const dow = date.getDay();
      if (!group.days.includes(dow)) continue;

      if (doc.y > 750) doc.addPage();

      const dk = year + '-' + String(m+1).padStart(2,'0') + '-' + String(d).padStart(2,'0');
      const rY = doc.y;
      const isAlt = rowCount % 2 === 1;

      if (isAlt) doc.rect(tableLeft, rY, totalW, rowHeight).fill('#e8f0fe');
      else doc.rect(tableLeft, rY, totalW, rowHeight).fill('white');

      doc.rect(tableLeft, rY, totalW, rowHeight).stroke('#cccccc');

      const vals = [
        String(d),
        DAY_NAMES[dow],
        schedMap['meia_hora'][dk] || '—',
        schedMap['culto'][dk] || '—',
        schedMap['jovens'][dk] || '—'
      ];

      let cX = tableLeft;
      vals.forEach((val, i) => {
        doc.fontSize(8).fillColor('#333')
           .text(val, cX + 2, rY + 5, { width: colWidths[i] - 4, align: 'center' });
        cX += colWidths[i];
      });

      doc.y = rY + rowHeight;
      rowCount++;
    }

    doc.moveDown(0.8);
  }

  doc.end();
});

// ===== FALLBACK =====
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log('Servidor rodando na porta ' + PORT));