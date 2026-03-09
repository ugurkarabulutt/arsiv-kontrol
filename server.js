const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcryptjs');
const multer   = require('multer');
const { v4: uuidv4 } = require('uuid');
const path     = require('path');
const fs       = require('fs');

const app    = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const SESSION_SECRET    = process.env.SESSION_SECRET || 'arsiv-gizli-v3-2025';
const DATA_FILE         = path.join(__dirname, 'data', 'db.json');
const RULES_FILE        = path.join(__dirname, 'data', 'rules.txt');

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(__dirname));

// ── Default rules ──────────────────────────────────────────────────────────
const DEFAULT_RULES = `════════════════════════════════════════
KURAL 1 — EFENDİMİZİN SÖZLÜĞÜ
════════════════════════════════════════
Allahû Tealâ, Allah'ın, Allah'a, Allah'tan, âyet, âyet-i kerime, Kur'ân,
hadîs, hadîs-i şerif, sahâbe, Efendimiz'in, Efendimiz (S.A.V), (R.A), (A.S),
mü'min, nefs, îmân, tilâvet, huşû, daimî, inşaallah, velî, resûl, nebî,
dîn, tâbî, ni'met, ulûl'elbab, Nefs-i Emmare, Nefs-i Levvame, Nefs-i Mülhime,
Nefs-i Mutmainne, Nefs-i Radiye, Nefs-i Mardiyye, Nefs-i Tezkiye,
hidayet, takva, îmân, âlem, azîm, ebedî, ciddî, dergâh, kelâm,
Sıratı Mustakîm, Tarîki Mustakîm, kıyâmet, mahlûk, manevî, mânâ,
Rahmân, Rahîm, rızık, salâvât, şefaat, tövbe, Tövbe-i Nasuh,
Eûzubillâhimineşşeytânirracîm, Bismillâhirrahmânirrahîm

════════════════════════════════════════
KURAL 2 — İMLÂ REHBERİ (Yanlış → Doğru)
════════════════════════════════════════
Allah Teala / Allahu Teala → Allahû Tealâ
Resul → resûl
Veli → velî
Nebi → nebî
Din → dîn
Ayet → âyet
Kuran → Kur'ân
Mumin → mü'min
Tabi → tâbî
Iman → îmân
Nefis → nefs
hidâyet → hidayet
Efendimizin → Efendimiz'in
Nimet → ni'met
Sahabe → sahâbe
İnşallah → inşaallah
Sallallahu aleyhi vesellem → (S.A.V)
hadis → hadîs
Radıyallahu anh → (R.A)
Aleyhisselam → (A.S)
ulül elbab → ulûl'elbab
tilavet → tilâvet
huşu → huşû
daimi → daimî

════════════════════════════════════════
KURAL 3 — NOKTALAMA
════════════════════════════════════════
- Konuşma çizgisi (---) sonrası mutlaka boşluk: "--- Söz"
- Tırnak açıldıktan sonra boşluk bırakılmaz
- Tırnak içinde cümle tamamlandığında noktalama tırnağın içinde
- Özel isimler ve rakamlara ek kesme işareti: Allah'a, Kur'ân'dan, 2024'te
- Nokta/virgül/iki nokta sonrası tek boşluk
- "E, ee, şey" gibi dolgu sesler silinmeli

════════════════════════════════════════
KURAL 4 — ETİKET STANDARTLARI
════════════════════════════════════════
- Her etiket kelimesi büyük harfle başlamalı
- Etiketler virgülle ayrılmalı, "ve" bağlacı kullanılmamalı
- Etiket bölümünde soru yazılmamalı
- Etiketlerin sonuna nokta konmamalı
- Âyet etiketleri: "Yûnus 7" formatında

════════════════════════════════════════
KURAL 5 — METİN YAPISI
════════════════════════════════════════
- Sorular "Muhterem Hocam" veya "Kıymetli Hocam" ile başlamalı
- Konuşmalar paragraf halinde olmalı (alt alt satır değil)
- Allahû Tealâ'nın sözleri "....." içinde
- Allahû Tealâ'ya ait zamirler büyük: Benim, Kendisine, Ben, Biz
- "Allah razı olsun" son cümlenin devamına yazılmalı
- Efendimizin öğrettiği sayılar rakamla: 7 safha, 4 teslim, 28 basamak`;

// ── DB helpers ─────────────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DATA_FILE)) {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    const initial = {
      users: [{
        id: uuidv4(), username: 'admin',
        password: bcrypt.hashSync('admin123', 10),
        role: 'admin', name: 'Yönetici',
        createdAt: new Date().toISOString(), active: true
      }],
      history: [],
      alerts: []
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function saveDB(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }

function loadRules() {
  if (!fs.existsSync(RULES_FILE)) {
    fs.mkdirSync(path.dirname(RULES_FILE), { recursive: true });
    fs.writeFileSync(RULES_FILE, DEFAULT_RULES, 'utf8');
  }
  return fs.readFileSync(RULES_FILE, 'utf8');
}
function saveRules(text) { fs.writeFileSync(RULES_FILE, text, 'utf8'); }

// ── Auth middleware ────────────────────────────────────────────────────────
const auth  = (req, res, next) => req.session?.userId ? next() : res.status(401).json({ error: 'Giriş gerekli.' });
const admin = (req, res, next) => req.session?.role === 'admin' ? next() : res.status(403).json({ error: 'Yönetici yetkisi gerekli.' });

// ── AUTH ──────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.username === username && u.active);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.name = user.name;
  req.session.role = user.role;
  res.json({ success: true, name: user.name, role: user.role, username: user.username });
});
app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth/me', (req, res) => {
  if (!req.session?.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, name: req.session.name, role: req.session.role, username: req.session.username });
});
app.post('/api/auth/change-password', auth, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user || !bcrypt.compareSync(oldPassword, user.password))
    return res.status(401).json({ error: 'Mevcut şifre hatalı.' });
  user.password = bcrypt.hashSync(newPassword, 10);
  saveDB(db);
  res.json({ success: true });
});

// ── USERS ─────────────────────────────────────────────────────────────────
app.get('/api/users', auth, admin, (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: u.active, createdAt: u.createdAt })));
});
app.post('/api/users', auth, admin, (req, res) => {
  const { username, password, name, role } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
  const db = loadDB();
  if (db.users.find(u => u.username === username)) return res.status(400).json({ error: 'Kullanıcı adı alınmış.' });
  db.users.push({ id: uuidv4(), username, name, password: bcrypt.hashSync(password, 10), role: role || 'user', active: true, createdAt: new Date().toISOString() });
  saveDB(db);
  res.json({ success: true });
});
app.put('/api/users/:id', auth, admin, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  const { name, password, role, active } = req.body;
  if (name !== undefined)   user.name   = name;
  if (role !== undefined)   user.role   = role;
  if (active !== undefined) user.active = active;
  if (password)             user.password = bcrypt.hashSync(password, 10);
  saveDB(db);
  res.json({ success: true });
});
app.delete('/api/users/:id', auth, admin, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
  if (db.users[idx].role === 'admin') return res.status(400).json({ error: 'Yönetici silinemez.' });
  db.users.splice(idx, 1);
  saveDB(db);
  res.json({ success: true });
});

// ── RULES ─────────────────────────────────────────────────────────────────
app.get('/api/rules', auth, admin, (req, res) => res.json({ rules: loadRules() }));
app.put('/api/rules', auth, admin, (req, res) => {
  const { rules } = req.body;
  if (!rules) return res.status(400).json({ error: 'Kural metni boş.' });
  saveRules(rules);
  res.json({ success: true });
});
app.post('/api/rules/reset', auth, admin, (req, res) => {
  saveRules(DEFAULT_RULES);
  res.json({ success: true, rules: DEFAULT_RULES });
});

// ── HISTORY ───────────────────────────────────────────────────────────────
app.get('/api/history', auth, (req, res) => {
  const db = loadDB();
  const isAdmin = req.session.role === 'admin';
  let hist = isAdmin ? db.history : db.history.filter(h => h.userId === req.session.userId);
  res.json(hist.slice().reverse().slice(0, 200));
});

// CSV export
app.get('/api/history/csv', auth, admin, (req, res) => {
  const db = loadDB();
  const rows = [['Tarih', 'Kullanıcı', 'Dosya/Metin', 'Skor', 'Toplam Hata', 'Sözlük', 'İmla', 'Noktalama', 'Etiket', 'Yapı', 'Durum', 'Onaylayan']];
  db.history.slice().reverse().forEach(h => {
    rows.push([
      new Date(h.createdAt).toLocaleString('tr-TR'),
      h.name || '', h.filename || '',
      h.score || 0, h.totalErrors || 0,
      h.catCounts?.sozluk || 0, h.catCounts?.imla || 0,
      h.catCounts?.noktalama || 0, h.catCounts?.etiket || 0, h.catCounts?.yapi || 0,
      h.status || 'bekliyor', h.approvedBy || ''
    ]);
  });
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="arsiv-gecmis-${Date.now()}.csv"`);
  res.send('\uFEFF' + csv); // BOM for Excel Turkish char support
});

// ── APPROVAL ──────────────────────────────────────────────────────────────
app.post('/api/history/:id/approve', auth, admin, (req, res) => {
  const db = loadDB();
  const item = db.history.find(h => h.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
  item.status = 'onaylandi';
  item.approvedBy = req.session.name;
  item.approvedAt = new Date().toISOString();
  saveDB(db);
  res.json({ success: true });
});
app.post('/api/history/:id/reject', auth, admin, (req, res) => {
  const db = loadDB();
  const item = db.history.find(h => h.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
  item.status = 'reddedildi';
  item.approvedBy = req.session.name;
  item.approvedAt = new Date().toISOString();
  saveDB(db);
  res.json({ success: true });
});

// ── ALERTS ────────────────────────────────────────────────────────────────
app.get('/api/alerts', auth, admin, (req, res) => {
  const db = loadDB();
  res.json((db.alerts || []).slice().reverse().slice(0, 50));
});
app.post('/api/alerts/:id/read', auth, admin, (req, res) => {
  const db = loadDB();
  const alert = (db.alerts || []).find(a => a.id === req.params.id);
  if (alert) alert.read = true;
  saveDB(db);
  res.json({ success: true });
});
app.post('/api/alerts/read-all', auth, admin, (req, res) => {
  const db = loadDB();
  (db.alerts || []).forEach(a => a.read = true);
  saveDB(db);
  res.json({ success: true });
});

// ── DASHBOARD STATS ───────────────────────────────────────────────────────
app.get('/api/stats', auth, admin, (req, res) => {
  const db = loadDB();
  const hist = db.history || [];
  const users = db.users.filter(u => u.active);

  // Last 30 days
  const now = Date.now();
  const day30 = hist.filter(h => now - new Date(h.createdAt).getTime() < 30 * 864e5);

  // Per user stats
  const perUser = {};
  hist.forEach(h => {
    if (!perUser[h.userId]) perUser[h.userId] = { name: h.name, count: 0, scoreSum: 0, errors: 0 };
    perUser[h.userId].count++;
    perUser[h.userId].scoreSum += h.score || 0;
    perUser[h.userId].errors += h.totalErrors || 0;
  });

  // Category totals
  const catTotals = { sozluk: 0, imla: 0, noktalama: 0, etiket: 0, yapi: 0 };
  hist.forEach(h => {
    if (h.catCounts) Object.keys(catTotals).forEach(k => catTotals[k] += h.catCounts[k] || 0);
  });

  // Daily chart (last 14 days)
  const daily = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    const label = `${d.getDate()}/${d.getMonth()+1}`;
    const dayItems = hist.filter(h => {
      const hd = new Date(h.createdAt);
      return hd.getDate() === d.getDate() && hd.getMonth() === d.getMonth() && hd.getFullYear() === d.getFullYear();
    });
    daily.push({ label, count: dayItems.length, avgScore: dayItems.length ? Math.round(dayItems.reduce((s,h) => s+(h.score||0),0)/dayItems.length) : 0 });
  }

  // Alerts (unread)
  const unreadAlerts = (db.alerts||[]).filter(a => !a.read).length;

  // Pending approvals
  const pending = hist.filter(h => h.status === 'bekliyor' || !h.status).length;

  res.json({
    totals: {
      allTime: hist.length,
      last30: day30.length,
      activeUsers: users.length,
      avgScore: hist.length ? Math.round(hist.reduce((s,h)=>s+(h.score||0),0)/hist.length) : 0,
      pendingApproval: pending,
      unreadAlerts
    },
    perUser: Object.values(perUser).map(u => ({
      name: u.name, count: u.count,
      avgScore: u.count ? Math.round(u.scoreSum / u.count) : 0,
      avgErrors: u.count ? Math.round(u.errors / u.count) : 0
    })).sort((a,b) => b.count - a.count),
    catTotals,
    daily
  });
});

// ── ANALYSIS ──────────────────────────────────────────────────────────────
function buildSystemPrompt() {
  const rules = loadRules();
  return `Sen "Arşiv Soru ve Cevap Ekibi" için özel bir denetim asistanısın.
Aşağıdaki kurallara göre metni eksiksiz kontrol et ve düzelt.

${rules}

ÇIKTI FORMATI — SADECE JSON DÖN, BAŞKA HİÇBİR ŞEY YAZMA:
{
  "score": 78,
  "correctedText": "Düzeltilmiş tam metin...",
  "categories": {
    "sozluk":    { "count": 3, "issues": [{"original": "...", "fixed": "...", "rule": "..."}] },
    "imla":      { "count": 2, "issues": [{"original": "...", "fixed": "...", "rule": "..."}] },
    "noktalama": { "count": 1, "issues": [{"original": "...", "fixed": "...", "rule": "..."}] },
    "etiket":    { "count": 0, "issues": [] },
    "yapi":      { "count": 1, "issues": [{"original": "...", "fixed": "...", "rule": "..."}] }
  },
  "totalErrors": 7,
  "summary": "Kısa genel değerlendirme."
}`;
}

async function claudeText(text) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 8000, system: buildSystemPrompt(),
      messages: [{ role: 'user', content: `Metni denetle:\n\n${text}` }] })
  });
  if (!r.ok) { const e = await r.json(); throw new Error(e.error?.message || 'API hatası'); }
  const d = await r.json(); return parseResult(d.content[0].text);
}

async function claudeFile(base64, mime) {
  const mt = mime.includes('pdf') ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'files-api-2025-04-14' },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 8000, system: buildSystemPrompt(),
      messages: [{ role: 'user', content: [
        { type: 'document', source: { type: 'base64', media_type: mt, data: base64 } },
        { type: 'text', text: 'Bu dosyayı denetle.' }
      ]}] })
  });
  if (!r.ok) { const e = await r.json(); throw new Error(e.error?.message || 'API hatası'); }
  const d = await r.json(); return parseResult(d.content[0].text);
}

function parseResult(raw) {
  try { return JSON.parse(raw.replace(/```json\n?|\n?```/g, '').trim()); }
  catch { const m = raw.match(/\{[\s\S]*\}/); if (m) return JSON.parse(m[0]); throw new Error('Yanıt ayrıştırılamadı'); }
}

const LOW_SCORE_THRESHOLD = 60;

function saveHistory(req, result, filename) {
  const db = loadDB();
  const catCounts = {};
  if (result.categories) Object.keys(result.categories).forEach(k => catCounts[k] = result.categories[k].count || 0);

  const entry = {
    id: uuidv4(), userId: req.session.userId,
    username: req.session.username, name: req.session.name,
    filename: filename || 'Metin Girişi',
    score: result.score || 0, totalErrors: result.totalErrors || 0,
    catCounts, summary: result.summary || '',
    correctedText: result.correctedText || '',
    status: 'bekliyor',
    createdAt: new Date().toISOString()
  };

  db.history.push(entry);
  if (db.history.length > 1000) db.history = db.history.slice(-1000);

  // Low score alert
  if ((result.score || 0) < LOW_SCORE_THRESHOLD) {
    if (!db.alerts) db.alerts = [];
    db.alerts.push({
      id: uuidv4(), type: 'low_score',
      message: `${req.session.name} tarafından düşük skorlu metin (${result.score}/100): "${filename || 'Metin Girişi'}"`,
      userId: req.session.userId, historyId: entry.id,
      score: result.score, read: false,
      createdAt: new Date().toISOString()
    });
  }

  saveDB(db);
  return entry.id;
}

app.post('/api/analyze', auth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Metin boş.' });
  try {
    const result = await claudeText(text);
    const id = saveHistory(req, result, 'Metin Girişi');
    res.json({ ...result, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/analyze-file', auth, upload.single('file'), async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  if (!req.file) return res.status(400).json({ error: 'Dosya bulunamadı.' });
  try {
    const result = await claudeFile(req.file.buffer.toString('base64'), req.file.mimetype);
    const id = saveHistory(req, result, req.file.originalname);
    res.json({ ...result, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Toplu denetim
app.post('/api/analyze-batch', auth, upload.array('files', 20), async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  if (!req.files?.length) return res.status(400).json({ error: 'Dosya bulunamadı.' });
  const results = [];
  for (const file of req.files) {
    try {
      const result = await claudeFile(file.buffer.toString('base64'), file.mimetype);
      const id = saveHistory(req, result, file.originalname);
      results.push({ filename: file.originalname, success: true, score: result.score, totalErrors: result.totalErrors, id });
    } catch (e) {
      results.push({ filename: file.originalname, success: false, error: e.message });
    }
  }
  res.json({ results });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Arşiv Kontrol v3: http://localhost:${PORT}`));
