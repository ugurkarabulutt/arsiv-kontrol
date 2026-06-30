require('dotenv').config();
const express  = require('express');
const cookieSession = require('cookie-session');
const bcrypt   = require('bcryptjs');
const multer   = require('multer');
const path     = require('path');
const mammoth  = require('mammoth');
const PDFDocument = require('pdfkit');
const { createClient } = require('@supabase/supabase-js');
const {
  LOW_SCORE_MSG, LOW_SCORE_THRESHOLD,
  candidateTextHashes, finalizeResult, textHash
} = require('./analysis-core');
const {
  ROLES, effectiveRole, isAdminRole, isAssignableRole,
  isReservedSuperAdminUsername, isSuperAdminRole
} = require('./authorization');

const app    = express();
const MAX_FILE_SIZE = 4 * 1024 * 1024; // Vercel Function istek gövdesi sınırının altında tut.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_FILE_SIZE } });

const OPENAI_API_KEY    = process.env.OPENAI_API_KEY;
const SESSION_SECRET    = process.env.SESSION_SECRET || 'arsiv-gizli-v3-2025';
const SUPABASE_URL      = process.env.SUPABASE_URL;
const SUPABASE_KEY      = process.env.SUPABASE_KEY;
const PROMPT_VERSION    = '2026-06-30.4';

if (process.env.VERCEL && !process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET Vercel ortamında zorunludur.');
}

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ SUPABASE_URL / SUPABASE_KEY tanımlı değil. .env dosyasını doldurun.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(cookieSession({
  name: 'arsiv_session',
  keys: [SESSION_SECRET],
  maxAge: 8 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  secure: Boolean(process.env.VERCEL || process.env.NODE_ENV === 'production')
}));
app.use(express.static(__dirname));

// Render/UptimeRobot için oturum ve veritabanı gerektirmeyen canlılık kontrolü.
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

// ── Default rules ──────────────────────────────────────────────────────────
const DEFAULT_RULES = `════════════════════════════════════════
KURAL 1 — EFENDİMİZİN SÖZLÜĞÜ
════════════════════════════════════════
Aşağıdaki yazımlar arşiv standardıdır; yalnızca kelime gerçekten aynı anlamda ve bağımsız
kelime olarak kullanılmışsa düzelt. Sure adı, özel isim, alıntı başlığı, tablo/slayt etiketi,
kelime içi parça veya farklı anlamlı kullanım ise dokunma:

Allahû Tealâ
Allah'ın, Allah'a, Allah'tan
âyet, âyet-i kerime
Kur'ân
hadîs, hadîs-i şerif
sahâbe
Efendimiz'in (kesme işareti zorunlu)
Peygamber Efendimiz (S.A.V) — yalnızca Peygamber Efendimiz açıkça kastediliyorsa
mü'min
nefs (nefis değil)
îmân
tilâvet
huşû
daimî
inşaallah
velî
resûl (küçük harf, özel isim değilse)
nebî
dîn (din kelimesi bağımsız kavramsa; dinlenmek/dinlemek köklerine dokunma)
tâbî (bağlı/uyan anlamındaysa; "Tabiî ki" ifadesi değildir)
ni'met
ulûl'elbab
hidayet (hidâyet değil)
takva
âlem
azîm
ebedî
ciddî
dergâh
kelâm
Sıratı Mustakîm
Tarîki Mustakîm
kıyâmet
mahlûk
manevî
mânâ
Rahmân, Rahîm
rızık
salâvât
şefaat
tövbe, Tövbe-i Nasuh
Eûzubillâhimineşşeytânirracîm
Bismillâhirrahmânirrahîm
fırkayı naciye
gayy yolu
sebîli gayy
âdâp
likâallah

════════════════════════════════════════
KURAL 2 — İMLÂ (Yanlış → Doğru)
════════════════════════════════════════
Bu dönüşümleri yalnızca tam kelime/ifade eşleşmesinde uygula. Kelime içi parça eşleşmesi yasaktır.
Sure adları ve özel adlar korunur.

Allah Teala → Allahû Tealâ
Allahu Teala → Allahû Tealâ
Resul → resûl
Veli → velî
Nebi → nebî
Din → dîn (yalnızca bağımsız din kavramıysa; dinlenmek/dinlemek türevleri hariç)
Ayet → âyet (sure/kitap adı veya özel başlık içinde değilse)
Ayet-i kerime → âyet-i kerime
Kuran → Kur'ân
Mumin → mü'min (Muminun/Mu'minûn/Mü'minûn Suresi içinde değilse)
Tabi → tâbî (Tabiî ki/Tabii ki ifadesi değilse)
Iman → îmân (özel isim veya başlık içinde değilse)
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
ulül elbab / ululelbab / ulul elbab → ulûl'elbab
tilavet → tilâvet
huşu → huşû
daimi → daimî

════════════════════════════════════════
KURAL 3 — PEYGAMBER VE NEBİ İSİMLERİ
════════════════════════════════════════
- Peygamber Efendimiz, Allah Resûlü, Hz. Muhammed → mutlaka (S.A.V) ekle
- Sallallahu aleyhi vesellem gibi uzun yazılmışsa → (S.A.V) olarak kısalt
- Resûlullah'tan sonra (S.A.V) yazılabilir veya yazılmayabilir
- Muhterem Efendimiz, Hocamız, Efendimiz ifadesi Peygamber Efendimiz'i açıkça kastetmiyorsa
  (S.A.V) ekleme.
- Tüm nebî isimlerinde mutlaka (A.S) ekle: Musa (A.S), Nuh (A.S), İsa (A.S)
- Mehdi (A.S) — mutlaka (A.S) ekle

════════════════════════════════════════
KURAL 4 — NOKTALAMA
════════════════════════════════════════
- Özel isimlere ek geldiğinde kesme işareti zorunlu:
  Allah'a, Kur'ân'dan, Efendimiz'in, Sıratı Mustakîm'e
- Tırnak işaretlerini keyfi değiştirme; kaynakta tek/çift tırnak dengesi doğruysa koru.
- Tırnak açıldıktan sonra boşluk bırakma
- Cümle tırnakla bitiyorsa nokta tırnağın içinde olmalı: "...vermiştir."
- Nokta, virgül, iki nokta sonrası tek boşluk
- "E, ee, şey, yani" gibi dolgu sesler silinmeli
- Konuşma çizgisi (—) sonrası boşluk bırak

════════════════════════════════════════
KURAL 5 — ALLAHÛ TEALÂ'NIN SÖZLERİ VE ZAMİRLER
════════════════════════════════════════
- Allahû Tealâ'nın sözleri "....." içinde yazılmalı
- Allahû Tealâ'ya ait şahıs zamirleri büyük harf ile başlamalı:
  Ben, Biz, Benim, Kendisine, Zat'ına, O (Allah için)
- Örnek doğru: "...Benim katımda senin yerin yok."
- Örnek yanlış: "...benim katımda senin yerin yok."

════════════════════════════════════════
KURAL 6 — METİN YAPISI VE PARAGRAF DÜZENİ
════════════════════════════════════════
- Düz anlatı metni paragraflar halinde olmalı; ancak slayt, hadîs dökümü, tablo, numaralı liste
  ve kısa satır düzeni varsa mevcut yapıyı koru.
- Paragraflar arasında boş satır bırak; tablo/slayt satır düzenini bu nedenle bozma.
- "Sevgili kardeşlerim" ifadesi metinde varsa koru, yoksa ekleme
- "Allah razı olsun." kaynakta ayrı cümleyse ayrı cümle olarak koru; önceki cümleyle virgül veya
  noktalı virgülle birleştirme. Yoksa ekleme.
- Âyetlerden ve uzun alıntılardan önce ve sonra boş satır bırak
- Hocamız'ın ifadesi değiştirilmemeli, sadece imlâ ve noktalama düzeltilmeli
- "E, ee, slaytı gösterelim, slayta bakalım" gibi dolgu ifadeler silinmeli
- "Resûl" kelimesi cümle içinde özel isim olarak kullanılıyorsa büyük R ile yazılmalı: "Bu Resûl, devrin imamıdır."

════════════════════════════════════════
KURAL 7 — SAYILAR
════════════════════════════════════════
- Efendimizin öğrettiği Allah'ın dizaynıyla ilgili sayılar rakamla yazılmalı:
  7 safha, 4 teslim, 28 basamak, 12 ihsan, 7 furkan,
  7 safha takva, 7 safha hidayet
- Diğer sayılar yazıyla yazılabilir

════════════════════════════════════════
KURAL 8 — ETİKETLER
════════════════════════════════════════
- Her etiket kelimesi büyük harfle başlamalı
- Etiketler araya virgül konarak yazılmalı: Hidayet, Zikir, Takva
- "ve" bağlacı kullanılmamalı
- Etiket bölümünde soru yazılmamalı
- Etiketlerin sonuna nokta konmamalı
- Âyet etiketleri: "Yûnus 7" formatında`;

// ── Row → API mappers (DB snake_case → frontend camelCase) ──────────────────
const mapUser    = u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: u.active, createdAt: u.created_at });
const mapHistory = h => ({
  id: h.id, userId: h.user_id, username: h.username, name: h.name,
  filename: h.filename, score: h.score, totalErrors: h.total_errors,
  catCounts: h.cat_counts || {}, summary: h.summary, correctedText: h.corrected_text,
  status: h.status, approvedBy: h.approved_by, approvedAt: h.approved_at,
  promptVersion: h.prompt_version, rulesHash: h.rules_hash,
  createdAt: h.created_at
});
const mapAlert   = a => ({
  id: a.id, type: a.type, message: a.message, userId: a.user_id,
  historyId: a.history_id, score: a.score, read: a.read, createdAt: a.created_at
});
const FEEDBACK_REASONS = Object.freeze({
  nonexistent: 'Metinde olmayan hata',
  wrong_fix: 'Yanlış düzeltme',
  missing_issue: 'Eksik hata',
  layout_broken: 'Düzen bozuldu',
  score_wrong: 'Skor yanlış',
  other: 'Diğer'
});

// ── Rules helpers (settings tablosunda key='rules') ─────────────────────────
async function loadRules() {
  const { data, error } = await supabase.from('settings').select('value').eq('key', 'rules').maybeSingle();
  if (error) {
    // settings tablosu yoksa/erişilemezse analiz yine de varsayılan kurallarla çalışsın
    console.warn('Kural okuma uyarısı (varsayılana düşülüyor):', error.message);
    return DEFAULT_RULES;
  }
  if (data?.value) return data.value;
  await supabase.from('settings').upsert({ key: 'rules', value: DEFAULT_RULES });
  return DEFAULT_RULES;
}
async function saveRules(text) {
  const { error } = await supabase.from('settings').upsert({ key: 'rules', value: text });
  if (error) throw new Error(error.message);
}

// ── Startup seed: admin kullanıcısı + varsayılan kurallar ───────────────────
async function seed() {
  const { count, error } = await supabase.from('users').select('id', { count: 'exact', head: true });
  if (error) { console.error('Seed kontrolü başarısız:', error.message); return; }
  if (!count) {
    const { error: insErr } = await supabase.from('users').insert({
      username: 'admin', password: bcrypt.hashSync('admin123', 10),
      role: ROLES.SUPER_ADMIN, name: 'Yönetici', active: true
    });
    if (insErr) console.error('Admin seed başarısız:', insErr.message);
    else console.log('✅ Varsayılan admin oluşturuldu (admin / admin123)');
  }
  // Yalnızca "admin" kullanıcı adı süper admin olabilir.
  const { error: demoteErr } = await supabase.from('users')
    .update({ role: ROLES.ADMIN }).eq('role', ROLES.SUPER_ADMIN).neq('username', 'admin');
  if (demoteErr) console.warn('Geçersiz süper admin rolleri düzeltilemedi:', demoteErr.message);
  const { error: promoteErr } = await supabase.from('users')
    .update({ role: ROLES.SUPER_ADMIN }).eq('username', 'admin');
  if (promoteErr) console.warn('Admin süper admin rolüne yükseltilemedi:', promoteErr.message);
  await loadRules(); // kural satırı yoksa oluşturur

  // history.text_hash kolonu var mı? (tekrar-gönderim kontrolü için)
  const { error: thErr } = await supabase.from('history').select('text_hash').limit(1);
  HAS_TEXT_HASH = !thErr;
  if (!HAS_TEXT_HASH) console.warn('⚠ history.text_hash kolonu yok — tekrar-gönderim kontrolü devre dışı. schema.sql içindeki ALTER ifadesini Supabase SQL Editor\'de çalıştırın.');

  const { error: metaErr } = await supabase.from('history').select('prompt_version,rules_hash').limit(1);
  HAS_ANALYSIS_META = !metaErr;
  if (!HAS_ANALYSIS_META) console.warn('⚠ history.prompt_version/rules_hash kolonları yok — analiz sürüm bilgisi kayıt geçmişine yazılmayacak.');
}

// ── Auth middleware ────────────────────────────────────────────────────────
function normalizeSessionRole(req) {
  if (req.session?.userId) req.session.role = effectiveRole(req.session.username, req.session.role);
}
const auth = async (req, res, next) => {
  try {
    if (!req.session?.userId) return res.status(401).json({ error: 'Giriş gerekli.' });
    await startupReady;
    normalizeSessionRole(req);
    next();
  } catch (error) {
    next(error);
  }
};
const admin = (req, res, next) => isAdminRole(req.session?.role)
  ? next() : res.status(403).json({ error: 'Yönetici yetkisi gerekli.' });
const superAdmin = (req, res, next) => isSuperAdminRole(req.session?.role)
  ? next() : res.status(403).json({ error: 'Süper admin yetkisi gerekli.' });

// ── AUTH ──────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    await startupReady;
    const { username, password } = req.body;
    const { data: user } = await supabase.from('users')
      .select('*').eq('username', username).eq('active', true).maybeSingle();
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
    const role = effectiveRole(user.username, user.role);
    if (role !== user.role) {
      const { error: roleError } = await supabase.from('users').update({ role }).eq('id', user.id);
      if (roleError) throw new Error(roleError.message);
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.name = user.name;
    req.session.role = role;
    res.json({ success: true, id: user.id, name: user.name, role, username: user.username });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/auth/logout', (req, res) => { req.session = null; res.json({ success: true }); });
app.get('/api/auth/me', async (req, res, next) => {
  if (!req.session?.userId) return res.json({ loggedIn: false });
  try {
    await startupReady;
    normalizeSessionRole(req);
    res.json({ loggedIn: true, id: req.session.userId, name: req.session.name, role: req.session.role, username: req.session.username });
  } catch (error) {
    next(error);
  }
});
// Varsayılan admin/admin123 hâlâ kullanılıyor mu? (Kullanıcılar sekmesindeki uyarı için)
app.get('/api/security/default-admin', auth, admin, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('password').eq('username', 'admin').maybeSingle();
    const usingDefault = data ? bcrypt.compareSync('admin123', data.password) : false;
    res.json({ usingDefault });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('id', req.session.userId).maybeSingle();
    if (!user || !bcrypt.compareSync(oldPassword, user.password))
      return res.status(401).json({ error: 'Mevcut şifre hatalı.' });
    const { error } = await supabase.from('users')
      .update({ password: bcrypt.hashSync(newPassword, 10) }).eq('id', user.id);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── USERS ─────────────────────────────────────────────────────────────────
app.get('/api/users', auth, admin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: true });
    if (error) throw new Error(error.message);
    res.json((data || []).map(mapUser));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/users', auth, admin, superAdmin, async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    if (!username || !password || !name) return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
    const cleanUsername = String(username).trim();
    const cleanRole = role || ROLES.USER;
    if (isReservedSuperAdminUsername(cleanUsername)) return res.status(400).json({ error: 'admin kullanıcı adı ayrılmıştır.' });
    if (!isAssignableRole(cleanRole)) return res.status(400).json({ error: 'Geçersiz kullanıcı rolü.' });
    const { data: existing } = await supabase.from('users').select('id').eq('username', cleanUsername).maybeSingle();
    if (existing) return res.status(400).json({ error: 'Kullanıcı adı alınmış.' });
    const { error } = await supabase.from('users').insert({
      username: cleanUsername, name, password: bcrypt.hashSync(password, 10), role: cleanRole, active: true
    });
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/users/:id', auth, admin, async (req, res) => {
  try {
    const { name, password, role, active } = req.body;
    const { data: target, error: targetError } = await supabase.from('users')
      .select('id,username,role').eq('id', req.params.id).maybeSingle();
    if (targetError) throw new Error(targetError.message);
    if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    const targetIsSuperAdmin = isReservedSuperAdminUsername(target.username) || target.role === ROLES.SUPER_ADMIN;
    if (targetIsSuperAdmin && !isSuperAdminRole(req.session.role)) {
      return res.status(403).json({ error: 'Süper admin hesabını yalnızca süper admin düzenleyebilir.' });
    }
    if (targetIsSuperAdmin && role !== undefined && role !== ROLES.SUPER_ADMIN) {
      return res.status(400).json({ error: 'Süper admin rolü değiştirilemez.' });
    }
    if (targetIsSuperAdmin && active === false) {
      return res.status(400).json({ error: 'Süper admin hesabı devre dışı bırakılamaz.' });
    }
    if (!targetIsSuperAdmin && role !== undefined && !isAssignableRole(role)) {
      return res.status(400).json({ error: 'Geçersiz kullanıcı rolü.' });
    }
    const patch = {};
    if (name !== undefined)   patch.name   = name;
    if (role !== undefined)   patch.role   = role;
    if (active !== undefined) patch.active = active;
    if (password)             patch.password = bcrypt.hashSync(password, 10);
    const { data, error } = await supabase.from('users').update(patch).eq('id', req.params.id).select('id');
    if (error) throw new Error(error.message);
    if (!data?.length) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    // Admin kendi adını değiştirdiyse oturumdaki ad da güncellensin (topbar için)
    if (req.params.id === req.session.userId && name !== undefined) req.session.name = name;
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/users/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('username,role').eq('id', req.params.id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    if (req.params.id === req.session.userId || isReservedSuperAdminUsername(user.username) || user.role === ROLES.SUPER_ADMIN) {
      return res.status(400).json({ error: 'Süper admin silinemez.' });
    }
    const { error } = await supabase.from('users').delete().eq('id', req.params.id);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── RULES ─────────────────────────────────────────────────────────────────
app.get('/api/rules', auth, admin, async (req, res) => {
  try { res.json({ rules: await loadRules() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/rules', auth, admin, async (req, res) => {
  try {
    const { rules } = req.body;
    if (!rules) return res.status(400).json({ error: 'Kural metni boş.' });
    await saveRules(rules);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/rules/reset', auth, admin, async (req, res) => {
  try {
    await saveRules(DEFAULT_RULES);
    res.json({ success: true, rules: DEFAULT_RULES });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HISTORY ───────────────────────────────────────────────────────────────
app.get('/api/history', auth, async (req, res) => {
  try {
    let q = supabase.from('history').select('*').order('created_at', { ascending: false }).limit(200);
    if (!isAdminRole(req.session.role)) q = q.eq('user_id', req.session.userId);
    const { data, error } = await q;
    if (error) throw new Error(error.message);
    res.json((data || []).map(mapHistory));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history/:id([0-9a-fA-F-]{36})', auth, async (req, res) => {
  try {
    let query = supabase.from('history').select('*').eq('id', req.params.id);
    if (!isAdminRole(req.session.role)) query = query.eq('user_id', req.session.userId);
    const { data, error } = await query.maybeSingle();
    if (error) throw new Error(error.message);
    if (!data) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    res.json(mapHistory(data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/history/:id([0-9a-fA-F-]{36})/feedback', auth, async (req, res) => {
  try {
    const { reason, note, category, original, fixed, rule } = req.body || {};
    const reasonLabel = FEEDBACK_REASONS[reason] || FEEDBACK_REASONS.other;
    const cleanNote = String(note || '').trim().slice(0, 1000);
    const cleanCategory = String(category || '').trim().slice(0, 40);
    const cleanOriginal = String(original || '').trim().slice(0, 220);
    const cleanFixed = String(fixed || '').trim().slice(0, 220);
    const cleanRule = String(rule || '').trim().slice(0, 220);

    let query = supabase.from('history').select('id,user_id,filename,score').eq('id', req.params.id);
    if (!isAdminRole(req.session.role)) query = query.eq('user_id', req.session.userId);
    const { data: history, error: historyError } = await query.maybeSingle();
    if (historyError) throw new Error(historyError.message);
    if (!history) return res.status(404).json({ error: 'Kayıt bulunamadı.' });

    const parts = [
      `Geri bildirim: ${reasonLabel}`,
      `Kayıt: ${history.filename || 'Metin Girişi'}`,
      `Gönderen: ${req.session.name || req.session.username}`
    ];
    if (cleanCategory) parts.push(`Kategori: ${cleanCategory}`);
    if (cleanOriginal || cleanFixed) parts.push(`Bulgu: "${cleanOriginal || '—'}" → "${cleanFixed || '—'}"`);
    if (cleanRule) parts.push(`Kural: ${cleanRule}`);
    if (cleanNote) parts.push(`Not: ${cleanNote}`);

    const { error } = await supabase.from('alerts').insert({
      type: 'feedback',
      message: parts.join(' | '),
      user_id: req.session.userId,
      history_id: history.id,
      score: history.score,
      read: false
    });
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pdf', auth, async (req, res) => {
  const text = String(req.body?.text || '');
  if (!text.trim()) return res.status(400).json({ error: 'PDF için metin bulunamadı.' });
  if (text.length > 1_000_000) return res.status(413).json({ error: 'Metin PDF için çok uzun.' });

  try {
    const doc = new PDFDocument({ size: 'A4', margins: { top: 56, right: 56, bottom: 56, left: 56 } });
    const fontPath = require.resolve('@fontsource/noto-serif/files/noto-serif-latin-ext-400-normal.woff');
    const filename = `duzeltilmis-metin-${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    doc.on('error', err => { if (!res.headersSent) res.status(500).json({ error: err.message }); else res.destroy(err); });
    doc.pipe(res);
    doc.font(fontPath).fontSize(16).fillColor('#8b6914').text('Arşiv Kontrol AI — Düzeltilmiş Metin');
    doc.moveDown(1).fontSize(11).fillColor('#1a1410').text(text, { lineGap: 5, align: 'left' });
    doc.moveDown(2).fontSize(8).fillColor('#7a6e5e').text(`Arşiv Kontrol AI — ${new Date().toLocaleDateString('tr-TR')}`);
    doc.end();
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// CSV export
app.get('/api/history/csv', auth, admin, async (req, res) => {
  try {
  const { data, error } = await supabase.from('history').select('*').order('created_at', { ascending: false });
  if (error) throw new Error(error.message);
  const rows = [['Tarih', 'Kullanıcı', 'Dosya/Metin', 'Skor', 'Toplam Hata', 'Sözlük', 'İmla', 'Noktalama', 'Etiket', 'Yapı', 'Durum', 'Onaylayan', 'Prompt Sürümü', 'Kural Hash']];
  (data || []).map(mapHistory).forEach(h => {
    rows.push([
      new Date(h.createdAt).toLocaleString('tr-TR'),
      h.name || '', h.filename || '',
      h.score || 0, h.totalErrors || 0,
      h.catCounts?.sozluk || 0, h.catCounts?.imla || 0,
      h.catCounts?.noktalama || 0, h.catCounts?.etiket || 0, h.catCounts?.yapi || 0,
      h.status || 'bekliyor', h.approvedBy || '',
      h.promptVersion || '', h.rulesHash || ''
    ]);
  });
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="arsiv-gecmis-${Date.now()}.csv"`);
  res.send('\uFEFF' + csv);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── APPROVAL ──────────────────────────────────────────────────────────────
async function setApproval(req, res, status) {
  try {
    const { data, error } = await supabase.from('history').update({
      status, approved_by: req.session.name, approved_at: new Date().toISOString()
    }).eq('id', req.params.id).select('id');
    if (error) throw new Error(error.message);
    if (!data?.length) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
}
app.post('/api/history/:id/approve', auth, admin, (req, res) => setApproval(req, res, 'onaylandi'));
app.post('/api/history/:id/reject',  auth, admin, (req, res) => setApproval(req, res, 'reddedildi'));

// ── ALERTS ────────────────────────────────────────────────────────────────
app.get('/api/alerts', auth, admin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('alerts').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) throw new Error(error.message);
    res.json((data || []).map(mapAlert));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/alerts/:id/read', auth, admin, async (req, res) => {
  try {
    const { error } = await supabase.from('alerts').update({ read: true }).eq('id', req.params.id);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/alerts/read-all', auth, admin, async (req, res) => {
  try {
    const { error } = await supabase.from('alerts').update({ read: true }).eq('read', false);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DASHBOARD STATS ───────────────────────────────────────────────────────
app.get('/api/stats', auth, admin, async (req, res) => {
  try {
    const [{ data: histRows, error: hErr }, { data: userRows, error: uErr }, { data: alertRows, error: aErr }] = await Promise.all([
      supabase.from('history').select('*'),
      supabase.from('users').select('active'),
      supabase.from('alerts').select('read')
    ]);
    if (hErr) throw new Error(hErr.message);
    if (uErr) throw new Error(uErr.message);
    if (aErr) throw new Error(aErr.message);

    const hist = (histRows || []).map(mapHistory);
    const users = (userRows || []).filter(u => u.active);

    const now = Date.now();
    const day30 = hist.filter(h => now - new Date(h.createdAt).getTime() < 30 * 864e5);

    const perUser = {};
    hist.forEach(h => {
      if (!perUser[h.userId]) perUser[h.userId] = { name: h.name, count: 0, scoreSum: 0, errors: 0 };
      perUser[h.userId].count++;
      perUser[h.userId].scoreSum += h.score || 0;
      perUser[h.userId].errors += h.totalErrors || 0;
    });

    const catTotals = { sozluk: 0, imla: 0, noktalama: 0, etiket: 0, yapi: 0 };
    hist.forEach(h => {
      if (h.catCounts) Object.keys(catTotals).forEach(k => catTotals[k] += h.catCounts[k] || 0);
    });

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

    const unreadAlerts = (alertRows || []).filter(a => !a.read).length;
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ANALYSIS ──────────────────────────────────────────────────────────────
async function buildSystemPrompt(rulesText) {
  const rules = rulesText ?? await loadRules();
  return `Sen "Arşiv Kontrol AI" sistemisin. Görevin yalnızca cevap metinlerini verilen kurallara göre denetlemek ve düzeltmektir.

NASIL ÇALIŞACAKSIN:
1. Metni baştan sona kelime kelime oku — tüm imlâ hatalarını tespit et.
2. Metni tekrar baştan sona oku — noktalama ve yapı hatalarını tespit et.
3. Tespit ettiğin HER hatayı hem bulgular bölümüne yaz HEM DE düzeltilmiş metne mutlaka uygula.
4. Aynı hata birden fazla yerde geçiyorsa tümünü düzelt, sadece birini değil.
5. Anlam değişikliği yapma, cümle ekleme veya çıkarma, sadeleştirme yapma.
6. Yalnızca imlâ, noktalama ve yapı kurallarını uygula.
7. Paragraflar arasında mutlaka boş satır bırak.
8. "Allah razı olsun." ifadesi kaynakta ayrı cümleyse ayrı cümle olarak koru; önceki cümleyle birleştirme.
9. "Bu Resûl" gibi kullanımlarda Resûl büyük R ile kalmalı — özel isim olarak kullanılıyor.
10. Tırnak içinde biten cümlelerde nokta tırnağın içinde olmalı: "...vermiştir."
11. Bağımsız iki cümleyi noktalama bahanesiyle birleştirme. Özellikle "Allah'ın izniyle. Allah razı olsun."
   iki ayrı cümle olarak kalmalıdır; virgülle tek cümle yapma.
12. Apostrof/kesme işareti türünü tek başına hata sayma. Allah'a, Allah’a, Allah’ın, Allah'ın gibi
   düz veya tipografik kesme işaretleri eşdeğer kabul edilir; sadece karakter tipini değiştirmek için issue yazma.
13. Çift tırnak ve tek tırnak arasında keyfi dönüşüm yapma. Tırnak işaretlerini silme; kaynakta kapanış tırnağı varsa
   düzeltilmiş metinde de korunmalıdır.
14. Kelime içinden parça yakalayıp düzeltme yapma. "Muminun/Mu'minûn Suresi" içindeki "Mumin/Mu'min" parçasını
   "mü'min" kelimesi sanma.
15. "Tabiî ki" ifadesi "tâbî" değildir; bu ifadeyi tâbî olarak düzeltme. "derecat" kelimesini otomatik olarak
   "derece" yapma. "dinlenmeye" kelimesini "dînlenmeye" yapma.
16. "Muhterem Efendimiz" bağlamında geçen Efendimiz'e "(S.A.V)" ekleme; bunu yalnızca açıkça Peygamber Efendimiz
   kastedildiğinde ve kaynak kural gerektiriyorsa uygula.
17. Slayt, hadîs dökümü, tablo benzeri satır düzenlerini koru. Satır sırası, başlıklar, numaralar ve tırnak dengesi
   düzeltilmiş metinde bozulmamalıdır.

BULGULARIN EKSIKSIZ OLMASI (ZORUNLU):
- Her yaptığın düzeltmeyi MUTLAKA ilgili kategorinin issues listesine ekle.
- Düzeltilmiş metinde değiştirdiğin HER kelime/ifade için bir issue objesi oluştur
  ({"original": "...", "fixed": "...", "rule": "..."}).
- Kaynak metinde birebir bulunmayan original değeriyle issue yazma. Bir kelimenin sadece daha uzun bir kelimenin
  içinde geçmesi yeterli değildir.
- original ve fixed kullanıcıya aynı görünüyorsa veya sadece düz/tipografik apostrof farkı varsa issue yazma.
- issues listesi boş bırakılamaz: bir kategoride düzeltme yaptıysan o issue mutlaka listede olmalı.
- count ile issues.length HER ZAMAN eşit olmalı. Düzelttiğin ama issues'a yazmadığın hiçbir
  değişiklik kalmamalı; düzeltilmiş metin ile issues listesi birebir tutarlı olmalı.
- Metinde aynı hata birden fazla yerde geçiyorsa HER BİRİNİ ayrı issue olarak listele.
  Örneğin "ayet" kelimesi metinde 5 yerde yanlışsa 5 ayrı issue yaz — sadece 1 örnek yazıp GEÇME.
- ASLA "ve benzeri", "vb.", "diğer örnekler" gibi özetleme yapma. Her geçiş ayrı bir satırdır.
- Metni kelime kelime tara; bir hatanın kaç kez geçtiğini say ve o sayıda issue üret.
  Eksik listeleme skoru haksız yere yükseltir ve KABUL EDİLMEZ.
- Son JSON'u vermeden önce correctedText ile özgün metni karşılaştır. Yaptığın her değişiklik için
  tam bir issue bulunduğunu ve listedeki her issue'nun correctedText'e uygulandığını tek tek doğrula.
- Aynı original/fixed çifti tekrar etse bile her metin konumu ayrı hata instance'ıdır ve ayrı issue'dur.
- Bir düzeltmeyi yalnızca en uygun TEK kategoriye yaz; aynı metin konumunu iki kategoride tekrar sayma.

${rules}

════════════════════════════════════════
PUANLAMA (ZORUNLU FORMÜL)
════════════════════════════════════════
Skor 100'den başlar ve her hata kategorinin ağırlığına göre düşülür:
- Sözlük hatası: her biri -5
- İmlâ hatası: her biri -4
- Noktalama hatası: her biri -3
- Etiket hatası: her biri -2
- Yapı hatası: her biri -4
Skor = max(0, 100 - toplam ceza). Sabit/keyfi puan VERME, formülü uygula.

60 PUAN ALTI KURALI:
- Eğer hesaplanan skor 60'ın altındaysa düzeltilmiş metin ÜRETME.
- Bu durumda "correctedText" alanını boş bırak ("") ve "summary" alanına şunu yaz:
  "${LOW_SCORE_MSG}"
- Tüm hataları yine de kategoriler altında listele (bulgular gösterilecek).

ÇIKTI FORMATI — SADECE JSON DÖN, BAŞKA HİÇBİR ŞEY YAZMA.
ÖRNEK: Girdi "ayet bize indi. Bu ayet açıktır. O ayet okundu." ise üç ayrı geçiş vardır;
"ayet → âyet" düzeltmesini bir kez özetlemek YASAKTIR. Beklenen sözlük kategorisi aynen şöyledir:
"sozluk": {
  "count": 3,
  "issues": [
    {"original":"ayet","fixed":"âyet","rule":"Sözlük standardı (1. geçiş)"},
    {"original":"ayet","fixed":"âyet","rule":"Sözlük standardı (2. geçiş)"},
    {"original":"ayet","fixed":"âyet","rule":"Sözlük standardı (3. geçiş)"}
  ]
}

Tam yanıt şeması:
{
  "score": 78,
  "correctedText": "Düzeltilmiş tam metin (skor 60 altındaysa boş)...",
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

async function openaiText(text) {
  const rules = await loadRules();
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
    body: JSON.stringify({
      model: 'gpt-4o',
      max_tokens: 16000,
      temperature: 0,
      response_format: { type: 'json_object' },   // geçerli JSON garantisi (satır başları escape edilir)
      messages: [
        { role: 'system', content: await buildSystemPrompt(rules) },
        { role: 'user', content: `Metni denetle:\n\n${text}` }
      ]
    })
  });
  if (!r.ok) { const e = await r.json(); throw new Error(e.error?.message || 'API hatası'); }
  const d = await r.json();
  const result = finalizeResult(parseResult(d.choices[0].message.content), text);
  result.analysisMeta = { promptVersion: PROMPT_VERSION, rulesHash: textHash(rules).slice(0, 12) };
  return result;
}

async function extractText(buffer) {
  const { value: text } = await mammoth.extractRawText({ buffer });
  if (!text?.trim()) throw new Error('Dosyadan metin çıkarılamadı.');
  return text;
}

// String literalleri içindeki HAM kontrol karakterlerini (satır başı, tab vb.) escape eder.
// Model JSON string'in içine gerçek \n koyduğunda JSON.parse patlar; bunu önler.
function sanitizeControlChars(s) {
  let out = '', inStr = false, esc = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i], code = s.charCodeAt(i);
    if (esc) { out += ch; esc = false; continue; }
    if (ch === '\\') { out += ch; esc = true; continue; }
    if (ch === '"') { inStr = !inStr; out += ch; continue; }
    if (inStr && code < 0x20) {
      out += ch === '\n' ? '\\n' : ch === '\r' ? '\\r' : ch === '\t' ? '\\t'
           : '\\u' + code.toString(16).padStart(4, '0');
      continue;
    }
    out += ch;
  }
  return out;
}

function parseResult(raw) {
  const cleaned = raw.replace(/```json\n?|\n?```/g, '').trim();
  const candidate = cleaned.startsWith('{') ? cleaned : (cleaned.match(/\{[\s\S]*\}/)?.[0] || cleaned);
  try { return JSON.parse(candidate); }
  catch {
    try { return JSON.parse(sanitizeControlChars(candidate)); }
    catch { throw new Error('Yanıt ayrıştırılamadı'); }
  }
}

const DUPLICATE_MSG = 'Bu metni daha önce denetlediniz. Aynı metni tekrar göndermek yerine düzeltilmiş halini kullanabilirsiniz.';

let HAS_TEXT_HASH = false; // startup'ta tespit edilir (history.text_hash kolonu)
let HAS_ANALYSIS_META = false; // startup'ta tespit edilir (history.prompt_version/rules_hash kolonları)
let startupReady = Promise.resolve();

// Bu kullanıcı aynı metni daha önce denetledi mi?
async function isDuplicate(req, text) {
  if (!HAS_TEXT_HASH) return false;
  const hashes = candidateTextHashes(text);
  const { data, error } = await supabase.from('history')
    .select('id').eq('user_id', req.session.userId).in('text_hash', hashes).limit(1);
  if (error) { console.warn('Tekrar kontrolü uyarısı:', error.message); return false; }
  return !!(data && data.length);
}

async function saveHistory(req, result, filename, hash) {
  const catCounts = {};
  if (result.categories) Object.keys(result.categories).forEach(k => catCounts[k] = result.categories[k].count || 0);
  const analysisMeta = result.analysisMeta || {};

  const row = {
    user_id: req.session.userId,
    username: req.session.username, name: req.session.name,
    filename: filename || 'Metin Girişi',
    score: result.score || 0, total_errors: result.totalErrors || 0,
    cat_counts: catCounts, summary: result.summary || '',
    corrected_text: result.correctedText || '',
    status: 'bekliyor'
  };
  if (HAS_TEXT_HASH && hash) row.text_hash = hash;
  if (HAS_ANALYSIS_META) {
    row.prompt_version = analysisMeta.promptVersion || PROMPT_VERSION;
    row.rules_hash = analysisMeta.rulesHash || null;
  }

  const { data, error } = await supabase.from('history').insert(row).select('id').single();
  if (error) throw new Error(error.message);
  const entryId = data.id;

  if ((result.score || 0) < LOW_SCORE_THRESHOLD) {
    await supabase.from('alerts').insert({
      type: 'low_score',
      message: `${req.session.name} tarafından düşük skorlu metin (${result.score}/100): "${filename || 'Metin Girişi'}"`,
      user_id: req.session.userId, history_id: entryId,
      score: result.score, read: false
    });
  }

  return entryId;
}

app.post('/api/analyze', auth, async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Metin boş.' });
  try {
    await startupReady;
    const hash = textHash(text);
    if (await isDuplicate(req, text)) return res.json({ duplicate: true, message: DUPLICATE_MSG });
    const result = await openaiText(text);
    const id = await saveHistory(req, result, 'Metin Girişi', hash);
    res.json({ ...result, id, originalText: text });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/analyze-file', auth, upload.single('file'), async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  if (!req.file) return res.status(400).json({ error: 'Dosya bulunamadı.' });
  try {
    await startupReady;
    const text = await extractText(req.file.buffer);
    const hash = textHash(text);
    if (await isDuplicate(req, text)) return res.json({ duplicate: true, message: DUPLICATE_MSG });
    const result = await openaiText(text);
    const id = await saveHistory(req, result, req.file.originalname, hash);
    res.json({ ...result, id, originalText: text });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/analyze-batch', auth, upload.array('files', 20), async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  if (!req.files?.length) return res.status(400).json({ error: 'Dosya bulunamadı.' });
  const results = [];
  await startupReady;
  for (const file of req.files) {
    try {
      const text = await extractText(file.buffer);
      const hash = textHash(text);
      if (await isDuplicate(req, text)) {
        results.push({ filename: file.originalname, success: false, duplicate: true, error: DUPLICATE_MSG });
        continue;
      }
      const result = await openaiText(text);
      const id = await saveHistory(req, result, file.originalname, hash);
      results.push({ filename: file.originalname, success: true, score: result.score, totalErrors: result.totalErrors, id });
    } catch (e) {
      results.push({ filename: file.originalname, success: false, error: e.message });
    }
  }
  res.json({ results });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'Dosya en fazla 4 MB olabilir.' });
  }
  if (err) return res.status(500).json({ error: err.message || 'Sunucu hatası.' });
  next();
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
startupReady = seed().catch(e => console.error('Seed hatası:', e.message));

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ Arşiv Kontrol AI: http://localhost:${PORT}`));
}

module.exports = app;
