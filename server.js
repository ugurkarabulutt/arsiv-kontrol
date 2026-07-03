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
  candidateTextHashes, finalizeResult, normalizeText, textHash
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
const AI_REPORT_MODEL   = 'gpt-4o-mini';
const MIN_ANALYSIS_TEXT_CHARS = 10;
const MAX_ANALYSIS_TEXT_CHARS = 120000;

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
const SYSTEM_SENDER_NAME = 'Arşiv Kontrol AI';

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

const SURE_STANDARD_LIST = `001. FÂTİHA
002. BAKARA
003. ÂLİ İMRÂN
004. NİSÂ
005. MÂİDE
006. EN'ÂM
007. A'RÂF
008. ENFÂL
009. TEVBE
010. YÛNUS
011. HÛD
012. YÛSUF
013. RA'D
014. İBRÂHÎM
015. HİCR
016. NAHL
017. İSRÂ
018. KEHF
019. MERYEM
020. TÂHÂ
021. ENBİYÂ
022. HACC
023. MU'MİNÛN
024. NÛR
025. FURKÂN
026. ŞUARÂ
027. NEML
028. KASAS
029. ANKEBÛT
030. RÛM
031. LOKMÂN
032. SECDE
033. AHZÂB
034. SEBE
035. FÂTIR
036. YÂSÎN
037. SÂFFÂT
038. SÂD
039. ZUMER
040. MU'MİN
041. FUSSİLET
042. ŞÛRÂ
043. ZUHRÛF
044. DUHÂN
045. CÂSİYE
046. AHKÂF
047. MUHAMMED
048. FETİH
049. HUCURÂT
050. KAF
051. ZÂRİYÂT
052. TÛR
053. NECM
054. KAMER
055. RAHMÂN
056. VÂKIA
057. HADÎD
058. MUCÂDELE
059. HAŞR
060. MUMTEHİNE
061. SAFF
062. CUMA
063. MUNÂFİKÛN
064. TEGÂBUN
065. TALÂK
066. TAHRÎM
067. MULK
068. KALEM
069. HÂKKA
070. MEÂRİC
071. NÛH
072. CİNN
073. MUZZEMMİL
074. MUDDESSİR
075. KIYÂME
076. İNSÂN
077. MURSELÂT
078. NEBE
079. NÂZİÂT
080. ABESE
081. TEKVÎR
082. İNFİTÂR
083. MUTAFFİFÎN
084. İNŞİKAK
085. BURÛC
086. TÂRIK
087. A'LÂ
088. GÂŞİYE
089. FECR
090. BELED
091. ŞEMS
092. LEYL
093. DUHÂ
094. İNŞİRÂH(ŞERH)
095. TÎN
096. ALAK
097. KADR(KADİR)
098. BEYYİNE
099. ZİLZÂL
100. ÂDİYÂT
101. KÂRİA
102. TEKÂSUR
103. ASR
104. HUMEZE
105. FÎL
106. KUREYŞ
107. MÂÛN
108. KEVSER
109. KÂFİRÛN
110. NASR
111. TEBBET(MESED)
112. İHLÂS
113. FELAK
114. NÂS`;

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
din (dîn değil; Efendimizin sözlüğünde bu kelime bundan sonra şapkasız yazılır)
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

SURE ADLARI STANDARDI:
- Sure adları aşağıdaki listeye göre yazılır; baştaki sıra numaraları imlâ kontrolüne dahil değildir.
- Sure adı başlıkta, metin içinde veya "Suresi" ifadesinden önce geçerse şapka/apostrof/harf dizilimi standardı bu listedir.
- Büyük/küçük harf farkını tek başına hata sayma; Fâtiha/fâtiha/FÂTİHA, Mulk/MULK, Muzzemmil/MUZZEMMİL gibi kullanımlar yalnızca harf büyüklüğü nedeniyle düzeltilmez.
- Metin akışında ilk harfin büyük olması yeterlidir; küçük yazılmış sure adı da sadece bu yüzden skor düşürmez.
- Sure adının içindeki parçayı ayrı sözlük kelimesi sanma; örneğin MU'MİNÛN içindeki MU'MİN parçasını değiştirme.
- Liste dışında kalan sure adı varyantlarını yalnızca tam sure adı olarak yakaladıysan listedeki imlâya göre düzelt; zorunlu olarak tamamen büyük harfe çevirme.

${SURE_STANDARD_LIST}

Allah Teala → Allahû Tealâ
Allahu Teala → Allahû Tealâ
Resul → resûl
Veli → velî
Nebi → nebî
dîn → din
her şey → herşey
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
  catCounts: h.cat_counts || {}, summary: h.summary, originalText: h.original_text, correctedText: h.corrected_text,
  status: h.status, approvedBy: h.approved_by, approvedAt: h.approved_at,
  promptVersion: h.prompt_version, rulesHash: h.rules_hash,
  createdAt: h.created_at
});
const mapAlert   = a => ({
  id: a.id, type: a.type, message: a.message, userId: a.user_id,
  historyId: a.history_id, score: a.score, read: a.read,
  feedbackStatus: a.feedback_status || (a.type === 'feedback' && a.read ? 'read' : 'open'),
  resolvedAt: a.resolved_at, resolvedBy: a.resolved_by,
  resolutionGroup: a.resolution_group, resolutionNote: a.resolution_note,
  createdAt: a.created_at
});
const USER_NOTICE_TYPES = ['announcement', 'feedback_resolution'];
const FEEDBACK_REASONS = Object.freeze({
  nonexistent: 'Metinde olmayan hata',
  wrong_fix: 'Yanlış düzeltme',
  missing_issue: 'Eksik hata',
  layout_broken: 'Düzen bozuldu',
  score_wrong: 'Skor yanlış',
  other: 'Diğer'
});

function parseAlertFields(message = '') {
  const fields = {};
  String(message || '').split(' | ').forEach(part => {
    const idx = part.indexOf(':');
    if (idx < 0) return;
    fields[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
  });
  return fields;
}

function feedbackSummary(alert) {
  const fields = parseAlertFields(alert?.message);
  const reason = fields['geri bildirim'] || 'Geri bildirim';
  const finding = fields.bulgu ? `: ${fields.bulgu}` : '';
  const record = fields['kayıt'] ? ` (${fields['kayıt']})` : '';
  return `${reason}${finding}${record}`.slice(0, 260);
}

function buildFeedbackResolutionMessage(userName, feedbacks, note) {
  const safeName = String(userName || 'kardeşimiz').trim();
  const lines = feedbacks.map((f, i) => `${i + 1}. ${feedbackSummary(f)}`);
  return [
    'Başlık: Geri Bildirimlerinizle Çözülen Sorunlar',
    `Mesaj: Sevgili ${safeName},`,
    'Geri bildirimleriniz sayesinde aşağıdaki sorunlar sistemde düzeltildi:',
    ...lines,
    note ? `Çözüm notu: ${note}` : '',
    'Geri bildirimleriniz, sistemi birlikte daha doğru, kullanışlı ve sağlıklı hale getirmemiz için çok kıymetlidir. Katkınız için teşekkür ederiz.',
    `Gönderen: ${SYSTEM_SENDER_NAME}`
  ].filter(Boolean).join('\n');
}

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

  const { error: originalTextErr } = await supabase.from('history').select('original_text').limit(1);
  HAS_ORIGINAL_TEXT = !originalTextErr;
  if (!HAS_ORIGINAL_TEXT) console.warn('⚠ history.original_text kolonu yok — geçmişte orijinal metin saklanmayacak.');

  const { error: feedbackMetaErr } = await supabase.from('alerts')
    .select('feedback_status,resolved_at,resolved_by,resolution_group,resolution_note').limit(1);
  HAS_ALERT_FEEDBACK_META = !feedbackMetaErr;
  if (!HAS_ALERT_FEEDBACK_META) console.warn('⚠ alerts feedback çözüm kolonları yok — çözüm durumu read/notification üzerinden sınırlı izlenecek.');

  const { error: resolutionLogErr } = await supabase.from('issue_resolution_log').select('id').limit(1);
  HAS_ISSUE_RESOLUTION_LOG = !resolutionLogErr;
  if (!HAS_ISSUE_RESOLUTION_LOG) console.warn('⚠ issue_resolution_log tablosu yok — çözüm kayıt defteri pasif.');

  const { error: aiReportsErr } = await supabase.from('ai_reports').select('id').limit(1);
  HAS_AI_REPORTS = !aiReportsErr;
  if (!HAS_AI_REPORTS) console.warn('⚠ ai_reports tablosu yok — AI rapor kayıtları pasif.');
}

// ── Auth middleware ────────────────────────────────────────────────────────
function normalizeSessionRole(req) {
  if (req.session?.userId) req.session.role = effectiveRole(req.session.username, req.session.role);
}

function prepareAnalysisText(text) {
  const cleaned = normalizeText(text);
  if (!cleaned) {
    const err = new Error('Metin boş.');
    err.statusCode = 400;
    throw err;
  }
  if (cleaned.length < MIN_ANALYSIS_TEXT_CHARS) {
    const err = new Error('Metin çok kısa. Sağlıklı denetim için birkaç cümle girin.');
    err.statusCode = 400;
    throw err;
  }
  if (cleaned.length > MAX_ANALYSIS_TEXT_CHARS) {
    const err = new Error('Metin çok uzun. Lütfen metni bölerek denetleyin.');
    err.statusCode = 413;
    throw err;
  }
  return cleaned;
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
app.post('/api/users/:id/notify', auth, admin, async (req, res) => {
  try {
    const cleanTitle = String(req.body?.title || 'Duyuru').trim().slice(0, 120);
    const cleanMessage = String(req.body?.message || '').trim().slice(0, 1200);
    if (!cleanMessage) return res.status(400).json({ error: 'Bildirim mesajı gerekli.' });

    const { data: target, error: targetError } = await supabase.from('users')
      .select('id,name,active').eq('id', req.params.id).maybeSingle();
    if (targetError) throw new Error(targetError.message);
    if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    if (!target.active) return res.status(400).json({ error: 'Pasif kullanıcıya bildirim gönderilemez.' });

    const message = [
      `Başlık: ${cleanTitle}`,
      `Mesaj: ${cleanMessage}`,
      `Gönderen: ${SYSTEM_SENDER_NAME}`
    ].join(' | ');
    const { error } = await supabase.from('alerts').insert({
      type: 'announcement',
      message,
      user_id: target.id,
      read: false
    });
    if (error) throw new Error(error.message);
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

    const feedbackRow = {
      type: 'feedback',
      message: parts.join(' | '),
      user_id: req.session.userId,
      history_id: history.id,
      score: history.score,
      read: false
    };
    if (HAS_ALERT_FEEDBACK_META) feedbackRow.feedback_status = 'open';
    const { error } = await supabase.from('alerts').insert(feedbackRow);
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

app.post('/api/feedback/work-package.pdf', auth, admin, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String).filter(Boolean).slice(0, 100) : [];
    let query = supabase.from('alerts')
      .select('*')
      .eq('type', 'feedback')
      .order('created_at', { ascending: false })
      .limit(80);
    if (ids.length) query = query.in('id', ids);
    const { data: rows, error } = await query;
    if (error) throw new Error(error.message);

    const items = (rows || []).filter(a => a.feedback_status !== 'resolved').slice(0, 50);
    if (!items.length) return res.status(400).json({ error: 'PDF paketi için açık geri bildirim bulunamadı.' });

    const userIds = [...new Set(items.map(a => a.user_id).filter(Boolean))];
    const usersById = new Map();
    if (userIds.length) {
      const { data: users, error: usersError } = await supabase.from('users')
        .select('id,name,username')
        .in('id', userIds);
      if (usersError) throw new Error(usersError.message);
      (users || []).forEach(u => usersById.set(u.id, u));
    }

    const fontPath = require.resolve('@fontsource/noto-serif/files/noto-serif-latin-ext-400-normal.woff');
    const filename = `geri-bildirim-cozum-paketi-${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    const doc = new PDFDocument({ size: 'A4', margins: { top: 48, right: 48, bottom: 54, left: 48 } });
    doc.on('error', err => { if (!res.headersSent) res.status(500).json({ error: err.message }); else res.destroy(err); });
    doc.pipe(res);

    doc.font(fontPath).fillColor('#1a1410').fontSize(18).text('Arşiv Kontrol AI - Geri Bildirim Çözüm Paketi');
    doc.moveDown(0.4).fontSize(9).fillColor('#6f6558')
      .text(`Hazırlayan: ${req.session.name || req.session.username || 'Admin'}   Tarih: ${new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' })}`);
    doc.moveDown(0.7).fontSize(10).fillColor('#1a1410')
      .text('Amaç: Aşağıdaki canlı kullanıcı geri bildirimlerini doğrulamak, gerçek hataları düzeltmek ve sonuçları kullanıcıya geri bildirmek.', { lineGap: 3 });
    doc.moveDown(0.5).fontSize(10).text(`Toplam açık geri bildirim: ${items.length}`);
    doc.moveDown(0.8);

    items.forEach((item, index) => {
      if (doc.y > 700) doc.addPage();
      const user = usersById.get(item.user_id);
      const who = user?.name || user?.username || 'Bilinmeyen kullanıcı';
      const fields = String(item.message || '').split(' | ').map(part => {
        const idx = part.indexOf(':');
        return idx > 0 ? [part.slice(0, idx).trim(), part.slice(idx + 1).trim()] : ['Not', part.trim()];
      }).filter(([, value]) => value);

      doc.roundedRect(44, doc.y, 507, 1, 0).fill('#d8c7a6');
      doc.moveDown(0.7).fillColor('#1a1410').fontSize(12).text(`${index + 1}. Geri Bildirim`, { continued: true });
      doc.fontSize(9).fillColor('#6f6558').text(`   ID: ${item.id}`);
      doc.moveDown(0.25).fillColor('#1a1410').fontSize(9)
        .text(`Kullanıcı: ${who}${user?.username ? ` (${user.username})` : ''}`, { lineGap: 2 })
        .text(`Tarih: ${new Date(item.created_at).toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' })}`, { lineGap: 2 })
        .text(`Skor: ${item.score ?? '-'}   Durum: ${item.feedback_status || 'open'}`, { lineGap: 2 });
      fields.forEach(([label, value]) => {
        doc.moveDown(0.15).fillColor('#1a1410').fontSize(9).text(`${label}:`, { continued: true });
        doc.fillColor('#352a20').text(` ${value}`, { lineGap: 3 });
      });
      doc.moveDown(0.7);
    });

    doc.moveDown(1).fontSize(8).fillColor('#7a6e5e').text('Bu dosya çözüm çalışması için hazırlanmıştır; kullanıcıya gönderilecek bildirim ayrıca panelden onaylanmalıdır.');
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
    const { data, error } = await supabase.from('alerts').select('*').order('created_at', { ascending: false }).limit(300);
    if (error) throw new Error(error.message);
    res.json((data || []).map(mapAlert));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/notification-log', auth, admin, superAdmin, async (req, res) => {
  try {
    const { data: notices, error } = await supabase.from('alerts')
      .select('*')
      .in('type', USER_NOTICE_TYPES)
      .order('created_at', { ascending: false })
      .limit(200);
    if (error) throw new Error(error.message);

    const userIds = [...new Set((notices || []).map(n => n.user_id).filter(Boolean))];
    const usersById = new Map();
    if (userIds.length) {
      const { data: users, error: usersError } = await supabase.from('users')
        .select('id,name,username')
        .in('id', userIds);
      if (usersError) throw new Error(usersError.message);
      (users || []).forEach(u => usersById.set(u.id, u));
    }

    res.json((notices || []).map(n => {
      const user = usersById.get(n.user_id);
      return {
        ...mapAlert(n),
        recipientName: user?.name || user?.username || 'Bilinmeyen kullanıcı',
        recipientUsername: user?.username || ''
      };
    }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/alerts/:id/read', auth, admin, async (req, res) => {
  try {
    const { error } = await supabase.from('alerts').update({ read: true }).eq('id', req.params.id).in('type', ['feedback', 'low_score']);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/alerts/read-all', auth, admin, async (req, res) => {
  try {
    const { error } = await supabase.from('alerts').update({ read: true }).eq('read', false).in('type', ['low_score']);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/alerts/:id/respond', auth, admin, async (req, res) => {
  try {
    const cleanNote = String(req.body?.note || '').trim().slice(0, 1200);
    if (!cleanNote) return res.status(400).json({ error: 'Çözüm notu gerekli.' });

    const { data: alert, error: alertError } = await supabase.from('alerts')
      .select('*').eq('id', req.params.id).eq('type', 'feedback').maybeSingle();
    if (alertError) throw new Error(alertError.message);
    if (!alert) return res.status(404).json({ error: 'Geri bildirim bulunamadı.' });
    if (!alert.user_id) return res.status(400).json({ error: 'Bu geri bildirim kullanıcıya bağlı değil.' });

    const message = [
      'Geri bildiriminiz incelendi',
      `Çözüm: ${cleanNote}`,
      `Yanıtlayan: ${SYSTEM_SENDER_NAME}`,
      alert.message ? `İlgili kayıt: ${String(alert.message).split(' | ')[1] || 'Denetim sonucu'}` : ''
    ].filter(Boolean).join(' | ');

    const { error: insertError } = await supabase.from('alerts').insert({
      type: 'feedback_resolution',
      message,
      user_id: alert.user_id,
      history_id: alert.history_id,
      score: alert.score,
      read: false
    });
    if (insertError) throw new Error(insertError.message);

    const patch = { read: true };
    if (HAS_ALERT_FEEDBACK_META) {
      patch.feedback_status = 'resolved';
      patch.resolved_at = new Date().toISOString();
      patch.resolved_by = req.session.name || req.session.username;
      patch.resolution_group = insertError ? null : `single-${alert.id}`;
      patch.resolution_note = cleanNote;
    }
    const { error: updateError } = await supabase.from('alerts').update(patch).eq('id', alert.id);
    if (updateError) throw new Error(updateError.message);

    if (HAS_ISSUE_RESOLUTION_LOG) {
      await supabase.from('issue_resolution_log').upsert({
        resolution_group: `single-${alert.id}`,
        title: cleanNote.slice(0, 160),
        summary: feedbackSummary(alert),
        status: 'resolved',
        feedback_count: 1,
        user_count: 1,
        created_by: req.session.name || req.session.username
      }, { onConflict: 'resolution_group' });
    }

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/alerts/resolve-bulk', auth, admin, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String).filter(Boolean).slice(0, 100) : [];
    const cleanNote = String(req.body?.note || '').trim().slice(0, 1200);
    if (!ids.length) return res.status(400).json({ error: 'Çözülecek geri bildirim seçilmedi.' });
    if (!cleanNote) return res.status(400).json({ error: 'Çözüm notu gerekli.' });

    const { data: rows, error: rowsError } = await supabase.from('alerts')
      .select('*')
      .in('id', ids)
      .eq('type', 'feedback');
    if (rowsError) throw new Error(rowsError.message);

    const feedbacks = (rows || []).filter(a => {
      if (!a.user_id) return false;
      if (HAS_ALERT_FEEDBACK_META && a.feedback_status === 'resolved') return false;
      return true;
    });
    if (!feedbacks.length) return res.status(400).json({ error: 'Bildirim gönderilecek açık geri bildirim bulunamadı.' });

    const byUser = new Map();
    feedbacks.forEach(alert => {
      const key = alert.user_id;
      if (!byUser.has(key)) byUser.set(key, []);
      byUser.get(key).push(alert);
    });

    const userIds = [...byUser.keys()];
    const usersById = new Map();
    if (userIds.length) {
      const { data: users, error: usersError } = await supabase.from('users')
        .select('id,name,username')
        .in('id', userIds);
      if (usersError) throw new Error(usersError.message);
      (users || []).forEach(u => usersById.set(u.id, u));
    }

    const groupId = `bulk-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const notices = [];
    for (const [userId, items] of byUser.entries()) {
      const first = items[0];
      const user = usersById.get(userId);
      const userName = user?.name || user?.username || 'kardeşimiz';
      notices.push({
        type: 'feedback_resolution',
        message: buildFeedbackResolutionMessage(userName, items, cleanNote),
        user_id: userId,
        history_id: first.history_id || null,
        score: first.score || null,
        read: false,
        ...(HAS_ALERT_FEEDBACK_META ? {
          feedback_status: 'notice',
          resolution_group: groupId,
          resolution_note: cleanNote
        } : {})
      });
    }

    const { error: insertError } = await supabase.from('alerts').insert(notices);
    if (insertError) throw new Error(insertError.message);

    const patch = { read: true };
    if (HAS_ALERT_FEEDBACK_META) {
      patch.feedback_status = 'resolved';
      patch.resolved_at = new Date().toISOString();
      patch.resolved_by = req.session.name || req.session.username;
      patch.resolution_group = groupId;
      patch.resolution_note = cleanNote;
    }
    const { error: updateError } = await supabase.from('alerts')
      .update(patch)
      .in('id', feedbacks.map(f => f.id));
    if (updateError) throw new Error(updateError.message);

    if (HAS_ISSUE_RESOLUTION_LOG) {
      const sampleItems = feedbacks.slice(0, 8).map(feedbackSummary).join('\n');
      const { error: logError } = await supabase.from('issue_resolution_log').insert({
        resolution_group: groupId,
        title: cleanNote.slice(0, 160),
        summary: sampleItems,
        status: 'resolved',
        feedback_count: feedbacks.length,
        user_count: byUser.size,
        created_by: req.session.name || req.session.username
      });
      if (logError) throw new Error(logError.message);
    }

    res.json({
      success: true,
      feedbackCount: feedbacks.length,
      userCount: byUser.size,
      groupId
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/my-notifications', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('alerts')
      .select('*')
      .eq('user_id', req.session.userId)
      .in('type', USER_NOTICE_TYPES)
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) throw new Error(error.message);
    res.json((data || []).map(mapAlert));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/my-notifications/:id/read', auth, async (req, res) => {
  try {
    const { error } = await supabase.from('alerts')
      .update({ read: true })
      .eq('id', req.params.id)
      .eq('user_id', req.session.userId)
      .in('type', USER_NOTICE_TYPES);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/my-notifications/read-all', auth, async (req, res) => {
  try {
    const { error } = await supabase.from('alerts')
      .update({ read: true })
      .eq('read', false)
      .eq('user_id', req.session.userId)
      .in('type', USER_NOTICE_TYPES);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── DASHBOARD STATS ───────────────────────────────────────────────────────
app.get('/api/stats', auth, admin, async (req, res) => {
  try {
    const [
      { data: histRows, error: hErr },
      { data: userRows, error: uErr },
      { data: alertRows, error: aErr },
      resolutionLogResult
    ] = await Promise.all([
      supabase.from('history').select('*'),
      supabase.from('users').select('id,name,username,active'),
      supabase.from('alerts').select('*'),
      HAS_ISSUE_RESOLUTION_LOG
        ? supabase.from('issue_resolution_log').select('*').order('created_at', { ascending: false }).limit(12)
        : Promise.resolve({ data: [], error: null })
    ]);
    if (hErr) throw new Error(hErr.message);
    if (uErr) throw new Error(uErr.message);
    if (aErr) throw new Error(aErr.message);
    if (resolutionLogResult.error) throw new Error(resolutionLogResult.error.message);

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

    const alerts = alertRows || [];
    const feedbackAlerts = alerts.filter(a => a.type === 'feedback');
    const lowScoreAlerts = alerts.filter(a => a.type === 'low_score');
    const resolutionAlerts = alerts.filter(a => a.type === 'feedback_resolution');
    const announcementAlerts = alerts.filter(a => a.type === 'announcement');
    const feedbackResolvedItems = feedbackAlerts.filter(a => a.feedback_status === 'resolved');
    const feedbackOpenItems = feedbackAlerts.filter(a => a.feedback_status !== 'resolved');
    const usersById = new Map((userRows || []).map(u => [u.id, u]));
    const feedbackByUser = {};
    feedbackAlerts.forEach(a => {
      const key = a.user_id || 'unknown';
      const u = usersById.get(a.user_id);
      if (!feedbackByUser[key]) {
        feedbackByUser[key] = {
          userId: a.user_id,
          name: u?.name || u?.username || 'Bilinmeyen',
          feedbackCount: 0,
          resolvedCount: 0,
          openCount: 0,
          lastAt: a.created_at
        };
      }
      feedbackByUser[key].feedbackCount++;
      if (a.feedback_status === 'resolved') feedbackByUser[key].resolvedCount++;
      else feedbackByUser[key].openCount++;
      if (new Date(a.created_at) > new Date(feedbackByUser[key].lastAt || 0)) feedbackByUser[key].lastAt = a.created_at;
    });
    const feedbackUsers = Object.values(feedbackByUser)
      .map(u => ({
        ...u,
        contributionScore: u.resolvedCount * 3 + u.feedbackCount,
        resolvedRate: u.feedbackCount ? Math.round((u.resolvedCount / u.feedbackCount) * 100) : 0
      }))
      .sort((a, b) => b.feedbackCount - a.feedbackCount || b.resolvedCount - a.resolvedCount);
    const topContributors = [...feedbackUsers]
      .sort((a, b) => b.contributionScore - a.contributionScore || b.resolvedCount - a.resolvedCount)
      .slice(0, 8);
    const feedback7 = feedbackAlerts.filter(a => now - new Date(a.created_at).getTime() < 7 * 864e5).length;
    const adminAlertTypes = ['feedback', 'low_score'];
    const unreadAlerts = alerts.filter(a => !a.read && adminAlertTypes.includes(a.type)).length;
    const unreadFeedback = feedbackAlerts.filter(a => !a.read).length;
    const pending = hist.filter(h => h.status === 'bekliyor' || !h.status).length;
    const riskItems = hist
      .filter(h => (h.score || 0) < 60 || (h.totalErrors || 0) >= 5)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 8)
      .map(h => ({
        id: h.id,
        name: h.name,
        filename: h.filename,
        score: h.score || 0,
        totalErrors: h.totalErrors || 0,
        status: h.status || 'bekliyor',
        createdAt: h.createdAt
      }));

    res.json({
      totals: {
        allTime: hist.length,
        last30: day30.length,
        activeUsers: users.length,
        avgScore: hist.length ? Math.round(hist.reduce((s,h)=>s+(h.score||0),0)/hist.length) : 0,
        pendingApproval: pending,
        unreadAlerts,
        feedback: feedbackAlerts.length,
        feedback7,
        feedbackOpen: feedbackOpenItems.length,
        feedbackResolvedItems: feedbackResolvedItems.length,
        feedbackResolutionRate: feedbackAlerts.length ? Math.round((feedbackResolvedItems.length / feedbackAlerts.length) * 100) : 0,
        feedbackContributors: feedbackUsers.filter(u => u.userId).length,
        unreadFeedback,
        lowScoreAlerts: lowScoreAlerts.length,
        feedbackResolved: resolutionAlerts.length,
        announcements: announcementAlerts.length
      },
      perUser: Object.values(perUser).map(u => ({
        name: u.name, count: u.count,
        avgScore: u.count ? Math.round(u.scoreSum / u.count) : 0,
        avgErrors: u.count ? Math.round(u.errors / u.count) : 0
      })).sort((a,b) => b.count - a.count),
      catTotals,
      daily,
      riskItems,
      feedbackUsers,
      topContributors,
      resolutionLog: (resolutionLogResult.data || []).map(row => ({
        id: row.id,
        title: row.title,
        summary: row.summary,
        status: row.status,
        feedbackCount: row.feedback_count,
        userCount: row.user_count,
        createdBy: row.created_by,
        createdAt: row.created_at
      }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ANALYSIS ──────────────────────────────────────────────────────────────
function istanbulDateParts(now = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Istanbul',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(now).reduce((acc, part) => {
    if (part.type !== 'literal') acc[part.type] = Number(part.value);
    return acc;
  }, {});
  const weekday = new Date(Date.UTC(parts.year, parts.month - 1, parts.day, 12)).getUTCDay();
  return { year: parts.year, month: parts.month, day: parts.day, weekday };
}

function istanbulMidnightUtc(year, month, day) {
  return new Date(Date.UTC(year, month - 1, day, 21, 0, 0, 0));
}

function shiftDateParts({ year, month, day }, days) {
  const d = new Date(Date.UTC(year, month - 1, day + days, 12));
  return { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, day: d.getUTCDate() };
}

function periodRange(period = 'daily', now = new Date()) {
  const today = istanbulDateParts(now);
  const todayStart = istanbulMidnightUtc(today.year, today.month, today.day);
  if (period === 'weekly') {
    const startParts = shiftDateParts(today, -7);
    return { start: istanbulMidnightUtc(startParts.year, startParts.month, startParts.day), end: todayStart };
  }
  if (period === 'monthly') {
    const end = istanbulMidnightUtc(today.year, today.month, 1);
    const prevMonth = today.month === 1 ? { year: today.year - 1, month: 12 } : { year: today.year, month: today.month - 1 };
    return { start: istanbulMidnightUtc(prevMonth.year, prevMonth.month, 1), end };
  }
  if (period === 'yearly') {
    return { start: istanbulMidnightUtc(today.year - 1, 1, 1), end: istanbulMidnightUtc(today.year, 1, 1) };
  }
  const yesterday = shiftDateParts(today, -1);
  return { start: istanbulMidnightUtc(yesterday.year, yesterday.month, yesterday.day), end: todayStart };
}

async function collectOperationalSnapshot(period = 'daily') {
  const { start, end } = periodRange(period);
  const [{ data: histRows, error: hErr }, { data: userRows, error: uErr }, { data: alertRows, error: aErr }, logResult] = await Promise.all([
    supabase.from('history').select('*').gte('created_at', start.toISOString()).lt('created_at', end.toISOString()),
    supabase.from('users').select('id,name,username,active,role'),
    supabase.from('alerts').select('*').gte('created_at', start.toISOString()).lt('created_at', end.toISOString()),
    HAS_ISSUE_RESOLUTION_LOG
      ? supabase.from('issue_resolution_log').select('*').gte('created_at', start.toISOString()).lt('created_at', end.toISOString()).order('created_at', { ascending: false }).limit(30)
      : Promise.resolve({ data: [], error: null })
  ]);
  if (hErr) throw new Error(hErr.message);
  if (uErr) throw new Error(uErr.message);
  if (aErr) throw new Error(aErr.message);
  if (logResult.error) throw new Error(logResult.error.message);

  const hist = (histRows || []).map(mapHistory);
  const alerts = alertRows || [];
  const usersById = new Map((userRows || []).map(u => [u.id, u]));
  const feedback = alerts.filter(a => a.type === 'feedback');
  const feedbackResolved = feedback.filter(a => a.feedback_status === 'resolved');
  const feedbackOpen = feedback.filter(a => a.feedback_status !== 'resolved');
  const lowScore = alerts.filter(a => a.type === 'low_score');
  const catTotals = { sozluk: 0, imla: 0, noktalama: 0, etiket: 0, yapi: 0 };
  hist.forEach(h => {
    if (h.catCounts) Object.keys(catTotals).forEach(k => { catTotals[k] += h.catCounts[k] || 0; });
  });

  const userActivity = {};
  hist.forEach(h => {
    const key = h.userId || h.username || 'unknown';
    if (!userActivity[key]) userActivity[key] = { name: h.name || h.username || 'Bilinmeyen', denetim: 0, scoreSum: 0, errors: 0 };
    userActivity[key].denetim++;
    userActivity[key].scoreSum += h.score || 0;
    userActivity[key].errors += h.totalErrors || 0;
  });
  feedback.forEach(a => {
    const key = a.user_id || 'unknown-feedback';
    const u = usersById.get(a.user_id);
    if (!userActivity[key]) userActivity[key] = { name: u?.name || u?.username || 'Bilinmeyen', denetim: 0, scoreSum: 0, errors: 0 };
    userActivity[key].feedback = (userActivity[key].feedback || 0) + 1;
    if (a.feedback_status === 'resolved') userActivity[key].resolvedFeedback = (userActivity[key].resolvedFeedback || 0) + 1;
  });
  const topUsers = Object.values(userActivity).map(u => ({
    ...u,
    avgScore: u.denetim ? Math.round(u.scoreSum / u.denetim) : 0,
    avgErrors: u.denetim ? Math.round(u.errors / u.denetim) : 0
  })).sort((a, b) => (b.denetim + (b.feedback || 0)) - (a.denetim + (a.feedback || 0))).slice(0, 12);

  const feedbackSamples = feedbackOpen.concat(feedbackResolved).slice(0, 20).map(a => ({
    status: a.feedback_status || 'open',
    score: a.score || null,
    summary: feedbackSummary(a),
    createdAt: a.created_at
  }));

  return {
    period,
    periodStart: start.toISOString(),
    periodEnd: end.toISOString(),
    totals: {
      denetim: hist.length,
      avgScore: hist.length ? Math.round(hist.reduce((sum, h) => sum + (h.score || 0), 0) / hist.length) : 0,
      totalErrors: hist.reduce((sum, h) => sum + (h.totalErrors || 0), 0),
      lowScore: lowScore.length,
      feedback: feedback.length,
      feedbackOpen: feedbackOpen.length,
      feedbackResolved: feedbackResolved.length,
      activeUsers: (userRows || []).filter(u => u.active).length,
      approvalsPending: hist.filter(h => !h.status || h.status === 'bekliyor').length
    },
    catTotals,
    topUsers,
    feedbackSamples,
    resolutionLog: (logResult.data || []).map(row => ({
      title: row.title,
      feedbackCount: row.feedback_count,
      userCount: row.user_count,
      createdBy: row.created_by,
      createdAt: row.created_at,
      summary: row.summary
    }))
  };
}

function fallbackReport(snapshot) {
  return {
    title: `${snapshot.period} operasyon raporu`,
    executiveSummary: `Bu dönemde ${snapshot.totals.denetim} denetim, ${snapshot.totals.feedback} geri bildirim ve ${snapshot.totals.feedbackResolved} çözülen geri bildirim kaydedildi.`,
    activitySummary: `Ortalama skor ${snapshot.totals.avgScore}. Toplam hata sayısı ${snapshot.totals.totalErrors}.`,
    feedbackSummary: `Açık geri bildirim ${snapshot.totals.feedbackOpen}, çözülen geri bildirim ${snapshot.totals.feedbackResolved}.`,
    risks: snapshot.totals.lowScore ? [`${snapshot.totals.lowScore} düşük skor uyarısı var.`] : ['Belirgin düşük skor uyarısı yok.'],
    recommendations: ['Tekrarlayan geri bildirimleri haftalık kalite regresyon testlerine ekleyin.'],
    nextActions: ['Açık geri bildirimleri Geri Bildirim Merkezi üzerinden çözüm paketine dönüştürün.']
  };
}

async function generateAiReportContent(snapshot) {
  if (!OPENAI_API_KEY) return fallbackReport(snapshot);
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
    body: JSON.stringify({
      model: AI_REPORT_MODEL,
      temperature: 0.2,
      max_tokens: 1800,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: 'Sen Arşiv Kontrol AI yönetim panelinin operasyon analisti asistanısın. Verilen metrikleri kısa, somut ve yönetime uygun Türkçe rapora dönüştür. Halüsinasyon yapma; yalnızca verilen veriye dayan. JSON döndür: title, executiveSummary, activitySummary, feedbackSummary, risks(array), recommendations(array), nextActions(array).' },
        { role: 'user', content: JSON.stringify(snapshot).slice(0, 24000) }
      ]
    })
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.error?.message || 'AI rapor API hatası');
  }
  const d = await r.json();
  try { return JSON.parse(d.choices[0].message.content); }
  catch { return { ...fallbackReport(snapshot), raw: d.choices[0].message.content }; }
}

async function createAiReport(period, createdBy = 'Sistem') {
  if (!HAS_AI_REPORTS) throw new Error('ai_reports tablosu yok. schema.sql içindeki ai_reports SQL bölümünü Supabase SQL Editor’de çalıştırın.');
  const snapshot = await collectOperationalSnapshot(period);
  const { data: existing, error: existingError } = await supabase.from('ai_reports')
    .select('*')
    .eq('period', period)
    .eq('period_start', snapshot.periodStart)
    .eq('period_end', snapshot.periodEnd)
    .maybeSingle();
  if (existingError) throw new Error(existingError.message);
  if (existing) return { ...existing, already_exists: true };

  const content = await generateAiReportContent(snapshot);
  const { data, error } = await supabase.from('ai_reports').insert({
    period,
    period_start: snapshot.periodStart,
    period_end: snapshot.periodEnd,
    title: content.title || `${period} AI raporu`,
    content,
    metrics: snapshot,
    model: OPENAI_API_KEY ? AI_REPORT_MODEL : 'fallback',
    created_by: createdBy
  }).select('*').single();
  if (error) throw new Error(error.message);
  return data;
}

function dueReportPeriods(now = new Date()) {
  const today = istanbulDateParts(now);
  const periods = ['daily'];
  if (today.weekday === 1) periods.push('weekly');
  if (today.day === 1) periods.push('monthly');
  if (today.month === 1 && today.day === 1) periods.push('yearly');
  return periods;
}

function reportPeriodLabel(period) {
  return period === 'weekly' ? 'Haftalık'
    : period === 'monthly' ? 'Aylık'
    : period === 'yearly' ? 'Yıllık'
    : 'Günlük';
}

async function notifyAdminsAboutReports(reports) {
  const created = reports.filter(r => !r.already_exists);
  if (!created.length) return 0;
  const { data: users, error } = await supabase.from('users')
    .select('id,role,active')
    .eq('active', true)
    .in('role', ['admin', 'super_admin']);
  if (error) throw new Error(error.message);
  const recipients = users || [];
  if (!recipients.length) return 0;
  const labels = created.map(r => reportPeriodLabel(r.period)).join(', ');
  const message = [
    `Başlık: AI Operasyon Raporu Hazır`,
    `Mesaj: İstanbul saatiyle 00:00 rapor akışı tamamlandı. Hazırlanan raporlar: ${labels}. Raporları admin panelindeki AI Asistan ve Raporlar ekranından inceleyebilirsiniz.`,
    `Gönderen: ${SYSTEM_SENDER_NAME}`
  ].join(' | ');
  const rows = recipients.map(u => ({
    type: 'announcement',
    message,
    user_id: u.id,
    read: false
  }));
  const { error: insertError } = await supabase.from('alerts').insert(rows);
  if (insertError) throw new Error(insertError.message);
  return rows.length;
}

async function createDueAiReports(createdBy = 'Sistem Cron', now = new Date()) {
  const reports = [];
  for (const period of dueReportPeriods(now)) {
    reports.push(await createAiReport(period, createdBy));
  }
  const notifiedUsers = await notifyAdminsAboutReports(reports);
  return { reports, notifiedUsers };
}

const mapAiReport = row => ({
  id: row.id,
  period: row.period,
  periodStart: row.period_start,
  periodEnd: row.period_end,
  title: row.title,
  content: row.content || {},
  metrics: row.metrics || {},
  model: row.model,
  createdBy: row.created_by,
  createdAt: row.created_at
});

app.get('/api/ai/reports', auth, admin, async (req, res) => {
  try {
    if (!HAS_AI_REPORTS) return res.status(400).json({ error: 'ai_reports tablosu yok. Supabase SQL gerekli.' });
    const { data, error } = await supabase.from('ai_reports').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) throw new Error(error.message);
    res.json((data || []).map(mapAiReport));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ai/reports/generate', auth, admin, async (req, res) => {
  try {
    const period = ['daily', 'weekly', 'monthly', 'yearly'].includes(req.body?.period) ? req.body.period : 'daily';
    const report = await createAiReport(period, req.session.name || req.session.username);
    res.json({ success: true, report: mapAiReport(report) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ai/insight', auth, admin, async (req, res) => {
  try {
    const question = String(req.body?.question || '').trim().slice(0, 1200);
    if (!question) return res.status(400).json({ error: 'Soru gerekli.' });
    const period = ['daily', 'weekly', 'monthly', 'yearly'].includes(req.body?.period) ? req.body.period : 'weekly';
    const snapshot = await collectOperationalSnapshot(period);
    if (!OPENAI_API_KEY) return res.json({ answer: fallbackReport(snapshot).executiveSummary, model: 'fallback' });
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
      body: JSON.stringify({
        model: AI_REPORT_MODEL,
        temperature: 0.2,
        max_tokens: 1200,
        messages: [
          { role: 'system', content: 'Sen Arşiv Kontrol AI admin panelinde çalışan veri analisti asistansın. Veriye dayan, kısa ve uygulanabilir Türkçe cevap ver.' },
          { role: 'user', content: `Soru: ${question}\n\nVeri:\n${JSON.stringify(snapshot).slice(0, 22000)}` }
        ]
      })
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      throw new Error(e.error?.message || 'AI asistan API hatası');
    }
    const d = await r.json();
    res.json({ answer: d.choices[0].message.content, model: AI_REPORT_MODEL });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/cron/daily-report', async (req, res) => {
  try {
    const cronSecret = process.env.CRON_SECRET;
    const isVercelCron = req.headers['x-vercel-cron'] === '1';
    const provided = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query.secret;
    if (cronSecret && provided !== cronSecret && !isVercelCron) return res.status(401).json({ error: 'Yetkisiz.' });
    const result = await createDueAiReports('Sistem Cron');
    res.json({
      success: true,
      reports: result.reports.map(r => ({ id: r.id, period: r.period, alreadyExists: Boolean(r.already_exists) })),
      notifiedUsers: result.notifiedUsers
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

async function buildSystemPrompt(rulesText) {
  const rules = rulesText ?? await loadRules();
  return `Sen "Arşiv Kontrol AI" sistemisin. Görevin yalnızca cevap metinlerini verilen kurallara göre denetlemek ve düzeltmektir.

GÜNCEL ÜST ÖNCELİKLİ SÖZLÜK KARARLARI:
- "din" doğru yazımdır; "din" kelimesini "dîn" olarak düzeltme. Metinde "dîn" varsa "din" olarak düzelt.
- "herşey" doğru yazımdır; "herşey" kelimesini "her şey" olarak ayırma. Metinde "her şey" varsa "herşey" olarak düzelt.
- Bu iki karar mevcut kural metninde ters yönde bir ifade görsen bile daha önceliklidir.

SURE ADLARI ÜST ÖNCELİKLİ STANDARDI:
- Sure adlarında aşağıdaki liste esastır; baştaki sıra numaralarını imlâ konusu yapma.
- Sure adlarında büyük/küçük harf farkını tek başına hata sayma; sadece şapka, apostrof ve harf dizilimi gibi gerçek imlâ farklarını düzelt.
- Metin içinde ilk harfin büyük olması yeterlidir; kullanıcı küçük yazdıysa sadece bu yüzden skor düşürme.
- Sure adı içinden parça yakalayıp ayrı kelime düzeltmesi yapma.
- Örnek: Muminun/Müminun/Mu'minun sure adı olarak geçiyorsa imlâ olarak Mu'minûn biçimine düzeltilir; mü'min kelimesine indirgenmez ve zorunlu olarak tamamen büyük harfe çevrilmez.
- Örnek: Zümer/Zumer sure adı olarak geçiyorsa imlâ olarak Zumer biçimi esastır; Zumer/zumer/ZUMER arasında sadece harf büyüklüğü farkı varsa hata yazma.

${SURE_STANDARD_LIST}

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
17. "Tabi/Tabiî" kelimesi konuşma içinde "elbette/doğal olarak" anlamındaysa "tâbî" yapma. "süre" zaman/uzunluk
   anlamındaysa "sûre" yapma. "afet", "zahid", "ahiret", "zülmanî", "Nebîler" ve "nefs" kelimelerini ters yöne
   bozma. "(S.A.V)" kısaltmasına fazladan nokta ekleme.
18. Slayt, hadîs dökümü, tablo benzeri satır düzenlerini koru. Satır sırası, başlıklar, numaralar ve tırnak dengesi
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
let HAS_ORIGINAL_TEXT = false; // startup'ta tespit edilir (history.original_text kolonu)
let HAS_ALERT_FEEDBACK_META = false; // startup'ta tespit edilir (alerts feedback çözüm kolonları)
let HAS_ISSUE_RESOLUTION_LOG = false; // startup'ta tespit edilir (çözüm kayıt defteri)
let HAS_AI_REPORTS = false; // startup'ta tespit edilir (AI rapor kayıtları)
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

async function saveHistory(req, result, filename, hash, sourceText = '') {
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
  if (HAS_ORIGINAL_TEXT) row.original_text = sourceText;
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
  try {
    await startupReady;
    const text = prepareAnalysisText(req.body?.text);
    const hash = textHash(text);
    if (await isDuplicate(req, text)) return res.json({ duplicate: true, message: DUPLICATE_MSG });
    const result = await openaiText(text);
    const id = await saveHistory(req, result, 'Metin Girişi', hash, text);
    res.json({ ...result, id, originalText: text });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/analyze-file', auth, upload.single('file'), async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  if (!req.file) return res.status(400).json({ error: 'Dosya bulunamadı.' });
  try {
    await startupReady;
    const text = prepareAnalysisText(await extractText(req.file.buffer));
    const hash = textHash(text);
    if (await isDuplicate(req, text)) return res.json({ duplicate: true, message: DUPLICATE_MSG });
    const result = await openaiText(text);
    const id = await saveHistory(req, result, req.file.originalname, hash, text);
    res.json({ ...result, id, originalText: text });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/analyze-batch', auth, upload.array('files', 20), async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  if (!req.files?.length) return res.status(400).json({ error: 'Dosya bulunamadı.' });
  const results = [];
  await startupReady;
  for (const file of req.files) {
    try {
      const text = prepareAnalysisText(await extractText(file.buffer));
      const hash = textHash(text);
      if (await isDuplicate(req, text)) {
        results.push({ filename: file.originalname, success: false, duplicate: true, error: DUPLICATE_MSG });
        continue;
      }
      const result = await openaiText(text);
      const id = await saveHistory(req, result, file.originalname, hash, text);
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
