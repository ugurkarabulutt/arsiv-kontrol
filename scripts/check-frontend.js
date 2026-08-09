const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
const vercelConfig = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
const script = html.match(/<script>([\s\S]*?)<\/script>/);
const root = path.join(__dirname, '..');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function indexOfRequired(source, needle, label) {
  const index = source.indexOf(needle);
  if (index === -1) throw new Error(`${label} bulunamadi.`);
  return index;
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const PUBLIC_FORBIDDEN_WORDS = ['AI', 'prompt', 'model', 'admin', 'denetim', 'onay kuyruğu', 'kalite kontrol', 'test verisi'];

function publicForbiddenWordHits(content, options = {}) {
  let scan = String(content || '');
  if (options.allowRobotsAdminPath) {
    scan = scan.replace(/^\s*(?:Disallow|Allow):\s*\/admin\/?\s*$/gmi, '');
  }
  return PUBLIC_FORBIDDEN_WORDS.filter(word => new RegExp(`(^|[^\\p{L}\\p{N}_])${escapeRegex(word)}([^\\p{L}\\p{N}_]|$)`, 'iu').test(scan));
}

if (!script) throw new Error('index.html içinde inline script bulunamadı.');
new Function(script[1]);

const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.webmanifest'), 'utf8'));
if (manifest.name !== 'Arşiv AI' || manifest.short_name !== 'Arşiv AI') {
  throw new Error('PWA uygulama adı Arşiv AI olmalı.');
}
if (manifest.id !== '/admin' || manifest.start_url !== '/admin' || manifest.scope !== '/') {
  throw new Error('Ana ekrana eklenen PWA admin uygulamasi /admin kimligi/adresiyle baslamali ve root scope korunmali.');
}
function readPngSize(filePath) {
  const png = fs.readFileSync(filePath);
  return `${png.readUInt32BE(16)}x${png.readUInt32BE(20)}`;
}
for (const icon of manifest.icons || []) {
  const iconPath = path.join(root, icon.src.replace(/^\//, ''));
  if (readPngSize(iconPath) !== icon.sizes) {
    throw new Error(`${icon.src} ölçüsü manifest ile eşleşmiyor.`);
  }
}

const favicon16 = path.join(root, 'icons', 'favicon-16.png');
const favicon32 = path.join(root, 'icons', 'favicon-32.png');
const faviconIco = path.join(root, 'icons', 'favicon.ico');
if (readPngSize(favicon16) !== '16x16' || readPngSize(favicon32) !== '32x32') {
  throw new Error('Favicon PNG ölçüleri 16x16 ve 32x32 olmalı.');
}
const ico = fs.readFileSync(faviconIco);
if (ico.readUInt16LE(0) !== 0 || ico.readUInt16LE(2) !== 1 || ico.readUInt16LE(4) < 1) {
  throw new Error('favicon.ico geçerli ICO başlığı taşımıyor.');
}
if (!html.includes('rel="icon" href="/favicon.ico"') || !html.includes('href="/icons/favicon-32.png"')) {
  throw new Error('Masaüstü favicon linkleri eksik.');
}

new Function(fs.readFileSync(path.join(root, 'sw.js'), 'utf8'));

const social = fs.readFileSync(path.join(root, 'icons', 'social-preview.png'));
if (social.readUInt32BE(16) !== 1200 || social.readUInt32BE(20) !== 630) {
  throw new Error('Sosyal paylaşım görseli 1200x630 olmalı.');
}
if (!html.includes('property="og:image"') || !html.includes('name="twitter:card"')) {
  throw new Error('Open Graph/Twitter paylaşım metaları eksik.');
}
if (!html.includes('function friendlyAnalyzeError') || !html.includes('AI servisi geçici olarak yanıt veremedi')) {
  throw new Error('Denetim hata mesajları kullanıcı dostu Türkçe metne bağlanmalı.');
}
if (!html.includes('Denetim tamamlanamadı. Metniniz korunuyor.')) {
  throw new Error('Denetim hatasında metnin korunduğu kullanıcıya belirtilmeli.');
}
if (!html.includes('LONG_TEXT_CHUNK_CHARS') || !html.includes('splitTextForLongAnalysis') || !html.includes('analyzeLongText')) {
  throw new Error('Uzun metinler frontend tarafinda parcali denetime bagli olmali.');
}
if (!html.includes('LONG_TEXT_CHUNK_CHARS=8000') || !html.includes('LONG_TEXT_CONCURRENCY=2') || !html.includes('fallbackChunkCount')) {
  throw new Error('Uzun metin modu 50k-200k konferans metinleri icin guvenli parca, eszamanlilik ve fallback davranisina sahip olmali.');
}
if (!html.includes('const MAX_TEXT_CHARS=200000') || !server.includes('const MAX_ANALYSIS_TEXT_CHARS = 200000')) {
  throw new Error('Metin denetimi 200.000 karaktere kadar kabul edecek sekilde frontend ve backend sinirlariyla hizalanmali.');
}
if (!html.includes('Metin 200.000 karakter sınırını aşıyor') || !server.includes('Metin 200.000 karakter sınırını aşıyor')) {
  throw new Error('200.000 karakter ustu icin kullaniciya net sinir mesaji gosterilmeli.');
}
if (!html.includes('/api/extract-file-text') || !server.includes('/api/extract-file-text') || !server.includes('skipDuplicate')) {
  throw new Error('Uzun dosya/metin denetimi icin metin cikarma ve parca denetimi altyapisi eksik.');
}
if (!server.includes("status = 'taslak'") || !server.includes('/api/history/submit-merged') || !server.includes("app.post('/api/history/:id([0-9a-fA-F-]{36})/submit'")) {
  throw new Error('Denetim sonucunun once taslak kalip ayrica onaya gonderilmesini saglayan API akisi eksik.');
}
if (!html.includes('id="approveDetailBtn"') || !html.includes('approveDetailFromModal') || !html.includes("window.setTimeout(()=>closeModal('detailModal'),450)")) {
  throw new Error('Denetim kaydi modalinda kopyalama yerine dogrudan onaylama akisi bulunmali.');
}
if (html.includes('id="copyDetailBtn"') || html.includes('function copyDetail()')) {
  throw new Error('Denetim kaydi modalinda eski Kopyala butonu/akisi kalmamali.');
}
const noStoreHeader = (vercelConfig.headers || []).some(item =>
  (item.headers || []).some(h => h.key === 'Cache-Control' && String(h.value || '').includes('no-store'))
);
const routeNoStoreHeader = (vercelConfig.routes || []).some(item =>
  item.dest === '/index.html' &&
  item.headers &&
  String(item.headers['Cache-Control'] || '').includes('no-store')
);
if (!noStoreHeader || !routeNoStoreHeader) {
  throw new Error('Canli HTML eski surumden calismasin diye Vercel no-store headeri top-level ve index route seviyesinde bulunmali.');
}
const rootFallback = "app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));";
assert(server.includes(rootFallback), 'Root legacy SPA fallback aynen index.html dondurmeli.');
for (const marker of [
  "app.use('/icons', express.static(path.join(__dirname, 'icons')))",
  "app.get('/favicon.ico'",
  "app.get('/manifest.webmanifest'",
  "app.get('/sw.js'"
]) {
  assert(server.includes(marker), `Static asset route korunmali: ${marker}`);
}
for (const marker of [
  "app.post('/api/auth/login'",
  "app.post('/api/auth/logout'",
  "app.get('/api/auth/me'"
]) {
  assert(server.includes(marker), `Auth/session API route korunmali: ${marker}`);
}
assert(server.includes('async function syncSessionUserFromDb'), 'Oturum rolü DBden yeniden senkronize edilmeli.');
assert(server.includes('await syncSessionUserFromDb(req)'), 'Auth/me ve korumali API akislari guncel DB rolunu okumali.');
assert(!server.includes('normalizeSessionRole(req);'), 'Eski session-only rol normalizasyonu kullanilmamali.');
assert(server.includes('const ADMIN_PARALLEL_ROUTE_ENABLED'), 'ADMIN_PARALLEL_ROUTE_ENABLED flag okunmali.');
assert(server.includes('function sendAdminIndex'), 'Admin index helper bulunmali.');
assert(server.includes("res.set('X-Robots-Tag', 'noindex, nofollow')"), '/admin HTML response noindex header almali.');
assert(server.includes("app.get(['/admin', '/admin/'], sendAdminIndex)"), '/admin ve /admin/ explicit admin fallback olmali.');
assert(server.includes("app.get('/admin/*', sendAdminIndex)"), '/admin/* deep link fallback olmali.');

const lastApiRouteIndex = [...server.matchAll(/app\.(?:get|post|put|patch|delete)\('\/api\//g)].pop()?.index ?? -1;
const adminRouteIndex = indexOfRequired(server, "app.get(['/admin', '/admin/'], sendAdminIndex)", 'Explicit /admin route');
const publicArchiveDemoIndex = indexOfRequired(server, "if (process.env.PUBLIC_ARCHIVE_DEMO === '1')", 'Public archive demo gate');
const publicArchiveDemoRequireIndex = indexOfRequired(server, "const { createPublicArchiveRouter } = require('./public-archive-demo');", 'Public archive demo lazy require');
const errorHandlerIndex = indexOfRequired(server, 'app.use((err, req, res, next) => {', 'Express error handler');
const rootFallbackIndex = indexOfRequired(server, rootFallback, 'Root legacy fallback');
assert(lastApiRouteIndex > -1 && lastApiRouteIndex < adminRouteIndex, '/api route lari /admin fallback tarafindan yutulmamali.');
assert(adminRouteIndex < publicArchiveDemoIndex, '/admin fallback public archive router dan once kayit edilmeli.');
assert(publicArchiveDemoIndex < publicArchiveDemoRequireIndex, 'Public archive demo modulu yalniz PUBLIC_ARCHIVE_DEMO flag icinde yuklenmeli.');
assert(adminRouteIndex < errorHandlerIndex, '/admin fallback error handler dan once kayit edilmeli.');
assert(adminRouteIndex < rootFallbackIndex, '/admin fallback broad root fallback dan once kayit edilmeli.');

const routes = vercelConfig.routes || [];
const apiVercelIndex = routes.findIndex(route => route.src === '/api/(.*)' && route.dest === '/server.js');
const finalIndexRouteIndex = routes.findIndex(route => route.src === '/(.*)' && route.dest === '/index.html');
assert(apiVercelIndex !== -1 && finalIndexRouteIndex !== -1 && apiVercelIndex < finalIndexRouteIndex, 'Vercel /api route final index catch-all dan once kalmali.');
const routeIndex = src => routes.findIndex(route => route.src === src);
const routeBySrc = src => routes.find(route => route.src === src);
const explicitRootRoutes = routes.filter(route => route.src === '/' || route.src === '/$');
assert(explicitRootRoutes.length === 0, 'Root / icin explicit Vercel route eklenmemeli; legacy root final catch-all ile kalmali.');

const adminVercelRoutes = routes.filter(route => route.src === '/admin');
const adminDeepVercelRoutes = routes.filter(route => route.src === '/admin/(.*)');
const adminLikeVercelRoutes = routes.filter(route => typeof route.src === 'string' && route.src.startsWith('/admin'));
const unexpectedAdminVercelRoutes = adminLikeVercelRoutes.filter(route => route.src !== '/admin' && route.src !== '/admin/(.*)');
assert(unexpectedAdminVercelRoutes.length === 0, 'Beklenmeyen Vercel admin route eklenmemeli; yalniz /admin ve /admin/(.*) desteklenir.');
assert(adminVercelRoutes.length === 1 && adminDeepVercelRoutes.length === 1, 'Vercel admin route lari partial olmamali; /admin ve /admin/(.*) birlikte olmali.');

const adminVercelRoute = adminVercelRoutes[0];
const adminDeepVercelRoute = adminDeepVercelRoutes[0];
const adminVercelIndex = routeIndex('/admin');
const adminDeepVercelIndex = routeIndex('/admin/(.*)');
const preAdminRoutes = [
  ['/api/(.*)', '/server.js', '/api route'],
  ['/manifest.webmanifest', '/manifest.webmanifest', 'manifest route'],
  ['/sw.js', '/sw.js', 'service worker route'],
  ['/icons/(.*)', '/icons/$1', 'icons route'],
  ['/favicon.ico', '/icons/favicon.ico', 'favicon route']
];

for (const [src, dest, label] of preAdminRoutes) {
  const route = routeBySrc(src);
  const index = routeIndex(src);
  assert(route && route.dest === dest, `${label} Vercel hedefi korunmali.`);
  assert(index < adminVercelIndex && index < adminDeepVercelIndex, `${label} Vercel admin route larindan once kalmali.`);
}

assert(adminVercelIndex < adminDeepVercelIndex, '/admin Vercel route /admin/(.*) route undan once kalmali.');
assert(adminVercelIndex < finalIndexRouteIndex, '/admin Vercel route final index catch-all dan once kalmali.');
assert(adminDeepVercelIndex < finalIndexRouteIndex, '/admin/(.*) Vercel route final index catch-all dan once kalmali.');
assert(adminVercelRoute.dest === '/index.html', '/admin Vercel route index.html dondurmeli.');
assert(adminDeepVercelRoute.dest === '/index.html', '/admin/(.*) Vercel route index.html dondurmeli.');

for (const [label, route] of [
  ['/admin', adminVercelRoute],
  ['/admin/(.*)', adminDeepVercelRoute]
]) {
  const headers = route.headers || {};
  assert(headers['X-Robots-Tag'] === 'noindex, nofollow', `${label} Vercel route X-Robots-Tag noindex header almali.`);
  const cacheControl = String(headers['Cache-Control'] || '');
  for (const token of ['no-store', 'no-cache', 'must-revalidate', 'proxy-revalidate']) {
    assert(cacheControl.includes(token), `${label} Vercel route Cache-Control ${token} icermeli.`);
  }
}

const robotsWithAdminPath = 'User-agent: *\nDisallow: /admin\nDisallow: /admin/\n';
assert(publicForbiddenWordHits(robotsWithAdminPath, { allowRobotsAdminPath: true }).length === 0, 'robots.txt teknik /admin path istisnasi public language guard icin false-positive olmamali.');
assert(publicForbiddenWordHits('<main>admin</main>').includes('admin'), 'Public language guard normal HTML icinde admin kelimesini yakalamali.');
if (
  !server.includes('SUBMITTED_CORRECTED_HASH_PREFIX') ||
  !server.includes('reserveSubmittedCorrectedHash') ||
  !server.includes('submitted_corrected_hash:') ||
  !server.includes('Bu düzeltilmiş metnin onaya gönderilmiş veya onaylanmış bir kaydı zaten var.')
) {
  throw new Error('Onaya gonderirken ayni duzeltilmis metnin ikinci kez bekliyor/onaylandi durumuna dusmesi hizli kilitle engellenmeli.');
}
if (/select\('id,corrected_text'\)[\s\S]{0,500}textHash\(row\.corrected_text\)/.test(server)) {
  throw new Error('Onaya gonderim eski agir corrected_text taramasina donmemeli.');
}
if (!html.includes('submitApprovalInFlight') || !html.includes('Gönderim kontrol ediliyor') || !html.includes('api(method,url,body)')) {
  throw new Error('Onaya gonderim UI bekleme/hata durumunu net yonetmeli.');
}
if (
  !server.includes('/api/history/:id([0-9a-fA-F-]{36})/approval-status') ||
  !server.includes('/api/history/:id([0-9a-fA-F-]{36})/withdraw') ||
  !html.includes('verifyApprovalStatus') ||
  !html.includes('Onay kuyruğu doğrulanıyor') ||
  !html.includes('withdrawApprovalFromHistory') ||
  !html.includes('Onaydan Geri Çek')
) {
  throw new Error('Onaya gonderim dogrulanmali ve kullanici bekleyen kaydi geri cekebilmelidir.');
}
const historyEndpoint = server.match(/app\.get\('\/api\/history'[\s\S]*?\n\}\);/);
if (!historyEndpoint || !historyEndpoint[0].includes('fetchAllPages') || historyEndpoint[0].includes('.limit(200)')) {
  throw new Error('Denetim gecmisi 200 kayitta kesilmemeli; tum ilgili kayitlar sayfali cekilmeli.');
}
if (!server.includes("ADMIN_HIDDEN_HISTORY_STATUSES = ['taslak'") || !server.includes('SUBMITTED_PART_STATUS') || !server.includes('isHiddenHistoryForRole')) {
  throw new Error('Admin tarafinda taslak/parca kayitlarini gizleyen onay kuyrugu korumasi eksik.');
}
if (!server.includes("const CHUNK_DRAFT_STATUS = 'chunk_draft'") || !server.includes("function isChunkHistoryRow") || !server.includes('/api/history/merged-draft')) {
  throw new Error('Uzun metin parcalari teknik chunk_draft olarak saklanmali ve tek birlesik taslak olusturulmali.');
}
if (!server.includes('Bu kayıt onaya gönderilemez. Lütfen sonuç ekranındaki Onaya Gönder butonunu kullanın.') || !html.includes('chunkPart:true') || !html.includes('saveMergedDraftResult')) {
  throw new Error('Uzun metin parcalari tek basina onaya gonderilememeli; frontend parcalari teknik kayit olarak isaretlemeli.');
}
if (!html.includes('submitApprovalModal') || !html.includes('renderApprovalActionButton') || !html.includes('confirmSubmitApproval') || !html.includes('Sonuç hazırlandı')) {
  throw new Error('Onaya Gonder son teyit penceresi ve taslak UX akisi eksik.');
}
const approvalSubmittedFn = html.match(/function approvalSubmitted\(d\)\{[\s\S]*?\n\}/)?.[0] || '';
if (
  !html.includes("const SUBMITTED_APPROVAL_STATUSES=new Set(['bekliyor','onaylandi','reddedildi'])") ||
  !approvalSubmittedFn.includes('SUBMITTED_APPROVAL_STATUSES.has(status)') ||
  approvalSubmittedFn.includes('!status')
) {
  throw new Error('Bos veya eksik status onaya gonderilmis sayilmamali; sadece bekliyor/onaylandi/reddedildi pasiflestirmeli.');
}
if (
  !html.includes('resetCurrentAnalysisStateForNewRun();') ||
  !html.includes('function resetSubmitApprovalModalState') ||
  !html.includes('if(restoredResult&&!approvalSubmitted(restoredResult))')
) {
  throw new Error('Onaydan sonra yeni denetim baslarken eski onay statei ve gonderilmis yerel taslak temizlenmeli.');
}
if (
  !html.includes('<div class="screen active" id="bootScreen">') ||
  !html.includes('<div class="screen" id="loginScreen">') ||
  !html.includes('function showLoginScreen()') ||
  !html.includes('showLoginScreen();') ||
  !html.includes("el('bootScreen')?.classList.remove('active')")
) {
  throw new Error('Sayfa yenilenirken auth kontrolu bitmeden login formu ve autofill bilgileri gorunmemeli.');
}
const logoutFn = html.match(/async function doLogout\(\)\{[\s\S]*?\n\}/)?.[0] || '';
if (
  !logoutFn.includes("await api('POST','/api/auth/logout')") ||
  !logoutFn.includes('clearAnalyze();') ||
  !logoutFn.includes('clearWorkDraft();') ||
  !logoutFn.includes('showLoginScreen();')
) {
  throw new Error('Cikis sonrasi cihazdaki calisma taslagi temizlenmeli ve login ekrani kontrollu acilmali.');
}
if (!html.includes('renderSubmittedWorkspace') || !html.includes('Onay kuyruğuna alındı') || !html.includes('resetInputAfterApprovalSubmit')) {
  throw new Error('Onaya gonderim basarili olunca calisma kapanmali ve net basari ekrani gorunmeli.');
}
if (!html.includes("renderApprovalActionButton(d,'panel')") || !html.includes('corrected-body-wrap') || !html.includes('corrected-copy-btn')) {
  throw new Error('Duzeltilmis metin bolumunde tek alt onay butonu ve kenarda modern kopyala butonu olmali.');
}
if (html.includes('corrected-btns') || html.includes('onclick="downloadPDF()"') || html.includes('${renderApprovalActionButton(d)}')) {
  throw new Error('Duzeltilmis metin basliginda ikinci onay, PDF indir veya eski aksiyon satiri gorunmemeli.');
}
if (!html.includes('function setApprovalAction') || !html.includes("await loadOnay();") || !html.includes("approveItem('${h.id}',this)") || !html.includes("rejectItem('${h.id}',this)")) {
  throw new Error('Is Panosu onay/red sonrasi paneli yenilemeli ve buton islemini gorunur sekilde kilitlemeli.');
}
if (
  !schema.includes("tags jsonb not null default '[]'::jsonb") ||
  !schema.includes('question_text  text') ||
  !schema.includes('history_tags_idx') ||
  !server.includes('HAS_HISTORY_TAGS') ||
  !server.includes('HAS_HISTORY_QUESTION_TEXT') ||
  !server.includes('function normalizeHistoryTags') ||
  !server.includes('function normalizeHistoryQuestion') ||
  !server.includes('function requireApprovalQuestionAndTags') ||
  !server.includes("app.post('/api/history/:id([0-9a-fA-F-]{36})/tags'") ||
  !server.includes('const approvalMeta = requireApprovalQuestionAndTags(req.body)') ||
  !server.includes('updateRow.tags = approvalMeta.tags') ||
  !server.includes('updateRow.question_text = approvalMeta.questionText') ||
  !server.includes('mergedRow.tags = approvalMeta.tags') ||
  !server.includes('mergedRow.question_text = approvalMeta.questionText') ||
  !server.includes('const importedQuestion = normalizeHistoryQuestion(match.excel_question)') ||
  !server.includes('if (!existingQuestion && importedQuestion) historyUpdate.question_text = importedQuestion;') ||
  !server.includes('function fetchHistoryQuestionRowsByIds') ||
  !server.includes('function backfillHistoryTagImportQuestionsChunk') ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions'") ||
  !server.includes('TAG_IMPORT_QUESTION_BACKFILL_JOB_KEY_PREFIX') ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions/start'") ||
  !server.includes("app.get('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions/status'") ||
  !server.includes('questionText: h.question_text') ||
  !server.includes('Soru Etiketleri') ||
  !server.includes('Soru') ||
  !html.includes('normalizeHistoryQuestionUi') ||
  !html.includes('id="submitApprovalQuestionMain"') ||
  !html.includes('id="submitApprovalQuestion"') ||
  !html.includes('id="submitApprovalTags"') ||
  !html.includes('Soru (zorunlu)') ||
  !html.includes('Etiketler (zorunlu)') ||
  !html.includes('Onaya göndermeden önce soru alanını doldurun.') ||
  !html.includes('Onaya göndermeden önce en az bir etiket ekleyin.') ||
  !html.includes('id="historyTagImportBackfillQuestionsBtn"') ||
  !html.includes('backfillHistoryTagImportQuestions') ||
  !html.includes('Excel Sorularını Ekle') ||
  !html.includes('Soru Aktarımı Sürüyor') ||
  !html.includes('Soru aktarımı başladı. Sayfadan ayrılsanız bile işlem kayıt altında kalır.') ||
  !html.includes('archive-question-backfill-pending') ||
  !html.includes('resumePendingHistoryTagImportQuestions') ||
  !html.includes('document.addEventListener(\'visibilitychange\'') ||
  !html.includes('Daha önce elle yazılmış sorular korunur') ||
  !html.includes('renderSubmitTagsPreview') ||
  !html.includes('id="detailHistoryQuestion"') ||
  !html.includes('id="detailHistoryTags"') ||
  !html.includes("setApprovalAction(id,'approve',btn,{questionText:normalizeHistoryQuestionUi(v('detailHistoryQuestion')),tags:parseHistoryTags(v('detailHistoryTags'))})") ||
  !html.includes('h.questionText') ||
  !html.includes('historyTagsChips(h.tags||[])')
) {
  throw new Error('Soru-cevap soru ve etiket alanlari onaya gonderme, admin onay duzeltmesi, Excel aktarimi, CSV ve DB semasinda korunmali.');
}
if (
  !schema.includes('history_tag_import_batches') ||
  !schema.includes('history_tag_import_matches') ||
  !server.includes('function parseHistoryTagImportWorkbook') ||
  !server.includes('function ensureHistoryTagImportReady') ||
  !server.includes("app.post('/api/history-tags/import/preview'") ||
  !server.includes("app.post('/api/history-tags/import/upload/start'") ||
  !server.includes("app.post('/api/history-tags/import/upload/chunk'") ||
  !server.includes("app.post('/api/history-tags/import/upload/complete'") ||
  !server.includes('TAG_IMPORT_MAX_CHUNK_BASE64_LENGTH') ||
  !server.includes('function historyTagImportSelectColumns()') ||
  !server.includes("app.get('/api/history-tags/import-batches'") ||
  !server.includes("app.delete('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})'") ||
  !server.includes("app.post('/api/history-tags/import-matches/:id([0-9a-fA-F-]{36})/apply'") ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/apply-ready'") ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/apply-review'") ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions'") ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions/start'") ||
  !server.includes("app.get('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions/status'") ||
  !server.includes('async function runHistoryTagImportQuestionBackfillJob') ||
  !server.includes('TAG_IMPORT_APPLY_CHUNK_SIZE') ||
  !server.includes('function historyTagImportApplyLimit') ||
  !server.includes('async function applyHistoryTagImportBatchChunk') ||
  !server.includes('async function backfillHistoryTagImportQuestionsChunk') ||
  server.includes(".order('updated_at', { ascending: true })\r\n    .limit(safeLimit)") ||
  server.includes(".order('updated_at', { ascending: true })\n    .limit(safeLimit)") ||
  !server.includes('remaining,') ||
  !server.includes('done: remaining === 0') ||
  !server.includes("const matches = await fetchAllPages(() => supabase.from('history_tag_import_matches')") ||
  !server.includes('const refreshedBatch = await refreshHistoryTagImportBatchCounts(req.params.id);') ||
  server.includes("const rows = await fetchAllPages(() => supabase.from('history_tag_import_matches')\n      .select('id')\n      .eq('batch_id', req.params.id)\n      .eq('match_status', 'ready')") ||
  !server.includes('TAG_IMPORT_INITIAL_DETAIL_LIMIT') ||
  !server.includes('insertHistoryTagImportMatches') ||
  !server.includes('publicHistoryTagImportHistory') ||
  !html.includes('data-ops-view="tagImport"') ||
  !html.includes('id="historyTagImportFile"') ||
  !html.includes('uploadHistoryTagImportFile') ||
  !html.includes('HISTORY_TAG_IMPORT_UPLOAD_CHUNK_BYTES') ||
  !html.includes('/api/history-tags/import/upload/start') ||
  !html.includes('/api/history-tags/import/upload/chunk') ||
  !html.includes('/api/history-tags/import/upload/complete') ||
  !html.includes('readHistoryTagImportUploadResponse') ||
  !html.includes('applyHistoryTagImportMatch') ||
  !html.includes('applyHistoryTagImportMatchesInSteps') ||
  !html.includes('applyReadyHistoryTagImportMatches') ||
  !html.includes('applyReviewHistoryTagImportMatches') ||
  !html.includes('backfillHistoryTagImportQuestions') ||
  !html.includes('/backfill-questions/start') ||
  !html.includes('/backfill-questions/status') ||
  !html.includes('archive-question-backfill-pending') ||
  !html.includes('visibilitychange') ||
  !html.includes('historyTagImportApplyReadyBtn') ||
  !html.includes('historyTagImportApplyReviewBtn') ||
  !html.includes('historyTagImportBackfillQuestionsBtn') ||
  !html.includes('deleteHistoryTagImportBatch') ||
  !html.includes('Seçili Aktarımı Sil') ||
  !html.includes('Güvenli Eşleşmeleri Uygula') ||
  !html.includes('Kontrol Gerekenleri Uygula') ||
  !html.includes('Excel Sorularını Ekle') ||
  !html.includes('Listeyi Yenile') ||
  html.includes('Yüksek Güvenlileri Uygula') ||
  html.includes('Partileri Yenile') ||
  html.includes('Aktarım partileri')
) {
  throw new Error('Excel etiket aktarimi icin super admin ekrani, import APIleri ve DB semasi korunmali.');
}
if (!html.includes('openSubmitApprovalFromHistory') || !html.includes('value="taslak"')) {
  throw new Error('Kullanici gecmisindeki taslaklari filtreleme ve onaya gonderme akisi eksik.');
}
if (
  html.includes('ekibe bildirim kapalı') ||
  html.includes("actions.style.display='none'") ||
  !html.includes('kaçan bir nokta olduğunu düşünüyorsanız ekibe bildirebilirsiniz') ||
  !html.includes('<div class="feedback-actions" id="resultFeedbackActions">')
) {
  throw new Error('100 puanli veya temiz gorunen denetimlerde de kullanici geri bildirim gonderebilmeli.');
}
if (
  !server.includes("app.get('/api/correction-packages'") ||
  !server.includes('content_correction_packages') ||
  !server.includes('content_correction_log') ||
  !server.includes('scanCorrectionPackage') ||
  !server.includes('historyScope') ||
  !server.includes('reportedHistoryIds') ||
  !server.includes('fetchFeedbackHistoryIds') ||
  !server.includes('resolution_group: resolutionGroup') ||
  !server.includes("feedback_status: 'resolved'") ||
  !html.includes('tabContent-corrections') ||
  !html.includes('loadCorrectionPackages') ||
  !html.includes('createCorrectionPackage') ||
  !html.includes('previewCorrectionPackage') ||
  !html.includes('correctionHistoryScopeFromForm') ||
  !html.includes('correctionScopeReported') ||
  !html.includes('correctionScopeAll') ||
  !html.includes('Bildirilen doküman')
) {
  throw new Error('Geri bildirim kaynakli gecmis icerik duzeltme kayitlari, bildirilen dokuman/benzer gecmis kapsami ve etki taramasi korunmali.');
}
if (
  !html.includes('Geçmiş Düzeltme Kontrolü') ||
  !html.includes('Geçmiş Düzeltmeleri') ||
  !html.includes('Yeni düzeltme kaydı') ||
  !html.includes('.correction-option input[type="checkbox"]') ||
  !html.includes('.correction-option input[type="radio"]') ||
  html.includes('Düzeltme Paketleri')
) {
  throw new Error('Gecmis duzeltme ekrani adminin anlayacagi isim ve mobil checkbox duzeniyle kalmali.');
}
if (
  !server.includes('selectedChangeIds') ||
  !server.includes('correctionChangeId') ||
  !server.includes('appliedTargets') ||
  !html.includes('Bildirilen doküman') ||
  !html.includes('Benzer geçmiş kayıtlar') ||
  !html.includes('correctionTargetSectionHtml') ||
  !html.includes('selectedCorrectionChangeIds') ||
  !html.includes('Bu Kaydı Uygula') ||
  !html.includes('Dokümanı Aç') ||
  !html.includes('.correction-target-check')
) {
  throw new Error('Gecmis duzeltme akisi bildirilen dokuman ve secilebilir gecmis hedefler uzerinden calismali.');
}
if (
  !html.includes('Onay Bekleyen Düzeltmeler') ||
  !html.includes('Uygulanan Düzeltmeler') ||
  !html.includes('correctionMetricsHtml') ||
  !html.includes('correctionPackageCard') ||
  !html.includes('correctionArchiveHtml') ||
  !html.includes('.correction-toolbar') ||
  !html.includes('.correction-card summary')
) {
  throw new Error('Gecmis duzeltme super admin paneli aktif kuyruk, uygulanan arsiv ve dropdown kart duzeniyle kalmali.');
}
if (
  !server.includes('alreadyApplied') ||
  !html.includes('correctionStateNote') ||
  !html.includes('setCorrectionPackageBusy') ||
  !html.includes('Düzeltme zaten uygulanmış') ||
  !html.includes("cache:'no-store'")
) {
  throw new Error('Gecmis duzeltme uygulama sonrasi durum netlesmeli, zaten uygulanmis kayit ekrani duzeltmeli ve API cache kullanmamali.');
}
if (
  !server.includes("status: existing?.status || 'pending_review'") ||
  !server.includes("pkg.status !== 'ready'") ||
  !server.includes('superAdminApproved') ||
  !html.includes('Süper admin son kontrolü') ||
  !html.includes('Süper admin onayı bekliyor') ||
  !html.includes('Seçilenleri Uygula')
) {
  throw new Error('Gecmis duzeltmeler super admin son kontrolu olmadan uygulanmamali.');
}
if (
  !html.includes('function isAdminRoute()') ||
  !html.includes('function isStandaloneApp()') ||
  !html.includes('function ensureStandaloneAdminRoute') ||
  !html.includes("window.history.replaceState(null,document.title,'/admin')") ||
  !html.includes("path==='/admin'||path.startsWith('/admin/')") ||
  !html.includes('ensureStandaloneAdminRoute(user);') ||
  !html.includes('refreshRouteScopedVisibility(user)')
) {
  throw new Error('/admin route guard ve PWA root acilisinda admin route a alma korumasi bozulmamali.');
}
if (
  !html.includes('Arşiv Operasyon Merkezi') ||
  !html.includes('tabContent-archiveOps') ||
  !html.includes('admin-route-only') ||
  !html.includes('function canUseArchiveOps') ||
  !html.includes("if(name==='archiveOps'&&!canUseArchiveOps())name='analiz'") ||
  !html.includes('Kaynak Kayıt Sistemi') ||
  !html.includes('archiveSourceText') ||
  !html.includes('function loadArchiveOpsSources') ||
  !html.includes('function saveArchiveSource(forceSave=false,changeConfirmed=false)') ||
  !html.includes('function openArchiveOps') ||
  !html.includes('function renderArchiveOpsView') ||
  !html.includes('function mArchiveOps') ||
  !html.includes('function toggleArchiveOpsMenu') ||
  !html.includes("archiveOpsState.menuOpen=false") ||
  !html.includes('.archive-ops-menu-group') ||
  !html.includes('.mobile-menu-group:not(.open) .mobile-subnav') ||
  !html.includes('border-right:1.5px solid currentColor') ||
  html.includes('<span class="side-caret">Aç</span>') ||
  html.includes("textContent=archiveOpsState.menuOpen?'Kapat':'Aç'") ||
  !html.includes('data-ops-view="sources"') ||
  !html.includes('data-ops-view="library"') ||
  !html.includes('data-ops-view="files"') ||
  !html.includes('Dosya Merkezi') ||
  !html.includes('archiveFileSearch') ||
  !html.includes('ops-file-grid') ||
  !html.includes('function renderArchiveFileCenter') ||
  !html.includes('function openArchiveFileSource') ||
  !html.includes("if(name==='archiveOps')renderArchiveOpsView()") ||
  !html.includes('Benzer kaynak bulundu') ||
  !html.includes('archiveSourceConflictDetail') ||
  !html.includes('archiveSourceChangeSummary') ||
  !html.includes('Kaynak kaydı güncellensin mi?') ||
  !html.includes('sourceSubmitInFlight') ||
  !html.includes("return {...data,error:data.error||") ||
  !server.includes('ARCHIVE_OPS_SOURCES_KEY') ||
  !server.includes('HAS_ARCHIVE_SOURCE_TABLES') ||
  !server.includes('archiveSourceToDbRow') ||
  !server.includes('archiveSourceFromDbRow') ||
  !server.includes('ensureArchiveSourcesMigratedFromSettings') ||
  !server.includes('insertArchiveSourceVersion') ||
  !server.includes('archive_source_versions') ||
  !server.includes('archive_source_events') ||
  !server.includes('findArchiveSourceConflicts') ||
  !server.includes('findArchiveSourceConflictsDb') ||
  !server.includes('archiveSourceFingerprint') ||
  !server.includes('input.forceSave !== true') ||
  !server.includes("app.get('/api/archive-ops/sources'") ||
  !server.includes("app.post('/api/archive-ops/sources'") ||
  !server.includes("app.put('/api/archive-ops/sources/:id'") ||
  !server.includes("app.get('/api/archive-ops/work-items'") ||
  !server.includes("app.post('/api/archive-ops/work-items'") ||
  !server.includes("app.put('/api/archive-ops/work-items/:id'") ||
  !server.includes("app.delete('/api/archive-ops/work-items/:id'") ||
  !server.includes("app.get('/api/archive-ops/publish-tasks'") ||
  !server.includes("app.post('/api/archive-ops/publish-tasks'") ||
  !server.includes("app.put('/api/archive-ops/publish-tasks/:id'") ||
  !server.includes("app.delete('/api/archive-ops/publish-tasks/:id'") ||
  !server.includes("app.get('/api/archive-ops/public-candidates'") ||
  !server.includes("app.post('/api/archive-ops/public-candidates/:kind/:id/decision'") ||
  !server.includes("app.get('/api/archive-ops/release-packages'") ||
  !server.includes("app.post('/api/archive-ops/release-packages'") ||
  !server.includes("app.put('/api/archive-ops/release-packages/:id'") ||
  !server.includes("app.post('/api/archive-ops/release-packages/:id/items/:itemId/review'") ||
  !server.includes("app.post('/api/archive-ops/release-packages/:id/lock'") ||
  !server.includes("app.post('/api/archive-ops/release-packages/:id/unlock'") ||
  !server.includes("app.get('/api/archive-ops/release-packages/:id/output'") ||
  !server.includes("app.post('/api/archive-ops/release-packages/:id/publication'") ||
  !server.includes("app.delete('/api/archive-ops/release-packages/:id'") ||
  !server.includes('ARCHIVE_OPS_RELEASE_PACKAGES_KEY') ||
  !server.includes('ARCHIVE_RELEASE_PUBLICATION_STATUSES') ||
  !server.includes('function archiveReleasePackageReadiness') ||
  !server.includes('function archiveReleaseItemReadiness') ||
  !server.includes('function archiveReleasePackageLockReadiness') ||
  !server.includes('function archiveReleasePackageOutputManifest') ||
  !server.includes('function archiveReleasePackageOutputMarkdown') ||
  !server.includes('function archiveReleasePackageOutputCsv') ||
  !server.includes('ARCHIVE_PUBLIC_RECORD_SCHEMA_VERSION') ||
  !server.includes('ARCHIVE_PUBLIC_RECORD_FORBIDDEN_TERMS') ||
  !server.includes('function validateArchivePublicRecords') ||
  !server.includes('publicReadiness') ||
  !server.includes('function archiveReleasePackagePublicRecords') ||
  !server.includes("format: 'public-json'") ||
  !server.includes('function updateArchiveReleasePackagePublication') ||
  !server.includes('function updateArchiveReleasePackageItemReview') ||
  !server.includes('function lockArchiveReleasePackage') ||
  !server.includes('function unlockArchiveReleasePackage') ||
  !server.includes('Paket hazır durumuna alınamaz') ||
  !server.includes('son hazırlık için kilitli') ||
  !server.includes('function listArchiveReleasePackages') ||
  !server.includes('function updateArchiveReleasePackage') ||
  !server.includes('ARCHIVE_PUBLIC_CANDIDATE_STATUSES') ||
  !server.includes('function updateArchivePublicCandidateDecision') ||
  !server.includes('function listArchivePublicCandidates') ||
  !server.includes("app.get('/api/archive-ops/import-batches'") ||
  !server.includes("app.post('/api/archive-ops/import-batches'") ||
  !server.includes("app.post('/api/archive-ops/import-batches/:id/items'") ||
  !server.includes("app.put('/api/archive-ops/import-items/:id'") ||
  !server.includes("app.delete('/api/archive-ops/import-items/:id'") ||
  !server.includes('ARCHIVE_SOURCE_TEXT_LIMIT = 200000') ||
  !server.includes('function normalizeArchiveSourceTypes') ||
  !server.includes(".in('source_type', types)") ||
  !server.includes('HAS_ARCHIVE_IMPORT_TABLES') ||
  !server.includes('archiveImportBatchToDbRow') ||
  !server.includes('archiveImportItemToDbRow') ||
  !server.includes('deleteArchiveImportItem') ||
  !schema.includes('create table if not exists public.archive_sources') ||
  !schema.includes('create table if not exists public.archive_source_versions') ||
  !schema.includes('create table if not exists public.archive_source_events') ||
  !schema.includes('create table if not exists public.archive_import_batches') ||
  !schema.includes('create table if not exists public.archive_import_items') ||
  !schema.includes('create table if not exists public.archive_work_items') ||
  !schema.includes('create table if not exists public.archive_publish_tasks') ||
  !schema.includes('archive_work_items_status_idx') ||
  !schema.includes('archive_publish_tasks_status_idx') ||
  !schema.includes('archive_import_items_batch_idx') ||
  !schema.includes('archive_sources_text_hash_idx') ||
  !html.includes('Hadis ve Slayt Metinleri') ||
  !html.includes('id="archiveTextSearch"') ||
  !html.includes('id="archiveTextList"') ||
  !html.includes('id="archiveTextDetail"') ||
  !html.includes('function loadArchiveTextSources') ||
  !html.includes('function renderArchiveTextLibrary') ||
  !html.includes("params.set('types','hadis,slayt')") ||
  !html.includes("newArchiveTextSource('hadis')") ||
  !html.includes('function openArchiveTextSource') ||
  !html.includes('id="archiveSourceText"') ||
  !html.includes('archiveImportFiles') ||
  !html.includes('ops-import-workspace') ||
  !html.includes('ops-import-flow') ||
  !html.includes('archiveImportBatchList') ||
  !html.includes('createArchiveImportBatch') ||
  !html.includes('loadArchiveImportBatches') ||
  !html.includes('archiveImportState.pendingSourceItemId') ||
  !html.includes('function handleArchiveImportFiles') ||
  !html.includes('function extractArchiveImportDocx') ||
  !html.includes("fetch('/api/extract-file-text'") ||
  !html.includes('function sendArchiveImportToSourceForm') ||
  !html.includes('function archiveImportCanCreateSource') ||
  !html.includes('function archiveImportSourcePayload') ||
  !html.includes('function createArchiveSourceFromImportItem') ||
  !html.includes('function openArchiveSourceFromImportItem') ||
  !html.includes('function skipArchiveImportItem') ||
  !html.includes('function deleteArchiveImportItem') ||
  !html.includes('archiveWorkState') ||
  !html.includes('archivePublishState') ||
  !html.includes('id="archivePublishTitle"') ||
  !html.includes('id="archivePublishSourceId"') ||
  !html.includes('id="archivePublishWorkId"') ||
  !html.includes('function loadArchivePublishTasks') ||
  !html.includes('function saveArchivePublishTask') ||
  !html.includes('function deleteArchivePublishTaskUi') ||
  !html.includes('id="archiveCandidateSearch"') ||
  !html.includes('id="archiveCandidateStatusFilter"') ||
  !html.includes('id="archiveCandidateList"') ||
  !html.includes('id="archiveCandidateDetail"') ||
  !html.includes('data-ops-view="ready"') ||
  !html.includes('id="archiveReadySearch"') ||
  !html.includes('id="archiveReadyList"') ||
  !html.includes('id="archiveReadyDetail"') ||
  !html.includes('archive-ready-layout') ||
  !html.includes('function loadArchiveReadyQueue') ||
  !html.includes("params.set('status','yayina_hazir')") ||
  !html.includes('function setArchiveReadyDecision') ||
  !html.includes('Yayın Hazırlık Kuyruğu') ||
  !html.includes('data-ops-view="packages"') ||
  !html.includes('Yayın Paketleri') ||
  !html.includes('id="archiveReleasePackageTitle"') ||
  !html.includes('id="archiveReleasePackageList"') ||
  !html.includes('id="archiveReleasePackageDetail"') ||
  !html.includes('id="archiveReleaseReadyList"') ||
  !html.includes('function loadArchiveReleasePackages') ||
  !html.includes('function addSelectedReadyToReleasePackage') ||
  !html.includes('function archiveReleasePackageReview') ||
  !html.includes('function archiveReleasePackageLockReview') ||
  !html.includes('data-ops-view="packageOutput"') ||
  !html.includes('Paket Çıktı Merkezi') ||
  !html.includes('id="archiveOutputPackageList"') ||
  !html.includes('id="archiveOutputPublicationUrl"') ||
  !html.includes('value="public-json"') ||
  !html.includes('archive-public-readiness') ||
  !html.includes('function archiveOutputPublicReadinessHtml') ||
  !html.includes('Public yayın kontrolü') ||
  !html.includes('Public JSON kalite kontrolünden geçmedi') ||
  !html.includes('Yayın Takibi') ||
  !html.includes('function loadArchiveOutputPackages') ||
  !html.includes('function generateArchivePackageOutput') ||
  !html.includes('function prepareArchivePublicRecordsOutput') ||
  !html.includes('function downloadArchivePackageOutput') ||
  !html.includes('function setArchivePackagePublicationStatus') ||
  !html.includes('/output?format=') ||
  !html.includes('/publication') ||
  !html.includes('function setArchiveReleasePackageItemReview') ||
  !html.includes('function lockArchiveReleasePackageUi') ||
  !html.includes('function unlockArchiveReleasePackageUi') ||
  !html.includes('function archiveReleaseItemChecksHtml') ||
  !html.includes('function openArchiveReleaseItemRecord') ||
  !html.includes('archive-release-review') ||
  !html.includes('archive-release-checks') ||
  !html.includes('archive-release-lock-panel') ||
  !html.includes('Paket son kontrolü') ||
  !html.includes('Son Hazırlığa Kilitle') ||
  !html.includes('Paket hazır değil') ||
  !html.includes("api('GET',`/api/archive-ops/release-packages") ||
  !html.includes("api('GET',`/api/archive-ops/public-candidates?${params}`)") ||
  !html.includes('function loadArchiveCandidates') ||
  !html.includes('function setArchiveCandidateDecision') ||
  !html.includes('function openArchiveCandidateRecord') ||
  !html.includes('function archiveCandidateChecklistHtml') ||
  !html.includes('function archiveCandidatePublicPreviewHtml') ||
  !html.includes('candidate-review-grid') ||
  !html.includes('Public görünüm ön izlemesi') ||
  !html.includes('Yayın öncesi durum') ||
  !html.includes("api('GET',`/api/archive-ops/public-candidates") ||
  !html.includes("/api/archive-ops/public-candidates/${encodeURIComponent(item.kind)}/${encodeURIComponent(item.recordId)}/decision") ||
  !html.includes('Yayına Hazır') ||
  !html.includes('Yayın Görevini Sakla') ||
  !html.includes('Yayın Görevleri') ||
  !html.includes('id="archiveWorkTitle"') ||
  !html.includes('id="archiveWorkSourceId"') ||
  !html.includes('function loadArchiveWorkItems') ||
  !html.includes('function saveArchiveWorkItem') ||
  !html.includes('function deleteArchiveWorkItemUi') ||
  !html.includes('id="archiveWorkAuditContext"') ||
  !html.includes('function transferArchiveWorkToAudit') ||
  !html.includes('function markArchiveWorkSubmittedAfterApproval') ||
  !html.includes('Çalışma kaydından denetleniyor') ||
  !html.includes('Denetime Aktar') ||
  !html.includes('Çalışma Kaydını Sakla') ||
  !html.includes('Kaynağı Aç') ||
  !html.includes('.ops-work-layout') ||
  !html.includes("api('DELETE',`/api/archive-ops/import-items/") ||
  !html.includes('Kaynak Olarak Kaydet') ||
  !html.includes('Formda Düzenle') ||
  !html.includes('Kaynak Havuzunda Aç') ||
  !html.includes("tone:'danger'") ||
  !html.includes('archiveImportCanTransfer') ||
  !html.includes('.ops-import-workspace{margin-top:18px') ||
  !html.includes('overflow-x:hidden') ||
  !html.includes('.ops-import-preview-text{white-space:pre-wrap') ||
  !html.includes('overflow-wrap:anywhere;word-break:break-word') ||
  !html.includes('.ops-detail-head>div{min-width:0;}') ||
  !html.includes('.ops-source-meta span,.ops-import-meta span') ||
  !html.includes('ops-import-suggestion') ||
  !html.includes('.ops-import-layout{padding:10px;gap:10px') ||
  !html.includes('ARCHIVE_IMPORT_TEXT_EXTENSIONS') ||
  !html.includes('accept=".docx,.txt,.md,.csv,.tsv,.json"')
) {
  throw new Error('Arsiv Operasyon Merkezi super admin kaynak kayit akisi ve /admin korumasi ile korunmali.');
}
if (
  html.includes('adminRouteProbe') ||
  html.includes('super-admin-admin-route-only') ||
  html.includes('updateAdminRouteProbeState') ||
  html.includes('/admin canli test') ||
  html.includes('Test anahtar')
) {
  throw new Error('/admin gecici canli test alani kaldirilmis kalmali.');
}
if (
  !html.includes('systemConfirmModal') ||
  !html.includes('openSystemConfirm') ||
  !html.includes('system-confirm-modal') ||
  /\b(confirm|alert|prompt)\s*\(/.test(html)
) {
  throw new Error('Tarayici confirm/alert/prompt yerine tema uyumlu sistem ici onay penceresi kullanilmali.');
}
const sidebarIndex = html.indexOf('<aside class="side-nav">');
const sidebarOnayIndex = html.indexOf('data-tab="onay"', sidebarIndex);
const sidebarArchiveOpsIndex = html.indexOf('<div class="side-group archive-ops-menu-group', sidebarIndex);
const sidebarFeedbackIndex = html.indexOf('Geri Bildirim', sidebarOnayIndex);
assert(
  sidebarIndex > -1 &&
  sidebarOnayIndex > sidebarIndex &&
  sidebarArchiveOpsIndex > sidebarOnayIndex &&
  sidebarArchiveOpsIndex < sidebarFeedbackIndex,
  'Desktop sidebar Arsiv Operasyon Merkezi grubu super admin icin Operasyon bolumunde gorunur kalmali.'
);
console.log('Frontend/PWA doğrulaması: başarılı');
