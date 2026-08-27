const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
const vercelConfig = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
const script = html.match(/<script>([\s\S]*?)<\/script>/);
const root = path.join(__dirname, '..');
const publicCss = fs.readFileSync(path.join(root, 'public-archive.css'), 'utf8');
const publicRendererSource = fs.readFileSync(path.join(root, 'public-archive-renderer.js'), 'utf8');
const publicAssetRoot = path.join(root, 'public-archive-assets');
const { ROUTE_PATHS, publicArchiveFixtures, renderPublicArchivePreviewRoute } = require('../public-archive-renderer');

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
  scan = scan.replace(/https?:\/\/arsiv\.ibrahimlive\.ai\/?/gi, '');
  if (options.allowRobotsAdminPath) {
    scan = scan.replace(/^\s*(?:Disallow|Allow):\s*\/admin\/?\s*$/gmi, '');
  }
  return PUBLIC_FORBIDDEN_WORDS.filter(word => new RegExp(`(^|[^\\p{L}\\p{N}_])${escapeRegex(word)}([^\\p{L}\\p{N}_]|$)`, 'iu').test(scan));
}

const PUBLIC_PREVIEW_FORBIDDEN_SNIPPETS = [
  'hocamız',
  'hoca',
  'uzmanlar',
  'uzman ekip',
  'uzmanlar inceler',
  'alanında uzman',
  'alanında uzman kişiler',
  'cevaplandırılması için hocamıza aktarılır',
  'uygun görülen sorular arşive eklenir',
  'uygun görülen sorular arşive eklenebilir',
  'Bu ekranda kayıt alınmıyor',
  'yalnızca arayüz davranışı gösteriliyor',
  'Bu ekranda kayıt alınmaz',
  'history',
  'source_history_id',
  'text_hash',
  'prompt_version',
  'rules_hash',
  'approved_by',
  'approved_at',
  'score',
  'total_errors',
  'cat_counts',
  'chunk_draft',
  'submitted_part',
  'taslak',
  'bekliyor',
  'onaylandi',
  'reddedildi',
  'Arşiv Kontrol AI',
  'Metin Denetimi',
  'Yayın Paketi',
  'Onaya Gönder',
  'Profil',
  'Kaydedilen',
  'Bildirim',
  'görüntülenme',
  'view count',
  'helpful voting',
  'Public arşiv',
  'Google OAuth',
  'bu ortam',
  'ön izleme alanı',
  'önizleme alanı'
];

function normalizePublicPreviewScan(content) {
  return String(content || '')
    .replace(/\s+/g, ' ')
    .toLocaleLowerCase('tr-TR');
}

function assertNoPublicPreviewLeaks(route, content) {
  const wordHits = publicForbiddenWordHits(content);
  const normalized = normalizePublicPreviewScan(content);
  const snippetHits = PUBLIC_PREVIEW_FORBIDDEN_SNIPPETS.filter(term =>
    normalized.includes(String(term).toLocaleLowerCase('tr-TR'))
  );
  const hits = [...new Set([...wordHits, ...snippetHits])];
  assert(hits.length === 0, `${route} public cikti yasakli dil/veri iceriyor: ${hits.join(', ')}`);
}

function assertOnlyPublicPreviewApi(route, content) {
  const fragments = [...String(content || '').matchAll(/.{0,40}\/api\/.{0,80}/g)].map(match => match[0]);
  const unsafe = fragments.filter(fragment => !fragment.includes('/public-preview/api/'));
  assert(unsafe.length === 0, `${route} beklenmeyen non-preview API referansi iceriyor: ${unsafe.join(' | ')}`);
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

const adminAuthApiRouteIndex = indexOfRequired(server, "app.post('/api/auth/login'", 'Admin auth API route');
const adminRouteIndex = indexOfRequired(server, "app.get(['/admin', '/admin/'], sendAdminIndex)", 'Explicit /admin route');
const publicPreviewFlagIndex = indexOfRequired(server, 'const PUBLIC_ARCHIVE_PREVIEW_ENABLED', 'Public archive preview flag');
const publicRootFlagIndex = indexOfRequired(server, 'const PUBLIC_ARCHIVE_ROOT_ENABLED', 'Public archive root flag');
const publicPreviewDisabledIndex = indexOfRequired(server, 'function sendPublicArchivePreviewDisabled', 'Public archive preview disabled handler');
const publicPreviewGateIndex = indexOfRequired(server, "app.use('/public-preview', (req, res, next) => {", 'Public archive preview gate');
const publicPreviewRouterRequireIndex = indexOfRequired(server, "const { createPublicArchivePreviewRouter } = require('./public-archive-renderer');", 'Public archive preview lazy require');
const errorHandlerIndex = indexOfRequired(server, 'app.use((err, req, res, next) => {', 'Express error handler');
const rootFallbackIndex = indexOfRequired(server, rootFallback, 'Root legacy fallback');
assert(adminAuthApiRouteIndex < adminRouteIndex, 'Admin auth API route lari /admin fallback tarafindan once tanimli kalmali.');
assert(publicPreviewFlagIndex < publicPreviewGateIndex, 'PUBLIC_ARCHIVE_PREVIEW_ENABLED gate kullanilmadan once okunmali.');
assert(publicPreviewDisabledIndex < publicPreviewGateIndex, 'Public preview kapali handler route tanimindan once bulunmali.');
assert(adminRouteIndex < publicPreviewGateIndex, '/admin fallback public preview route undan once korunmali.');
assert(publicPreviewGateIndex < publicPreviewRouterRequireIndex, 'Public preview router yalniz gate sonrasinda lazy yuklenmeli.');
assert(publicPreviewGateIndex < errorHandlerIndex, '/public-preview route error handler dan once kayit edilmeli.');
assert(publicPreviewGateIndex < rootFallbackIndex, '/public-preview final root fallback a dusmemeli.');
assert(server.includes("if (!PUBLIC_ARCHIVE_PREVIEW_ENABLED) return sendPublicArchivePreviewDisabled(req, res);"), 'Preview gate kapaliyken /public-preview 404 donmeli.');
assert(server.includes('const PUBLIC_ARCHIVE_ROOT_INDEXING_ENABLED'), 'Public root indexing flag okunmali.');
assert(server.includes('GOOGLE_ROOT_REDIRECT_URI'), 'Root Google callback icin GOOGLE_ROOT_REDIRECT_URI destegi bulunmali.');
assert(server.includes("app.get('/api/session', publicArchiveSessionHandler)"), 'Root public session endpoint bayrakli olarak tanimli olmali.');
assert(server.includes("app.get('/auth/google', publicArchiveGoogleStartHandler)"), 'Root public Google login endpoint bayrakli olarak tanimli olmali.');
assert(server.includes("app.post('/api/auth/email/register', publicArchiveEmailRegisterHandler)"), 'Root public e-posta kayit endpointi bayrakli olarak tanimli olmali.');
assert(server.includes("app.post('/api/public-analytics/visit', publicArchiveVisitHandler)"), 'Root public analitik endpointi bayrakli olarak tanimli olmali.');
assert(server.includes("app.post('/api/question-submissions', publicArchiveQuestionSubmissionHandler)"), 'Root public soru gonderim endpointi bayrakli olarak tanimli olmali.');
assert(server.includes("app.get('/api/my-question-submissions', publicArchiveMyQuestionSubmissionsHandler)"), 'Root public kullanici soru takip endpointi bayrakli olarak tanimli olmali.');
assert(server.includes("app.post('/api/my-question-submissions/:id/seen', publicArchiveQuestionSeenHandler)"), 'Root public soru okundu endpointi bayrakli olarak tanimli olmali.');
assert(server.includes("source: publicArchiveRequestBasePath(req) ? 'public-preview' : 'public-root'"), 'Soru gonderimi preview/root kaynagini ayirmali.');
assert(server.includes("basePath: ''"), 'Root public renderer bos basePath ile baglanmali.');
assert(server.includes('noindex: !PUBLIC_ARCHIVE_ROOT_INDEXING_ENABLED'), 'Root public indexing flag noindex davranisina baglanmali.');
assert(publicRootFlagIndex < publicPreviewRouterRequireIndex, 'PUBLIC_ARCHIVE_ROOT_ENABLED renderer baglantisindan once okunmali.');
assert(server.includes("cssFile: path.join(__dirname, 'public-archive.css')"), 'Public preview CSS yalniz public-preview router icinden servis edilmeli.');
assert(!server.includes('PUBLIC_ARCHIVE_DEMO'), 'Eski PUBLIC_ARCHIVE_DEMO mekanizmasi server.js icinde kalmamali.');
assert(!server.includes("require('./public-archive-demo')"), 'Eski public-archive-demo router server.js icinde kalmamali.');
assert(!server.includes('archive-public.css'), 'Eski archive-public.css referansi server.js icinde kalmamali.');
assert(server.includes('loadPublicArchiveRouteDataset'), 'Public preview route bazli veri yukleyici kullanilmali.');
assert(server.includes('ensurePublicArchiveContentReady'), 'Public preview admin startup seed tamamini beklemeden public tablo hazirligini kontrol etmeli.');
assert(server.includes('PUBLIC_ARCHIVE_LIST_SELECT') && server.includes('PUBLIC_ARCHIVE_DETAIL_SELECT'), 'Public preview liste/detay kolon secimleri ayrilmali.');
assert(server.includes('publicArchiveRouteCache') && server.includes('PUBLIC_ARCHIVE_ROUTE_CACHE_MS'), 'Public preview route cache eksik.');
assert(!server.includes('loadArchiveData: async () =>'), 'Public preview router tum dataset yukleyen eski loadArchiveData imzasina donmemeli.');
assert(!server.includes('loadPublicArchiveStatsMap(qaRows.map'), 'Public dataset ilk yuklemede tum okunma sayaclarini topluca beklememeli.');
assert(!server.includes('const usedSlugs = rows.map'), 'Public history fallback ilk yuklemede tum okunma sayaclarini topluca beklememeli.');
assert(!fs.existsSync(path.join(root, 'scripts', 'build-archive-demo-static.js')), 'Eski statik demo build scripti repoda kalmamali.');
assert(adminRouteIndex < errorHandlerIndex, '/admin fallback error handler dan once kayit edilmeli.');
assert(adminRouteIndex < rootFallbackIndex, '/admin fallback broad root fallback dan once kayit edilmeli.');

const routes = vercelConfig.routes || [];
const apiVercelIndex = routes.findIndex(route => route.src === '/api/(.*)' && route.dest === '/server.js');
const finalServerRouteIndex = routes.findIndex(route => route.src === '/(.*)' && route.dest === '/server.js');
assert(apiVercelIndex !== -1 && finalServerRouteIndex !== -1 && apiVercelIndex < finalServerRouteIndex, 'Vercel /api route final server catch-all dan once kalmali.');
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

const previewVercelRoutes = [
  routeBySrc('/public-preview'),
  routeBySrc('/public-preview/(.*)')
];
const previewVercelIndexes = [
  routeIndex('/public-preview'),
  routeIndex('/public-preview/(.*)')
];
assert(previewVercelRoutes.every(Boolean), 'Vercel public preview route lari explicit tanimli olmali.');
for (const [i, route] of previewVercelRoutes.entries()) {
  assert(route.dest === '/server.js', 'Vercel public preview route server.js uzerinden gate e gitmeli.');
  assert(previewVercelIndexes[i] < adminVercelIndex && previewVercelIndexes[i] < finalServerRouteIndex, 'Vercel public preview route final catch-all ve admin route larindan once kalmali.');
  assert(route.headers?.['X-Robots-Tag'] === 'noindex, nofollow', 'Vercel public preview route noindex,nofollow header almali.');
  const cacheControl = String(route.headers?.['Cache-Control'] || '');
  for (const token of ['no-store', 'no-cache', 'must-revalidate', 'proxy-revalidate']) {
    assert(cacheControl.includes(token), `Vercel public preview route Cache-Control ${token} icermeli.`);
  }
}
assert(routeIndex('/public-preview') < routeIndex('/public-preview/(.*)'), 'Vercel /public-preview route deep route tanimindan once kalmali.');

assert(adminVercelIndex < adminDeepVercelIndex, '/admin Vercel route /admin/(.*) route undan once kalmali.');
assert(adminVercelIndex < finalServerRouteIndex, '/admin Vercel route final server catch-all dan once kalmali.');
assert(adminDeepVercelIndex < finalServerRouteIndex, '/admin/(.*) Vercel route final server catch-all dan once kalmali.');
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
  !html.includes("const SUBMITTED_APPROVAL_STATUSES=new Set(['bekliyor','teyit_bekliyor','onaylandi','reddedildi'])") ||
  !approvalSubmittedFn.includes('SUBMITTED_APPROVAL_STATUSES.has(status)') ||
  approvalSubmittedFn.includes('!status')
) {
  throw new Error('Bos veya eksik status onaya gonderilmis sayilmamali; sadece bekliyor/teyit_bekliyor/onaylandi/reddedildi pasiflestirmeli.');
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
  !server.includes("const APPROVAL_REVIEW_STATUS = 'teyit_bekliyor'") ||
  !server.includes("app.post('/api/history/:id/review'") ||
  !server.includes("app.post('/api/history/:id/pending'") ||
  !server.includes("app.get('/api/history/favorites'") ||
  !server.includes("app.post('/api/history/:id([0-9a-fA-F-]{36})/favorite'") ||
  !html.includes('Teyit Bekleyenler') ||
  !html.includes('toggleApprovalFavorite') ||
  !html.includes("reviewItem('${h.id}',this)") ||
  !html.includes("pendingItem('${h.id}',this)") ||
  !html.includes('Favorilerim')
) {
  throw new Error('Admin onay akisi Teyit Bekleyenler ve Favorilerim ozelliklerini korumali.');
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
  !server.includes("if (importedQuestion && (!existingQuestion || options.replaceQuestion === true))") ||
  !server.includes('function fetchHistoryQuestionRowsByIds') ||
  !server.includes('function historyTagImportQuestionLimit') ||
  !server.includes('function updateHistoryQuestionsBulk') ||
  !server.includes('function backfillHistoryTagImportQuestionsChunk') ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions'") ||
  !server.includes('TAG_IMPORT_QUESTION_BACKFILL_JOB_KEY_PREFIX') ||
  !server.includes('TAG_IMPORT_QUESTION_BACKFILL_START_BUDGET_MS') ||
  !server.includes('TAG_IMPORT_QUESTION_BACKFILL_STATUS_BUDGET_MS') ||
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
  !html.includes('Sorular Arka Planda Ekleniyor') ||
  !html.includes('boş soru alanı tamamlandı') ||
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
  !server.includes("app.get('/api/history-tags/import-matches/:id([0-9a-fA-F-]{36})/candidates'") ||
  !server.includes("app.post('/api/history-tags/import-matches/:id([0-9a-fA-F-]{36})/select-candidate'") ||
  !server.includes('replaceQuestion: true') ||
  !server.includes("applied: applyNow") ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions'") ||
  !server.includes("app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions/start'") ||
  !server.includes("app.get('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions/status'") ||
  !server.includes('async function runHistoryTagImportQuestionBackfillJob') ||
  !server.includes('function loadHistoryTagImportExcelItems') ||
  !server.includes('function findHistoryTagImportCandidatesForMatch') ||
  !server.includes('TAG_IMPORT_QUESTION_BACKFILL_START_BUDGET_MS') ||
  !server.includes('TAG_IMPORT_QUESTION_BACKFILL_STATUS_BUDGET_MS') ||
  !server.includes('function historyTagImportQuestionLimit') ||
  !server.includes('async function updateHistoryQuestionsBulk') ||
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
  !html.includes('toggleHistoryTagImportCandidates') ||
  !html.includes('selectHistoryTagImportCandidate') ||
  !html.includes('tag-import-candidate-panel') ||
  !html.includes('Excel Adayları') ||
  !html.includes('Bu Satırı Seç') ||
  !html.includes('{rowNumber,applyNow}') ||
  !html.includes('soru ve etiketler kayda uygulandı') ||
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
assert(!html.includes('/public-preview/public-archive.css'), 'Admin index.html public preview CSS dosyasini yuklememeli.');
assert(!html.includes('public-archive-renderer'), 'Admin index.html public preview JS/render dosyasina baglanmamali.');
assert(publicCss.includes('--pa-bg: #F7F3EA') && publicCss.includes('--pa-bg: #0D1412'), 'Public preview light/dark tokenlari bulunmali.');
assert(publicCss.includes('--pa-primary: #145A3A') && publicCss.includes('--pa-primary: #79C99E'), 'Public preview ana yesil tokenlari light/dark palete bagli olmali.');
for (const asset of [
  'assets/hero-open-book-warm.jpg',
  'icons/search.svg',
  'icons/arrow-left.svg',
  'icons/arrow-right.svg',
  'icons/user.svg',
  'icons/home.svg',
  'icons/topics.svg',
  'icons/edit.svg',
  'icons/eye.svg',
  'icons/ask-question.svg'
]) {
  assert(fs.existsSync(path.join(publicAssetRoot, asset)), `Public preview handoff asset missing: ${asset}`);
}
for (const marker of [
  'public-archive-assets',
  'hero-open-book-warm.jpg',
  "iconSvg('search')",
  "iconSvg('arrow-left')",
  "iconSvg('arrow-right')",
  "iconSvg('user')",
  "ask: 'edit'",
  'data-public-read-count',
  'normalizePublicArchiveData',
  'withPublicArchiveData',
  'loadArchiveData'
]) {
  assert(publicRendererSource.includes(marker), `Public renderer final handoff marker missing: ${marker}`);
}
assert(!publicRendererSource.includes('hero-bookshelf'), 'Eski kitaplik hero gorseli public preview icinde kalmamali.');
assert(!publicRendererSource.includes('function readingPath'), 'Public home eski Arsiv ana kapilari bolumu kaldirilmis olmali.');
assert(!publicCss.includes('.pa-reading-path') && !publicCss.includes('.pa-path-step'), 'Public CSS eski Arsiv ana kapilari kart grid stillerini icermemeli.');
assert(publicRendererSource.includes('<a class="pa-archive-shortcut"') && publicRendererSource.includes('pa-archive-shortcut-link'), 'Public home arsiv yonlendirme bandi tek parca tiklanabilir olmali.');
assert(publicCss.includes('.pa-archive-shortcut::after') && publicCss.includes('radial-gradient(circle at 92% 50%') && publicCss.includes('grid-template-columns: 34px minmax(0, 1fr) auto'), 'Public home arsiv banner modern ince serit stilleri eksik.');
assert(
  publicCss.includes('.pa-hero > .pa-still-life') &&
    publicCss.includes('object-position: 56% 72%') &&
    publicCss.includes('opacity: 0.72') &&
    publicCss.includes('object-position: 50% 74%') &&
    publicCss.includes('opacity: 0.78') &&
    publicCss.includes('mix-blend-mode: normal'),
  'Public CSS mobil acik kitap hero gorunur yerlesim markerlari eksik.'
);
assert(
  publicCss.includes('justify-content: flex-start') &&
    publicCss.includes('padding: 36px 24px 24px') &&
    publicCss.includes('padding: 34px 22px 22px'),
  'Public mobil hero ust boslugu geri gelmemeli.'
);
assert(publicCss.includes('.pa-shelf-arch') && publicCss.includes('display: none !important'), 'Public CSS old placeholder shelf graphics must be disabled.');
assert(!/--(?:bg|ink|gold)\b/.test(publicCss), 'Public CSS eski admin tokenlarina baglanmamali.');
assert(!/#[0-9A-Fa-f]{3,6}/.test(publicCss.replace(/#F7F3EA|#FFFDF7|#EFE8DC|#17201C|#66736D|#8A7662|#DDD2C0|#F5E8C8|#CFE8D9|#145A3A|#0F4930|#B68A2A|#0D1412|#121B18|#101916|#F6F0E6|#B8C0B8|#8F9B93|#2C3A34|#2F2A1B|#294D3A|#79C99E|#9ADDB8|#D7B35D|#FFFFFF|#000000/g, '')), 'Public CSS final palet disinda hex renk icermemeli.');
for (const marker of [
  'overflow-x: hidden',
  '@media (max-width: 430px)',
  'env(safe-area-inset-bottom)',
  'grid-template-columns: repeat(4, minmax(0, 1fr))',
  'width: calc(100% - 24px)',
  'minmax(0, 1fr)',
  'backdrop-filter: blur(24px)'
]) {
  assert(publicCss.includes(marker), `390px ve mobil alt gezinme guard eksik: ${marker}`);
}
for (const marker of [
  '-webkit-text-size-adjust: 100%',
  '.pa-search:focus-within',
  'grid-template-columns: 40px minmax(0, 1fr) 49px',
  'font-size: 16px'
]) {
  assert(publicCss.includes(marker), `Mobil input/focus guard eksik: ${marker}`);
}
assert(publicRendererSource.includes('placeholder="Soru veya kategori arayın..."'), 'Mobil arama placeholder kisa ve okunabilir olmali.');
assert(!publicRendererSource.includes('placeholder="Sorunuzu veya kategorinizi yazın..."'), 'Uzun arama placeholder mobilde okunamaz, geri gelmemeli.');
for (const match of publicCss.matchAll(/\.pa-search input\s*\{([\s\S]*?)\}/g)) {
  assert(!/font-size:\s*(?:1[0-5](?:\.\d+)?px|0\.\d+rem)/.test(match[1]), 'Arama input fontu 16px altina dusmemeli; iOS zoom yapar.');
}

for (const marker of [
  "const GOOGLE_CLIENT_ID",
  "app.get('/public-preview/auth/google'",
  "app.get('/public-preview/auth/google/callback'",
  "app.get('/public-preview/api/session'",
  'async function ensurePublicArchiveAuthReady',
  "app.post('/public-preview/api/auth/email/register'",
  "app.post('/public-preview/api/auth/email/login'",
  "app.get('/public-preview/api/question-stats'",
  "app.post('/public-preview/api/questions/:slug/read'",
  "app.post('/public-preview/api/question-submissions'",
  "app.get('/public-preview/api/my-question-submissions'",
  "app.post('/public-preview/api/my-question-submissions/:id/seen'",
  "app.get('/api/public-archive/question-submissions'",
  "app.post('/api/public-archive/question-submissions/:id/answer'",
  "app.get('/api/public-archive/sync-status'",
  "app.post('/api/public-archive/sync-approved'",
  'loadPublicArchiveDataset',
  'loadApprovedHistoryForPublicArchive',
  'syncApprovedHistoryToPublicArchive',
  'loadExistingPublicArchiveRowsByHistoryId',
  'preservedExistingContent',
  'PUBLIC_ARCHIVE_PARAGRAPH_TARGET_LENGTH',
  'publicArchiveInsertStructuralBreaks',
  'publicArchiveSentenceSegments',
  'publicArchiveSplitLongParagraph',
  'publicArchiveSubmittedText',
  'loadArchiveData: loadPublicArchiveRouteDataset',
  'await startupReady',
  'PUBLIC_QUESTION_STATS_FALLBACK_KEY',
  'incrementPublicQuestionReadFallback',
  "storage: 'settings'",
  "question_text,tags"
]) {
  assert(server.includes(marker), `Public archive live preview backend marker eksik: ${marker}`);
}
assert(server.includes('.split(/\\n+/)'), 'Public cevap paragraflari onaylanan metindeki anlamli satirlari korumali.');
assert(publicCss.includes('white-space: pre-line'), 'Public cevap ekrani satir sonlarini gorsel olarak korumali.');
assert(!server.includes('Soru göndermek için Google ile oturum açın.'), 'Public soru gonderim hatasi artik Google-only olmamali.');
assert(server.includes('Soru göndermek için önce hesabınızla oturum açın.'), 'Public soru gonderim hatasi hesap diliyle donmeli.');
for (const marker of [
  'create table if not exists public.public_users',
  'password_hash text',
  'auth_provider text not null default',
  'public_users_email_unique_idx',
  'create table if not exists public.public_question_submissions',
  'answer_text text',
  'answered_by text',
  'answered_at timestamptz',
  'user_notified_at timestamptz',
  'user_seen_at timestamptz',
  'public_question_submissions_answered_idx',
  'create table if not exists public.public_question_stats',
  'create table if not exists public.public_visit_events',
  'create table if not exists public.public_categories',
  'create table if not exists public.public_topics',
  'create table if not exists public.public_qa',
  'create table if not exists public.public_qa_topics',
  'alter table public.history add column if not exists question_text text',
  "alter table public.history add column if not exists tags jsonb not null default '[]'::jsonb",
  'alter table public.public_users enable row level security',
  'alter table public.public_question_submissions enable row level security',
  'alter table public.public_question_stats enable row level security',
  'alter table public.public_visit_events enable row level security',
  'alter table public.public_categories enable row level security',
  'alter table public.public_topics enable row level security',
  'alter table public.public_qa enable row level security',
  'alter table public.public_qa_topics enable row level security',
  'public_visit_events_source_idx',
  'create or replace function public.increment_public_question_read'
]) {
  assert(schema.includes(marker), `Public archive schema marker eksik: ${marker}`);
}
for (const marker of [
  'Canlı Site',
  'Ziyaret İstatistikleri',
  'Soru Talepleri',
  'live-site-menu-group',
  'openLiveSite',
  'archivePublicQuestionList',
  'archivePublicQuestionDetail',
  'archivePublicQuestionAnswer',
  'answerArchivePublicQuestion',
  'archivePublicSyncSummary',
  'archivePublicAnalyticsSummary',
  'humanVisits',
  'Konum Notu',
  'Şehirler (IP ağına göre)',
  'Saat dilimleri',
  'Tarayıcılar',
  'İşletim sistemleri',
  'Sayfa türleri',
  'publicAnalyticsRouteTypeLabel',
  'loadArchivePublicAnalytics',
  'syncApprovedPublicArchive',
  'Onaylıları Siteye Hazırla',
  '/api/public-archive/question-submissions',
  '/api/public-archive/sync-status',
  '/api/public-archive/sync-approved',
  '/api/public-archive/analytics'
]) {
  assert(html.includes(marker), `Admin panel public soru talepleri gorunurluk marker eksik: ${marker}`);
}

const publicRenderCases = [
  ...ROUTE_PATHS.map(route => ({ route, query: route.endsWith('/arama') ? { q: 'zikir' } : {} })),
  { route: '/public-preview/arama', query: { q: 'bulunmayan-kelime' } },
  { route: '/public-preview/soru/gizli-icerik' },
  { route: '/public-preview/konu/yok' },
  { route: '/public-preview/kategori/yok' }
];

for (const item of publicRenderCases) {
  const rendered = renderPublicArchivePreviewRoute(item.route, item.query || {});
  assert(rendered.html.includes('<meta name="robots" content="noindex,nofollow">'), `${item.route} noindex meta icermeli.`);
  assert(rendered.html.includes('Dini Sorular') && rendered.html.includes('ve Cevaplar Arşivi'), `${item.route} tipografik logo icermeli.`);
  assert(rendered.html.includes('Cevaplara delilleri ve kaynak bağlamıyla kolayca ulaşın.'), `${item.route} ana public cumleyi icermeli.`);
  assert(rendered.html.includes('/public-preview/public-archive.css?v=20260827-answer-format-v1'), `${item.route} yalniz versiyonlu public CSS yuklemeli.`);
  assert(!rendered.html.includes('rel="canonical"'), `${item.route} preview noindex modunda canonical uretmemeli.`);
  assertOnlyPublicPreviewApi(item.route, rendered.html);
  assertNoPublicPreviewLeaks(item.route, rendered.html);
}

const rootLaunchPreview = renderPublicArchivePreviewRoute('/', {}, { ...publicArchiveFixtures, basePath: '', noindex: false }).html;
assert(rootLaunchPreview.includes('href="/arsiv"'), 'Root public mode Arsiv linkini root path ile uretmeli.');
assert(rootLaunchPreview.includes('href="/hesabim"'), 'Root public mode Hesabim linkini root path ile uretmeli.');
assert(rootLaunchPreview.includes('/api/session'), 'Root public mode session API adresini root path ile uretmeli.');
assert(rootLaunchPreview.includes('href="/public-archive.css?v=20260827-answer-format-v1"'), 'Root public mode versiyonlu CSS adresini root path ile uretmeli.');
assert(rootLaunchPreview.includes('<meta name="robots" content="index,follow">'), 'Root public mode indexing acikken index,follow meta uretmeli.');
assert(rootLaunchPreview.includes('<link rel="canonical" href="https://arsiv.ibrahimlive.ai/">'), 'Root public mode ana sayfa canonical adresini uretmeli.');
assert(rootLaunchPreview.includes('"@type":"WebSite"') && rootLaunchPreview.includes('"@type":"SearchAction"'), 'Root public mode WebSite/SearchAction yapisal veri uretmeli.');
assert(!rootLaunchPreview.includes('/public-preview/'), 'Root public mode public-preview path sizintisi icermemeli.');
for (const route of ['/arama', '/soru-sor', '/hesabim', '/kategoriler', '/gizlilik', '/kullanim-kosullari']) {
  const rendered = renderPublicArchivePreviewRoute(route, {}, { ...publicArchiveFixtures, basePath: '', noindex: false }).html;
  assert(rendered.includes('<meta name="robots" content="noindex,follow">'), `${route} SEO disi yardimci sayfa noindex,follow olmali.`);
  assert(!rendered.includes('rel="canonical"'), `${route} noindex oldugu icin canonical uretmemeli.`);
}

const homePreview = renderPublicArchivePreviewRoute('/public-preview').html;
for (const assetUrl of [
  '/public-preview/assets/hero-open-book-warm.jpg',
  '/public-preview/assets/arsiv-logo-mark.png',
  '/public-preview/assets/favicon-16.png',
  '/public-preview/assets/favicon-32.png',
  '/public-preview/assets/favicon-48.png',
  '/public-preview/assets/apple-touch-icon.png',
  '/public-preview/assets/site.webmanifest'
]) {
  assert(homePreview.includes(assetUrl), `Rendered public preview hero asset missing: ${assetUrl}`);
}
for (const marker of ['PUBLIC_ARCHIVE_STATIC_CACHE', 'PUBLIC_ARCHIVE_ASSET_VERSION', '20260827-answer-format-v1', "immutable: !noindex", "maxAge: noindex ? 0 : '1y'", "res.set('Cache-Control', noindex ? 'no-store, no-cache, must-revalidate, proxy-revalidate' : PUBLIC_ARCHIVE_STATIC_CACHE)"]) {
  assert(publicRendererSource.includes(marker), `Public statik asset cache guard marker eksik: ${marker}`);
}
for (const marker of ['hero-open-book-warm.jpg', 'width="1280" height="1024"', 'fetchpriority="high"']) {
  assert(homePreview.includes(marker), `Public hero LCP/CLS marker eksik: ${marker}`);
}
for (const [fileName, expectedSize] of [
  ['favicon-16.png', '16x16'],
  ['favicon-32.png', '32x32'],
  ['favicon-48.png', '48x48'],
  ['apple-touch-icon.png', '180x180'],
  ['app-icon-192.png', '192x192'],
  ['app-icon-512.png', '512x512'],
  ['app-icon-maskable-512.png', '512x512'],
  ['public-share-card.png', '1200x630'],
  ['public-share-card-20260823-v3.png', '1200x630']
]) {
  assert(readPngSize(path.join(publicAssetRoot, 'assets', fileName)) === expectedSize, `Public asset olcusu hatali: ${fileName}`);
}
const publicManifest = JSON.parse(fs.readFileSync(path.join(publicAssetRoot, 'assets', 'site.webmanifest'), 'utf8'));
assert(publicManifest.name === 'Dini Sorular ve Cevaplar Arşivi' && publicManifest.short_name === 'Dini Sorular', 'Public app manifest isimleri dogru olmali.');
assert(publicManifest.id === '/' && publicManifest.start_url === '/' && publicManifest.scope === '/', 'Public app manifest root uygulama kimligi/adresiyle acilmali.');
assert((publicManifest.icons || []).some(icon => icon.src === 'app-icon-maskable-512.png' && icon.purpose === 'maskable'), 'Public manifest maskable icon icermeli.');
for (const marker of ['class="pa-logo-mark"', 'class="pa-logo-text"', 'width="256" height="256"', 'aria-hidden="true"']) {
  assert(homePreview.includes(marker), `Public logo mark HTML marker eksik: ${marker}`);
}
for (const marker of ['<title>Dini Sorular ve Cevaplar Arşivi</title>', 'name="apple-mobile-web-app-title" content="Dini Sorular"', 'name="mobile-web-app-capable" content="yes"', 'name="apple-mobile-web-app-capable" content="yes"', 'name="apple-mobile-web-app-status-bar-style" content="default"', 'property="og:locale" content="tr_TR"', 'property="og:title" content="Dini Sorular ve Cevaplar Arşivi"', 'property="og:updated_time"', 'property="og:image"', 'public-share-card-20260823-v3.png?v=telegram-cache-refresh-20260823', 'property="og:image:secure_url"', 'property="og:image:type" content="image/png"', 'property="og:image:width" content="1200"', 'property="og:image:height" content="630"', 'name="twitter:card" content="summary_large_image"', 'name="twitter:title"', 'name="twitter:description"', 'name="twitter:image"', 'name="twitter:image:alt"', 'rel="apple-touch-icon"', 'rel="manifest"']) {
  assert(homePreview.includes(marker), `Public sosyal/app meta marker eksik: ${marker}`);
}
assert(!homePreview.includes('hero-bookshelf'), 'Rendered public preview eski kitaplik assetini icermemeli.');
assert(homePreview.includes('Sorularınıza, kaynaklarıyla birlikte cevap bulun.'), 'Public home yeni hero basligini icermeli.');
assert(!homePreview.includes('<p class="pa-kicker">Cevaplara delilleri ve kaynak bağlamıyla kolayca ulaşın.</p>'), 'Public home hero ust aciklama cumlesi geri gelmemeli.');
assert(homePreview.includes('ilgili soruları, cevapları ve delilleri bir arada okuyun.'), 'Public home delil vurgulu aciklama metnini icermeli.');
for (const marker of ['Arşivin tamamını açın.', 'Tüm soru ve cevaplara hızlıca ulaşın.', 'pa-archive-shortcut-link', 'Öne Çıkan Sorular', 'Aktif arşiv', 'Yayındaki soru ve cevaplar', 'aktif soru', 'aktif cevap', 'pa-active-stats', 'pa-live-dot', 'data-count-up', 'data-count-target', 'Aklınızda bir soru mu var?', 'Cevapları nasıl keşfedebilirsiniz?', 'Sorularınız Dr. Abdulcabbar Boran tarafından Kur’an ve Hadis-i Şerif ışığında cevaplandırılır', 'aynı kategori altındaki diğer sorulara']) {
  assert(homePreview.includes(marker), `Public home bolumu eksik: ${marker}`);
}
for (const marker of ['homeQuestionSets', 'uniqueHomeQuestions', 'weightedHomeScore', 'homeRotationHour', 'hashString']) {
  assert(publicRendererSource.includes(marker), `Public ana sayfa saatlik vitrin marker eksik: ${marker}`);
}
for (const marker of ['trackPublicVisit', '/api/public-analytics/visit', 'dsca-visitor-id', "iconSvg('arrow-up'"]) {
  assert(publicRendererSource.includes(marker), `Public analitik/yukari cik marker eksik: ${marker}`);
}
for (const marker of ['data-scroll-top aria-label="Yukarı çık" aria-hidden="true" tabindex="-1"', 'button.tabIndex = visible ? 0 : -1']) {
  assert(publicRendererSource.includes(marker), `Public yukari cik erisilebilirlik marker eksik: ${marker}`);
}
for (const marker of ['bindFastPublicNavigation', 'replacePublicArchiveShell', 'DOMParser', 'replaceWith', 'cleanupPublicArchivePage', '__publicArchiveFastNavBound', 'dsca-page-cache:v5', 'X-Public-Navigation', 'pushState({ paFast: true }', "window['his' + 'tory']", 'requestIdleCallback']) {
  assert(publicRendererSource.includes(marker), `Public hizli sayfa gecisi marker eksik: ${marker}`);
}
assert(!publicRendererSource.includes('document.write(') && !publicRendererSource.includes('document.open('), 'Public hizli gecis tam sayfa document.write kullanmamali.');
for (const marker of ['PUBLIC_ARCHIVE_DATA_UNAVAILABLE', 'publicArchiveDataUnavailableError', 'isPublicArchiveRootRequest']) {
  assert(server.includes(marker), `Public root veri hatasi fallback korumasi eksik: ${marker}`);
}
for (const marker of ['renderPublicArchiveUnavailableRoute', 'Arşiv geçici olarak hazırlanıyor', "res.set('Retry-After', '120')"]) {
  assert(publicRendererSource.includes(marker), `Public root gecici veri hatasi ekrani eksik: ${marker}`);
}
for (const marker of ['uniquePublicArchiveRecords', 'hidePublicArchiveDuplicateRows', '/api/public-archive/duplicates/hide', 'publicArchiveQuestionIdentity']) {
  assert(server.includes(marker), `Public mukerrer temizlik marker eksik: ${marker}`);
}
const duplicateHomePreview = renderPublicArchivePreviewRoute('/public-preview', {}, {
  brand: { sentence: 'Cevaplara delilleri ve kaynak bağlamıyla kolayca ulaşın.' },
  categories: [{ slug: 'karar-vermek', name: 'Karar Vermek', description: 'Karar verme soruları.', topicSlugs: [] }],
  topics: [],
  qa: [
    {
      slug: 'mukerrer-soru-a',
      title: 'Aynı karar sorusu mükerrer görünmemeli mi?',
      question: 'Aynı karar sorusu mükerrer görünmemeli mi?',
      answer: ['Bu kayıt ilk örnek olarak gelir.'],
      categorySlug: 'karar-vermek',
      publishedAt: '2026-08-20T09:00:00.000Z',
      readCount: 1,
      isFeatured: true
    },
    {
      slug: 'mukerrer-soru-b',
      title: 'Aynı karar sorusu mükerrer görünmemeli mi?',
      question: 'Aynı karar sorusu mükerrer görünmemeli mi?',
      answer: ['Bu kayıt aynı sorunun daha çok okunan sürümüdür.'],
      categorySlug: 'karar-vermek',
      publishedAt: '2026-08-21T09:00:00.000Z',
      readCount: 20,
      isFeatured: true
    },
    {
      slug: 'mukerrer-soru-c',
      title: 'Aynı karar sorusu mükerrer görünmemeli mi?',
      question: 'Aynı karar sorusu mükerrer görünmemeli mi?',
      answer: ['Bu kayıt aynı sorunun daha çok okunan sürümüdür.'],
      categorySlug: 'karar-vermek',
      publishedAt: '2026-08-18T09:00:00.000Z',
      readCount: 2,
      isFeatured: true
    },
    {
      slug: 'cok-okunan-vitrin-sorusu',
      title: 'Çok okunan soru vitrinde yer bulur mu?',
      question: 'Çok okunan soru vitrinde yer bulur mu?',
      answer: ['Bu kayıt okuma ağırlığı kontrolü için kullanılır.'],
      categorySlug: 'karar-vermek',
      publishedAt: '2026-08-19T09:00:00.000Z',
      readCount: 999
    }
  ]
}).html;
assert(duplicateHomePreview.includes('/public-preview/soru/mukerrer-soru-b'), 'Public ana sayfa mukerrer sorunun secilen surumunu gostermeli.');
assert(duplicateHomePreview.includes('/public-preview/soru/mukerrer-soru-a'), 'Public ana sayfa ayni sorunun farkli cevabini gizlememeli.');
assert(!duplicateHomePreview.includes('/public-preview/soru/mukerrer-soru-c'), 'Public ana sayfa yalniz birebir soru-cevap kopyasini gizlemeli.');
assert(duplicateHomePreview.includes('Çok okunan soru vitrinde yer bulur mu?'), 'Public ana sayfa okuma agirlikli soruyu vitrine alabilmeli.');
assert(!homePreview.includes('Okuma düzeni'), 'Public home eski Okuma duzeni kicker ini icermemeli.');
assert(!homePreview.includes('Her cevap; soru, ana kapı ve ilgili kavramlarla birlikte hazırlanır.'), 'Public home eski okuma duzeni basligini icermemeli.');
assert(!homePreview.includes('Öne Çıkan Cevaplar'), 'Public home eski One Cikan Cevaplar basligini icermemeli.');
const featuredStart = homePreview.indexOf('Öne Çıkan Sorular');
const featuredEnd = homePreview.indexOf('Aktif arşiv');
assert(featuredStart >= 0 && featuredEnd > featuredStart, 'Public home featured bolum sinirlari bulunmali.');
const featuredSection = homePreview.slice(featuredStart, featuredEnd);
assert(featuredSection.includes('has-strong-cta'), 'Public home featured kart CTA vurgusu eksik.');
assert(!featuredSection.includes('pa-card-meta') && !featuredSection.includes('class="pa-chip"'), 'Public home featured kartlarda etiket/chip gorunmemeli.');
const activeStatsStart = homePreview.indexOf('class="pa-active-stats"');
const activeStatsEnd = homePreview.indexOf('Son Yayınlanan Sorular');
assert(activeStatsStart >= 0 && activeStatsEnd > activeStatsStart, 'Public home aktif arsiv sayaci sinirlari bulunmali.');
const activeStatsSection = homePreview.slice(activeStatsStart, activeStatsEnd);
assert(!activeStatsSection.includes('href=') && !activeStatsSection.includes('Arşive Git') && !activeStatsSection.includes('pa-active-stats-link'), 'Public home aktif arsiv sayacinda arsiv yonlendirme olmamali.');
assert(!homePreview.includes('Kavram Haritası'), 'Public home Kavram Haritasi bolumu geri gelmemeli.');
assert(!homePreview.includes('Ana Kategoriler'), 'Public home ana kategori vitrini geri gelmemeli.');
assert(!homePreview.includes('>Konular</a>') && !homePreview.includes('>Kategoriler</a>') && !homePreview.includes('>Konular</span>'), 'Public ana gezinmede Konular/Kategoriler gorunmemeli.');
assert(homePreview.includes('href="/public-preview/arama#arama"'), 'Public ana gezinmede arama kapisi gorunmeli.');
assert(!homePreview.includes('Arşivin tamamına buradan ulaşabilirsiniz.'), 'Public home eski hacimli arsiv banner metnini icermemeli.');
assert(!homePreview.includes('Tüm soru ve cevapları tek sayfada görmek için Arşiv bölümüne geçin.'), 'Public home eski hacimli arsiv banner aciklamasini icermemeli.');
assert(!homePreview.includes('Arşiv ana kapıları'), 'Public home eski Arsiv ana kapilari basligini icermemeli.');
assert(!homePreview.includes('Cevapları yalnız liste olarak değil, kavram yolu olarak okuyun.'), 'Public home eski Arsiv ana kapilari aciklamasini icermemeli.');
for (const marker of ['Allah’a Ulaşmayı Dilemek', 'Hidayet', 'Mürşid', 'Zikir', 'Teslimiyet', 'Tabiiyet', 'Nefs', 'Ruh']) {
  assert(homePreview.includes(marker), `Public home arsiv kategori omurgasi eksik: ${marker}`);
}
for (const marker of [
  'data-concept-slider',
  'data-concept-track',
  'data-concept-rail',
  'pa-concept-pill',
  'href="/public-preview/kategori/nefs"',
  'href="/public-preview/kategori/ruh"'
]) {
  assert(homePreview.includes(marker), `Public home kategori slider marker eksik: ${marker}`);
}
assert(homePreview.includes('Sorularınız Dr. Abdulcabbar Boran tarafından Kur’an ve Hadis-i Şerif ışığında cevaplandırılır'), 'Public home author/source context eksik.');
assert(homePreview.includes('Hesab\u0131m'), 'Public account control eksik.');
assert(homePreview.includes('href="/public-preview/hesabim"'), 'Public account control hesap route una gitmeli.');
assert(homePreview.includes('href="/public-preview/arsiv"'), 'Public arsiv linki gercek arsiv route una gitmeli.');
for (const marker of ['pa-mobile-nav', 'pa-scroll-top', 'data-scroll-top', 'Yukarı çık']) {
  assert(homePreview.includes(marker), `Public global mobil kontrol marker eksik: ${marker}`);
}
for (const marker of ['bindScrollTopControl', 'window.scrollY > 420', "window.scrollTo({ top: 0, behavior: 'smooth' })", 'data-visible']) {
  assert(publicRendererSource.includes(marker), `Public yukari cik davranis marker eksik: ${marker}`);
}
for (const marker of ['Cevabı oku', 'pa-card-bottom', 'pa-card-cta', 'has-strong-cta', 'data-read-count-label', 'okunma']) {
  assert(homePreview.includes(marker), `Public soru karti aksiyon/okunma marker eksik: ${marker}`);
}
assert(!homePreview.includes('pa-question-excerpt'), 'Public soru kartlarinda kisa aciklama paragraflari geri gelmemeli.');
const archivePreview = renderPublicArchivePreviewRoute('/public-preview/arsiv').html;
assert(archivePreview.includes('Merak ettiğiniz konunun cevaplarına ulaşın.') && archivePreview.includes('Soru ve cevapları kategorilerine göre inceleyebilir, aradığınız konuyu alfabetik olarak kolayca bulabilirsiniz.') && archivePreview.includes('Tüm Sorular'), 'Public arsiv sayfasi yeni metin ve browse/list yapiyla gorunmeli.');
assert(archivePreview.includes('soru cevap') && !/<span>\d+ soru<\/span>\s*<span>\d+ cevap<\/span>/.test(archivePreview), 'Public arsiv sayacinda soru/cevap ayrimi tek ifadeye inmeli.');
assert(!/for \(const row of uniquePublicArchiveRecords\(qaRows \|\| \[\]\)\)\s*{\s*const slugs = Array\.isArray\(row\.topic_slugs\)/.test(server), 'Public arsiv kategori dizini yalniz slug/topic alanlariyla dedupe edilmemeli; bu harflerde kategorileri eksiltir.');
assert(/for \(const row of qaRows \|\| \[\]\)\s*{\s*const slugs = Array\.isArray\(row\.topic_slugs\)/.test(server), 'Public arsiv kategori dizini aktif published topic_slugs havuzunu dogrudan saymali.');
for (const marker of ['PUBLIC_CATEGORY_INDEX_MIN_QUESTIONS = 5', 'PUBLIC_CATEGORY_SEO_SLUGS', 'publicCategorySeoIndexable', 'noindex,follow', 'pageNoindex']) {
  assert(publicRendererSource.includes(marker), `Public kategori SEO index kural marker eksik: ${marker}`);
}
for (const marker of ['publicArchiveCategorySeoIndexable', ".select('slug,category_slug,topic_slugs,updated_at,published_at')", 'if (publicArchiveCategorySeoIndexable(slug, meta.count))', "publicArchiveSitemapEntry('/hakkimizda'", "publicArchiveSitemapEntry('/iletisim'"]) {
  assert(server.includes(marker), `Public sitemap kategori SEO kural marker eksik: ${marker}`);
}
for (const forbidden of ["publicArchiveSitemapEntry('/arama'", "publicArchiveSitemapEntry('/soru-sor'", "publicArchiveSitemapEntry('/gizlilik'", "publicArchiveSitemapEntry('/kullanim-kosullari'"]) {
  assert(!server.includes(forbidden), `SEO disi yardimci sayfa sitemap icinde kalmamali: ${forbidden}`);
}
for (const marker of ['pa-alpha-index', 'data-alpha-index', 'pa-alpha-shell', 'data-alpha-track', 'data-alpha-scroll="prev"', 'data-alpha-scroll="next"', 'pa-alpha-track', 'pa-alpha-letter', 'pa-letter-panel', 'pa-letter-search', 'Bu harfte ara...', 'A harfiyle başlayan kategoriler', '/public-preview/arsiv?harf=A']) {
  assert(archivePreview.includes(marker), `Public arsiv alfabetik kategori dizini eksik: ${marker}`);
}
assert(/<button class="pa-alpha-nav" type="button" data-alpha-scroll="next"/.test(archivePreview), 'Public arsiv ileri oku harf secmeyen kaydirma butonu olmali.');
assert(/<button class="pa-alpha-nav" type="button" data-alpha-scroll="prev"/.test(archivePreview), 'Public arsiv geri oku harf secmeyen kaydirma butonu olmali.');
assert(!/class="pa-alpha-nav" href=/.test(archivePreview), 'Public arsiv okları harf secen linke donmemeli.');
for (const marker of ['ARCHIVE_PAGE_SIZE', 'archivePaginationState', 'archivePagination(', 'pa-pagination', 'pa-pagination-actions', 'Sayfa ', 'soru gösteriliyor', 'sayfa: req.query.sayfa']) {
  assert(publicRendererSource.includes(marker) || publicArchiveCss.includes(marker), `Public arsiv sayfalama marker eksik: ${marker}`);
}
assert(!archivePreview.includes('Soru ve cevapları kavramlarıyla birlikte keşfedin.') && !archivePreview.includes('Yayınlanan kayıtları Allah’a ulaşmayı dilemek'), 'Public arsiv sayfasi eski hero metnini icermemeli.');
assert(!archivePreview.includes('<h2>Kategoriler</h2>') && !archivePreview.includes('<h2>Kavramlar</h2>') && !archivePreview.includes('/public-preview/konular'), 'Public arsiv sayfasinda kategori/kavram vitrinleri gorunmemeli.');
const hArchivePreview = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'H' }).html;
assert(hArchivePreview.includes('H harfiyle başlayan kategoriler') && hArchivePreview.includes('/public-preview/arsiv?harf=H&amp;kategori=hidayet#sorular'), 'Public arsiv H harfi kategori listesi calismali.');
const numericArchiveData = {
  ...publicArchiveFixtures,
  categories: [
    { slug: 'iki', name: '2', description: '2 başlığı.', topicSlugs: [] },
    { slug: 'adem', name: 'Âdem', description: 'Âdem soruları.', topicSlugs: [] }
  ],
  topics: [],
  qa: [
    {
      slug: 'iki-sorusu',
      title: '2 hakkında soru',
      question: '2 hakkında soru',
      answer: ['Cevap metni.'],
      categorySlug: 'iki',
      topicSlugs: [],
      publishedAt: '2026-08-23T00:00:00.000Z',
      updatedAt: '2026-08-23T00:00:00.000Z'
    },
    {
      slug: 'adem-sorusu',
      title: 'Âdem hakkında soru',
      question: 'Âdem hakkında soru',
      answer: ['Cevap metni.'],
      categorySlug: 'adem',
      topicSlugs: [],
      publishedAt: '2026-08-23T00:00:00.000Z',
      updatedAt: '2026-08-23T00:00:00.000Z'
    }
  ]
};
const defaultNumericArchivePreview = renderPublicArchivePreviewRoute('/public-preview/arsiv', {}, numericArchiveData).html;
const hashArchivePreview = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: '#' }, numericArchiveData).html;
assert(defaultNumericArchivePreview.includes('A harfiyle başlayan kategoriler') && !defaultNumericArchivePreview.includes('# harfiyle başlayan kategoriler'), 'Public arsiv bos harfte # yerine ilk gercek harfle acilmali.');
assert(hashArchivePreview.includes('# harfiyle başlayan kategoriler') && hashArchivePreview.includes('>2</strong>'), 'Public arsiv # harfi sadece acikca istenirse acilmali.');
const circumflexArchivePreview = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'Â' }, {
  ...publicArchiveFixtures,
  categories: [
    { slug: 'adem', name: 'Âdem', description: 'Âdem soruları.', topicSlugs: [] },
    { slug: 'ahlak', name: 'Ahlak', description: 'Ahlak soruları.', topicSlugs: [] }
  ],
  topics: [],
  qa: [{
    slug: 'adem-sorusu',
    title: 'Âdem hakkında soru',
    question: 'Âdem hakkında soru',
    answer: ['Cevap metni.'],
    categorySlug: 'adem',
    topicSlugs: [],
    publishedAt: '2026-08-23T00:00:00.000Z',
    updatedAt: '2026-08-23T00:00:00.000Z'
  }]
}).html;
assert(circumflexArchivePreview.includes('A harfiyle başlayan kategoriler') && circumflexArchivePreview.includes('Âdem') && !circumflexArchivePreview.includes('Â harfiyle başlayan kategoriler') && !circumflexArchivePreview.includes('harf=Â'), 'Public arsiv sapkali harfleri ana harfte birlestirmeli.');
const filteredArchivePreview = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'H', kategori: 'hidayet' }).html;
assert(filteredArchivePreview.includes('Hidayet soruları') && filteredArchivePreview.includes('Tümünü göster') && !filteredArchivePreview.includes('<h2>Tüm Sorular</h2>'), 'Public arsiv kategori seciminde soru listesi filtrelenmeli.');
const searchPreview = renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'zikir' }).html;
assert(searchPreview.includes('Zikir kalbi nasıl değiştirir'), 'Public search fixture data ile sonuc dondurmeli.');
assert(!searchPreview.includes('class="pa-breadcrumb"') && !searchPreview.includes('Sayfa yolu'), 'Public arama sayfasi gereksiz breadcrumb gostermemeli.');
const noResultPreview = renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'bulunmayan-kelime' }).html;
assert(noResultPreview.includes('Sonuç bulunamadı.') && noResultPreview.includes('Aklınızda bir soru mu var?'), 'Public search no-results state soru CTA ile gorunmeli.');
const accountPreview = renderPublicArchivePreviewRoute('/public-preview/hesabim').html;
assert(accountPreview.includes('Soru göndermek için hesabınıza giriş yapın.') && accountPreview.includes('Google ile Devam Et'), 'Public hesap sayfasi Google oturum girisi sunmali.');
assert(accountPreview.includes('class="pa-google-button"') && accountPreview.includes('data-auth-tab="login"') && accountPreview.includes('data-auth-tab="register"'), 'Public hesap sayfasi modern sekmeli auth paneli sunmali.');
assert(accountPreview.includes('data-email-login-form') && accountPreview.includes('data-email-register-form'), 'Public hesap sayfasi e-posta giris ve kayit formlarini sunmali.');
assert(accountPreview.includes('/public-preview/auth/google'), 'Public hesap sayfasi Google auth route una baglanmali.');
assert(accountPreview.includes('/public-preview/api/auth/email/login') && accountPreview.includes('/public-preview/api/auth/email/register'), 'Public hesap sayfasi e-posta auth API lerine baglanmali.');
assert(accountPreview.includes('data-user-questions') && accountPreview.includes('data-user-questions-list'), 'Public hesap sayfasi kullanici soru takip alanini sunmali.');
assert(accountPreview.includes('/public-preview/api/my-question-submissions'), 'Public hesap sayfasi kullanicinin soru cevap durum API sine baglanmali.');
assertOnlyPublicPreviewApi('/public-preview/hesabim', accountPreview);
const detailPreview = renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html;
for (const marker of ['Soru', 'Cevap', 'Cevap bilgileri', 'İlgili Sorular', 'Paylaş', 'Bağlantıyı kopyala']) {
  assert(detailPreview.includes(marker), `Public detail bolumu eksik: ${marker}`);
}
for (const marker of ['application/ld+json', '"@type":"Article"', '"mainEntityOfPage"', '"articleBody"', '"@type":"BreadcrumbList"', '"@type":"SearchAction"']) {
  assert(detailPreview.includes(marker), `Public detail SEO/LLM yapisal veri eksik: ${marker}`);
}
assert(!detailPreview.includes('"@type":"QAPage"') && !detailPreview.includes('"acceptedAnswer"'), 'Public detail forum tipi QAPage/acceptedAnswer yapisina donmemeli.');
assert(detailPreview.includes('Yanıtlayan: Dr. Abdulcabbar Boran'), 'Public detail author meta eksik.');
assert(detailPreview.includes('data-public-read-count="ornek-soru"'), 'Public detail gercek okunma sayaci marker eksik.');
assert(!detailPreview.includes('class="pa-detail-subtitle"'), 'Public detail ust ozet paragrafinin geri gelmemesi gerekir.');
assert(!detailPreview.includes('<h1>Allah’a ulaşmayı dilemek ne demektir?</h1>'), 'Public detail ustte buyuk tekrar soru basligini gostermemeli.');
assert(!detailPreview.includes('görüntülenme') && !detailPreview.includes('Faydalı oldu mu'), 'Public detail fake canli ozellik gostermemeli.');
assert(!detailPreview.includes('Yazdır') && !detailPreview.includes('data-print') && !publicRendererSource.includes('data-print'), 'Public detail yazdir aksiyonu geri gelmemeli.');
const sourceDetailPreview = renderPublicArchivePreviewRoute('/public-preview/soru/kaynakli-soru', {}, {
  brand: { authorLine: 'Sorular Dr. Abdulcabbar Boran tarafından yanıtlanır.', answererLabel: 'Yanıtlayan: Dr. Abdulcabbar Boran' },
  categories: [{ slug: 'hidayet', name: 'Hidayet', description: 'Hidayet kayıtları.', topicSlugs: ['zikir'], featured: true }],
  topics: [{ slug: 'zikir', name: 'Zikir', description: 'Zikir kayıtları.', categorySlug: 'hidayet', relatedTopicSlugs: [], featured: true }],
  qa: [{
    slug: 'kaynakli-soru',
    title: 'Kaynaklı soru nasıl görünür?',
    question: 'Kaynaklı soru nasıl görünür?',
    summary: 'Bu özet detay üstünde görünmemeli.',
    answer: ['Cevap içinde Bakara-256 ve YÂSÎN-62 açık ayet atfı olarak yer alır.'],
    categorySlug: 'hidayet',
    topicSlugs: ['zikir'],
    publishedAt: '2026-08-15',
    updatedAt: '2026-08-15',
    readTime: 1,
    readCount: 3,
    isFeatured: true,
    relatedSlugs: []
  }]
}).html;
for (const marker of ['Kaynak ve deliller', 'Bakara-256', 'Yâsîn-62', 'data-source-reference']) {
  assert(sourceDetailPreview.includes(marker), `Public detail kaynak marker eksik: ${marker}`);
}
assert(sourceDetailPreview.includes('Bu cevapta açıkça adı geçen ayet atıfları'), 'Public kaynak metni gorunur ve acik olmali.');
assert(sourceDetailPreview.includes('"citation":["Bakara-256","Yâsîn-62"]'), 'Public kaynaklar Article citation alanina yazilmali.');
assert(!sourceDetailPreview.includes('Bu özet detay üstünde görünmemeli.</p>'), 'Public detail kaynakli kayitta ust ozet gorunmemeli.');
assert(publicRendererSource.includes('data-card-href') && publicRendererSource.includes("closest('a, button, input, select, textarea')"), 'Soru kartlari tum kart tiklamasiyla soru detayina gitmeli.');
for (const marker of ['bindConceptSliders', 'requestAnimationFrame', 'data-paused', 'setTimeout(function(){ setPaused(false); }, 2000)', 'translate3d', 'setPointerCapture', 'data-dragging']) {
  assert(publicRendererSource.includes(marker), `Kategori slider davranis marker eksik: ${marker}`);
}
for (const marker of ['bindActiveStatsCounters', 'IntersectionObserver', 'data-count-up', 'data-count-target', 'duration = 2400', 'data-counted']) {
  assert(publicRendererSource.includes(marker), `Aktif arsiv sayac animasyon marker eksik: ${marker}`);
}
for (const marker of ['bindShrinkingHeader', 'data-pa-scrolled', 'bindPublicAuthTabs', 'data-auth-tab']) {
  assert(publicRendererSource.includes(marker), `Public sticky header/auth JS marker eksik: ${marker}`);
}
for (const marker of ['loadPublicUserQuestions', 'publicSubmissionCardHtml', 'data-account-notice-dot', 'data-mark-question-seen', 'window.__publicArchiveSession']) {
  assert(publicRendererSource.includes(marker), `Public kullanici soru takip JS marker eksik: ${marker}`);
}
for (const marker of ['data-pa-theme-boot', 'data-theme="dark"', 'freezeRouteBackground', 'style="background-color:#0D1412;color-scheme:dark"']) {
  assert(publicRendererSource.includes(marker), `Public sayfa gecisi tema/zemin marker eksik: ${marker}`);
}
for (const marker of ['.pa-concept-track', 'overflow: hidden;', 'touch-action: pan-y;', 'mask-image: linear-gradient', '.pa-concept-rail', 'will-change: transform;', '.pa-concept-pill']) {
  assert(publicCss.includes(marker), `Kategori slider CSS marker eksik: ${marker}`);
}
for (const marker of ['.pa-alpha-index', '.pa-alpha-shell', '.pa-alpha-nav', '.pa-alpha-track', 'scroll-snap-type: x proximity', 'scroll-behavior: smooth', 'mask-image: linear-gradient', '.pa-alpha-letter', '.pa-letter-search', '.pa-letter-categories', '.pa-index-category']) {
  assert(publicCss.includes(marker), `Arsiv alfabetik kategori dizini CSS marker eksik: ${marker}`);
}
for (const marker of ['ARCHIVE_LETTER_ALIASES', 'normalizeArchiveLetter', 'bindArchiveAlphaIndexes', 'data-alpha-scroll']) {
  assert(publicRendererSource.includes(marker), `Arsiv alfabetik kategori dizini JS marker eksik: ${marker}`);
}
for (const marker of ['.pa-archive-hero .pa-collection-meta span', 'border-radius: 11px', 'border-radius: 12px', 'border-radius: 14px']) {
  assert(publicCss.includes(marker), `Arsiv alfabetik kategori dizini koseli stil marker eksik: ${marker}`);
}
for (const marker of ['.pa-card-bottom', '.pa-card-cta', '.pa-card-cta::after', '@keyframes pa-cta-shine', '.pa-question-card:hover .pa-card-cta', '.pa-cta-icon']) {
  assert(publicCss.includes(marker), `Public soru karti CTA CSS marker eksik: ${marker}`);
}
assert(!publicCss.includes('.pa-question-card.has-strong-cta .pa-card-cta'), 'Public soru karti CTA stili yalniz featured kartlara bagli olmamali.');
const cardMetaCss = publicCss.match(/\.pa-card-meta\s*\{([\s\S]*?)\}/)?.[1] || '';
const chipWrapCss = publicCss.match(/\.pa-chip-wrap\s*\{([\s\S]*?)\}/)?.[1] || '';
for (const [name, source] of [['pa-card-meta', cardMetaCss], ['pa-chip-wrap', chipWrapCss]]) {
  assert(source.includes('flex-wrap: nowrap'), `${name} tek satir yatay etiket rail olmali.`);
  assert(source.includes('overflow-x: auto'), `${name} yatay kaydirilabilir olmali.`);
  assert(source.includes('scroll-snap-type: x proximity'), `${name} scroll snap davranisi olmali.`);
  assert(source.includes('overscroll-behavior-inline: contain'), `${name} yatay tasma davranisi izole olmali.`);
  assert(!source.includes('flex-wrap: wrap'), `${name} etiketleri iki satira dusurmemeli.`);
}
assert(publicCss.includes('white-space: nowrap;') && publicCss.includes('.pa-card-meta::-webkit-scrollbar'), 'Public etiket chipleri tek satir ve gizli scrollbar olmali.');
for (const marker of ['.pa-mobile-nav::before', '.pa-mobile-nav::after', '-webkit-backdrop-filter: blur(34px) saturate(1.72)', 'inset 0 1px 0', '.pa-bottom-link.is-active', '.pa-bottom-link.is-pending', 'data-pa-navigating="true"', '@keyframes pa-fast-nav-progress', '.pa-scroll-top', '.pa-scroll-top[data-visible="true"]', '.pa-scroll-top-icon']) {
  assert(publicCss.includes(marker), `Public Apple glass nav/scroll CSS marker eksik: ${marker}`);
}
for (const marker of ['--pa-safe-top: env(safe-area-inset-top, 0px)', '--pa-header-total-height', '--pa-header-compact-total-height', 'padding-top: var(--pa-safe-top)', 'scroll-padding-top: calc(var(--pa-header-total-height) + 18px)']) {
  assert(publicCss.includes(marker), `Public iOS safe-area header CSS marker eksik: ${marker}`);
}
const scrollTopIconCss = publicCss.match(/\.pa-scroll-top-icon\s*\{([\s\S]*?)\}/)?.[1] || '';
assert(!scrollTopIconCss.includes('rotate('), 'Yukari cik ikonu CSS ile dondurulmemeli.');
for (const marker of ['.pa-account-notice-dot', '.pa-account-questions', '.pa-ask-questions', '.pa-user-question-card', '.pa-new-answer-badge', '.pa-user-answer']) {
  assert(publicCss.includes(marker), `Public hesap soru takip CSS marker eksik: ${marker}`);
}
for (const marker of ['position: fixed;', 'var(--pa-header-height)', 'scroll-padding-top', ':root[data-pa-scrolled="true"] .pa-header', '.pa-auth-shell', '.pa-auth-panel', '.pa-google-button', '.pa-auth-tabs', '.pa-auth-form']) {
  assert(publicCss.includes(marker), `Public sticky header/e-posta auth CSS marker eksik: ${marker}`);
}
for (const marker of ['.pa-logo-mark', 'width: 42px', 'height: 42px', '.pa-logo-text', ':root[data-theme="dark"] .pa-logo-mark', ':root[data-pa-scrolled="true"] .pa-logo-mark', 'width: 32px']) {
  assert(publicCss.includes(marker), `Public logo mark CSS marker eksik: ${marker}`);
}
for (const marker of ['.pa-active-stats', '.pa-active-stats-grid', '.pa-active-stat strong', '.pa-live-dot', '@keyframes pa-live-pulse', '@keyframes pa-live-blink']) {
  assert(publicCss.includes(marker), `Public aktif arsiv sayaci CSS marker eksik: ${marker}`);
}
assert(!publicCss.includes('.pa-active-stats-link'), 'Public aktif arsiv sayacinda eski CTA CSS geri gelmemeli.');
const topicPreview = renderPublicArchivePreviewRoute('/public-preview/konu/kalbin-yonelisi').html;
const categoryPreview = renderPublicArchivePreviewRoute('/public-preview/kategori/allaha-ulasmayi-dilemek').html;
assert(topicPreview.includes('Kategori') && !topicPreview.includes('Kavram'), 'Eski konu route u publicte kategori diliyle sunulmali.');
assert(categoryPreview.includes('Kategori') && categoryPreview.includes('Bu Kategorideki Sorular'), 'Kategori sayfasi etiket omurgasiyla calismali.');
const askPreview = renderPublicArchivePreviewRoute('/public-preview/soru-sor').html;
assert(askPreview.includes('data-question-form') && !askPreview.includes('data-static-question-form'), 'Soru Sor gercek public talep formu olarak isaretlenmeli.');
assert(askPreview.includes('/public-preview/api/question-submissions'), 'Soru Sor public preview submission endpoint ine baglanmali.');
assert(askPreview.includes('/public-preview/hesabim'), 'Soru Sor hesap girisine baglanmali.');
assert(askPreview.includes('Sorunuzu kısa ve açık şekilde yazabilirsiniz.'), 'Soru Sor public mikrocopy eksik.');
assert(askPreview.includes('Tek soruya odaklanın') && askPreview.includes('Mahrem bilgi yazmayın'), 'Soru Sor rehber metinleri eksik.');
assert(!askPreview.includes('Kategori seçin') && !askPreview.includes('İsteğe bağlı kategori') && !askPreview.includes('İsteğe bağlı konu'), 'Soru Sor kullaniciya kategori/kavram sectirmemeli.');
assert(!askPreview.includes('Bu ekranda kayıt alınmıyor') && !askPreview.includes('yalnızca arayüz davranışı gösteriliyor') && !askPreview.includes('Bu ekranda kayıt alınmaz'), 'Soru Sor teknik preview dili gostermemeli.');
assert(askPreview.includes('Sorular Dr. Abdulcabbar Boran tarafından yanıtlanır.'), 'Soru Sor author context eksik.');
const howToPreview = renderPublicArchivePreviewRoute('/public-preview/nasil-kullanilir').html;
assert(howToPreview.includes('Nasıl Kullanılır') && howToPreview.includes('Arayın') && howToPreview.includes('Cevabı okuyun'), 'Nasıl Kullanılır bilgilendirme sayfasi eksik.');
const aboutPreview = renderPublicArchivePreviewRoute('/public-preview/hakkimizda').html;
const contactPreview = renderPublicArchivePreviewRoute('/public-preview/iletisim').html;
const privacyPreview = renderPublicArchivePreviewRoute('/public-preview/gizlilik').html;
const termsPreview = renderPublicArchivePreviewRoute('/public-preview/kullanim-kosullari').html;
assert(aboutPreview.includes('delilleri ve kaynak bağlamıyla') && aboutPreview.includes('Arşivi İncele'), 'Hakkımızda sayfasi kendi amacina uygun aciklayici metin tasimali.');
assert(howToPreview.includes('Arama Yap') && howToPreview.includes('alfabetik olarak inceleyebilir'), 'Nasıl Kullanılır sayfasi arama/arsiv kullanimini aciklamali.');
assert(contactPreview.includes('Düzeltme notu') && contactPreview.includes('Gizliliği Oku'), 'İletişim sayfasi duzeltme ve soru talebi ayrimini aciklamali.');
assert(privacyPreview.includes('Üçüncü kişiler') && privacyPreview.includes('Soru Sorarken Dikkat Edin'), 'Gizlilik sayfasi mahremiyet odakli olmali.');
assert(termsPreview.includes('Okuma ve paylaşım') && termsPreview.includes('Arşivi Aç'), 'Kullanım Koşulları sayfasi kullanim ilkelerini aciklamali.');
const notFoundPreview = renderPublicArchivePreviewRoute('/public-preview/soru/gizli-icerik');
assert(notFoundPreview.status === 404 && notFoundPreview.html.includes('Sayfa bulunamadı.'), 'Gizli veya eksik public icerik 404 state dondurmeli.');

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
