require('dotenv').config();
const express  = require('express');
const cookieSession = require('cookie-session');
const bcrypt   = require('bcryptjs');
const multer   = require('multer');
const path     = require('path');
const crypto   = require('crypto');
const mammoth  = require('mammoth');
const XLSX     = require('xlsx');
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
const tagImportUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 16 * 1024 * 1024 } });

const OPENAI_API_KEY    = process.env.OPENAI_API_KEY;
const SESSION_SECRET    = process.env.SESSION_SECRET || 'arsiv-gizli-v3-2025';
const SUPABASE_URL      = process.env.SUPABASE_URL;
const SUPABASE_KEY      = process.env.SUPABASE_KEY;
const PROMPT_VERSION    = '2026-06-30.4';
const AI_REPORT_MODEL   = 'gpt-4o-mini';
const MIN_ANALYSIS_TEXT_CHARS = 10;
const MAX_ANALYSIS_TEXT_CHARS = 200000;
const OPENAI_CHAT_URL = 'https://api.openai.com/v1/chat/completions';
const OPENAI_TIMEOUT_MS = Number(process.env.OPENAI_TIMEOUT_MS || 70000);
const OPENAI_RETRY_DELAYS_MS = [800, 1800];
const OPENAI_RETRYABLE_STATUS = new Set([408, 409, 429, 500, 502, 503, 504]);
const ADMIN_PARALLEL_ROUTE_ENABLED = process.env.ADMIN_PARALLEL_ROUTE_ENABLED !== '0';
const AI_TEMPORARY_UNAVAILABLE_MSG = 'AI servisi geçici olarak yanıt veremedi. Lütfen birkaç dakika sonra tekrar deneyin. Metniniz ekranda korunuyor; tekrar Denetle & Düzelt düğmesine basabilirsiniz.';
const AI_CONFIG_ERROR_MSG = 'AI bağlantısı şu anda yapılandırma nedeniyle çalışmıyor. Lütfen ekibe bildirin.';
const AI_REQUEST_REJECTED_MSG = 'AI isteği işlenemedi. Lütfen metni kısaltarak tekrar deneyin veya ekipten destek isteyin.';

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

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function httpError(message, statusCode, cause) {
  const err = new Error(message);
  err.statusCode = statusCode;
  if (cause) err.cause = cause;
  return err;
}

async function safeJson(response) {
  try { return await response.json(); }
  catch { return {}; }
}

function openaiUserMessage(status) {
  if (status === 401 || status === 403) return AI_CONFIG_ERROR_MSG;
  if (status === 400 || status === 413) return AI_REQUEST_REJECTED_MSG;
  if (OPENAI_RETRYABLE_STATUS.has(status)) return AI_TEMPORARY_UNAVAILABLE_MSG;
  return 'AI servisi şu anda beklenmeyen bir yanıt verdi. Lütfen tekrar deneyin; devam ederse ekibe bildirin.';
}

async function fetchOpenAIChatCompletion(payload, contextLabel = 'AI isteği') {
  let lastStatus = 503;
  let lastMessage = '';
  for (let attempt = 0; attempt <= OPENAI_RETRY_DELAYS_MS.length; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), OPENAI_TIMEOUT_MS);
    try {
      const response = await fetch(OPENAI_CHAT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (response.ok) {
        const data = await safeJson(response);
        if (!data?.choices?.length) throw httpError('AI servisi eksik yanıt döndürdü. Lütfen tekrar deneyin.', 502);
        return data;
      }

      const upstream = await safeJson(response);
      lastStatus = response.status;
      lastMessage = upstream.error?.message || response.statusText || '';
      const retryable = OPENAI_RETRYABLE_STATUS.has(response.status);
      if (!retryable || attempt === OPENAI_RETRY_DELAYS_MS.length) {
        console.warn(`[OpenAI] ${contextLabel} başarısız: status=${response.status} message=${lastMessage}`);
        throw httpError(openaiUserMessage(response.status), retryable ? 503 : response.status);
      }
    } catch (err) {
      clearTimeout(timeout);
      if (err.statusCode) throw err;
      lastMessage = err.name === 'AbortError' ? 'timeout' : (err.message || 'network');
      if (attempt === OPENAI_RETRY_DELAYS_MS.length) {
        const status = err.name === 'AbortError' ? 504 : lastStatus;
        console.warn(`[OpenAI] ${contextLabel} bağlantı hatası: ${lastMessage}`);
        throw httpError(AI_TEMPORARY_UNAVAILABLE_MSG, status, err);
      }
    }
    await sleep(OPENAI_RETRY_DELAYS_MS[attempt]);
  }
  throw httpError(AI_TEMPORARY_UNAVAILABLE_MSG, 503);
}

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);
app.use(cookieSession({
  name: 'arsiv_session',
  keys: [SESSION_SECRET],
  maxAge: 30 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  secure: Boolean(process.env.VERCEL || process.env.NODE_ENV === 'production')
}));
app.use('/icons', express.static(path.join(__dirname, 'icons')));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'icons', 'favicon.ico')));
app.get('/manifest.webmanifest', (req, res) => res.sendFile(path.join(__dirname, 'manifest.webmanifest')));
app.get('/sw.js', (req, res) => res.sendFile(path.join(__dirname, 'sw.js')));

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
dinde (dînde değil)
vücut (vücud/vücût değil)
şerr (şer değil)
derecat (derecât değil)
afet (âfet değil)
beka (bekâ değil)
Mehdi (mehdî değil)
arif (ârif değil)
cahiliye (câhiliye değil)
tâbî (bağlı/uyan anlamındaysa; "Tabiî ki" ifadesi değildir)
ni'met
fazl’ıl azîm
keyfe mâ yeşâ
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
dîn → din (özel kaynak/kitap adı içinde, örn. İhyâ’u Ulûmi’d-dîn, özgün yazım korunur)
her şey → herşey
MULK-8 âyetindeki "herbir grup" yazımı birleşik korunur; "her bir grup" yapma
Ayet → âyet (sure/kitap adı veya özel başlık içinde değilse)
Ayet-i kerime → âyet-i kerime
Kuran → Kur'ân
Kur'an / Kur’an → Kur'ân
Mumin → mü'min (Muminun/Mu'minûn/Mü'minûn Suresi içinde değilse)
Tabi → tâbî (Tabiî ki/Tabii ki ifadesi değilse)
Iman → îmân (özel isim veya başlık içinde değilse)
Nefis → nefs
nefisleri / nefisleriyle → nefsleri / nefsleriyle (âyet/kaynak metninde "nefislerinin" geçiyorsa bunu "nefslerinin" yapma)
hidâyet → hidayet
Efendimizin → Efendimiz'in
Nimet → ni'met
Sahabe → sahâbe
İnşallah → inşaallah
Sallallahu aleyhi vesellem → (S.A.V)
hadis → hadîs
Hadis-i Şerif / HADİS-İ ŞERİF → Hadîs-i Şerif / HADÎS-İ ŞERİF (Şerif kelimesindeki i şapkasızdır)
hadîsi / hadîsin / hadîste gibi ekli kullanımları köke kırpma; "hadîsi" kelimesini "hadîs" yapma
fedakarlık → fedakârlık
Şura suresinin → Şûrâ Suresinin
Âli İmrân doğru yazımdır; "Âlî", "Âl-i" veya "Ali-İmran" yapma.
Câsiye, Yûnus, Hûd, Fâtır, Hacc ve A'râf sure adlarında şapka/apostrof standardını uygula; Felak kelimesine şapka ekleme.
derecat ve afet ailelerinde "a" harfini şapkalama; derecata/derecatı ve AFETİ/afetleri şapkasız kalır.
şer kelimesi arşiv standardında şerr olarak düzeltilir; şerr kelimesindeki çift r korunur. Bu standart yalnız bağımsız şer kelimesi içindir; ŞERİF, şeriat ve şerh gibi kelimelerin içine girmez.
MUSİBET/musibet yazımı musîbet/MUSÎBET olarak düzeltilir; VELI başlığı VELÎ olur; zahit yazımı zahid olmalıdır.
(S.AV.) veya (S.A.V.) gibi bozuk kısaltmaları (S.A.V) standardına getir.
Sayı alternatifi içeren ifadeleri anlam ekleyerek değiştirme; örnek: "6 tane, 7 tane âyet-i kerime var." cümlesi aynen korunur, "6 tane âyet-i kerime âyet-i kerime var" yapılmaz.
Radıyallahu anh → (R.A)
Aleyhisselam → (A.S)
ulül elbab / ululelbab / ulul elbab → ulûl'elbab
tilavet → tilâvet
huşu → huşû
daimi → daimî
taktir de / takdirde → taktirde (arşiv kullanımında bitişik kabul edilir)
Resûlallah → Resûlullah

KORUNACAK BAĞLAMLAR:
- Kaynakta şapkalı doğru yazılmış kelimeleri şapkasızlaştırma: manevî, itikâf, daimî, âyet, Allahû Tealâ.
- "dîn" ailesi güncel karar gereği istisnadır; dîn/dînin/dîni yerine din/dinin/dini kullanılır.
- Âyet okunuşu/transliterasyon içinde geçen "dînâ/dînen" gibi kelimeleri Türkçe din standardına çevirme; âyet metni korunur.
- "vücut" doğru yazımdır; "vücud" veya "vücût" görürsen "vücut" olarak düzelt. "şerr", "arif", "cahiliye" ve "dinde" yazımlarını ters yönde şapkalı veya sadeleştirilmiş biçime çevirme.
- "beka" ve "Mehdi" arşiv standardıdır; bunları "bekâ" veya "mehdî" yapma.
- "ilim" kelimesini bağlam ekleyerek "Kur'ân ilmi" yapma; kaynakta yalnız "ilim" varsa yalnız "ilim" kalır.
- "münezzehtir" ifadesini "Sûbhân'dır/Sübhan'dır" diye değiştirme; anlam açıklaması ekleme.
- "lânetle lânetle" gibi âyet/alıntı tekrarlarını yazım tekrarı sanıp tek kelimeye düşürme.
- "Allah ile bile olursanız" ifadesindeki "bile" kelimesini silme.
- "herşey" ailesi birleşik kalır: herşey, herşeye, herşeydir gibi ekli biçimleri "her şey..." diye ayırma.
- "birşey" ile "herşey" anlamca farklıdır; birini diğerine dönüştürme.
- "bir şey" ifadesi ayrı yazılır; bunu "birşey" yapma. Özel karar yalnızca "her şey" → "herşey" içindir.
- "surette" doğru yazımdır; özellikle "mutlak surette" ifadesini "sürette" veya "sûrette" yapma.
- "suretiyle" ayrı ve doğru bir kullanımdır; bunu "surette" yapma.
- "keyfe meaşadır / keyfe meşadır" görülürse doğru standart "keyfe mâ yeşâdır" olmalıdır.
- "Allah arasındadır" ifadesinde Allah kelimesine kesme eki ekleme; "Allah'a arasındadır" yanlıştır.
- "kaadirdir" ve "halifesi" yazımlarını "kâdirdir/halîfesi" yapma.
- "takva" doğru yazımdır; bunu "takvâ" yapma.
- "afet" kelimesini anlamca ilgisiz şekilde "ni'met" yapma.
- "Allah'ın Zat'ında ifna olur" ifadesini "fena bulur" diye değiştirme; bağlamdaki ifade korunur.
- "mürşide" ve "mürşide tâbiiyet" ifadelerini "mürşidin/mürşidin tâbiiyet" yapma; hâl eki anlamı korunur.
- Kaynaklarda sayfa referansı "s 120" gibi yazılmışsa standart "s.120" biçimidir; "s. 120" araya boşluklu biçimi kullanma.
- Sure adında eksik harf varsa düzelt ama yalnız bunun için kelimeyi zorunlu tamamen büyük harfe çevirme: "Hac" metin akışında "Hacc" olur, "HAC" başlık/listede "HACC" olur.
- Kaynakta zaten "o taktirde" varsa "taktirde" bulgusunu "o taktirde" yaparak "o o taktirde" üretme.
- Arapça âyet okunuşu/transliterasyon satırlarını Türkçe sözlük standardına çevirme; "sırâtekel mustekîm(mustekîme)" gibi ifadeler aynen korunur.
- Türkçe anlatıdaki "Sıratı Mustakîm" standardı korunur; bu standart Arapça okunuş/transliterasyon içindeki mustekîm/mustekîme ifadelerine uygulanmaz.
- "Hristiyan/Hristiyanlar" doğru yazımdır; bu kelimeleri "Hıristiyan/Hıristiyanlar" yapma.
- "salih/salihler/salihlerle" yazımlarını otomatik "sâlih/sâlihler/sâlihlerle" yapma.
- Numaralı nimet listelerinde "1. nimet, 2. nimet, 3. nimet" biçimini kullan; bu bağlamda "nimet" kelimesini "ni'met" yapma. Eksik nokta varsa yalnızca numarayı düzelt: "3 nimet" → "3. nimet".
- "şekli şemali/şekli şemalinize" gibi ifadelerde "şekli" ekini düşürme; "şekil şemalinize" yapma.
- "(S.A.V:" gibi kapanmamış parantezleri gerçek noktalama hatası say; parantezi kapatıp "(S.A.V):" olarak düzelt. S.A.V kısaltmasının harflerini veya nokta yapısını bozma.
- "tavsiye" kelimesini "tâbî" veya başka bir kelimeye dönüştürme.
- "hayy" kökünden gelen ifadeleri "hayat/hayatta" diye sadeleştirme; hayydırlar gibi kullanımları koru.
- "hayydırlar" gibi ifadeleri "diridirler" diye Türkçe açıklamaya çevirme.
- "Allah (cc.)" ifadesini "Allah (A.S)" yapma.
- "ahlaki" sıfatını "ahlakı" diye değiştirme.
- "ardarda" ve "aciz" kullanımları bu bağlamlarda korunur; otomatik "ard arda" veya "âciz" yapma.
- "Sebîlel gayy" ve "Sebîlel rüşd" ifadelerini "Sebîli gayy" / "Sebîli rüşd" yapma.
- "Tabi ki" / "Tabii ki" ifadesini "Tabiatıyla" diye değiştirme.
- "Hidayet" kelimesine kaynakta olmayan ek ekleme; "hidayet" kelimesini "hidayete" gibi genişletme. Kaynakta "hidayete/hidayeti/hidayetten" gibi ekli kullanım varsa eki düşürme.
- Metnin başındaki veya cümle içindeki "ve, veya, ama, fakat, çünkü" gibi bağlaçları imlâ gerekçesiyle silme.
- "nefsi", "nefsin" ve "Nefs-i Mutmainne/Mülhime/Levvame/Emmare" kullanımlarını eklerinden koparma.
- "A.S" ve "S.A.V" kısaltmalarını bağlamdan emin olmadan birbirine çevirme.
- Kur'ân-ı Kerim, Kur'ân-ı, kelâm-ı, Resûl'ü gibi tamlayan/ekli ifadelerde ek veya ikinci kelime silinmez.
- "Kur'ân-ı Kerîm" tamlamasını "Kur'ân" diye kısaltma; "-ı Kerîm" kısmı kaynakta varsa aynen korunur.

════════════════════════════════════════
KURAL 3 — PEYGAMBER VE NEBİ İSİMLERİ
════════════════════════════════════════
- Peygamber Efendimiz, Allah Resûlü, Hz. Muhammed → mutlaka (S.A.V) ekle
- Bu ifadeden hemen sonra (S.A.V) zaten varsa ikinci kez ekleme.
- Sallallahu aleyhi vesellem gibi uzun yazılmışsa → (S.A.V) olarak kısalt
- Resûlullah'tan sonra (S.A.V) yazılabilir veya yazılmayabilir
- Muhterem Efendimiz, Hocamız, Efendimiz ifadesi Peygamber Efendimiz'i açıkça kastetmiyorsa
  (S.A.V) ekleme.
- Tüm nebî isimlerinde mutlaka (A.S) ekle: Musa (A.S), Nuh (A.S), İsa (A.S)
- "Hazreti İsa" ifadesi her zaman "Hazreti İsa (A.S)" olmalıdır.
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
  questionText: h.question_text || '',
  status: h.status, approvedBy: h.approved_by, approvedAt: h.approved_at,
  tags: Array.isArray(h.tags) ? h.tags : [],
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

function historyStatusLabel(status) {
  return status === 'taslak' ? 'Taslak'
    : status === 'onaylandi' ? 'Onaylandı'
    : status === 'reddedildi' ? 'Reddedildi'
    : 'Bekliyor';
}

function historyStatusForApproval(status) {
  return !status || status === 'bekliyor';
}

const CHUNK_DRAFT_STATUS = 'chunk_draft';
const SUBMITTED_PART_STATUS = 'submitted_part';
const SUBMITTED_CORRECTED_HASH_PREFIX = 'submitted_corrected_hash:';
const HIDDEN_HISTORY_STATUSES = [CHUNK_DRAFT_STATUS, SUBMITTED_PART_STATUS];
const ADMIN_HIDDEN_HISTORY_STATUSES = ['taslak', ...HIDDEN_HISTORY_STATUSES];
const TAG_IMPORT_HISTORY_TEXT_LIMIT = 18000;
const TAG_IMPORT_INITIAL_DETAIL_LIMIT = 120;
const TAG_IMPORT_INSERT_CHUNK_SIZE = 180;
const TAG_IMPORT_APPLY_CHUNK_SIZE = 60;
const TAG_IMPORT_UPLOAD_KEY_PREFIX = 'history_tag_import_upload';
const TAG_IMPORT_MAX_UPLOAD_SIZE = 32 * 1024 * 1024;
const TAG_IMPORT_MAX_UPLOAD_CHUNKS = 160;
const TAG_IMPORT_MAX_CHUNK_BASE64_LENGTH = 900000;

function isChunkFilename(filename = '') {
  return /\s-\sParça\s+\d+\/\d+$/u.test(String(filename || '').trim());
}

function isChunkHistoryRow(row = {}) {
  return row.status === CHUNK_DRAFT_STATUS || isChunkFilename(row.filename);
}

function isHiddenHistoryForRole(row = {}, role = ROLES.USER) {
  const status = row.status || 'bekliyor';
  if (isChunkHistoryRow(row)) return true;
  if (HIDDEN_HISTORY_STATUSES.includes(status)) return true;
  return isAdminRole(role) && status === 'taslak';
}

async function fetchAllPages(makeQuery, pageSize = 1000) {
  const rows = [];
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await makeQuery().range(from, from + pageSize - 1);
    if (error) throw new Error(error.message);
    const page = data || [];
    rows.push(...page);
    if (page.length < pageSize) break;
  }
  return rows;
}

async function loadApprovalGroup(filterQuery) {
  const { data, error, count } = await filterQuery(
    supabase.from('history')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .limit(80)
  );
  if (error) throw new Error(error.message);
  return {
    count: count || 0,
    items: (data || []).map(mapHistory)
  };
}
const USER_NOTICE_TYPES = ['announcement', 'feedback_resolution'];
const RESOLUTION_RESPONSE_KEY = 'resolution_feedback_responses';
const CORRECTION_PACKAGE_SETTING_KEY = 'content_correction_packages';
const ARCHIVE_OPS_SOURCES_KEY = 'archive_ops_sources';
const ARCHIVE_OPS_WORK_ITEMS_KEY = 'archive_ops_work_items';
const ARCHIVE_OPS_PUBLISH_TASKS_KEY = 'archive_ops_publish_tasks';
const ARCHIVE_OPS_RELEASE_PACKAGES_KEY = 'archive_ops_release_packages';
const ARCHIVE_SOURCE_TEXT_LIMIT = 200000;
const ARCHIVE_SOURCE_LIST_LIMIT = 300;
const ARCHIVE_SOURCE_TYPES = ['transkript', 'hadis', 'slayt', 'dokuman', 'standart', 'not'];
const ARCHIVE_PUBLIC_CANDIDATE_STATUSES = ['arsiv_adayi', 'yayina_hazir', 'kaynak_eksik', 'revizyon_gerekli', 'beklet'];
const ARCHIVE_SOURCE_STATUSES = ['kaynak', 'hazirlaniyor', 'kontrol', ...ARCHIVE_PUBLIC_CANDIDATE_STATUSES];
const ARCHIVE_WORK_ITEM_LIMIT = 300;
const ARCHIVE_WORK_STATUSES = ['taslak', 'hazirlaniyor', 'kontrol', 'onay_bekliyor', ...ARCHIVE_PUBLIC_CANDIDATE_STATUSES, 'tamamlandi'];
const ARCHIVE_WORK_PRIORITIES = ['normal', 'onemli', 'kritik'];
const ARCHIVE_PUBLISH_TASK_LIMIT = 300;
const ARCHIVE_PUBLISH_STATUSES = ['planlandi', 'hazirlaniyor', 'kontrol', 'kaynak_bekliyor', ...ARCHIVE_PUBLIC_CANDIDATE_STATUSES, 'tamamlandi', 'iptal'];
const ARCHIVE_PUBLISH_PRIORITIES = ['normal', 'onemli', 'kritik'];
const ARCHIVE_RELEASE_PACKAGE_LIMIT = 80;
const ARCHIVE_RELEASE_PACKAGE_ITEM_LIMIT = 200;
const ARCHIVE_RELEASE_PACKAGE_STATUSES = ['taslak', 'son_kontrol', 'hazir', 'beklet'];
const ARCHIVE_RELEASE_PACKAGE_ITEM_REVIEW_STATUSES = ['bekliyor', 'kontrol_edildi', 'revizyon', 'beklet'];
const ARCHIVE_RELEASE_PUBLICATION_STATUSES = ['bekliyor', 'yayinda', 'arsive_aktarildi', 'geri_alindi'];
const ARCHIVE_PUBLIC_RECORD_SCHEMA_VERSION = 'public_archive_records_v1';
const ARCHIVE_IMPORT_BATCH_LIMIT = 60;
const ARCHIVE_IMPORT_ITEM_LIMIT = 500;
const ARCHIVE_IMPORT_BATCH_STATUSES = ['open', 'review', 'completed', 'archived'];
const ARCHIVE_IMPORT_ITEM_STATUSES = ['extracted', 'review', 'form', 'source_created', 'skipped', 'error'];
const ARCHIVE_SOURCE_DB_LIST_COLUMNS = [
  'id',
  'title',
  'source_type',
  'status',
  'category',
  'source_date',
  'source_url',
  'tags',
  'note',
  'text_preview',
  'text_length',
  'source_text_hash',
  'title_key',
  'source_url_key',
  'created_at',
  'updated_at',
  'created_by',
  'updated_by',
  'conflict_accepted_at',
  'conflict_accepted_by',
  'conflict_accepted_conflicts'
].join(',');
const ARCHIVE_SOURCE_DB_FULL_COLUMNS = `${ARCHIVE_SOURCE_DB_LIST_COLUMNS},source_text`;
const ARCHIVE_IMPORT_BATCH_DB_COLUMNS = [
  'id',
  'title',
  'status',
  'note',
  'created_by',
  'updated_by',
  'created_at',
  'updated_at'
].join(',');
const ARCHIVE_IMPORT_ITEM_DB_LIST_COLUMNS = [
  'id',
  'batch_id',
  'file_name',
  'file_extension',
  'file_size',
  'source_type',
  'status',
  'title',
  'category',
  'tags',
  'note',
  'text_preview',
  'text_length',
  'text_hash',
  'source_id',
  'error_message',
  'created_by',
  'updated_by',
  'created_at',
  'updated_at'
].join(',');
const ARCHIVE_IMPORT_ITEM_DB_FULL_COLUMNS = `${ARCHIVE_IMPORT_ITEM_DB_LIST_COLUMNS},extracted_text`;
const ARCHIVE_WORK_ITEM_DB_LIST_COLUMNS = [
  'id',
  'title',
  'status',
  'priority',
  'assigned_to',
  'due_date',
  'source_id',
  'source_title',
  'category',
  'topics',
  'text_preview',
  'text_length',
  'created_by',
  'updated_by',
  'created_at',
  'updated_at'
].join(',');
const ARCHIVE_WORK_ITEM_DB_FULL_COLUMNS = `${ARCHIVE_WORK_ITEM_DB_LIST_COLUMNS},question,answer_draft,note`;
const ARCHIVE_PUBLISH_TASK_DB_LIST_COLUMNS = [
  'id',
  'title',
  'status',
  'priority',
  'assigned_to',
  'due_date',
  'publish_date',
  'publication_url',
  'platform',
  'source_id',
  'source_title',
  'work_item_id',
  'work_item_title',
  'category',
  'topics',
  'text_preview',
  'text_length',
  'created_by',
  'updated_by',
  'created_at',
  'updated_at'
].join(',');
const ARCHIVE_PUBLISH_TASK_DB_FULL_COLUMNS = `${ARCHIVE_PUBLISH_TASK_DB_LIST_COLUMNS},description,note`;
const CORRECTION_DEFAULT_FIELDS = ['corrected_text'];
const CORRECTION_ALLOWED_FIELDS = ['corrected_text', 'summary'];
const CORRECTION_DEFAULT_STATUSES = ['taslak', 'bekliyor', 'onaylandi'];
const CORRECTION_ALLOWED_STATUSES = ['taslak', 'bekliyor', 'onaylandi', 'reddedildi'];
const CORRECTION_ALLOWED_SCOPES = ['reported', 'all'];
const CORRECTION_SCAN_TARGET_LIMIT = 500;
const USER_LAST_SEEN_LEGACY_KEY = 'user_last_seen';
const USER_LAST_SEEN_KEY_PREFIX = 'user_last_seen:';
const DEFAULT_STANDARDS = [
  {
    id: 'imla-din-hersey-2026-07',
    title: 'Din ve herşey yazımı',
    category: 'İmlâ Standardı',
    content: 'Efendimizin sözlüğünde dîn yerine din yazımı esas alınır. Ayrıca her şey ifadesi arşiv standardında birleşik olarak herşey şeklinde kabul edilir.',
    createdAt: '2026-07-01T00:00:00.000Z'
  },
  {
    id: 'sure-adlari-mihr-2026-07',
    title: 'Sure isimleri standardı',
    category: 'Sure Adları',
    content: 'Sure isimleri mihr.com imlâ standardına göre değerlendirilir. Büyük/küçük harf farkı tek başına hata sayılmaz; asıl kontrol şapka, apostrof ve harf dizilimidir.',
    createdAt: '2026-07-02T00:00:00.000Z'
  },
  {
    id: 'duzen-koruma-2026-07',
    title: 'Metin düzeni koruma standardı',
    category: 'Düzen',
    content: 'Slayt, tablo, numaralı liste, hadîs dökümü ve paragraf yapısı korunur. Sistem yalnızca gerekli imlâ ve noktalama düzeltmelerini yapmalı; metin düzenini düz yazıya çevirmemelidir.',
    createdAt: '2026-07-07T00:00:00.000Z'
  }
];
const FEEDBACK_REASONS = Object.freeze({
  nonexistent: 'Metinde olmayan hata',
  wrong_fix: 'Yanlış düzeltme',
  missing_issue: 'Eksik hata',
  layout_broken: 'Düzen bozuldu',
  score_wrong: 'Skor yanlış',
  other: 'Diğer'
});

async function loadJsonSetting(key, fallback) {
  const { data, error } = await supabase.from('settings').select('value').eq('key', key).maybeSingle();
  if (error || !data?.value) return fallback;
  try { return JSON.parse(data.value); }
  catch { return fallback; }
}

async function saveJsonSetting(key, value) {
  const { error } = await supabase.from('settings').upsert({ key, value: JSON.stringify(value) });
  if (error) throw new Error(error.message);
}

async function deleteSettingsByKeys(keys = []) {
  const cleanKeys = [...new Set(keys.filter(Boolean))];
  for (let i = 0; i < cleanKeys.length; i += 100) {
    const { error } = await supabase.from('settings').delete().in('key', cleanKeys.slice(i, i + 100));
    if (error) throw new Error(error.message);
  }
}

function parseJsonSettingValue(value, fallback) {
  if (!value) return fallback;
  try { return JSON.parse(value); }
  catch { return fallback; }
}

function normalizeIsoDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function escapeRegExpServer(value = '') {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function correctionPackageId() {
  return `cp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function archiveSourceId() {
  return `src-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function archiveReleasePackageId() {
  return `rel-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeArchiveSourceType(value) {
  const type = String(value || '').trim();
  return ARCHIVE_SOURCE_TYPES.includes(type) ? type : 'dokuman';
}

function normalizeArchiveSourceTypes(value) {
  const raw = Array.isArray(value) ? value.join(',') : String(value || '');
  return [...new Set(raw.split(',').map(part => String(part || '').trim()).filter(type => ARCHIVE_SOURCE_TYPES.includes(type)))];
}

function normalizeArchiveSourceStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_SOURCE_STATUSES.includes(status) ? status : 'kaynak';
}

function archiveTextPreview(text = '', max = 260) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function normalizeArchiveTags(value) {
  const raw = Array.isArray(value) ? value.join(',') : String(value || '');
  return [...new Set(raw.split(',').map(item => item.trim()).filter(Boolean).slice(0, 20))]
    .map(item => item.slice(0, 48));
}

function normalizeHistoryTags(value) {
  const raw = Array.isArray(value) ? value.join(',') : String(value || '');
  const seen = new Set();
  const tags = [];
  raw.split(',').forEach(part => {
    const tag = String(part || '').replace(/\s+/g, ' ').trim();
    if (!tag) return;
    const key = tag.toLocaleLowerCase('tr-TR');
    if (seen.has(key)) return;
    seen.add(key);
    tags.push(tag.slice(0, 96));
  });
  return tags;
}

function normalizeHistoryQuestion(value) {
  return String(value || '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map(line => line.replace(/[ \t]+/g, ' ').trim())
    .filter(Boolean)
    .join('\n')
    .slice(0, 8000);
}

function requireApprovalQuestionAndTags(body = {}) {
  if (!HAS_HISTORY_QUESTION_TEXT || !HAS_HISTORY_TAGS) {
    const err = new Error('Soru ve etiket alanları aktif değil. Lütfen gerekli SQL güncellemesini uygulayın.');
    err.statusCode = 400;
    throw err;
  }
  const questionText = normalizeHistoryQuestion(body.questionText);
  const tags = normalizeHistoryTags(body.tags);
  if (!questionText) {
    const err = new Error('Onaya göndermeden önce soru alanını doldurun.');
    err.statusCode = 400;
    throw err;
  }
  if (!tags.length) {
    const err = new Error('Onaya göndermeden önce en az bir etiket ekleyin.');
    err.statusCode = 400;
    throw err;
  }
  return { questionText, tags };
}

function normalizeImportTags(value) {
  return normalizeHistoryTags(String(value || '').replace(/[;\n\r]+/g, ','));
}

const TAG_IMPORT_STOPWORDS = new Set([
  've', 'veya', 'ile', 'icin', 'için', 'bir', 'bu', 'su', 'şu', 'da', 'de', 'ki',
  'mi', 'mu', 'mı', 'mü', 'ne', 'nasil', 'nasıl', 'olan', 'olarak', 'vardir',
  'vardır', 'diyor', 'sevgili', 'kardeslerim', 'kardeşlerim', 'allah', 'allahu',
  'teala', 'tealâ', 'biz', 'siz', 'onlar', 'olanlar', 'ama', 'fakat', 'cunku',
  'çünkü', 'ise', 'icin', 'olarak', 'olur', 'oluyor', 'oldu'
]);

function normalizeTagImportText(value = '') {
  return normalizeText(value)
    .replace(/[’‘`´]/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
    .toLocaleLowerCase('tr-TR');
}

function tagImportTokens(value = '', limit = 120) {
  const tokens = normalizeTagImportText(value)
    .split(/[^0-9a-zA-ZığüşöçİĞÜŞÖÇâÂîÎûÛ']+/u)
    .map(token => token.replace(/^'+|'+$/g, '').trim())
    .filter(token => token.length >= 4 && !TAG_IMPORT_STOPWORDS.has(token));
  return [...new Set(tokens)].slice(0, limit);
}

function tagImportOverlapScore(aTokens = [], bTokens = []) {
  if (!aTokens.length || !bTokens.length) return 0;
  const a = new Set(aTokens);
  const b = new Set(bTokens);
  let hit = 0;
  a.forEach(token => { if (b.has(token)) hit++; });
  const smaller = Math.min(a.size, b.size) || 1;
  const larger = Math.max(a.size, b.size) || 1;
  return Math.min(1, (hit / smaller) * 0.72 + (hit / larger) * 0.28);
}

function tagImportHeaderKey(value = '') {
  return normalizeTagImportText(value)
    .replace(/ı/g, 'i')
    .replace(/ğ/g, 'g')
    .replace(/ü/g, 'u')
    .replace(/ş/g, 's')
    .replace(/ö/g, 'o')
    .replace(/ç/g, 'c')
    .replace(/[^a-z0-9]+/g, '');
}

function tagImportCellValue(row, aliases = []) {
  for (const [key, value] of Object.entries(row || {})) {
    if (aliases.includes(tagImportHeaderKey(key))) return value;
  }
  return '';
}

function parseHistoryTagImportWorkbook(buffer, fileName = '') {
  let workbook;
  try {
    workbook = XLSX.read(buffer, { type: 'buffer', cellDates: false, raw: false });
  } catch (error) {
    const err = new Error('Excel dosyasi okunamadi. Lutfen .xlsx, .csv veya .tsv dosyasi yukleyin.');
    err.statusCode = 400;
    throw err;
  }
  const sheetName = workbook.SheetNames?.[0];
  if (!sheetName) {
    const err = new Error('Dosyada okunabilir sayfa bulunamadi.');
    err.statusCode = 400;
    throw err;
  }
  const sheet = workbook.Sheets[sheetName];
  const rows = XLSX.utils.sheet_to_json(sheet, { defval: '', raw: false });
  const items = rows.map((row, index) => {
    const question = String(tagImportCellValue(row, ['soru']) || '').trim();
    const tagText = tagImportCellValue(row, ['etiketsinif', 'etiketsınıf', 'etiket', 'sinif', 'sınıf']);
    const answer = String(tagImportCellValue(row, ['cevap']) || '').trim();
    const sourceUrl = String(tagImportCellValue(row, ['yayinlink', 'yayınlink', 'link']) || '').trim();
    const program = String(tagImportCellValue(row, ['program']) || '').trim();
    const note = String(tagImportCellValue(row, ['notlar', 'not']) || '').trim();
    const tags = normalizeImportTags(tagText);
    const combined = `${question}\n${answer}`;
    return {
      rowNumber: index + 2,
      question,
      answer,
      answerPreview: archiveTextPreview(answer || question, 320),
      sourceUrl,
      program,
      note,
      tags,
      normalizedText: normalizeTagImportText(combined),
      questionTokens: tagImportTokens(question, 80),
      answerTokens: tagImportTokens(answer, 160),
      tokens: tagImportTokens(combined, 200)
    };
  });
  return {
    fileName,
    sheetName,
    totalRows: rows.length,
    usableRows: items.filter(item => item.tags.length && (item.question || item.answer)).length,
    items: items.filter(item => item.tags.length && (item.question || item.answer))
  };
}

function buildTagImportExcelIndex(items = []) {
  const tokenMap = new Map();
  items.forEach((item, index) => {
    item.tokens.forEach(token => {
      if (!tokenMap.has(token)) tokenMap.set(token, []);
      tokenMap.get(token).push(index);
    });
  });
  return { items, tokenMap };
}

function tagImportHistoryCandidate(history = {}) {
  const original = history.original_text || '';
  const corrected = history.corrected_text || '';
  const summary = history.summary || '';
  const fullText = [original, corrected, summary].filter(Boolean).join('\n');
  const text = fullText.slice(0, TAG_IMPORT_HISTORY_TEXT_LIMIT);
  return {
    id: history.id,
    userId: history.user_id,
    username: history.username,
    name: history.name,
    filename: history.filename,
    status: history.status,
    score: history.score,
    totalErrors: history.total_errors,
    createdAt: history.created_at,
    tags: Array.isArray(history.tags) ? history.tags : [],
    originalText: original,
    correctedText: corrected,
    normalizedText: normalizeTagImportText(text),
    tokens: tagImportTokens(text, 240),
    textLength: fullText.length
  };
}

function tagImportCandidateIndexes(history, excelIndex) {
  const counts = new Map();
  history.tokens.slice(0, 120).forEach(token => {
    const indexes = excelIndex.tokenMap.get(token);
    if (!indexes || indexes.length > 280) return;
    indexes.forEach(index => counts.set(index, (counts.get(index) || 0) + 1));
  });
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 80)
    .map(([index]) => index);
}

function scoreTagImportMatch(history, excelItem) {
  const historyText = history.normalizedText;
  const excelText = excelItem.normalizedText;
  const answerText = normalizeTagImportText(excelItem.answer);
  const questionText = normalizeTagImportText(excelItem.question);
  const allOverlap = tagImportOverlapScore(history.tokens, excelItem.tokens);
  const answerOverlap = tagImportOverlapScore(history.tokens, excelItem.answerTokens);
  const questionOverlap = tagImportOverlapScore(history.tokens, excelItem.questionTokens);
  let score = Math.round(Math.max(allOverlap * 72, answerOverlap * 88, (answerOverlap * 0.68 + questionOverlap * 0.32) * 100));
  const reasons = [];

  if (answerText.length >= 120) {
    const answerStart = answerText.slice(0, 120);
    const answerMiddle = answerText.slice(Math.max(0, Math.floor(answerText.length / 2) - 60), Math.floor(answerText.length / 2) + 60);
    const answerEnd = answerText.slice(-120);
    const hitCount = [answerStart, answerMiddle, answerEnd].filter(part => part && historyText.includes(part)).length;
    if (hitCount >= 2) {
      score = Math.max(score, 96);
      reasons.push('cevap metni guclu eslesti');
    } else if (hitCount === 1) {
      score = Math.max(score, 84);
      reasons.push('cevap metni kismen eslesti');
    }
  }
  if (questionText.length >= 50 && historyText.includes(questionText.slice(0, Math.min(100, questionText.length)))) {
    score = Math.max(score, 82);
    reasons.push('soru baslangici eslesti');
  }
  if (excelText.length >= 120 && historyText.includes(excelText.slice(0, 120))) {
    score = Math.max(score, 90);
    reasons.push('excel kaydi baslangici eslesti');
  }
  if (history.textLength > 15000 && score < 98) {
    score = Math.min(score, 74);
    reasons.push('uzun dokuman manuel kontrol gerektirir');
  }
  if (answerOverlap >= 0.55) reasons.push('cevap kelime benzerligi yuksek');
  else if (allOverlap >= 0.45) reasons.push('genel kelime benzerligi var');
  return {
    confidence: Math.max(0, Math.min(100, score)),
    reason: reasons.length ? reasons.join('; ') : 'dusuk benzerlik'
  };
}

function historyTagImportStatus(confidence, history, excelItem) {
  if (!excelItem?.tags?.length) return 'unmatched';
  if (!history?.id) return 'unmatched';
  if (history.textLength > 15000 && confidence < 98) return 'review';
  if (confidence >= 86) return 'ready';
  if (confidence >= 62) return 'review';
  return 'unmatched';
}

function publicHistoryTagImportBatch(row = {}) {
  return {
    id: row.id,
    filename: row.filename || '',
    sheetName: row.sheet_name || '',
    totalRows: row.total_rows || 0,
    usableRows: row.usable_rows || 0,
    historyCount: row.history_count || 0,
    readyCount: row.ready_count || 0,
    reviewCount: row.review_count || 0,
    unmatchedCount: row.unmatched_count || 0,
    appliedCount: row.applied_count || 0,
    skippedCount: row.skipped_count || 0,
    status: row.status || 'preview',
    note: row.note || '',
    createdBy: row.created_by || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function publicHistoryTagImportMatch(row = {}) {
  return {
    id: row.id,
    batchId: row.batch_id,
    historyId: row.history_id,
    excelRow: row.excel_row,
    question: row.excel_question || '',
    answerPreview: row.answer_preview || '',
    tags: Array.isArray(row.tags) ? row.tags : [],
    currentTags: Array.isArray(row.current_tags) ? row.current_tags : [],
    confidence: Number(row.confidence || 0),
    status: row.match_status || 'review',
    reason: row.match_reason || '',
    appliedAt: row.applied_at,
    appliedBy: row.applied_by || '',
    history: row.history ? publicHistoryTagImportHistory(row.history) : null,
    createdAt: row.created_at
  };
}

function publicHistoryTagImportHistory(row = {}) {
  const original = String(row.original_text || '');
  const corrected = String(row.corrected_text || '');
  const summary = String(row.summary || '');
  return {
    id: row.id,
    userId: row.user_id,
    username: row.username || '',
    name: row.name || '',
    filename: row.filename || '',
    score: row.score,
    totalErrors: row.total_errors,
    catCounts: row.cat_counts || {},
    summary,
    originalText: archiveTextPreview(original, 700),
    correctedText: archiveTextPreview(corrected || original || summary, 900),
    status: row.status || 'bekliyor',
    approvedBy: row.approved_by,
    approvedAt: row.approved_at,
    tags: Array.isArray(row.tags) ? row.tags : [],
    questionText: row.question_text || '',
    promptVersion: row.prompt_version,
    rulesHash: row.rules_hash,
    createdAt: row.created_at
  };
}

function historyTagImportSelectColumns() {
  const columns = [
    'id',
    'user_id',
    'username',
    'name',
    'filename',
    'status',
    'score',
    'total_errors',
    'cat_counts',
    'summary',
    'corrected_text',
    'approved_by',
    'approved_at',
    'created_at'
  ];
  if (HAS_ORIGINAL_TEXT) columns.splice(10, 0, 'original_text');
  if (HAS_HISTORY_TAGS) columns.splice(columns.indexOf('created_at'), 0, 'tags');
  if (HAS_HISTORY_QUESTION_TEXT) columns.splice(columns.indexOf('created_at'), 0, 'question_text');
  if (HAS_ANALYSIS_META) columns.splice(columns.indexOf('created_at'), 0, 'prompt_version', 'rules_hash');
  return columns.join(',');
}

function archiveComparableText(value = '') {
  return normalizeText(value).replace(/\s+/g, ' ').toLocaleLowerCase('tr-TR');
}

function archiveSourceFingerprint(value = '') {
  const comparable = archiveComparableText(value);
  return comparable ? textHash(comparable) : '';
}

function archiveSourceTitleKey(value = '') {
  return archiveComparableText(value).slice(0, 220);
}

function archiveSourceUrlKey(value = '') {
  return String(value || '').trim().replace(/\/+$/, '').toLocaleLowerCase('tr-TR').slice(0, 700);
}

function buildArchiveSourceSearchBlob(source = {}) {
  return [
    source.title,
    source.sourceType,
    source.status,
    source.category,
    source.sourceUrl,
    source.note,
    ...(Array.isArray(source.tags) ? source.tags : []),
    source.sourceText
  ].join(' ').replace(/\s+/g, ' ').trim().slice(0, ARCHIVE_SOURCE_TEXT_LIMIT + 4000);
}

function archiveSourceToDbRow(source = {}) {
  return {
    id: source.id,
    title: source.title || '',
    source_type: source.sourceType || 'dokuman',
    status: source.status || 'kaynak',
    category: source.category || '',
    source_date: source.sourceDate || null,
    source_url: source.sourceUrl || '',
    tags: Array.isArray(source.tags) ? source.tags : [],
    note: source.note || '',
    source_text: source.sourceText || '',
    text_preview: archiveTextPreview(source.sourceText || ''),
    text_length: String(source.sourceText || '').length,
    source_text_hash: source.sourceTextHash || archiveSourceFingerprint(source.sourceText),
    title_key: source.titleKey || archiveSourceTitleKey(source.title),
    source_url_key: source.sourceUrlKey || archiveSourceUrlKey(source.sourceUrl),
    search_blob: buildArchiveSourceSearchBlob(source),
    created_by: source.createdBy || '',
    updated_by: source.updatedBy || '',
    created_at: source.createdAt || new Date().toISOString(),
    updated_at: source.updatedAt || new Date().toISOString(),
    conflict_accepted_at: source.conflictAcceptedAt || null,
    conflict_accepted_by: source.conflictAcceptedBy || '',
    conflict_accepted_conflicts: Array.isArray(source.conflictAcceptedConflicts) ? source.conflictAcceptedConflicts : []
  };
}

function archiveSourceFromDbRow(row = {}, options = {}) {
  const sourceText = options.full ? String(row.source_text || '') : '';
  return {
    id: row.id,
    title: row.title || '',
    sourceType: row.source_type || 'dokuman',
    status: row.status || 'kaynak',
    category: row.category || '',
    sourceDate: row.source_date || null,
    sourceUrl: row.source_url || '',
    tags: Array.isArray(row.tags) ? row.tags : [],
    note: row.note || '',
    sourceText,
    textPreview: row.text_preview || archiveTextPreview(sourceText),
    textLength: Number(row.text_length || sourceText.length || 0),
    sourceTextHash: row.source_text_hash || '',
    titleKey: row.title_key || '',
    sourceUrlKey: row.source_url_key || '',
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null,
    createdBy: row.created_by || '',
    updatedBy: row.updated_by || '',
    conflictAcceptedAt: row.conflict_accepted_at || null,
    conflictAcceptedBy: row.conflict_accepted_by || '',
    conflictAcceptedConflicts: Array.isArray(row.conflict_accepted_conflicts) ? row.conflict_accepted_conflicts : []
  };
}

function archiveSourceConflictSummary(source = {}, reason = '', matchType = '') {
  const text = String(source.sourceText || '');
  return {
    id: source.id,
    title: source.title || 'Başlıksız kaynak',
    sourceType: source.sourceType || 'dokuman',
    status: source.status || 'kaynak',
    textLength: Number(source.textLength || text.length || 0),
    updatedAt: source.updatedAt || source.createdAt || null,
    reason,
    matchType
  };
}

function findArchiveSourceConflicts(sources = [], candidate = {}, currentId = '') {
  const candidateTextHash = candidate.sourceTextHash || archiveSourceFingerprint(candidate.sourceText);
  const candidateUrlKey = candidate.sourceUrlKey || archiveSourceUrlKey(candidate.sourceUrl);
  const candidateTitleKey = candidate.titleKey || archiveSourceTitleKey(candidate.title);
  const candidateType = candidate.sourceType || 'dokuman';
  const conflicts = [];

  for (const source of sources) {
    if (!source || source.id === currentId) continue;
    const existingTextHash = source.sourceTextHash || archiveSourceFingerprint(source.sourceText);
    const existingUrlKey = source.sourceUrlKey || archiveSourceUrlKey(source.sourceUrl);
    const existingTitleKey = source.titleKey || archiveSourceTitleKey(source.title);
    const existingType = source.sourceType || 'dokuman';

    if (candidateTextHash && existingTextHash && candidateTextHash === existingTextHash) {
      conflicts.push(archiveSourceConflictSummary(source, 'Aynı kaynak metni daha önce kaydedilmiş.', 'same_text'));
      continue;
    }
    if (candidateUrlKey && existingUrlKey && candidateUrlKey === existingUrlKey) {
      conflicts.push(archiveSourceConflictSummary(source, 'Aynı kaynak linkiyle daha önce kayıt açılmış.', 'same_url'));
      continue;
    }
    if (candidateTitleKey && existingTitleKey && candidateTitleKey === existingTitleKey && candidateType === existingType) {
      conflicts.push(archiveSourceConflictSummary(source, 'Aynı başlık ve kaynak türüyle benzer kayıt var.', 'same_title_type'));
    }
  }

  return conflicts.slice(0, 8);
}

function normalizeArchiveSourceInput(input = {}, existing = {}) {
  const title = String(input.title ?? existing.title ?? '').trim().slice(0, 180);
  const sourceText = String(input.sourceText ?? input.text ?? existing.sourceText ?? '').trim();
  if (!title) throw httpError('Kaynak başlığı gerekli.', 400);
  if (!sourceText) throw httpError('Kaynak metni gerekli.', 400);
  if (sourceText.length > ARCHIVE_SOURCE_TEXT_LIMIT) {
    throw httpError('Kaynak metni 200.000 karakter sınırını aşıyor.', 413);
  }
  return {
    ...existing,
    title,
    sourceType: normalizeArchiveSourceType(input.sourceType ?? existing.sourceType),
    status: normalizeArchiveSourceStatus(input.status ?? existing.status),
    category: String(input.category ?? existing.category ?? '').trim().slice(0, 120),
    sourceDate: normalizeIsoDate(input.sourceDate ?? existing.sourceDate),
    sourceUrl: String(input.sourceUrl ?? existing.sourceUrl ?? '').trim().slice(0, 700),
    tags: normalizeArchiveTags(input.tags ?? existing.tags),
    note: String(input.note ?? existing.note ?? '').trim().slice(0, 2000),
    sourceText,
    sourceTextHash: archiveSourceFingerprint(sourceText),
    titleKey: archiveSourceTitleKey(title),
    sourceUrlKey: archiveSourceUrlKey(input.sourceUrl ?? existing.sourceUrl)
  };
}

function publicArchiveSource(source = {}, options = {}) {
  const text = String(source.sourceText || '');
  const textPreview = source.textPreview || archiveTextPreview(text);
  const textLength = Number(source.textLength || text.length || 0);
  const base = {
    id: source.id,
    title: source.title,
    sourceType: source.sourceType || 'dokuman',
    status: source.status || 'kaynak',
    category: source.category || '',
    sourceDate: source.sourceDate || null,
    sourceUrl: source.sourceUrl || '',
    tags: Array.isArray(source.tags) ? source.tags : [],
    note: source.note || '',
    textLength,
    textPreview,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
    createdBy: source.createdBy || '',
    updatedBy: source.updatedBy || '',
    duplicateWarning: Boolean(source.conflictAcceptedAt),
    conflictAcceptedAt: source.conflictAcceptedAt || null,
    conflictAcceptedBy: source.conflictAcceptedBy || ''
  };
  if (options.full) base.sourceText = text;
  return base;
}

async function loadArchiveOpsSources() {
  const sources = await loadJsonSetting(ARCHIVE_OPS_SOURCES_KEY, []);
  return Array.isArray(sources) ? sources : [];
}

async function saveArchiveOpsSources(sources) {
  const clean = Array.isArray(sources) ? sources.slice(0, ARCHIVE_SOURCE_LIST_LIMIT) : [];
  await saveJsonSetting(ARCHIVE_OPS_SOURCES_KEY, clean);
}

function escapeSupabaseLikePattern(value = '') {
  return String(value || '').replace(/[\\%_]/g, match => `\\${match}`);
}

async function ensureArchiveSourcesMigratedFromSettings() {
  if (!HAS_ARCHIVE_SOURCE_TABLES) return;
  const { count, error: countError } = await supabase
    .from('archive_sources')
    .select('id', { count: 'exact', head: true });
  if (countError) throw new Error(countError.message);
  if ((count || 0) > 0) return;

  const legacySources = await loadArchiveOpsSources();
  if (!legacySources.length) return;

  const rows = legacySources
    .filter(source => source?.id && source?.title && source?.sourceText)
    .map(source => archiveSourceToDbRow(source));
  for (let i = 0; i < rows.length; i += 100) {
    const { error } = await supabase.from('archive_sources').upsert(rows.slice(i, i + 100), { onConflict: 'id' });
    if (error) throw new Error(error.message);
  }
  await insertArchiveSourceEvent(null, 'legacy_migration', 'Sistem', `${rows.length} pilot kaynak kaydı tablo yapısına taşındı.`, {
    legacyKey: ARCHIVE_OPS_SOURCES_KEY,
    migratedCount: rows.length
  });
}

async function insertArchiveSourceEvent(sourceId, eventType, actor, summary, metadata = {}) {
  if (!HAS_ARCHIVE_SOURCE_TABLES) return;
  const { error } = await supabase.from('archive_source_events').insert({
    source_id: sourceId || null,
    event_type: eventType,
    actor: actor || 'Sistem',
    summary: summary || '',
    metadata
  });
  if (error) console.warn('archive_source_events yazılamadı:', error.message);
}

async function nextArchiveSourceVersionNo(sourceId) {
  const { data, error } = await supabase
    .from('archive_source_versions')
    .select('version_no')
    .eq('source_id', sourceId)
    .order('version_no', { ascending: false })
    .limit(1);
  if (error) throw new Error(error.message);
  return Number(data?.[0]?.version_no || 0) + 1;
}

function archiveSourceAuditSnapshot(source = {}) {
  return {
    id: source.id,
    title: source.title || '',
    sourceType: source.sourceType || 'dokuman',
    status: source.status || 'kaynak',
    category: source.category || '',
    sourceDate: source.sourceDate || null,
    sourceUrl: source.sourceUrl || '',
    tags: Array.isArray(source.tags) ? source.tags : [],
    note: source.note || '',
    sourceText: source.sourceText || '',
    sourceTextHash: source.sourceTextHash || archiveSourceFingerprint(source.sourceText),
    textLength: Number(source.textLength || String(source.sourceText || '').length || 0),
    createdAt: source.createdAt || null,
    updatedAt: source.updatedAt || null,
    createdBy: source.createdBy || '',
    updatedBy: source.updatedBy || ''
  };
}

function archiveSourceChangeKeys(before = {}, after = {}) {
  const keys = ['title', 'sourceType', 'status', 'category', 'sourceDate', 'sourceUrl', 'tags', 'note', 'sourceText'];
  return keys.filter(key => JSON.stringify(before[key] || '') !== JSON.stringify(after[key] || ''));
}

async function insertArchiveSourceVersion(source = {}, actor = 'Sistem', eventType = 'update', previous = null) {
  if (!HAS_ARCHIVE_SOURCE_TABLES || !source.id) return;
  const snapshot = archiveSourceAuditSnapshot(source);
  const previousSnapshot = previous ? archiveSourceAuditSnapshot(previous) : null;
  const versionNo = await nextArchiveSourceVersionNo(source.id);
  const { error } = await supabase.from('archive_source_versions').insert({
    source_id: source.id,
    version_no: versionNo,
    event_type: eventType,
    snapshot,
    previous_snapshot: previousSnapshot,
    change_keys: previousSnapshot ? archiveSourceChangeKeys(previousSnapshot, snapshot) : [],
    created_by: actor || 'Sistem'
  });
  if (error) throw new Error(error.message);
}

async function findArchiveSourceConflictsDb(candidate = {}, currentId = '') {
  const checks = [];
  const candidateTextHash = candidate.sourceTextHash || archiveSourceFingerprint(candidate.sourceText);
  const candidateUrlKey = candidate.sourceUrlKey || archiveSourceUrlKey(candidate.sourceUrl);
  const candidateTitleKey = candidate.titleKey || archiveSourceTitleKey(candidate.title);
  const candidateType = candidate.sourceType || 'dokuman';

  if (candidateTextHash) {
    checks.push({
      query: () => supabase.from('archive_sources').select(ARCHIVE_SOURCE_DB_LIST_COLUMNS).eq('source_text_hash', candidateTextHash).limit(4),
      reason: 'Aynı kaynak metni daha önce kaydedilmiş.',
      matchType: 'same_text'
    });
  }
  if (candidateUrlKey) {
    checks.push({
      query: () => supabase.from('archive_sources').select(ARCHIVE_SOURCE_DB_LIST_COLUMNS).eq('source_url_key', candidateUrlKey).limit(4),
      reason: 'Aynı kaynak linkiyle daha önce kayıt açılmış.',
      matchType: 'same_url'
    });
  }
  if (candidateTitleKey) {
    checks.push({
      query: () => supabase.from('archive_sources').select(ARCHIVE_SOURCE_DB_LIST_COLUMNS).eq('title_key', candidateTitleKey).eq('source_type', candidateType).limit(4),
      reason: 'Aynı başlık ve kaynak türüyle benzer kayıt var.',
      matchType: 'same_title_type'
    });
  }

  const conflicts = [];
  const seen = new Set();
  for (const check of checks) {
    let query = check.query();
    if (currentId) query = query.neq('id', currentId);
    const { data, error } = await query;
    if (error) throw new Error(error.message);
    for (const row of data || []) {
      if (seen.has(row.id)) continue;
      seen.add(row.id);
      conflicts.push(archiveSourceConflictSummary(archiveSourceFromDbRow(row), check.reason, check.matchType));
    }
  }
  return conflicts.slice(0, 8);
}

async function listArchiveOpsSources(query = {}) {
  if (!HAS_ARCHIVE_SOURCE_TABLES) {
    const sources = await loadArchiveOpsSources();
    const filtered = filterArchiveSources(sources, query)
      .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
    return { storage: 'settings', sources, filtered };
  }

  await ensureArchiveSourcesMigratedFromSettings();
  const q = String(query.q || '').trim();
  const type = String(query.type || '').trim();
  const types = normalizeArchiveSourceTypes(query.types);
  if (ARCHIVE_SOURCE_TYPES.includes(type) && !types.includes(type)) types.push(type);
  const status = String(query.status || '').trim();
  let sourceQuery = supabase
    .from('archive_sources')
    .select(ARCHIVE_SOURCE_DB_LIST_COLUMNS, { count: 'exact' })
    .order('updated_at', { ascending: false })
    .limit(ARCHIVE_SOURCE_LIST_LIMIT);
  if (types.length === 1) sourceQuery = sourceQuery.eq('source_type', types[0]);
  else if (types.length > 1) sourceQuery = sourceQuery.in('source_type', types);
  if (status) sourceQuery = sourceQuery.eq('status', status);
  if (q) sourceQuery = sourceQuery.ilike('search_blob', `%${escapeSupabaseLikePattern(q)}%`);
  const { data, error, count } = await sourceQuery;
  if (error) throw new Error(error.message);

  const { count: totalCount, error: totalError } = await supabase
    .from('archive_sources')
    .select('id', { count: 'exact', head: true });
  if (totalError) throw new Error(totalError.message);

  const rowsForCounts = await fetchAllPages(() => supabase.from('archive_sources').select('source_type,status'));
  const counts = {
    total: totalCount || 0,
    filtered: count || 0,
    byType: {},
    byStatus: {}
  };
  for (const row of rowsForCounts) {
    counts.byType[row.source_type || 'dokuman'] = (counts.byType[row.source_type || 'dokuman'] || 0) + 1;
    counts.byStatus[row.status || 'kaynak'] = (counts.byStatus[row.status || 'kaynak'] || 0) + 1;
  }
  return {
    storage: 'database',
    counts,
    filtered: (data || []).map(row => archiveSourceFromDbRow(row)),
    sources: []
  };
}

async function getArchiveOpsSource(id) {
  if (!HAS_ARCHIVE_SOURCE_TABLES) {
    const sources = await loadArchiveOpsSources();
    return sources.find(item => item.id === id) || null;
  }
  await ensureArchiveSourcesMigratedFromSettings();
  const { data, error } = await supabase
    .from('archive_sources')
    .select(ARCHIVE_SOURCE_DB_FULL_COLUMNS)
    .eq('id', id)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data ? archiveSourceFromDbRow(data, { full: true }) : null;
}

async function createArchiveOpsSource(input = {}, actor = 'Sistem') {
  const now = new Date().toISOString();
  const source = {
    id: archiveSourceId(),
    ...normalizeArchiveSourceInput(input),
    createdAt: now,
    updatedAt: now,
    createdBy: actor,
    updatedBy: actor
  };

  if (!HAS_ARCHIVE_SOURCE_TABLES) {
    const sources = await loadArchiveOpsSources();
    const conflicts = findArchiveSourceConflicts(sources, source);
    if (conflicts.length && input.forceSave !== true) return { conflict: true, conflicts };
    if (conflicts.length) {
      source.conflictAcceptedAt = now;
      source.conflictAcceptedBy = actor;
      source.conflictAcceptedConflicts = conflicts;
    }
    await saveArchiveOpsSources([source, ...sources]);
    return { source };
  }

  await ensureArchiveSourcesMigratedFromSettings();
  const conflicts = await findArchiveSourceConflictsDb(source);
  if (conflicts.length && input.forceSave !== true) return { conflict: true, conflicts };
  if (conflicts.length) {
    source.conflictAcceptedAt = now;
    source.conflictAcceptedBy = actor;
    source.conflictAcceptedConflicts = conflicts;
  }
  const { data, error } = await supabase
    .from('archive_sources')
    .insert(archiveSourceToDbRow(source))
    .select(ARCHIVE_SOURCE_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  const inserted = archiveSourceFromDbRow(data, { full: true });
  await insertArchiveSourceVersion(inserted, actor, 'create');
  await insertArchiveSourceEvent(inserted.id, 'create', actor, 'Kaynak kaydı oluşturuldu.', {
    title: inserted.title,
    sourceType: inserted.sourceType,
    textLength: inserted.textLength
  });
  return { source: inserted };
}

async function updateArchiveOpsSource(id, input = {}, actor = 'Sistem') {
  if (!HAS_ARCHIVE_SOURCE_TABLES) {
    const sources = await loadArchiveOpsSources();
    const index = sources.findIndex(item => item.id === id);
    if (index < 0) return null;
    const updated = {
      ...normalizeArchiveSourceInput(input, sources[index]),
      id: sources[index].id,
      createdAt: sources[index].createdAt,
      createdBy: sources[index].createdBy,
      updatedAt: new Date().toISOString(),
      updatedBy: actor
    };
    const conflicts = findArchiveSourceConflicts(sources, updated, id);
    if (conflicts.length && input.forceSave !== true) return { conflict: true, conflicts };
    if (conflicts.length) {
      updated.conflictAcceptedAt = updated.updatedAt;
      updated.conflictAcceptedBy = actor;
      updated.conflictAcceptedConflicts = conflicts;
    } else {
      delete updated.conflictAcceptedAt;
      delete updated.conflictAcceptedBy;
      delete updated.conflictAcceptedConflicts;
    }
    sources[index] = updated;
    await saveArchiveOpsSources(sources);
    return { source: updated };
  }

  await ensureArchiveSourcesMigratedFromSettings();
  const existing = await getArchiveOpsSource(id);
  if (!existing) return null;
  const updated = {
    ...normalizeArchiveSourceInput(input, existing),
    id: existing.id,
    createdAt: existing.createdAt,
    createdBy: existing.createdBy,
    updatedAt: new Date().toISOString(),
    updatedBy: actor
  };
  const conflicts = await findArchiveSourceConflictsDb(updated, id);
  if (conflicts.length && input.forceSave !== true) return { conflict: true, conflicts };
  if (conflicts.length) {
    updated.conflictAcceptedAt = updated.updatedAt;
    updated.conflictAcceptedBy = actor;
    updated.conflictAcceptedConflicts = conflicts;
  } else {
    updated.conflictAcceptedAt = null;
    updated.conflictAcceptedBy = '';
    updated.conflictAcceptedConflicts = [];
  }
  const { data, error } = await supabase
    .from('archive_sources')
    .update(archiveSourceToDbRow(updated))
    .eq('id', id)
    .select(ARCHIVE_SOURCE_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  const saved = archiveSourceFromDbRow(data, { full: true });
  await insertArchiveSourceVersion(saved, actor, 'update', existing);
  await insertArchiveSourceEvent(saved.id, 'update', actor, 'Kaynak kaydı güncellendi.', {
    title: saved.title,
    sourceType: saved.sourceType,
    changeKeys: archiveSourceChangeKeys(archiveSourceAuditSnapshot(existing), archiveSourceAuditSnapshot(saved))
  });
  return { source: saved };
}

function archiveWorkItemId() {
  return `wrk-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeArchiveWorkStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_WORK_STATUSES.includes(status) ? status : 'taslak';
}

function normalizeArchiveWorkPriority(value) {
  const priority = String(value || '').trim();
  return ARCHIVE_WORK_PRIORITIES.includes(priority) ? priority : 'normal';
}

function buildArchiveWorkPreview(work = {}) {
  return archiveTextPreview([
    work.question,
    work.answerDraft,
    work.note
  ].filter(Boolean).join(' '), 320);
}

function buildArchiveWorkSearchBlob(work = {}) {
  return [
    work.title,
    work.status,
    work.priority,
    work.assignedTo,
    work.sourceTitle,
    work.category,
    ...(Array.isArray(work.topics) ? work.topics : []),
    work.question,
    work.answerDraft,
    work.note
  ].join(' ').replace(/\s+/g, ' ').trim().slice(0, ARCHIVE_SOURCE_TEXT_LIMIT + 4000);
}

function archiveWorkTextLength(work = {}) {
  return [work.question, work.answerDraft, work.note].join('\n').length;
}

function normalizeArchiveWorkInput(input = {}, existing = {}) {
  const question = String(input.question ?? existing.question ?? '').trim().slice(0, 20000);
  const answerDraft = String(input.answerDraft ?? input.answer_draft ?? existing.answerDraft ?? '').trim().slice(0, ARCHIVE_SOURCE_TEXT_LIMIT);
  const note = String(input.note ?? existing.note ?? '').trim().slice(0, 10000);
  const rawTitle = String(input.title ?? existing.title ?? '').trim();
  const title = (rawTitle || question.slice(0, 120) || 'Başlıksız çalışma').trim().slice(0, 180);
  return {
    ...existing,
    title,
    status: normalizeArchiveWorkStatus(input.status ?? existing.status),
    priority: normalizeArchiveWorkPriority(input.priority ?? existing.priority),
    assignedTo: String(input.assignedTo ?? input.assigned_to ?? existing.assignedTo ?? '').trim().slice(0, 120),
    dueDate: normalizeIsoDate(input.dueDate ?? input.due_date ?? existing.dueDate),
    sourceId: String(input.sourceId ?? input.source_id ?? existing.sourceId ?? '').trim().slice(0, 160),
    sourceTitle: String(input.sourceTitle ?? input.source_title ?? existing.sourceTitle ?? '').trim().slice(0, 220),
    category: String(input.category ?? existing.category ?? '').trim().slice(0, 120),
    topics: normalizeArchiveTags(input.topics ?? existing.topics),
    question,
    answerDraft,
    note
  };
}

function archiveWorkToDbRow(work = {}) {
  return {
    id: work.id,
    title: work.title || '',
    status: work.status || 'taslak',
    priority: work.priority || 'normal',
    assigned_to: work.assignedTo || '',
    due_date: work.dueDate || null,
    source_id: work.sourceId || null,
    source_title: work.sourceTitle || '',
    category: work.category || '',
    topics: Array.isArray(work.topics) ? work.topics : [],
    question: work.question || '',
    answer_draft: work.answerDraft || '',
    note: work.note || '',
    text_preview: work.textPreview || buildArchiveWorkPreview(work),
    text_length: Number(work.textLength || archiveWorkTextLength(work) || 0),
    search_blob: buildArchiveWorkSearchBlob(work),
    created_by: work.createdBy || '',
    updated_by: work.updatedBy || '',
    created_at: work.createdAt || new Date().toISOString(),
    updated_at: work.updatedAt || new Date().toISOString()
  };
}

function archiveWorkFromDbRow(row = {}, options = {}) {
  return {
    id: row.id,
    title: row.title || '',
    status: row.status || 'taslak',
    priority: row.priority || 'normal',
    assignedTo: row.assigned_to || '',
    dueDate: row.due_date || null,
    sourceId: row.source_id || '',
    sourceTitle: row.source_title || '',
    category: row.category || '',
    topics: Array.isArray(row.topics) ? row.topics : [],
    question: options.full ? String(row.question || '') : '',
    answerDraft: options.full ? String(row.answer_draft || '') : '',
    note: options.full ? String(row.note || '') : '',
    textPreview: row.text_preview || '',
    textLength: Number(row.text_length || 0),
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null,
    createdBy: row.created_by || '',
    updatedBy: row.updated_by || ''
  };
}

function publicArchiveWorkItem(work = {}, options = {}) {
  const base = {
    id: work.id,
    title: work.title,
    status: work.status || 'taslak',
    priority: work.priority || 'normal',
    assignedTo: work.assignedTo || '',
    dueDate: work.dueDate || null,
    sourceId: work.sourceId || '',
    sourceTitle: work.sourceTitle || '',
    category: work.category || '',
    topics: Array.isArray(work.topics) ? work.topics : [],
    textPreview: work.textPreview || buildArchiveWorkPreview(work),
    textLength: Number(work.textLength || archiveWorkTextLength(work) || 0),
    createdAt: work.createdAt,
    updatedAt: work.updatedAt,
    createdBy: work.createdBy || '',
    updatedBy: work.updatedBy || ''
  };
  if (options.full) {
    base.question = work.question || '';
    base.answerDraft = work.answerDraft || '';
    base.note = work.note || '';
  }
  return base;
}

async function loadArchiveWorkItems() {
  const items = await loadJsonSetting(ARCHIVE_OPS_WORK_ITEMS_KEY, []);
  return Array.isArray(items) ? items : [];
}

async function saveArchiveWorkItems(items) {
  const clean = Array.isArray(items) ? items.slice(0, ARCHIVE_WORK_ITEM_LIMIT) : [];
  await saveJsonSetting(ARCHIVE_OPS_WORK_ITEMS_KEY, clean);
}

function filterArchiveWorkItems(items = [], query = {}) {
  const q = String(query.q || '').trim().toLocaleLowerCase('tr-TR');
  const status = String(query.status || '').trim();
  const priority = String(query.priority || '').trim();
  return items.filter(item => {
    if (status && item.status !== status) return false;
    if (priority && item.priority !== priority) return false;
    if (!q) return true;
    return buildArchiveWorkSearchBlob(item).toLocaleLowerCase('tr-TR').includes(q);
  });
}

async function listArchiveWorkItems(query = {}) {
  if (!HAS_ARCHIVE_WORK_TABLES) {
    const items = await loadArchiveWorkItems();
    const filtered = filterArchiveWorkItems(items, query)
      .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
    return { storage: 'settings', items, filtered };
  }

  const q = String(query.q || '').trim();
  const status = String(query.status || '').trim();
  const priority = String(query.priority || '').trim();
  let workQuery = supabase
    .from('archive_work_items')
    .select(ARCHIVE_WORK_ITEM_DB_LIST_COLUMNS, { count: 'exact' })
    .order('updated_at', { ascending: false })
    .limit(ARCHIVE_WORK_ITEM_LIMIT);
  if (status) workQuery = workQuery.eq('status', status);
  if (priority) workQuery = workQuery.eq('priority', priority);
  if (q) workQuery = workQuery.ilike('search_blob', `%${escapeSupabaseLikePattern(q)}%`);
  const { data, error, count } = await workQuery;
  if (error) throw new Error(error.message);

  const { count: totalCount, error: totalError } = await supabase
    .from('archive_work_items')
    .select('id', { count: 'exact', head: true });
  if (totalError) throw new Error(totalError.message);

  const rowsForCounts = await fetchAllPages(() => supabase.from('archive_work_items').select('status,priority'));
  const counts = {
    total: totalCount || 0,
    filtered: count || 0,
    byStatus: {},
    byPriority: {}
  };
  for (const row of rowsForCounts) {
    counts.byStatus[row.status || 'taslak'] = (counts.byStatus[row.status || 'taslak'] || 0) + 1;
    counts.byPriority[row.priority || 'normal'] = (counts.byPriority[row.priority || 'normal'] || 0) + 1;
  }
  return {
    storage: 'database',
    counts,
    filtered: (data || []).map(row => archiveWorkFromDbRow(row)),
    items: []
  };
}

async function getArchiveWorkItem(id) {
  if (!HAS_ARCHIVE_WORK_TABLES) {
    const items = await loadArchiveWorkItems();
    return items.find(item => item.id === id) || null;
  }
  const { data, error } = await supabase
    .from('archive_work_items')
    .select(ARCHIVE_WORK_ITEM_DB_FULL_COLUMNS)
    .eq('id', id)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data ? archiveWorkFromDbRow(data, { full: true }) : null;
}

async function createArchiveWorkItem(input = {}, actor = 'Sistem') {
  const now = new Date().toISOString();
  const work = {
    id: archiveWorkItemId(),
    ...normalizeArchiveWorkInput(input),
    createdAt: now,
    updatedAt: now,
    createdBy: actor,
    updatedBy: actor
  };
  work.textPreview = buildArchiveWorkPreview(work);
  work.textLength = archiveWorkTextLength(work);

  if (!HAS_ARCHIVE_WORK_TABLES) {
    const items = await loadArchiveWorkItems();
    await saveArchiveWorkItems([work, ...items]);
    return work;
  }

  const { data, error } = await supabase
    .from('archive_work_items')
    .insert(archiveWorkToDbRow(work))
    .select(ARCHIVE_WORK_ITEM_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  return archiveWorkFromDbRow(data, { full: true });
}

async function updateArchiveWorkItem(id, input = {}, actor = 'Sistem') {
  if (!HAS_ARCHIVE_WORK_TABLES) {
    const items = await loadArchiveWorkItems();
    const index = items.findIndex(item => item.id === id);
    if (index < 0) return null;
    const updated = {
      ...normalizeArchiveWorkInput(input, items[index]),
      id: items[index].id,
      createdAt: items[index].createdAt,
      createdBy: items[index].createdBy,
      updatedAt: new Date().toISOString(),
      updatedBy: actor
    };
    updated.textPreview = buildArchiveWorkPreview(updated);
    updated.textLength = archiveWorkTextLength(updated);
    items[index] = updated;
    await saveArchiveWorkItems(items);
    return updated;
  }

  const existing = await getArchiveWorkItem(id);
  if (!existing) return null;
  const updated = {
    ...normalizeArchiveWorkInput(input, existing),
    id: existing.id,
    createdAt: existing.createdAt,
    createdBy: existing.createdBy,
    updatedAt: new Date().toISOString(),
    updatedBy: actor
  };
  updated.textPreview = buildArchiveWorkPreview(updated);
  updated.textLength = archiveWorkTextLength(updated);
  const { data, error } = await supabase
    .from('archive_work_items')
    .update(archiveWorkToDbRow(updated))
    .eq('id', id)
    .select(ARCHIVE_WORK_ITEM_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  return archiveWorkFromDbRow(data, { full: true });
}

async function deleteArchiveWorkItem(id) {
  if (!HAS_ARCHIVE_WORK_TABLES) {
    const items = await loadArchiveWorkItems();
    const next = items.filter(item => item.id !== id);
    if (next.length === items.length) return null;
    await saveArchiveWorkItems(next);
    return { id };
  }
  const { data, error } = await supabase
    .from('archive_work_items')
    .delete()
    .eq('id', id)
    .select('id')
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data || null;
}

function archivePublishTaskId() {
  return `pub-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeArchivePublishStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_PUBLISH_STATUSES.includes(status) ? status : 'planlandi';
}

function normalizeArchivePublishPriority(value) {
  const priority = String(value || '').trim();
  return ARCHIVE_PUBLISH_PRIORITIES.includes(priority) ? priority : 'normal';
}

function buildArchivePublishPreview(task = {}) {
  return archiveTextPreview([
    task.description,
    task.note,
    task.publicationUrl,
    task.sourceTitle,
    task.workItemTitle
  ].filter(Boolean).join(' '), 320);
}

function buildArchivePublishSearchBlob(task = {}) {
  return [
    task.title,
    task.status,
    task.priority,
    task.assignedTo,
    task.publicationUrl,
    task.platform,
    task.sourceTitle,
    task.workItemTitle,
    task.category,
    ...(Array.isArray(task.topics) ? task.topics : []),
    task.description,
    task.note
  ].join(' ').replace(/\s+/g, ' ').trim().slice(0, ARCHIVE_SOURCE_TEXT_LIMIT + 4000);
}

function archivePublishTextLength(task = {}) {
  return [task.description, task.note].join('\n').length;
}

function normalizeArchivePublishInput(input = {}, existing = {}) {
  const description = String(input.description ?? existing.description ?? '').trim().slice(0, 30000);
  const note = String(input.note ?? existing.note ?? '').trim().slice(0, 10000);
  const publicationUrl = String(input.publicationUrl ?? input.publication_url ?? existing.publicationUrl ?? '').trim().slice(0, 700);
  const rawTitle = String(input.title ?? existing.title ?? '').trim();
  const title = (rawTitle || publicationUrl || description.slice(0, 120) || 'Başlıksız yayın görevi').trim().slice(0, 180);
  return {
    ...existing,
    title,
    status: normalizeArchivePublishStatus(input.status ?? existing.status),
    priority: normalizeArchivePublishPriority(input.priority ?? existing.priority),
    assignedTo: String(input.assignedTo ?? input.assigned_to ?? existing.assignedTo ?? '').trim().slice(0, 120),
    dueDate: normalizeIsoDate(input.dueDate ?? input.due_date ?? existing.dueDate),
    publishDate: normalizeIsoDate(input.publishDate ?? input.publish_date ?? existing.publishDate),
    publicationUrl,
    platform: String(input.platform ?? existing.platform ?? '').trim().slice(0, 80),
    sourceId: String(input.sourceId ?? input.source_id ?? existing.sourceId ?? '').trim().slice(0, 160),
    sourceTitle: String(input.sourceTitle ?? input.source_title ?? existing.sourceTitle ?? '').trim().slice(0, 220),
    workItemId: String(input.workItemId ?? input.work_item_id ?? existing.workItemId ?? '').trim().slice(0, 160),
    workItemTitle: String(input.workItemTitle ?? input.work_item_title ?? existing.workItemTitle ?? '').trim().slice(0, 220),
    category: String(input.category ?? existing.category ?? '').trim().slice(0, 120),
    topics: normalizeArchiveTags(input.topics ?? existing.topics),
    description,
    note
  };
}

function archivePublishTaskToDbRow(task = {}) {
  return {
    id: task.id,
    title: task.title || '',
    status: task.status || 'planlandi',
    priority: task.priority || 'normal',
    assigned_to: task.assignedTo || '',
    due_date: task.dueDate || null,
    publish_date: task.publishDate || null,
    publication_url: task.publicationUrl || '',
    platform: task.platform || '',
    source_id: task.sourceId || null,
    source_title: task.sourceTitle || '',
    work_item_id: task.workItemId || null,
    work_item_title: task.workItemTitle || '',
    category: task.category || '',
    topics: Array.isArray(task.topics) ? task.topics : [],
    description: task.description || '',
    note: task.note || '',
    text_preview: task.textPreview || buildArchivePublishPreview(task),
    text_length: Number(task.textLength || archivePublishTextLength(task) || 0),
    search_blob: buildArchivePublishSearchBlob(task),
    created_by: task.createdBy || '',
    updated_by: task.updatedBy || '',
    created_at: task.createdAt || new Date().toISOString(),
    updated_at: task.updatedAt || new Date().toISOString()
  };
}

function archivePublishTaskFromDbRow(row = {}, options = {}) {
  return {
    id: row.id,
    title: row.title || '',
    status: row.status || 'planlandi',
    priority: row.priority || 'normal',
    assignedTo: row.assigned_to || '',
    dueDate: row.due_date || null,
    publishDate: row.publish_date || null,
    publicationUrl: row.publication_url || '',
    platform: row.platform || '',
    sourceId: row.source_id || '',
    sourceTitle: row.source_title || '',
    workItemId: row.work_item_id || '',
    workItemTitle: row.work_item_title || '',
    category: row.category || '',
    topics: Array.isArray(row.topics) ? row.topics : [],
    description: options.full ? String(row.description || '') : '',
    note: options.full ? String(row.note || '') : '',
    textPreview: row.text_preview || '',
    textLength: Number(row.text_length || 0),
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null,
    createdBy: row.created_by || '',
    updatedBy: row.updated_by || ''
  };
}

function publicArchivePublishTask(task = {}, options = {}) {
  const base = {
    id: task.id,
    title: task.title,
    status: task.status || 'planlandi',
    priority: task.priority || 'normal',
    assignedTo: task.assignedTo || '',
    dueDate: task.dueDate || null,
    publishDate: task.publishDate || null,
    publicationUrl: task.publicationUrl || '',
    platform: task.platform || '',
    sourceId: task.sourceId || '',
    sourceTitle: task.sourceTitle || '',
    workItemId: task.workItemId || '',
    workItemTitle: task.workItemTitle || '',
    category: task.category || '',
    topics: Array.isArray(task.topics) ? task.topics : [],
    textPreview: task.textPreview || buildArchivePublishPreview(task),
    textLength: Number(task.textLength || archivePublishTextLength(task) || 0),
    createdAt: task.createdAt,
    updatedAt: task.updatedAt,
    createdBy: task.createdBy || '',
    updatedBy: task.updatedBy || ''
  };
  if (options.full) {
    base.description = task.description || '';
    base.note = task.note || '';
  }
  return base;
}

function publicArchiveCandidate(kind = '', record = {}) {
  if (kind === 'source') {
    const source = publicArchiveSource(record);
    return {
      id: `source:${source.id}`,
      kind: 'source',
      recordId: source.id,
      title: source.title || 'Başlıksız kaynak',
      status: source.status || 'arsiv_adayi',
      sourceType: source.sourceType || 'dokuman',
      category: source.category || '',
      topics: Array.isArray(source.tags) ? source.tags : [],
      sourceId: source.id,
      sourceTitle: source.title || '',
      textPreview: source.textPreview || '',
      textLength: Number(source.textLength || 0),
      updatedAt: source.updatedAt || source.createdAt || null,
      createdAt: source.createdAt || null
    };
  }
  if (kind === 'work') {
    const work = publicArchiveWorkItem(record);
    return {
      id: `work:${work.id}`,
      kind: 'work',
      recordId: work.id,
      title: work.title || 'Başlıksız çalışma',
      status: work.status || 'arsiv_adayi',
      priority: work.priority || 'normal',
      assignedTo: work.assignedTo || '',
      category: work.category || '',
      topics: Array.isArray(work.topics) ? work.topics : [],
      sourceId: work.sourceId || '',
      sourceTitle: work.sourceTitle || '',
      textPreview: work.textPreview || '',
      textLength: Number(work.textLength || 0),
      updatedAt: work.updatedAt || work.createdAt || null,
      createdAt: work.createdAt || null
    };
  }
  const task = publicArchivePublishTask(record);
  return {
    id: `publish:${task.id}`,
    kind: 'publish',
    recordId: task.id,
    title: task.title || 'Başlıksız yayın görevi',
    status: task.status || 'arsiv_adayi',
    priority: task.priority || 'normal',
    assignedTo: task.assignedTo || '',
    category: task.category || '',
    topics: Array.isArray(task.topics) ? task.topics : [],
    sourceId: task.sourceId || '',
    sourceTitle: task.sourceTitle || '',
    workItemId: task.workItemId || '',
    workItemTitle: task.workItemTitle || '',
    publicationUrl: task.publicationUrl || '',
    textPreview: task.textPreview || '',
    textLength: Number(task.textLength || 0),
    updatedAt: task.updatedAt || task.createdAt || null,
    createdAt: task.createdAt || null
  };
}

function normalizeArchiveCandidateStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_PUBLIC_CANDIDATE_STATUSES.includes(status) ? status : '';
}

function archiveCandidateDecisionLabel(status = '') {
  return {
    arsiv_adayi: 'Son kontrol bekliyor',
    yayina_hazir: 'Yayına hazır',
    kaynak_eksik: 'Kaynak eksik',
    revizyon_gerekli: 'Revizyon gerekli',
    beklet: 'Beklet'
  }[status] || status || 'Karar yok';
}

function appendArchiveCandidateDecisionNote(existingNote = '', status = '', note = '', actor = 'Sistem') {
  const cleanNote = String(note || '').trim().replace(/\s+/g, ' ').slice(0, 1000);
  const stamp = new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' });
  const decision = `Public arşiv kararı: ${archiveCandidateDecisionLabel(status)}.`;
  const detail = cleanNote ? ` Not: ${cleanNote}` : '';
  const entry = `[${stamp}] ${decision}${detail} Kararı veren: ${actor || 'Sistem'}.`;
  return [entry, String(existingNote || '').trim()].filter(Boolean).join('\n').slice(0, 10000);
}

async function listArchiveCandidateRows(loader, q = '', status = '') {
  const statuses = status ? [status] : ARCHIVE_PUBLIC_CANDIDATE_STATUSES;
  const rows = [];
  const seen = new Set();
  for (const candidateStatus of statuses) {
    const list = await loader({ q, status: candidateStatus });
    for (const row of list.filtered || []) {
      if (!row?.id || seen.has(row.id)) continue;
      seen.add(row.id);
      rows.push(row);
    }
  }
  return rows;
}

async function listArchivePublicCandidates(query = {}) {
  const q = String(query.q || '').trim();
  const requestedKind = String(query.kind || '').trim();
  const kind = ['source', 'work', 'publish'].includes(requestedKind) ? requestedKind : '';
  const status = normalizeArchiveCandidateStatus(query.status);
  const candidates = [];
  const counts = { total: 0, source: 0, work: 0, publish: 0, byStatus: {} };

  if (!kind || kind === 'source') {
    const rows = await listArchiveCandidateRows(listArchiveOpsSources, q, status);
    counts.source = rows.length;
    candidates.push(...rows.map(row => publicArchiveCandidate('source', row)));
  }
  if (!kind || kind === 'work') {
    const rows = await listArchiveCandidateRows(listArchiveWorkItems, q, status);
    counts.work = rows.length;
    candidates.push(...rows.map(row => publicArchiveCandidate('work', row)));
  }
  if (!kind || kind === 'publish') {
    const rows = await listArchiveCandidateRows(listArchivePublishTasks, q, status);
    counts.publish = rows.length;
    candidates.push(...rows.map(row => publicArchiveCandidate('publish', row)));
  }

  candidates.sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
  counts.total = candidates.length;
  for (const candidate of candidates) {
    const key = normalizeArchiveCandidateStatus(candidate.status) || 'diger';
    counts.byStatus[key] = (counts.byStatus[key] || 0) + 1;
  }
  return { counts, candidates: candidates.slice(0, ARCHIVE_SOURCE_LIST_LIMIT) };
}

async function updateArchivePublicCandidateDecision(kind = '', id = '', status = '', note = '', actor = 'Sistem') {
  const nextStatus = normalizeArchiveCandidateStatus(status);
  if (!nextStatus) throw httpError('Geçerli bir public arşiv kararı seçin.', 400);
  if (!id) throw httpError('Karar uygulanacak kayıt bulunamadı.', 400);

  if (kind === 'source') {
    const source = await getArchiveOpsSource(id);
    if (!source) return null;
    const result = await updateArchiveOpsSource(id, {
      ...source,
      status: nextStatus,
      note: appendArchiveCandidateDecisionNote(source.note, nextStatus, note, actor),
      forceSave: true
    }, actor);
    return result?.source ? publicArchiveCandidate('source', result.source) : null;
  }

  if (kind === 'work') {
    const work = await getArchiveWorkItem(id);
    if (!work) return null;
    const updated = await updateArchiveWorkItem(id, {
      ...work,
      status: nextStatus,
      note: appendArchiveCandidateDecisionNote(work.note, nextStatus, note, actor)
    }, actor);
    return updated ? publicArchiveCandidate('work', updated) : null;
  }

  if (kind === 'publish') {
    const task = await getArchivePublishTask(id);
    if (!task) return null;
    const updated = await updateArchivePublishTask(id, {
      ...task,
      status: nextStatus,
      note: appendArchiveCandidateDecisionNote(task.note, nextStatus, note, actor)
    }, actor);
    return updated ? publicArchiveCandidate('publish', updated) : null;
  }

  throw httpError('Geçersiz aday türü.', 400);
}

function normalizeArchiveReleasePackageStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_RELEASE_PACKAGE_STATUSES.includes(status) ? status : 'taslak';
}

function archiveReleasePackageStatusLabel(status = '') {
  return {
    taslak: 'Taslak',
    son_kontrol: 'Son kontrol',
    hazir: 'Hazır',
    beklet: 'Beklet'
  }[status] || status || 'Taslak';
}

function normalizeArchiveReleasePublicationStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_RELEASE_PUBLICATION_STATUSES.includes(status) ? status : 'bekliyor';
}

function archiveReleasePublicationStatusLabel(status = '') {
  return {
    bekliyor: 'Yayın bekliyor',
    yayinda: 'Yayına verildi',
    arsive_aktarildi: 'Public arşive aktarıldı',
    geri_alindi: 'Geri alındı'
  }[status] || 'Yayın bekliyor';
}

function normalizeArchiveReleaseItemReviewStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_RELEASE_PACKAGE_ITEM_REVIEW_STATUSES.includes(status) ? status : 'bekliyor';
}

function archiveReleaseItemReviewStatusLabel(status = '') {
  return {
    bekliyor: 'Kontrol bekliyor',
    kontrol_edildi: 'Kontrol edildi',
    revizyon: 'Revizyon gerekli',
    beklet: 'Beklet'
  }[status] || 'Kontrol bekliyor';
}

function archiveReleaseItemReadiness(item = {}) {
  const topics = Array.isArray(item.topics) ? item.topics.filter(Boolean) : [];
  const textLength = Number(item.textLength || 0);
  const textPreview = String(item.textPreview || '').trim();
  const hasSourceTrace = Boolean(item.sourceTitle || item.sourceId || item.publicationUrl || item.workItemTitle || item.workItemId);
  const checks = [
    { key: 'title', label: 'Başlık', ok: Boolean(String(item.title || '').trim()) && String(item.title || '').trim() !== 'Başlıksız kayıt', severity: 'blocker' },
    { key: 'text', label: 'Metin', ok: textLength > 0 || Boolean(textPreview), severity: 'blocker' },
    { key: 'category', label: 'Kategori', ok: Boolean(String(item.category || '').trim()), severity: 'blocker' },
    { key: 'source', label: 'Kaynak izi', ok: hasSourceTrace, severity: 'blocker' },
    { key: 'topics', label: 'Kavramlar', ok: topics.length > 0, severity: 'warning' }
  ];
  if (item.kind === 'publish') {
    checks.push({ key: 'publicationUrl', label: 'Yayın linki', ok: Boolean(String(item.publicationUrl || '').trim()), severity: 'warning' });
  }
  const blockers = checks.filter(check => !check.ok && check.severity === 'blocker');
  const warnings = checks.filter(check => !check.ok && check.severity !== 'blocker');
  return {
    checks,
    done: checks.filter(check => check.ok).length,
    total: checks.length,
    ready: blockers.length === 0,
    blockers,
    warnings
  };
}

function sanitizeArchiveReleasePackageItem(item = {}) {
  const kind = String(item.kind || '').trim();
  const recordId = String(item.recordId || '').trim();
  if (!['source', 'work', 'publish'].includes(kind) || !recordId) return null;
  const topics = Array.isArray(item.topics)
    ? item.topics.map(topic => String(topic || '').trim()).filter(Boolean).slice(0, 12)
    : [];
  return {
    id: `${kind}:${recordId}`,
    kind,
    recordId,
    title: String(item.title || '').trim().slice(0, 220) || 'Başlıksız kayıt',
    category: String(item.category || '').trim().slice(0, 120),
    topics,
    sourceTitle: String(item.sourceTitle || '').trim().slice(0, 220),
    sourceId: String(item.sourceId || '').trim().slice(0, 80),
    workItemTitle: String(item.workItemTitle || '').trim().slice(0, 220),
    workItemId: String(item.workItemId || '').trim().slice(0, 80),
    publicationUrl: String(item.publicationUrl || '').trim().slice(0, 700),
    textLength: Number(item.textLength || 0) || 0,
    textPreview: archiveTextPreview(item.textPreview || '', 520),
    reviewStatus: normalizeArchiveReleaseItemReviewStatus(item.reviewStatus),
    reviewStatusLabel: archiveReleaseItemReviewStatusLabel(item.reviewStatus),
    reviewNote: String(item.reviewNote || '').trim().slice(0, 1000),
    reviewedAt: String(item.reviewedAt || '').trim().slice(0, 40),
    reviewedBy: String(item.reviewedBy || '').trim().slice(0, 160),
    updatedAt: String(item.updatedAt || '').trim().slice(0, 40),
    createdAt: String(item.createdAt || '').trim().slice(0, 40)
  };
}

function archiveReleasePackageReadiness(pkg = {}) {
  const items = Array.isArray(pkg.items) ? pkg.items.map(sanitizeArchiveReleasePackageItem).filter(Boolean) : [];
  const packageChecks = [
    { key: 'packageTitle', label: 'Paket başlığı', ok: Boolean(String(pkg.title || '').trim()), severity: 'blocker' },
    { key: 'packageItems', label: 'Paket içeriği', ok: items.length > 0, severity: 'blocker' },
    { key: 'packageNote', label: 'Yayın notu', ok: Boolean(String(pkg.note || '').trim()), severity: 'warning' }
  ];
  const itemReviews = items.map(item => ({ itemId: item.id, title: item.title, ...archiveReleaseItemReadiness(item) }));
  const blockers = [
    ...packageChecks.filter(check => !check.ok && check.severity === 'blocker').map(check => ({ scope: 'package', label: check.label })),
    ...itemReviews.flatMap(review => review.blockers.map(check => ({ scope: 'item', itemId: review.itemId, title: review.title, label: check.label })))
  ];
  const warnings = [
    ...packageChecks.filter(check => !check.ok && check.severity !== 'blocker').map(check => ({ scope: 'package', label: check.label })),
    ...itemReviews.flatMap(review => review.warnings.map(check => ({ scope: 'item', itemId: review.itemId, title: review.title, label: check.label })))
  ];
  return {
    ready: blockers.length === 0,
    blockers,
    warnings,
    itemReviews,
    done: packageChecks.filter(check => check.ok).length + itemReviews.reduce((sum, review) => sum + review.done, 0),
    total: packageChecks.length + itemReviews.reduce((sum, review) => sum + review.total, 0)
  };
}

function archiveReleasePackageLockReadiness(pkg = {}) {
  const base = archiveReleasePackageReadiness(pkg);
  const items = Array.isArray(pkg.items) ? pkg.items.map(sanitizeArchiveReleasePackageItem).filter(Boolean) : [];
  const unreviewed = items.filter(item => normalizeArchiveReleaseItemReviewStatus(item.reviewStatus) !== 'kontrol_edildi');
  const reviewBlockers = unreviewed.map(item => ({
    scope: 'item',
    itemId: item.id,
    title: item.title,
    label: 'Paket son kontrolü'
  }));
  return {
    ready: base.ready && reviewBlockers.length === 0,
    blockers: [...base.blockers, ...reviewBlockers],
    warnings: base.warnings,
    reviewedCount: items.length - unreviewed.length,
    itemCount: items.length
  };
}

function normalizeArchiveReleasePackageInput(input = {}, existing = {}) {
  const seen = new Set();
  const items = (Array.isArray(input.items) ? input.items : existing.items || [])
    .map(sanitizeArchiveReleasePackageItem)
    .filter(Boolean)
    .filter(item => {
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    })
    .slice(0, ARCHIVE_RELEASE_PACKAGE_ITEM_LIMIT);
  return {
    title: String(input.title ?? existing.title ?? '').trim().slice(0, 160),
    note: String(input.note ?? existing.note ?? '').trim().slice(0, 2000),
    status: normalizeArchiveReleasePackageStatus(input.status ?? existing.status),
    items
  };
}

function publicArchiveReleasePackage(pkg = {}) {
  const items = Array.isArray(pkg.items) ? pkg.items.map(sanitizeArchiveReleasePackageItem).filter(Boolean) : [];
  const readiness = archiveReleasePackageReadiness({ ...pkg, items });
  const lockReadiness = archiveReleasePackageLockReadiness({ ...pkg, items });
  return {
    id: pkg.id,
    title: pkg.title || 'Başlıksız yayın paketi',
    note: pkg.note || '',
    status: normalizeArchiveReleasePackageStatus(pkg.status),
    statusLabel: archiveReleasePackageStatusLabel(pkg.status),
    itemCount: items.length,
    totalTextLength: items.reduce((sum, item) => sum + Number(item.textLength || 0), 0),
    items,
    readiness,
    lockReadiness,
    locked: Boolean(pkg.locked),
    lockedAt: pkg.lockedAt || null,
    lockedBy: pkg.lockedBy || '',
    publicationStatus: normalizeArchiveReleasePublicationStatus(pkg.publicationStatus),
    publicationStatusLabel: archiveReleasePublicationStatusLabel(pkg.publicationStatus),
    publicationUrl: String(pkg.publicationUrl || '').trim().slice(0, 700),
    publicationNote: String(pkg.publicationNote || '').trim().slice(0, 2000),
    publishedAt: pkg.publishedAt || null,
    publishedBy: pkg.publishedBy || '',
    archivedAt: pkg.archivedAt || null,
    archivedBy: pkg.archivedBy || '',
    withdrawnAt: pkg.withdrawnAt || null,
    withdrawnBy: pkg.withdrawnBy || '',
    publicationUpdatedAt: pkg.publicationUpdatedAt || null,
    publicationUpdatedBy: pkg.publicationUpdatedBy || '',
    createdAt: pkg.createdAt || null,
    updatedAt: pkg.updatedAt || null,
    createdBy: pkg.createdBy || '',
    updatedBy: pkg.updatedBy || ''
  };
}

function archiveReleaseOutputStatus(pkg = {}) {
  const clean = publicArchiveReleasePackage(pkg);
  const blockers = [];
  const lockReadiness = archiveReleasePackageLockReadiness(clean);
  if (!clean.locked) {
    blockers.push({ scope: 'package', label: 'Son hazırlık kilidi', help: 'Çıktı oluşturmak için paket kilitlenmiş olmalı.' });
  }
  if (normalizeArchiveReleasePackageStatus(clean.status) !== 'hazir') {
    blockers.push({ scope: 'package', label: 'Paket durumu', help: 'Çıktı oluşturmak için paket Hazır durumunda olmalı.' });
  }
  blockers.push(...(lockReadiness.blockers || []));
  return {
    ready: blockers.length === 0,
    blockers,
    warnings: lockReadiness.warnings || [],
    itemCount: clean.items.length,
    reviewedCount: lockReadiness.reviewedCount || 0
  };
}

async function loadArchiveReleaseOutputRecord(item = {}) {
  if (item.kind === 'source') {
    const source = await getArchiveOpsSource(item.recordId);
    if (!source) return null;
    const full = publicArchiveSource(source, { full: true });
    return {
      title: full.title || item.title,
      category: full.category || item.category,
      topics: Array.isArray(full.tags) ? full.tags : item.topics || [],
      sourceTitle: full.title || item.sourceTitle,
      sourceUrl: full.sourceUrl || '',
      text: full.sourceText || item.textPreview || '',
      summary: full.note || ''
    };
  }
  if (item.kind === 'work') {
    const work = await getArchiveWorkItem(item.recordId);
    if (!work) return null;
    const full = publicArchiveWorkItem(work, { full: true });
    const sections = [
      full.question ? `Soru:\n${full.question}` : '',
      full.answerDraft ? `Cevap:\n${full.answerDraft}` : ''
    ].filter(Boolean);
    return {
      title: full.title || item.title,
      category: full.category || item.category,
      topics: Array.isArray(full.topics) ? full.topics : item.topics || [],
      sourceTitle: full.sourceTitle || item.sourceTitle,
      sourceUrl: '',
      text: sections.join('\n\n') || full.textPreview || item.textPreview || '',
      summary: full.note || ''
    };
  }
  if (item.kind === 'publish') {
    const task = await getArchivePublishTask(item.recordId);
    if (!task) return null;
    const full = publicArchivePublishTask(task, { full: true });
    return {
      title: full.title || item.title,
      category: full.category || item.category,
      topics: Array.isArray(full.topics) ? full.topics : item.topics || [],
      sourceTitle: full.sourceTitle || item.sourceTitle,
      sourceUrl: full.publicationUrl || item.publicationUrl || '',
      text: full.description || full.textPreview || item.textPreview || '',
      summary: full.note || ''
    };
  }
  return null;
}

async function archiveReleasePackageOutputManifest(pkg = {}) {
  const clean = publicArchiveReleasePackage(pkg);
  const outputStatus = archiveReleaseOutputStatus(clean);
  if (!outputStatus.ready) {
    throw httpError('Paket çıktısı için paket hazır ve kilitli olmalı.', 409);
  }
  const items = [];
  for (const [index, item] of clean.items.entries()) {
    const record = await loadArchiveReleaseOutputRecord(item);
    items.push({
      order: index + 1,
      id: item.id,
      kind: item.kind,
      recordId: item.recordId,
      title: record?.title || item.title,
      category: record?.category || item.category || '',
      topics: Array.isArray(record?.topics) ? record.topics : item.topics || [],
      sourceTitle: record?.sourceTitle || item.sourceTitle || item.workItemTitle || '',
      sourceUrl: record?.sourceUrl || item.publicationUrl || '',
      summary: record?.summary || '',
      text: record?.text || item.textPreview || '',
      textLength: String(record?.text || item.textPreview || '').length,
      reviewStatus: item.reviewStatus,
      reviewedAt: item.reviewedAt || '',
      reviewedBy: item.reviewedBy || '',
      updatedAt: item.updatedAt || ''
    });
  }
  return {
    exportVersion: 1,
    generatedAt: new Date().toISOString(),
    packageId: clean.id,
    title: clean.title,
    status: clean.status,
    statusLabel: clean.statusLabel,
    publicationStatus: clean.publicationStatus,
    publicationStatusLabel: clean.publicationStatusLabel,
    publicationUrl: clean.publicationUrl,
    publicationNote: clean.publicationNote,
    publishedAt: clean.publishedAt,
    archivedAt: clean.archivedAt,
    locked: clean.locked,
    lockedAt: clean.lockedAt,
    lockedBy: clean.lockedBy,
    note: clean.note,
    itemCount: items.length,
    totalTextLength: items.reduce((sum, item) => sum + item.textLength, 0),
    readiness: outputStatus,
    items
  };
}

function archiveReleaseMarkdownMeta(label, value) {
  const text = Array.isArray(value) ? value.filter(Boolean).join(', ') : String(value || '').trim();
  return text ? `- ${label}: ${text}` : '';
}

function archiveReleasePackageOutputMarkdown(manifest = {}) {
  const lines = [
    `# ${manifest.title || 'Yayın Paketi'}`,
    '',
    archiveReleaseMarkdownMeta('Paket ID', manifest.packageId),
    archiveReleaseMarkdownMeta('Durum', manifest.statusLabel),
    archiveReleaseMarkdownMeta('Yayın takibi', manifest.publicationStatusLabel),
    archiveReleaseMarkdownMeta('Yayın linki', manifest.publicationUrl),
    archiveReleaseMarkdownMeta('Yayın notu', manifest.publicationNote),
    archiveReleaseMarkdownMeta('Kilit tarihi', manifest.lockedAt),
    archiveReleaseMarkdownMeta('Kilitleyen', manifest.lockedBy),
    archiveReleaseMarkdownMeta('Oluşturulma', manifest.generatedAt),
    archiveReleaseMarkdownMeta('Kayıt sayısı', manifest.itemCount),
    '',
    manifest.note ? `> ${manifest.note}` : '',
    ''
  ].filter(line => line !== '');
  for (const item of manifest.items || []) {
    lines.push(`## ${item.order}. ${item.title || 'Başlıksız kayıt'}`);
    lines.push('');
    lines.push(archiveReleaseMarkdownMeta('Tür', item.kind));
    lines.push(archiveReleaseMarkdownMeta('Kategori', item.category));
    lines.push(archiveReleaseMarkdownMeta('Kavramlar', item.topics));
    lines.push(archiveReleaseMarkdownMeta('Kaynak', item.sourceTitle));
    lines.push(archiveReleaseMarkdownMeta('Bağlantı', item.sourceUrl));
    lines.push('');
    if (item.summary) {
      lines.push(`Özet: ${item.summary}`);
      lines.push('');
    }
    lines.push(String(item.text || '').trim() || 'Metin yok.');
    lines.push('');
  }
  return lines.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

function csvEscape(value = '') {
  const text = String(value ?? '');
  return /[",\r\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function archiveReleasePackageOutputCsv(manifest = {}) {
  const header = ['order', 'title', 'kind', 'category', 'topics', 'sourceTitle', 'sourceUrl', 'summary', 'text'];
  const rows = (manifest.items || []).map(item => [
    item.order,
    item.title,
    item.kind,
    item.category,
    Array.isArray(item.topics) ? item.topics.join('|') : '',
    item.sourceTitle,
    item.sourceUrl,
    item.summary,
    item.text
  ].map(csvEscape).join(','));
  return [header.join(','), ...rows].join('\n') + '\n';
}

function archiveReleaseOutputFileName(title = 'yayin-paketi', extension = 'json') {
  const slug = String(title || 'yayin-paketi')
    .toLocaleLowerCase('tr-TR')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 72) || 'yayin-paketi';
  return `${slug}.${extension}`;
}

function archivePublicSlugPart(text = '', fallback = 'kayit') {
  const slug = String(text || fallback || 'kayit')
    .toLocaleLowerCase('tr-TR')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/ı/g, 'i')
    .replace(/ğ/g, 'g')
    .replace(/ü/g, 'u')
    .replace(/ş/g, 's')
    .replace(/ö/g, 'o')
    .replace(/ç/g, 'c')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 90);
  return slug || fallback || 'kayit';
}

function estimateArchiveReadTime(text = '') {
  const words = String(text || '').trim().split(/\s+/).filter(Boolean).length;
  const minutes = Math.max(1, Math.ceil(words / 180));
  return { words, minutes, label: `${minutes} dk okuma` };
}

function splitArchiveQuestionAnswer(text = '', fallbackTitle = '') {
  const clean = String(text || '').trim();
  if (!clean) return { question: fallbackTitle || '', answer: '', body: '' };
  const lines = clean.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const questionMarker = lines.findIndex(line => /^(soru|sual)\s*[:：-]/i.test(line));
  const answerMarker = lines.findIndex(line => /^(cevap|yanıt|yanit)\s*[:：-]/i.test(line));
  if (questionMarker >= 0 && answerMarker > questionMarker) {
    const question = lines
      .slice(questionMarker, answerMarker)
      .join('\n')
      .replace(/^(soru|sual)\s*[:：-]\s*/i, '')
      .trim();
    const answer = lines
      .slice(answerMarker)
      .join('\n')
      .replace(/^(cevap|yanıt|yanit)\s*[:：-]\s*/i, '')
      .trim();
    return { question: question || fallbackTitle || '', answer, body: clean };
  }
  const firstQuestionLine = lines.find(line => line.endsWith('?'));
  if (firstQuestionLine && clean.length > firstQuestionLine.length + 20) {
    const answer = clean.slice(clean.indexOf(firstQuestionLine) + firstQuestionLine.length).trim();
    return { question: firstQuestionLine, answer, body: clean };
  }
  return {
    question: fallbackTitle || lines[0] || '',
    answer: clean,
    body: clean
  };
}

function archiveReleasePublicRecordFromItem(item = {}, manifest = {}) {
  const title = String(item.title || item.summary || manifest.title || 'Arşiv kaydı').trim();
  const text = String(item.text || item.summary || '').trim();
  const qa = splitArchiveQuestionAnswer(text, title);
  const summary = String(item.summary || qa.answer || qa.body || '').trim().slice(0, 420);
  const category = String(item.category || 'Genel').trim();
  const topics = normalizeArchiveTopicList(item.topics || []);
  const slugBase = `${title}-${item.kind || 'kayit'}-${item.recordId || item.id || item.order || ''}`;
  return {
    schemaVersion: ARCHIVE_PUBLIC_RECORD_SCHEMA_VERSION,
    id: `${item.kind || 'record'}:${item.recordId || item.id || item.order || archivePublicSlugPart(title)}`,
    slug: archivePublicSlugPart(slugBase),
    sourceRecord: {
      packageId: manifest.id || '',
      packageTitle: manifest.title || '',
      order: item.order || 0,
      kind: item.kind || '',
      recordId: item.recordId || item.id || ''
    },
    title,
    summary,
    question: qa.question,
    answer: qa.answer,
    body: qa.body,
    category,
    topics,
    source: {
      title: item.sourceTitle || '',
      url: item.sourceUrl || '',
      trace: [item.sourceTitle, item.sourceUrl].filter(Boolean).join(' | ')
    },
    publication: {
      packageStatus: manifest.status || '',
      publicationStatus: manifest.publicationStatus || '',
      publicationUrl: manifest.publicationUrl || '',
      publicationNote: manifest.publicationNote || ''
    },
    seo: {
      title,
      description: summary || qa.question || title,
      canonicalPath: `/soru/${archivePublicSlugPart(slugBase)}`
    },
    reading: estimateArchiveReadTime(qa.body || qa.answer),
    updatedAt: manifest.generatedAt || new Date().toISOString()
  };
}

const ARCHIVE_PUBLIC_RECORD_FORBIDDEN_TERMS = [
  { label: 'AI', pattern: /\bAI\b/i },
  { label: 'admin', pattern: /\badmin\b/i },
  { label: 'prompt', pattern: /\bprompt\b/i },
  { label: 'model', pattern: /\bmodel\b/i },
  { label: 'denetim', pattern: /\bdenetim\b/i },
  { label: 'kalite kontrol', pattern: /kalite\s+kontrol/i },
  { label: 'onay kuyrugu', pattern: /onay\s+kuyru[ğg]u/i },
  { label: 'test verisi', pattern: /test\s+verisi/i }
];

function archivePublicIssue(record = {}, type = 'warning', field = '', message = '') {
  return {
    type,
    recordId: record.id || '',
    slug: record.slug || '',
    title: record.title || '',
    field,
    message
  };
}

function archivePublicVisibleFields(record = {}) {
  return [
    ['baslik', record.title],
    ['ozet', record.summary],
    ['soru', record.question],
    ['cevap', record.answer],
    ['metin', record.body],
    ['kategori', record.category],
    ['kavramlar', Array.isArray(record.topics) ? record.topics.join(' ') : record.topics],
    ['kaynak', record.source?.title],
    ['kaynak_izi', record.source?.trace]
  ].map(([field, value]) => [field, String(value || '').trim()]);
}

function archivePublicRecordReadiness(record = {}, slugCounts = new Map()) {
  const blockers = [];
  const warnings = [];
  const title = String(record.title || '').trim();
  const body = String(record.body || record.answer || '').trim();
  const category = String(record.category || '').trim();
  const topics = Array.isArray(record.topics) ? record.topics.filter(Boolean) : [];
  const sourceRecord = record.sourceRecord || {};
  const hasSourceTrace = Boolean(sourceRecord.kind || sourceRecord.recordId || record.source?.title || record.source?.trace || record.source?.url);

  if (!title || title === 'Arsiv kaydi' || title === 'Arşiv kaydı') {
    blockers.push(archivePublicIssue(record, 'blocker', 'title', 'Baslik eksik veya otomatik varsayilan baslik kullaniliyor.'));
  }
  if (!body) {
    blockers.push(archivePublicIssue(record, 'blocker', 'body', 'Public kayit metni bos.'));
  }
  if (!record.slug) {
    blockers.push(archivePublicIssue(record, 'blocker', 'slug', 'Public URL slug olusmadi.'));
  } else if ((slugCounts.get(record.slug) || 0) > 1) {
    blockers.push(archivePublicIssue(record, 'blocker', 'slug', 'Ayni slug birden fazla kayitta kullaniliyor.'));
  }
  if (!hasSourceTrace) {
    blockers.push(archivePublicIssue(record, 'blocker', 'source', 'Kaynak izi bulunamadi.'));
  }

  if (!record.question) warnings.push(archivePublicIssue(record, 'warning', 'question', 'Soru alani ayrismadi; metin arsiv kaydi olarak kalacak.'));
  if (!record.summary || String(record.summary).trim().length < 40) warnings.push(archivePublicIssue(record, 'warning', 'summary', 'Ozet kisa veya eksik gorunuyor.'));
  if (!category || category === 'Genel') warnings.push(archivePublicIssue(record, 'warning', 'category', 'Kategori genel gorunuyor; gerekirse net kategori secilmeli.'));
  if (!topics.length) warnings.push(archivePublicIssue(record, 'warning', 'topics', 'Kavram/etiket bilgisi yok.'));
  if (!record.source?.url) warnings.push(archivePublicIssue(record, 'warning', 'source.url', 'Kaynak linki yok; metin kaynak iziyle yayinlanacak.'));

  for (const [field, value] of archivePublicVisibleFields(record)) {
    if (!value) continue;
    for (const term of ARCHIVE_PUBLIC_RECORD_FORBIDDEN_TERMS) {
      if (term.pattern.test(value)) {
        blockers.push(archivePublicIssue(record, 'blocker', field, `Public kayitta ic surec ifadesi gorunuyor: ${term.label}`));
      }
    }
  }

  return {
    recordId: record.id || '',
    slug: record.slug || '',
    title: record.title || '',
    blockerCount: blockers.length,
    warningCount: warnings.length,
    blockers,
    warnings
  };
}

function validateArchivePublicRecords(records = []) {
  const slugCounts = new Map();
  for (const record of records) {
    if (!record?.slug) continue;
    slugCounts.set(record.slug, (slugCounts.get(record.slug) || 0) + 1);
  }
  const recordReports = records.map(record => archivePublicRecordReadiness(record, slugCounts));
  const blockers = recordReports.flatMap(report => report.blockers);
  const warnings = recordReports.flatMap(report => report.warnings);
  return {
    ready: blockers.length === 0,
    recordCount: records.length,
    blockerCount: blockers.length,
    warningCount: warnings.length,
    blockers,
    warnings,
    records: recordReports
  };
}

function archiveReleasePackagePublicRecords(manifest = {}) {
  const records = (manifest.items || []).map(item => archiveReleasePublicRecordFromItem(item, manifest));
  const readiness = validateArchivePublicRecords(records);
  return {
    schemaVersion: ARCHIVE_PUBLIC_RECORD_SCHEMA_VERSION,
    generatedAt: manifest.generatedAt || new Date().toISOString(),
    package: {
      id: manifest.id || '',
      title: manifest.title || '',
      status: manifest.status || '',
      itemCount: records.length,
      publicationStatus: manifest.publicationStatus || '',
      publicationUrl: manifest.publicationUrl || ''
    },
    contract: {
      purpose: 'public_archive_frontend',
      language: 'tr',
      excludesInternalWorkflow: true,
      excludes: ['AI', 'admin', 'prompt', 'model', 'denetim', 'kalite kontrol', 'onay kuyrugu', 'test verisi'],
      recordFields: ['id', 'slug', 'title', 'summary', 'question', 'answer', 'body', 'category', 'topics', 'source', 'publication', 'seo', 'reading', 'updatedAt']
    },
    readiness,
    records
  };
}

async function getArchiveReleasePackageOutput(id = '', format = 'json') {
  const packages = await loadArchiveReleasePackages();
  const pkg = packages.find(item => item.id === id);
  if (!pkg) return null;
  const manifest = await archiveReleasePackageOutputManifest(pkg);
  const normalizedFormat = ['json', 'markdown', 'csv', 'public-json'].includes(String(format || '').trim()) ? String(format || '').trim() : 'json';
  if (normalizedFormat === 'markdown') {
    return {
      format: 'markdown',
      contentType: 'text/markdown; charset=utf-8',
      filename: archiveReleaseOutputFileName(manifest.title, 'md'),
      content: archiveReleasePackageOutputMarkdown(manifest),
      manifest
    };
  }
  if (normalizedFormat === 'csv') {
    return {
      format: 'csv',
      contentType: 'text/csv; charset=utf-8',
      filename: archiveReleaseOutputFileName(manifest.title, 'csv'),
      content: archiveReleasePackageOutputCsv(manifest),
      manifest
    };
  }
  if (normalizedFormat === 'public-json') {
    const publicRecords = archiveReleasePackagePublicRecords(manifest);
    const blocked = !publicRecords.readiness.ready;
    return {
      format: 'public-json',
      contentType: 'application/json; charset=utf-8',
      filename: archiveReleaseOutputFileName(`${manifest.title || 'yayin-paketi'}-public-kayitlar`, 'json'),
      content: blocked ? '' : JSON.stringify(publicRecords, null, 2),
      manifest,
      publicRecords,
      publicReadiness: publicRecords.readiness,
      blocked
    };
  }
  return {
    format: 'json',
    contentType: 'application/json; charset=utf-8',
    filename: archiveReleaseOutputFileName(manifest.title, 'json'),
    content: JSON.stringify(manifest, null, 2),
    manifest
  };
}

async function loadArchiveReleasePackages() {
  const packages = await loadJsonSetting(ARCHIVE_OPS_RELEASE_PACKAGES_KEY, []);
  return Array.isArray(packages) ? packages : [];
}

async function saveArchiveReleasePackages(packages = []) {
  const clean = Array.isArray(packages)
    ? packages.map(publicArchiveReleasePackage).slice(0, ARCHIVE_RELEASE_PACKAGE_LIMIT)
    : [];
  await saveJsonSetting(ARCHIVE_OPS_RELEASE_PACKAGES_KEY, clean);
}

function filterArchiveReleasePackages(packages = [], query = {}) {
  const q = String(query.q || '').trim().toLocaleLowerCase('tr-TR');
  const status = normalizeArchiveReleasePackageStatus(query.status || '');
  const hasStatusFilter = String(query.status || '').trim();
  return packages.filter(pkg => {
    if (hasStatusFilter && normalizeArchiveReleasePackageStatus(pkg.status) !== status) return false;
    if (!q) return true;
    const blob = [
      pkg.title,
      pkg.note,
      pkg.status,
      ...(Array.isArray(pkg.items) ? pkg.items.flatMap(item => [
        item.title,
        item.category,
        item.sourceTitle,
        item.workItemTitle,
        item.publicationUrl,
        item.textPreview,
        ...(Array.isArray(item.topics) ? item.topics : [])
      ]) : [])
    ].join(' ').replace(/\s+/g, ' ').toLocaleLowerCase('tr-TR');
    return blob.includes(q);
  });
}

async function listArchiveReleasePackages(query = {}) {
  const packages = await loadArchiveReleasePackages();
  const filtered = filterArchiveReleasePackages(packages, query)
    .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
  const counts = {
    total: packages.length,
    filtered: filtered.length,
    byStatus: {}
  };
  for (const pkg of packages) {
    const key = normalizeArchiveReleasePackageStatus(pkg.status);
    counts.byStatus[key] = (counts.byStatus[key] || 0) + 1;
  }
  return { counts, packages: filtered.map(publicArchiveReleasePackage) };
}

async function createArchiveReleasePackage(input = {}, actor = 'Sistem') {
  const clean = normalizeArchiveReleasePackageInput(input);
  if (!clean.title) throw httpError('Yayın paketi için başlık gerekli.', 400);
  if (clean.status === 'hazir' && !archiveReleasePackageReadiness(clean).ready) {
    throw httpError('Paket hazır durumuna alınamaz. Eksik alanları kontrol edin.', 400);
  }
  const now = new Date().toISOString();
  const pkg = {
    id: archiveReleasePackageId(),
    ...clean,
    createdAt: now,
    updatedAt: now,
    createdBy: actor,
    updatedBy: actor
  };
  const packages = await loadArchiveReleasePackages();
  await saveArchiveReleasePackages([pkg, ...packages]);
  return publicArchiveReleasePackage(pkg);
}

async function updateArchiveReleasePackage(id = '', input = {}, actor = 'Sistem') {
  const packages = await loadArchiveReleasePackages();
  const index = packages.findIndex(pkg => pkg.id === id);
  if (index < 0) return null;
  const existing = packages[index];
  if (existing.locked) {
    throw httpError('Bu yayın paketi son hazırlık için kilitli. Düzenlemek için önce kilidi kaldırın.', 409);
  }
  const clean = normalizeArchiveReleasePackageInput(input, existing);
  if (!clean.title) throw httpError('Yayın paketi için başlık gerekli.', 400);
  if (clean.status === 'hazir' && !archiveReleasePackageReadiness(clean).ready) {
    throw httpError('Paket hazır durumuna alınamaz. Eksik alanları kontrol edin.', 400);
  }
  const updated = {
    ...existing,
    ...clean,
    updatedAt: new Date().toISOString(),
    updatedBy: actor
  };
  packages[index] = updated;
  await saveArchiveReleasePackages(packages);
  return publicArchiveReleasePackage(updated);
}

async function updateArchiveReleasePackageItemReview(packageId = '', itemId = '', input = {}, actor = 'Sistem') {
  const packages = await loadArchiveReleasePackages();
  const index = packages.findIndex(pkg => pkg.id === packageId);
  if (index < 0) return null;
  const existing = packages[index];
  if (existing.locked) {
    throw httpError('Bu yayın paketi son hazırlık için kilitli. Kayıt kontrolünü değiştirmek için önce kilidi kaldırın.', 409);
  }
  const items = Array.isArray(existing.items) ? existing.items.map(sanitizeArchiveReleasePackageItem).filter(Boolean) : [];
  const itemIndex = items.findIndex(item => item.id === itemId);
  if (itemIndex < 0) throw httpError('Paket içindeki kayıt bulunamadı.', 404);
  const now = new Date().toISOString();
  items[itemIndex] = {
    ...items[itemIndex],
    reviewStatus: normalizeArchiveReleaseItemReviewStatus(input.status),
    reviewStatusLabel: archiveReleaseItemReviewStatusLabel(input.status),
    reviewNote: String(input.note || '').trim().slice(0, 1000),
    reviewedAt: now,
    reviewedBy: actor
  };
  const updated = {
    ...existing,
    items,
    updatedAt: now,
    updatedBy: actor
  };
  packages[index] = updated;
  await saveArchiveReleasePackages(packages);
  return publicArchiveReleasePackage(updated);
}

async function lockArchiveReleasePackage(id = '', actor = 'Sistem') {
  const packages = await loadArchiveReleasePackages();
  const index = packages.findIndex(pkg => pkg.id === id);
  if (index < 0) return null;
  const existing = publicArchiveReleasePackage(packages[index]);
  if (existing.locked) return existing;
  const lockReadiness = archiveReleasePackageLockReadiness(existing);
  if (!lockReadiness.ready) {
    throw httpError('Paket kilitlenemez. Önce paket eksiklerini tamamlayın ve paketteki her kaydı kontrol edildi olarak işaretleyin.', 400);
  }
  const now = new Date().toISOString();
  const updated = {
    ...existing,
    status: 'hazir',
    locked: true,
    lockedAt: now,
    lockedBy: actor,
    updatedAt: now,
    updatedBy: actor
  };
  packages[index] = updated;
  await saveArchiveReleasePackages(packages);
  return publicArchiveReleasePackage(updated);
}

async function unlockArchiveReleasePackage(id = '', actor = 'Sistem') {
  const packages = await loadArchiveReleasePackages();
  const index = packages.findIndex(pkg => pkg.id === id);
  if (index < 0) return null;
  const existing = packages[index];
  const updated = {
    ...existing,
    locked: false,
    lockedAt: null,
    lockedBy: '',
    status: normalizeArchiveReleasePackageStatus(existing.status) === 'hazir' ? 'son_kontrol' : normalizeArchiveReleasePackageStatus(existing.status),
    updatedAt: new Date().toISOString(),
    updatedBy: actor
  };
  packages[index] = updated;
  await saveArchiveReleasePackages(packages);
  return publicArchiveReleasePackage(updated);
}

async function updateArchiveReleasePackagePublication(id = '', input = {}, actor = 'Sistem') {
  const packages = await loadArchiveReleasePackages();
  const index = packages.findIndex(pkg => pkg.id === id);
  if (index < 0) return null;
  const existing = publicArchiveReleasePackage(packages[index]);
  const status = normalizeArchiveReleasePublicationStatus(input.status);
  const outputStatus = archiveReleaseOutputStatus(existing);
  if (['yayinda', 'arsive_aktarildi'].includes(status) && !outputStatus.ready) {
    throw httpError('Paket yayın takibine alınamaz. Önce paket hazır, kilitli ve son kontrolü tamamlanmış olmalı.', 409);
  }
  const now = new Date().toISOString();
  const updated = {
    ...existing,
    publicationStatus: status,
    publicationStatusLabel: archiveReleasePublicationStatusLabel(status),
    publicationUrl: String(input.publicationUrl ?? existing.publicationUrl ?? '').trim().slice(0, 700),
    publicationNote: String(input.publicationNote ?? existing.publicationNote ?? '').trim().slice(0, 2000),
    publicationUpdatedAt: now,
    publicationUpdatedBy: actor,
    updatedAt: now,
    updatedBy: actor
  };
  if (status === 'yayinda') {
    updated.publishedAt = existing.publishedAt || now;
    updated.publishedBy = existing.publishedBy || actor;
  }
  if (status === 'arsive_aktarildi') {
    updated.publishedAt = existing.publishedAt || now;
    updated.publishedBy = existing.publishedBy || actor;
    updated.archivedAt = existing.archivedAt || now;
    updated.archivedBy = existing.archivedBy || actor;
  }
  if (status === 'geri_alindi') {
    updated.withdrawnAt = existing.withdrawnAt || now;
    updated.withdrawnBy = existing.withdrawnBy || actor;
  }
  packages[index] = updated;
  await saveArchiveReleasePackages(packages);
  return publicArchiveReleasePackage(updated);
}

async function deleteArchiveReleasePackage(id = '') {
  const packages = await loadArchiveReleasePackages();
  const existing = packages.find(pkg => pkg.id === id);
  if (existing?.locked) {
    throw httpError('Bu yayın paketi son hazırlık için kilitli. Silmek için önce kilidi kaldırın.', 409);
  }
  const next = packages.filter(pkg => pkg.id !== id);
  if (next.length === packages.length) return null;
  await saveArchiveReleasePackages(next);
  return { id };
}

async function loadArchivePublishTasks() {
  const tasks = await loadJsonSetting(ARCHIVE_OPS_PUBLISH_TASKS_KEY, []);
  return Array.isArray(tasks) ? tasks : [];
}

async function saveArchivePublishTasks(tasks) {
  const clean = Array.isArray(tasks) ? tasks.slice(0, ARCHIVE_PUBLISH_TASK_LIMIT) : [];
  await saveJsonSetting(ARCHIVE_OPS_PUBLISH_TASKS_KEY, clean);
}

function filterArchivePublishTasks(tasks = [], query = {}) {
  const q = String(query.q || '').trim().toLocaleLowerCase('tr-TR');
  const status = String(query.status || '').trim();
  const priority = String(query.priority || '').trim();
  return tasks.filter(task => {
    if (status && task.status !== status) return false;
    if (priority && task.priority !== priority) return false;
    if (!q) return true;
    return buildArchivePublishSearchBlob(task).toLocaleLowerCase('tr-TR').includes(q);
  });
}

async function listArchivePublishTasks(query = {}) {
  if (!HAS_ARCHIVE_PUBLISH_TABLES) {
    const tasks = await loadArchivePublishTasks();
    const filtered = filterArchivePublishTasks(tasks, query)
      .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
    return { storage: 'settings', tasks, filtered };
  }

  const q = String(query.q || '').trim();
  const status = String(query.status || '').trim();
  const priority = String(query.priority || '').trim();
  let taskQuery = supabase
    .from('archive_publish_tasks')
    .select(ARCHIVE_PUBLISH_TASK_DB_LIST_COLUMNS, { count: 'exact' })
    .order('updated_at', { ascending: false })
    .limit(ARCHIVE_PUBLISH_TASK_LIMIT);
  if (status) taskQuery = taskQuery.eq('status', status);
  if (priority) taskQuery = taskQuery.eq('priority', priority);
  if (q) taskQuery = taskQuery.ilike('search_blob', `%${escapeSupabaseLikePattern(q)}%`);
  const { data, error, count } = await taskQuery;
  if (error) throw new Error(error.message);

  const { count: totalCount, error: totalError } = await supabase
    .from('archive_publish_tasks')
    .select('id', { count: 'exact', head: true });
  if (totalError) throw new Error(totalError.message);

  const rowsForCounts = await fetchAllPages(() => supabase.from('archive_publish_tasks').select('status,priority'));
  const counts = {
    total: totalCount || 0,
    filtered: count || 0,
    byStatus: {},
    byPriority: {}
  };
  for (const row of rowsForCounts) {
    counts.byStatus[row.status || 'planlandi'] = (counts.byStatus[row.status || 'planlandi'] || 0) + 1;
    counts.byPriority[row.priority || 'normal'] = (counts.byPriority[row.priority || 'normal'] || 0) + 1;
  }
  return {
    storage: 'database',
    counts,
    filtered: (data || []).map(row => archivePublishTaskFromDbRow(row)),
    tasks: []
  };
}

async function getArchivePublishTask(id) {
  if (!HAS_ARCHIVE_PUBLISH_TABLES) {
    const tasks = await loadArchivePublishTasks();
    return tasks.find(task => task.id === id) || null;
  }
  const { data, error } = await supabase
    .from('archive_publish_tasks')
    .select(ARCHIVE_PUBLISH_TASK_DB_FULL_COLUMNS)
    .eq('id', id)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data ? archivePublishTaskFromDbRow(data, { full: true }) : null;
}

async function createArchivePublishTask(input = {}, actor = 'Sistem') {
  const now = new Date().toISOString();
  const task = {
    id: archivePublishTaskId(),
    ...normalizeArchivePublishInput(input),
    createdAt: now,
    updatedAt: now,
    createdBy: actor,
    updatedBy: actor
  };
  task.textPreview = buildArchivePublishPreview(task);
  task.textLength = archivePublishTextLength(task);

  if (!HAS_ARCHIVE_PUBLISH_TABLES) {
    const tasks = await loadArchivePublishTasks();
    await saveArchivePublishTasks([task, ...tasks]);
    return task;
  }

  const { data, error } = await supabase
    .from('archive_publish_tasks')
    .insert(archivePublishTaskToDbRow(task))
    .select(ARCHIVE_PUBLISH_TASK_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  return archivePublishTaskFromDbRow(data, { full: true });
}

async function updateArchivePublishTask(id, input = {}, actor = 'Sistem') {
  if (!HAS_ARCHIVE_PUBLISH_TABLES) {
    const tasks = await loadArchivePublishTasks();
    const index = tasks.findIndex(task => task.id === id);
    if (index < 0) return null;
    const updated = {
      ...normalizeArchivePublishInput(input, tasks[index]),
      id: tasks[index].id,
      createdAt: tasks[index].createdAt,
      createdBy: tasks[index].createdBy,
      updatedAt: new Date().toISOString(),
      updatedBy: actor
    };
    updated.textPreview = buildArchivePublishPreview(updated);
    updated.textLength = archivePublishTextLength(updated);
    tasks[index] = updated;
    await saveArchivePublishTasks(tasks);
    return updated;
  }

  const existing = await getArchivePublishTask(id);
  if (!existing) return null;
  const updated = {
    ...normalizeArchivePublishInput(input, existing),
    id: existing.id,
    createdAt: existing.createdAt,
    createdBy: existing.createdBy,
    updatedAt: new Date().toISOString(),
    updatedBy: actor
  };
  updated.textPreview = buildArchivePublishPreview(updated);
  updated.textLength = archivePublishTextLength(updated);
  const { data, error } = await supabase
    .from('archive_publish_tasks')
    .update(archivePublishTaskToDbRow(updated))
    .eq('id', id)
    .select(ARCHIVE_PUBLISH_TASK_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  return archivePublishTaskFromDbRow(data, { full: true });
}

async function deleteArchivePublishTask(id) {
  if (!HAS_ARCHIVE_PUBLISH_TABLES) {
    const tasks = await loadArchivePublishTasks();
    const next = tasks.filter(task => task.id !== id);
    if (next.length === tasks.length) return null;
    await saveArchivePublishTasks(next);
    return { id };
  }
  const { data, error } = await supabase
    .from('archive_publish_tasks')
    .delete()
    .eq('id', id)
    .select('id')
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data || null;
}

function archiveImportBatchId() {
  return `aib-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function archiveImportItemId() {
  return `aii-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeArchiveImportBatchStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_IMPORT_BATCH_STATUSES.includes(status) ? status : 'open';
}

function normalizeArchiveImportItemStatus(value) {
  const status = String(value || '').trim();
  return ARCHIVE_IMPORT_ITEM_STATUSES.includes(status) ? status : 'extracted';
}

function archiveImportExtension(name = '') {
  const clean = String(name || '').trim().toLocaleLowerCase('tr-TR');
  const parts = clean.split('.');
  return parts.length > 1 ? parts.pop().slice(0, 20) : '';
}

function archiveImportBaseTitle(name = '') {
  return String(name || 'Kaynak dosyası').replace(/\.[^.]+$/, '').trim().slice(0, 180) || 'Kaynak dosyası';
}

function archiveImportTextHash(text = '') {
  const comparable = archiveComparableText(text);
  return comparable ? textHash(comparable) : '';
}

function requireArchiveImportTables() {
  if (!HAS_ARCHIVE_IMPORT_TABLES) {
    throw httpError('Kalıcı içe aktarım tabloları henüz kurulmadı. Supabase SQL uygulandıktan sonra bu alan aktif olur.', 503);
  }
}

function archiveImportBatchToDbRow(batch = {}) {
  return {
    id: batch.id,
    title: batch.title || '',
    status: batch.status || 'open',
    note: batch.note || '',
    created_by: batch.createdBy || '',
    updated_by: batch.updatedBy || '',
    created_at: batch.createdAt || new Date().toISOString(),
    updated_at: batch.updatedAt || new Date().toISOString()
  };
}

function archiveImportBatchFromDbRow(row = {}, counts = {}) {
  return {
    id: row.id,
    title: row.title || '',
    status: row.status || 'open',
    note: row.note || '',
    createdBy: row.created_by || '',
    updatedBy: row.updated_by || '',
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null,
    counts: counts[row.id] || { total: 0, extracted: 0, review: 0, form: 0, source_created: 0, skipped: 0, error: 0 }
  };
}

function normalizeArchiveImportBatchInput(input = {}, existing = {}) {
  const title = String(input.title ?? existing.title ?? '').trim().slice(0, 180);
  if (!title) throw httpError('İçe aktarım listesi için başlık gerekli.', 400);
  return {
    ...existing,
    title,
    status: normalizeArchiveImportBatchStatus(input.status ?? existing.status),
    note: String(input.note ?? existing.note ?? '').trim().slice(0, 1200)
  };
}

function archiveImportItemToDbRow(item = {}) {
  return {
    id: item.id,
    batch_id: item.batchId,
    file_name: item.fileName || '',
    file_extension: item.fileExtension || archiveImportExtension(item.fileName),
    file_size: Number(item.fileSize || 0),
    source_type: item.sourceType || 'dokuman',
    status: item.status || 'extracted',
    title: item.title || '',
    category: item.category || '',
    tags: Array.isArray(item.tags) ? item.tags : [],
    note: item.note || '',
    extracted_text: item.extractedText || '',
    text_preview: archiveTextPreview(item.extractedText || '', 360),
    text_length: String(item.extractedText || '').length,
    text_hash: item.textHash || archiveImportTextHash(item.extractedText),
    source_id: item.sourceId || null,
    error_message: item.errorMessage || '',
    created_by: item.createdBy || '',
    updated_by: item.updatedBy || '',
    created_at: item.createdAt || new Date().toISOString(),
    updated_at: item.updatedAt || new Date().toISOString()
  };
}

function archiveImportItemFromDbRow(row = {}, options = {}) {
  const extractedText = options.full ? String(row.extracted_text || '') : '';
  return {
    id: row.id,
    batchId: row.batch_id,
    fileName: row.file_name || '',
    fileExtension: row.file_extension || '',
    fileSize: Number(row.file_size || 0),
    sourceType: row.source_type || 'dokuman',
    status: row.status || 'extracted',
    title: row.title || '',
    category: row.category || '',
    tags: Array.isArray(row.tags) ? row.tags : [],
    note: row.note || '',
    extractedText,
    textPreview: row.text_preview || archiveTextPreview(extractedText, 360),
    textLength: Number(row.text_length || extractedText.length || 0),
    textHash: row.text_hash || '',
    sourceId: row.source_id || '',
    errorMessage: row.error_message || '',
    createdBy: row.created_by || '',
    updatedBy: row.updated_by || '',
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null
  };
}

function normalizeArchiveImportItemInput(input = {}, existing = {}) {
  const fileName = String(input.fileName ?? input.name ?? existing.fileName ?? '').trim().slice(0, 240);
  const extractedText = String(input.extractedText ?? input.text ?? existing.extractedText ?? '').trim();
  if (!fileName) throw httpError('Dosya adı gerekli.', 400);
  const nextStatus = normalizeArchiveImportItemStatus(input.status ?? existing.status);
  if (!extractedText && !['error', 'skipped'].includes(nextStatus)) {
    throw httpError('İçe aktarılacak metin gerekli.', 400);
  }
  if (extractedText.length > ARCHIVE_SOURCE_TEXT_LIMIT) {
    throw httpError('İçe aktarılan metin 200.000 karakter sınırını aşıyor.', 413);
  }
  const title = String(input.title ?? existing.title ?? archiveImportBaseTitle(fileName)).trim().slice(0, 180) || archiveImportBaseTitle(fileName);
  return {
    ...existing,
    fileName,
    fileExtension: String(input.fileExtension ?? input.extension ?? existing.fileExtension ?? archiveImportExtension(fileName)).trim().slice(0, 20),
    fileSize: Number(input.fileSize ?? input.size ?? existing.fileSize ?? 0),
    sourceType: normalizeArchiveSourceType(input.sourceType ?? existing.sourceType),
    status: nextStatus,
    title,
    category: String(input.category ?? existing.category ?? '').trim().slice(0, 120),
    tags: normalizeArchiveTags(input.tags ?? existing.tags),
    note: String(input.note ?? existing.note ?? '').trim().slice(0, 1600),
    extractedText,
    textHash: archiveImportTextHash(extractedText),
    sourceId: input.sourceId ?? existing.sourceId ?? null,
    errorMessage: String(input.errorMessage ?? existing.errorMessage ?? '').trim().slice(0, 800)
  };
}

function publicArchiveImportItem(item = {}, options = {}) {
  const base = {
    id: item.id,
    batchId: item.batchId,
    fileName: item.fileName,
    fileExtension: item.fileExtension,
    fileSize: item.fileSize,
    sourceType: item.sourceType,
    status: item.status,
    title: item.title,
    category: item.category,
    tags: item.tags || [],
    note: item.note || '',
    textPreview: item.textPreview || archiveTextPreview(item.extractedText || '', 360),
    textLength: item.textLength || String(item.extractedText || '').length,
    sourceId: item.sourceId || '',
    errorMessage: item.errorMessage || '',
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    createdBy: item.createdBy || '',
    updatedBy: item.updatedBy || ''
  };
  if (options.full) base.extractedText = item.extractedText || '';
  return base;
}

async function listArchiveImportBatches() {
  requireArchiveImportTables();
  const { data, error } = await supabase
    .from('archive_import_batches')
    .select(ARCHIVE_IMPORT_BATCH_DB_COLUMNS)
    .order('updated_at', { ascending: false })
    .limit(ARCHIVE_IMPORT_BATCH_LIMIT);
  if (error) throw new Error(error.message);

  const batchIds = (data || []).map(row => row.id);
  const counts = {};
  for (const id of batchIds) {
    counts[id] = { total: 0, extracted: 0, review: 0, form: 0, source_created: 0, skipped: 0, error: 0 };
  }
  if (batchIds.length) {
    const { data: rows, error: itemError } = await supabase
      .from('archive_import_items')
      .select('batch_id,status')
      .in('batch_id', batchIds);
    if (itemError) throw new Error(itemError.message);
    for (const row of rows || []) {
      const bucket = counts[row.batch_id];
      if (!bucket) continue;
      bucket.total += 1;
      const status = normalizeArchiveImportItemStatus(row.status);
      bucket[status] = (bucket[status] || 0) + 1;
    }
  }
  return (data || []).map(row => archiveImportBatchFromDbRow(row, counts));
}

async function createArchiveImportBatch(input = {}, actor = 'Sistem') {
  requireArchiveImportTables();
  const now = new Date().toISOString();
  const batch = {
    id: archiveImportBatchId(),
    ...normalizeArchiveImportBatchInput(input),
    createdAt: now,
    updatedAt: now,
    createdBy: actor,
    updatedBy: actor
  };
  const { data, error } = await supabase
    .from('archive_import_batches')
    .insert(archiveImportBatchToDbRow(batch))
    .select(ARCHIVE_IMPORT_BATCH_DB_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  return archiveImportBatchFromDbRow(data);
}

async function getArchiveImportBatch(batchId) {
  requireArchiveImportTables();
  const { data: batchRow, error: batchError } = await supabase
    .from('archive_import_batches')
    .select(ARCHIVE_IMPORT_BATCH_DB_COLUMNS)
    .eq('id', batchId)
    .maybeSingle();
  if (batchError) throw new Error(batchError.message);
  if (!batchRow) return null;
  const { data: itemRows, error: itemError } = await supabase
    .from('archive_import_items')
    .select(ARCHIVE_IMPORT_ITEM_DB_FULL_COLUMNS)
    .eq('batch_id', batchId)
    .order('updated_at', { ascending: false })
    .limit(ARCHIVE_IMPORT_ITEM_LIMIT);
  if (itemError) throw new Error(itemError.message);
  const batch = archiveImportBatchFromDbRow(batchRow);
  const items = (itemRows || []).map(row => archiveImportItemFromDbRow(row, { full: true }));
  batch.counts = items.reduce((acc, item) => {
    acc.total += 1;
    acc[item.status] = (acc[item.status] || 0) + 1;
    return acc;
  }, { total: 0, extracted: 0, review: 0, form: 0, source_created: 0, skipped: 0, error: 0 });
  return { batch, items };
}

async function createArchiveImportItem(batchId, input = {}, actor = 'Sistem') {
  requireArchiveImportTables();
  const batch = await getArchiveImportBatch(batchId);
  if (!batch) return null;
  const now = new Date().toISOString();
  const item = {
    id: archiveImportItemId(),
    batchId,
    ...normalizeArchiveImportItemInput(input),
    createdAt: now,
    updatedAt: now,
    createdBy: actor,
    updatedBy: actor
  };
  const { data, error } = await supabase
    .from('archive_import_items')
    .insert(archiveImportItemToDbRow(item))
    .select(ARCHIVE_IMPORT_ITEM_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  await supabase.from('archive_import_batches').update({ updated_at: now, updated_by: actor }).eq('id', batchId);
  return archiveImportItemFromDbRow(data, { full: true });
}

async function updateArchiveImportItem(itemId, input = {}, actor = 'Sistem') {
  requireArchiveImportTables();
  const { data: existingRow, error: existingError } = await supabase
    .from('archive_import_items')
    .select(ARCHIVE_IMPORT_ITEM_DB_FULL_COLUMNS)
    .eq('id', itemId)
    .maybeSingle();
  if (existingError) throw new Error(existingError.message);
  if (!existingRow) return null;
  const existing = archiveImportItemFromDbRow(existingRow, { full: true });
  const now = new Date().toISOString();
  const updated = {
    ...normalizeArchiveImportItemInput(input, existing),
    id: existing.id,
    batchId: existing.batchId,
    createdAt: existing.createdAt,
    createdBy: existing.createdBy,
    updatedAt: now,
    updatedBy: actor
  };
  const { data, error } = await supabase
    .from('archive_import_items')
    .update(archiveImportItemToDbRow(updated))
    .eq('id', itemId)
    .select(ARCHIVE_IMPORT_ITEM_DB_FULL_COLUMNS)
    .single();
  if (error) throw new Error(error.message);
  await supabase.from('archive_import_batches').update({ updated_at: now, updated_by: actor }).eq('id', existing.batchId);
  return archiveImportItemFromDbRow(data, { full: true });
}

async function deleteArchiveImportItem(itemId, actor = 'Sistem') {
  requireArchiveImportTables();
  const { data: existingRow, error: existingError } = await supabase
    .from('archive_import_items')
    .select('id,batch_id')
    .eq('id', itemId)
    .maybeSingle();
  if (existingError) throw new Error(existingError.message);
  if (!existingRow) return null;
  const { error } = await supabase
    .from('archive_import_items')
    .delete()
    .eq('id', itemId);
  if (error) throw new Error(error.message);
  await supabase
    .from('archive_import_batches')
    .update({ updated_at: new Date().toISOString(), updated_by: actor })
    .eq('id', existingRow.batch_id);
  return { id: existingRow.id, batchId: existingRow.batch_id };
}

function filterArchiveSources(sources, query = {}) {
  const q = String(query.q || '').trim().toLocaleLowerCase('tr-TR');
  const type = String(query.type || '').trim();
  const types = normalizeArchiveSourceTypes(query.types);
  if (ARCHIVE_SOURCE_TYPES.includes(type) && !types.includes(type)) types.push(type);
  const status = String(query.status || '').trim();
  return sources.filter(source => {
    if (types.length && !types.includes(source.sourceType)) return false;
    if (status && source.status !== status) return false;
    if (!q) return true;
    const haystack = [
      source.title,
      source.category,
      source.note,
      source.sourceUrl,
      ...(Array.isArray(source.tags) ? source.tags : []),
      source.sourceText
    ].join(' ').toLocaleLowerCase('tr-TR');
    return haystack.includes(q);
  });
}

function loadCorrectionPackagesFromValue(value) {
  return Array.isArray(value) ? value : [];
}

async function loadCorrectionPackages() {
  return loadCorrectionPackagesFromValue(await loadJsonSetting(CORRECTION_PACKAGE_SETTING_KEY, []));
}

async function saveCorrectionPackages(packages) {
  await saveJsonSetting(CORRECTION_PACKAGE_SETTING_KEY, loadCorrectionPackagesFromValue(packages));
}

function normalizeCorrectionFields(fields) {
  const list = Array.isArray(fields) ? fields : CORRECTION_DEFAULT_FIELDS;
  const clean = [...new Set(list.map(String).filter(field => CORRECTION_ALLOWED_FIELDS.includes(field)))];
  return clean.length ? clean : [...CORRECTION_DEFAULT_FIELDS];
}

function normalizeCorrectionStatuses(statuses) {
  const list = Array.isArray(statuses) ? statuses : CORRECTION_DEFAULT_STATUSES;
  const clean = [...new Set(list.map(String).filter(status => CORRECTION_ALLOWED_STATUSES.includes(status)))];
  return clean.length ? clean : [...CORRECTION_DEFAULT_STATUSES];
}

function normalizeCorrectionHistoryScope(scope, hasLinkedFeedback = false) {
  if (CORRECTION_ALLOWED_SCOPES.includes(scope)) return scope;
  return hasLinkedFeedback ? 'reported' : 'all';
}

function normalizeUuidList(values) {
  return Array.isArray(values)
    ? [...new Set(values.map(String).filter(id => /^[0-9a-fA-F-]{36}$/.test(id))).values()]
    : [];
}

function correctionChangeId(historyId, field) {
  return `${historyId}:${field}`;
}

function normalizeCorrectionChangeIds(values) {
  return Array.isArray(values)
    ? [...new Set(values.map(String).filter(id => /^[0-9a-fA-F-]{36}:(corrected_text|summary)$/.test(id))).values()]
    : [];
}

function correctionAppliedTargetIds(pkg = {}) {
  return normalizeCorrectionChangeIds((pkg.appliedTargets || []).map(target => target?.changeId || target));
}

function normalizeCorrectionPackageInput(body = {}, existing = null) {
  const from = String(body.from ?? existing?.from ?? '').trim();
  const to = String(body.to ?? existing?.to ?? '').trim();
  const title = String(body.title ?? existing?.title ?? '').trim().slice(0, 160);
  const note = String(body.note ?? existing?.note ?? '').trim().slice(0, 1200);
  if (!from) {
    const err = new Error('Duzeltilecek ifade gerekli.');
    err.statusCode = 400;
    throw err;
  }
  if (!to) {
    const err = new Error('Dogru ifade gerekli.');
    err.statusCode = 400;
    throw err;
  }
  if (from === to) {
    const err = new Error('Yanlis ve dogru ifade ayni olamaz.');
    err.statusCode = 400;
    throw err;
  }
  const feedbackIds = Array.isArray(body.feedbackIds)
    ? normalizeUuidList(body.feedbackIds).slice(0, 100)
    : (existing?.feedbackIds || []);
  const reportedHistoryIds = normalizeUuidList(body.reportedHistoryIds ?? existing?.reportedHistoryIds);
  const historyScope = normalizeCorrectionHistoryScope(body.historyScope ?? existing?.historyScope, feedbackIds.length > 0 || reportedHistoryIds.length > 0);
  return {
    ...(existing || {}),
    id: existing?.id || correctionPackageId(),
    title: title || `${from} -> ${to}`,
    from,
    to,
    note,
    fields: normalizeCorrectionFields(body.fields ?? existing?.fields),
    statuses: normalizeCorrectionStatuses(body.statuses ?? existing?.statuses),
    matchMode: body.matchMode === 'regex' ? 'regex' : 'literal',
    requiresReview: Boolean(body.requiresReview ?? existing?.requiresReview ?? true),
    feedbackIds,
    reportedHistoryIds,
    historyScope,
    status: existing?.status || 'pending_review',
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

function correctionRegex(pkg) {
  const flags = pkg.caseInsensitive ? 'giu' : 'gu';
  if (pkg.matchMode === 'regex') return new RegExp(pkg.from, flags);
  return new RegExp(escapeRegExpServer(pkg.from), flags);
}

function applyCorrectionRuleToText(text, pkg) {
  const oldValue = String(text ?? '');
  if (!oldValue || !pkg?.from) return { changed: false, count: 0, oldValue, newValue: oldValue };
  const re = correctionRegex(pkg);
  let count = 0;
  const newValue = oldValue.replace(re, () => {
    count++;
    return pkg.to;
  });
  return { changed: count > 0, count, oldValue, newValue };
}

function correctionExcerpt(text, pkg) {
  const source = String(text || '');
  if (!source) return '';
  let index = -1;
  if (pkg.matchMode === 'regex') {
    const match = source.match(correctionRegex(pkg));
    if (match?.[0]) index = source.indexOf(match[0]);
  } else {
    index = source.indexOf(pkg.from);
  }
  if (index < 0) return source.slice(0, 180);
  const start = Math.max(0, index - 70);
  const end = Math.min(source.length, index + String(pkg.from).length + 90);
  return `${start > 0 ? '...' : ''}${source.slice(start, end)}${end < source.length ? '...' : ''}`;
}

function correctionPreviewSnippet(text, needle) {
  const source = String(text || '');
  if (!source) return '';
  const search = String(needle || '');
  let index = search ? source.indexOf(search) : -1;
  if (index < 0) index = 0;
  const start = Math.max(0, index - 90);
  const end = Math.min(source.length, index + Math.max(search.length, 1) + 120);
  return `${start > 0 ? '...' : ''}${source.slice(start, end)}${end < source.length ? '...' : ''}`;
}

function correctionHistoryStatus(row = {}) {
  return row.status || 'bekliyor';
}

function isCorrectionCandidateRow(row = {}, pkg = {}, options = {}) {
  const status = correctionHistoryStatus(row);
  if (HIDDEN_HISTORY_STATUSES.includes(status) || isChunkHistoryRow(row)) {
    return Boolean(options.includeHiddenReported);
  }
  return (pkg.statuses || CORRECTION_DEFAULT_STATUSES).includes(status);
}

async function fetchFeedbackHistoryIds(feedbackIds = []) {
  const ids = normalizeUuidList(feedbackIds);
  if (!ids.length) return [];
  const { data, error } = await supabase.from('alerts')
    .select('id,history_id')
    .eq('type', 'feedback')
    .in('id', ids);
  if (error) throw new Error(error.message);
  return normalizeUuidList((data || []).map(row => row.history_id).filter(Boolean));
}

async function fetchCorrectionHistoryRows(pkg = {}) {
  const reportedIds = normalizeUuidList(pkg.reportedHistoryIds);
  const useReportedOnly = pkg.historyScope === 'reported';
  if (useReportedOnly && !reportedIds.length) return [];
  const rows = useReportedOnly
    ? await fetchAllPages(() => supabase.from('history')
      .select('id,user_id,username,name,filename,score,total_errors,status,summary,corrected_text,created_at')
      .in('id', reportedIds)
      .order('created_at', { ascending: false }))
    : await fetchAllPages(() => supabase.from('history')
      .select('id,user_id,username,name,filename,score,total_errors,status,summary,corrected_text,created_at')
      .order('created_at', { ascending: false }));
  return (rows || []).filter(row => isCorrectionCandidateRow(row, pkg, { includeHiddenReported: useReportedOnly }));
}

async function scanCorrectionPackage(pkg = {}, options = {}) {
  const includeValues = Boolean(options.includeValues);
  const rows = await fetchCorrectionHistoryRows(pkg);
  const fields = normalizeCorrectionFields(pkg.fields);
  const reportedIds = new Set(normalizeUuidList(pkg.reportedHistoryIds));
  const appliedIds = new Set(correctionAppliedTargetIds(pkg));
  const changes = [];
  const byStatus = {};
  const byField = {};
  for (const row of rows) {
    const status = correctionHistoryStatus(row);
    for (const field of fields) {
      const result = applyCorrectionRuleToText(row[field], pkg);
      if (!result.changed) continue;
      const changeId = correctionChangeId(row.id, field);
      byStatus[status] = (byStatus[status] || 0) + 1;
      byField[field] = (byField[field] || 0) + 1;
      changes.push({
        changeId,
        historyId: row.id,
        userId: row.user_id,
        field,
        count: result.count,
        status,
        reported: reportedIds.has(row.id),
        alreadyApplied: appliedIds.has(changeId),
        filename: row.filename || 'Metin',
        userName: row.name || row.username || '',
        createdAt: row.created_at,
        score: row.score,
        totalErrors: row.total_errors,
        excerpt: correctionExcerpt(result.oldValue, pkg),
        beforePreview: correctionPreviewSnippet(result.oldValue, pkg.from),
        afterPreview: correctionPreviewSnippet(result.newValue, pkg.to),
        ...(includeValues ? { oldValue: result.oldValue, newValue: result.newValue } : {})
      });
    }
  }
  const affectedRecords = new Set(changes.map(change => change.historyId)).size;
  return {
    packageId: pkg.id,
    historyScope: pkg.historyScope || 'all',
    reportedHistoryCount: normalizeUuidList(pkg.reportedHistoryIds).length,
    affectedRecords,
    changeCount: changes.length,
    replacementCount: changes.reduce((sum, change) => sum + Number(change.count || 0), 0),
    byStatus,
    byField,
    needsReview: pkg.requiresReview ? affectedRecords : 0,
    sample: changes.slice(0, 12),
    changes
  };
}

function publicCorrectionPackage(pkg, scan = null) {
  const hasAppliedTargets = Array.isArray(pkg.appliedTargets) && pkg.appliedTargets.length > 0;
  return {
    ...pkg,
    lastScan: scan || pkg.lastScan || null,
    canApply: HAS_CONTENT_CORRECTION_LOG && pkg.status === 'ready',
    canRevert: HAS_CONTENT_CORRECTION_LOG && (pkg.status === 'applied' || hasAppliedTargets)
  };
}

function sanitizeCorrectionScan(scan = {}) {
  const { changes = [], ...rest } = scan;
  const safeChanges = changes.slice(0, CORRECTION_SCAN_TARGET_LIMIT).map(change => {
    const { oldValue, newValue, ...safe } = change;
    return safe;
  });
  return {
    ...rest,
    sample: safeChanges.slice(0, 12),
    reportedTargets: safeChanges.filter(change => change.reported),
    historyTargets: safeChanges.filter(change => !change.reported),
    targetLimit: CORRECTION_SCAN_TARGET_LIMIT,
    targetTruncated: changes.length > safeChanges.length
  };
}

async function insertCorrectionLogs(logs) {
  for (let i = 0; i < logs.length; i += 500) {
    const { error } = await supabase.from('content_correction_log').insert(logs.slice(i, i + 500));
    if (error) throw new Error(error.message);
  }
}

async function updateCorrectionPackage(id, patch) {
  const packages = await loadCorrectionPackages();
  const index = packages.findIndex(pkg => pkg.id === id);
  if (index < 0) {
    const err = new Error('Duzeltme paketi bulunamadi.');
    err.statusCode = 404;
    throw err;
  }
  packages[index] = { ...packages[index], ...patch, updatedAt: new Date().toISOString() };
  await saveCorrectionPackages(packages);
  return packages[index];
}

function latestActivity(...items) {
  let winner = null;
  for (const item of items) {
    const at = normalizeIsoDate(item?.at || item);
    if (!at) continue;
    if (!winner || new Date(at) > new Date(winner.at)) winner = { at, source: item?.source || 'activity' };
  }
  return winner;
}

async function saveUserLastSeenBackup(userId, now) {
  try {
    await saveJsonSetting(`${USER_LAST_SEEN_KEY_PREFIX}${userId}`, { at: now });
    return;
  } catch (error) {
    console.warn('Tekil son aktiflik yedeği yazılamadı, eski yedeğe düşülüyor:', error.message);
  }
  const activity = await loadJsonSetting(USER_LAST_SEEN_LEGACY_KEY, {});
  const next = activity && typeof activity === 'object' ? activity : {};
  next[userId] = now;
  await saveJsonSetting(USER_LAST_SEEN_LEGACY_KEY, next);
}

async function loadUserLastSeenBackups() {
  const result = {};
  const legacy = await loadJsonSetting(USER_LAST_SEEN_LEGACY_KEY, {});
  if (legacy && typeof legacy === 'object' && !Array.isArray(legacy)) {
    Object.entries(legacy).forEach(([userId, at]) => {
      const seenAt = normalizeIsoDate(at);
      if (seenAt) result[userId] = seenAt;
    });
  }

  const { data, error } = await supabase.from('settings')
    .select('key,value')
    .like('key', `${USER_LAST_SEEN_KEY_PREFIX}%`);
  if (error) {
    console.warn('Tekil son aktiflik yedekleri okunamadı:', error.message);
    return result;
  }
  for (const row of data || []) {
    const userId = String(row.key || '').slice(USER_LAST_SEEN_KEY_PREFIX.length);
    if (!userId) continue;
    const parsed = parseJsonSettingValue(row.value, null);
    const seenAt = normalizeIsoDate(parsed?.at || parsed?.lastSeenAt || parsed);
    if (!seenAt) continue;
    const latest = latestActivity({ at: result[userId] }, { at: seenAt });
    result[userId] = latest?.at || seenAt;
  }
  return result;
}

async function loadLatestHistoryByUser(userIds) {
  const ids = Array.isArray(userIds) ? userIds.filter(Boolean) : [];
  if (!ids.length) return {};
  const { data, error } = await supabase.from('history')
    .select('user_id,created_at')
    .in('user_id', ids)
    .order('created_at', { ascending: false })
    .limit(5000);
  if (error) {
    console.warn('Kullanıcı son denetim tarihleri okunamadı:', error.message);
    return {};
  }
  const result = {};
  for (const row of data || []) {
    if (row.user_id && !result[row.user_id]) result[row.user_id] = row.created_at;
  }
  return result;
}

async function recordUserActivity(userId) {
  if (!userId) return;
  const now = new Date().toISOString();
  try {
    if (HAS_USER_LAST_SEEN) {
      const { error } = await supabase.from('users').update({ last_seen_at: now }).eq('id', userId);
      if (error) {
        HAS_USER_LAST_SEEN = false;
        console.warn('users.last_seen_at yazılamadı, settings yedeğine düşülüyor:', error.message);
      }
    }
    await saveUserLastSeenBackup(userId, now);
  } catch (error) {
    console.warn('Son aktiflik kaydedilemedi:', error.message);
  }
}

async function loadStandardsCatalog() {
  const catalog = await loadJsonSetting('standards_catalog', null);
  if (Array.isArray(catalog) && catalog.length) return catalog;
  await saveJsonSetting('standards_catalog', DEFAULT_STANDARDS);
  return DEFAULT_STANDARDS;
}

function readReceiptIds(receiptValue) {
  if (Array.isArray(receiptValue)) return receiptValue;
  if (receiptValue && typeof receiptValue === 'object') return Object.keys(receiptValue);
  return [];
}

function addReadReceipt(readMap, userId, itemId) {
  const current = readMap[userId];
  const next = current && typeof current === 'object' && !Array.isArray(current) ? current : {};
  if (Array.isArray(current)) current.forEach(id => { next[id] = next[id] || new Date().toISOString(); });
  next[itemId] = next[itemId] || new Date().toISOString();
  readMap[userId] = next;
}

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

const FEEDBACK_ROOT_CATEGORIES = [
  { key: 'reference-format', label: 'Referans / sure formatı', patterns: [/referans/u, /meal/u, /meâl/u, /kur'?an/u, /sure/u, /ayet/u, /\d+\s*[/.]\s*[\p{L}'’\s]+-\d+/u] },
  { key: 'punctuation-existing', label: 'Noktalama zaten kaynakta var', patterns: [/nokta/u, /virgul/u, /virgül/u, /noktalama/u, /ustunu ciz/u, /üstünü çiz/u, /zaten/u] },
  { key: 'diacritic-dictionary', label: 'Şapka / sözlük standardı', patterns: [/sapka/u, /şapka/u, /kitab/u, /kitâb/u, /sozluk/u, /sözlük/u, /â/u, /î/u, /û/u] },
  { key: 'quote-safety', label: 'Tırnak / çift tırnak güvenliği', patterns: [/tirnak/u, /tırnak/u, /cift tirnak/u, /çift tırnak/u, /""/u] },
  { key: 'apply-corrected-text', label: 'Düzeltilmiş metne uygulama', patterns: [/duzeltilmis metin/u, /düzeltilmiş metin/u, /uygulamiyor/u, /uygulamıyor/u, /hatalari veriyor/u, /hataları veriyor/u] },
  { key: 'layout-structure', label: 'Düzen / tablo / paragraf koruma', patterns: [/duzen/u, /düzen/u, /tablo/u, /slayt/u, /paragraf/u, /satir/u, /satır/u] },
  { key: 'content-addition', label: 'Kaynakta olmayan içerik ekleme', patterns: [/kaynakta olmayan/u, /metinde yok/u, /ekleme/u, /eklenmis/u, /eklenmiş/u] },
  { key: 'general-quality', label: 'Genel denetim kalitesi', patterns: [/.+/u] }
];

function foldFeedbackText(value = '') {
  return String(value || '')
    .toLocaleLowerCase('tr-TR')
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/ı/g, 'i')
    .replace(/ğ/g, 'g')
    .replace(/ü/g, 'u')
    .replace(/ş/g, 's')
    .replace(/ö/g, 'o')
    .replace(/ç/g, 'c');
}

function feedbackRootCategory(alertOrMessage) {
  const raw = typeof alertOrMessage === 'string' ? alertOrMessage : alertOrMessage?.message;
  const fields = parseAlertFields(raw || '');
  const haystack = foldFeedbackText([
    raw,
    fields.bulgu,
    fields.kural,
    fields.not,
    fields['geri bildirim']
  ].filter(Boolean).join(' '));
  const category = FEEDBACK_ROOT_CATEGORIES.find(item => item.patterns.some(pattern => pattern.test(haystack)))
    || FEEDBACK_ROOT_CATEGORIES[FEEDBACK_ROOT_CATEGORIES.length - 1];
  return { key: category.key, label: category.label };
}

function feedbackRootCategorySummary(feedbacks = []) {
  const byKey = new Map();
  feedbacks.forEach(feedback => {
    const category = feedbackRootCategory(feedback);
    if (!byKey.has(category.key)) byKey.set(category.key, { ...category, count: 0 });
    byKey.get(category.key).count++;
  });
  return [...byKey.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label, 'tr'));
}

function appendRootCategoryNote(note, feedbacks = []) {
  const roots = feedbackRootCategorySummary(feedbacks);
  if (!roots.length) return note;
  return `${note}\nKök kategoriler: ${roots.map(root => `${root.label} (${root.count})`).join(', ')}`;
}

function feedbackSimilarityMap(feedbackAlerts = []) {
  const resolvedByRoot = new Map();
  feedbackAlerts
    .filter(alert => alert.feedback_status === 'resolved')
    .forEach(alert => {
      const category = feedbackRootCategory(alert);
      const current = resolvedByRoot.get(category.key) || {
        key: category.key,
        label: category.label,
        count: 0,
        latestAt: null,
        examples: []
      };
      current.count++;
      if (!current.latestAt || new Date(alert.resolved_at || alert.created_at) > new Date(current.latestAt)) {
        current.latestAt = alert.resolved_at || alert.created_at;
      }
      if (current.examples.length < 3) current.examples.push(feedbackSummary(alert));
      resolvedByRoot.set(category.key, current);
    });

  const result = new Map();
  feedbackAlerts.forEach(alert => {
    const category = feedbackRootCategory(alert);
    const resolved = category.key === 'general-quality' ? null : resolvedByRoot.get(category.key);
    result.set(alert.id, {
      rootCategory: category,
      similarResolved: alert.feedback_status !== 'resolved' && resolved ? resolved : null
    });
  });
  return result;
}

function buildFeedbackResolutionMessage(userName, feedbacks, note) {
  const safeName = String(userName || 'kardeşimiz').trim();
  const lines = feedbacks.map((f, i) => `${i + 1}. ${feedbackSummary(f)}`);
  return [
    'Başlık: Geri Bildirimlerinizle Çözülen Sorunlar',
    `Sevgili ${safeName},`,
    'Geri bildirimleriniz sayesinde aşağıdaki sorunlar sistemde düzeltildi:',
    ...lines,
    note ? `Çözüm notu: ${note}` : '',
    'Geri bildirimleriniz, sistemi birlikte daha doğru, kullanışlı ve sağlıklı hale getirmemiz için çok kıymetlidir. Katkınız için teşekkür ederiz.',
    `Gönderen: ${SYSTEM_SENDER_NAME}`
  ].filter(Boolean).join('\n');
}

function normalizeResolutionResponse(row, notice, user) {
  if (!row) return null;
  return {
    noticeId: notice?.id || row.noticeId,
    status: row.status,
    note: row.note || '',
    respondedAt: row.respondedAt,
    userId: row.userId || notice?.user_id || '',
    userName: user?.name || row.userName || user?.username || '',
    username: user?.username || row.username || '',
    message: notice?.message || row.message || ''
  };
}

function resolutionResponseLabel(status) {
  return status === 'confirmed' ? 'Sorun çözüldü' : status === 'unresolved' ? 'Çözülmedi' : 'Yanıt bekleniyor';
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

  const { error: historyTagsErr } = await supabase.from('history').select('tags').limit(1);
  HAS_HISTORY_TAGS = !historyTagsErr;
  if (!HAS_HISTORY_TAGS) console.warn('⚠ history.tags kolonu yok — onay etiketleri saklanmayacak. schema.sql içindeki ALTER ifadesini Supabase SQL Editor\'de çalıştırın.');

  const { error: historyQuestionTextErr } = await supabase.from('history').select('question_text').limit(1);
  HAS_HISTORY_QUESTION_TEXT = !historyQuestionTextErr;
  if (!HAS_HISTORY_QUESTION_TEXT) console.warn('⚠ history.question_text kolonu yok — soru alanı saklanmayacak. schema.sql içindeki ALTER ifadesini Supabase SQL Editor\'de çalıştırın.');

  const { error: tagImportBatchErr } = await supabase.from('history_tag_import_batches').select('id').limit(1);
  const { error: tagImportMatchErr } = await supabase.from('history_tag_import_matches').select('id').limit(1);
  HAS_HISTORY_TAG_IMPORT_TABLES = !tagImportBatchErr && !tagImportMatchErr;
  if (!HAS_HISTORY_TAG_IMPORT_TABLES) console.warn('⚠ history tag import tabloları yok — Excel etiket aktarımı pasif.');

  const { error: feedbackMetaErr } = await supabase.from('alerts')
    .select('feedback_status,resolved_at,resolved_by,resolution_group,resolution_note').limit(1);
  HAS_ALERT_FEEDBACK_META = !feedbackMetaErr;
  if (!HAS_ALERT_FEEDBACK_META) console.warn('⚠ alerts feedback çözüm kolonları yok — çözüm durumu read/notification üzerinden sınırlı izlenecek.');

  const { error: resolutionLogErr } = await supabase.from('issue_resolution_log').select('id').limit(1);
  HAS_ISSUE_RESOLUTION_LOG = !resolutionLogErr;
  if (!HAS_ISSUE_RESOLUTION_LOG) console.warn('⚠ issue_resolution_log tablosu yok — çözüm kayıt defteri pasif.');

  const { error: contentCorrectionLogErr } = await supabase.from('content_correction_log').select('id').limit(1);
  HAS_CONTENT_CORRECTION_LOG = !contentCorrectionLogErr;
  if (!HAS_CONTENT_CORRECTION_LOG) console.warn('⚠ content_correction_log tablosu yok — geçmiş içerik düzeltme uygulaması pasif.');

  const { error: aiReportsErr } = await supabase.from('ai_reports').select('id').limit(1);
  HAS_AI_REPORTS = !aiReportsErr;
  if (!HAS_AI_REPORTS) console.warn('⚠ ai_reports tablosu yok — AI rapor kayıtları pasif.');

  const { error: lastSeenErr } = await supabase.from('users').select('last_seen_at').limit(1);
  HAS_USER_LAST_SEEN = !lastSeenErr;
  if (!HAS_USER_LAST_SEEN) console.warn('⚠ users.last_seen_at kolonu yok — son aktiflik settings yedeğinden okunacak.');

  const { error: archiveSourcesErr } = await supabase.from('archive_sources').select('id').limit(1);
  const { error: archiveVersionsErr } = await supabase.from('archive_source_versions').select('id').limit(1);
  const { error: archiveEventsErr } = await supabase.from('archive_source_events').select('id').limit(1);
  HAS_ARCHIVE_SOURCE_TABLES = !archiveSourcesErr && !archiveVersionsErr && !archiveEventsErr;
  if (!HAS_ARCHIVE_SOURCE_TABLES) console.warn('⚠ archive source tabloları yok — Arşiv Operasyon Merkezi pilot JSON deposuyla çalışacak.');

  const { error: archiveImportBatchesErr } = await supabase.from('archive_import_batches').select('id').limit(1);
  const { error: archiveImportItemsErr } = await supabase.from('archive_import_items').select('id').limit(1);
  HAS_ARCHIVE_IMPORT_TABLES = !archiveImportBatchesErr && !archiveImportItemsErr;
  if (!HAS_ARCHIVE_IMPORT_TABLES) console.warn('⚠ archive import tabloları yok — kalıcı içe aktarım listeleri pasif.');

  const { error: archiveWorkErr } = await supabase.from('archive_work_items').select('id').limit(1);
  HAS_ARCHIVE_WORK_TABLES = !archiveWorkErr;
  if (!HAS_ARCHIVE_WORK_TABLES) console.warn('⚠ archive_work_items tablosu yok — çalışma kayıtları settings yedeğiyle çalışacak.');

  const { error: archivePublishErr } = await supabase.from('archive_publish_tasks').select('id').limit(1);
  HAS_ARCHIVE_PUBLISH_TABLES = !archivePublishErr;
  if (!HAS_ARCHIVE_PUBLISH_TABLES) console.warn('⚠ archive_publish_tasks tablosu yok — yayın görevleri settings yedeğiyle çalışacak.');
}

// ── Auth middleware ────────────────────────────────────────────────────────
async function syncSessionUserFromDb(req) {
  if (!req.session?.userId) return null;
  const { data: user, error } = await supabase.from('users')
    .select('id,username,name,role,active')
    .eq('id', req.session.userId)
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!user || user.active === false) {
    req.session = null;
    return null;
  }

  const role = effectiveRole(user.username, user.role);
  if (role !== user.role) {
    const { error: roleError } = await supabase.from('users').update({ role }).eq('id', user.id);
    if (roleError) throw new Error(roleError.message);
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.name = user.name;
  req.session.role = role;
  return { id: user.id, username: user.username, name: user.name, role, active: user.active };
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
    const err = new Error('Metin 200.000 karakter sınırını aşıyor. Lütfen metni kısaltıp tekrar deneyin.');
    err.statusCode = 413;
    throw err;
  }
  return cleaned;
}
const auth = async (req, res, next) => {
  try {
    if (!req.session?.userId) return res.status(401).json({ error: 'Giriş gerekli.' });
    await startupReady;
    const currentUser = await syncSessionUserFromDb(req);
    if (!currentUser) return res.status(401).json({ error: 'Giriş gerekli.' });
    const now = Date.now();
    const lastWrite = Number(req.session.lastSeenWriteAt || 0);
    if (!lastWrite || now - lastWrite > 60_000) {
      req.session.lastSeenWriteAt = now;
      await recordUserActivity(currentUser.id);
    }
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
    await recordUserActivity(user.id);
    res.json({ success: true, id: user.id, name: user.name, role, username: user.username });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/auth/logout', (req, res) => { req.session = null; res.json({ success: true }); });
app.get('/api/auth/me', async (req, res, next) => {
  if (!req.session?.userId) return res.json({ loggedIn: false });
  try {
    await startupReady;
    const currentUser = await syncSessionUserFromDb(req);
    if (!currentUser) return res.json({ loggedIn: false });
    await recordUserActivity(currentUser.id);
    res.json({ loggedIn: true, id: currentUser.id, name: currentUser.name, role: currentUser.role, username: currentUser.username });
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
    const users = data || [];
    const userIds = users.map(u => u.id).filter(Boolean);
    const [lastSeenBackups, latestHistoryByUser] = await Promise.all([
      loadUserLastSeenBackups(),
      loadLatestHistoryByUser(userIds)
    ]);
    res.json(users.map(u => {
      const activity = latestActivity(
        { at: u.last_seen_at, source: 'activity' },
        { at: lastSeenBackups?.[u.id], source: 'activity' },
        { at: latestHistoryByUser?.[u.id], source: 'history' }
      );
      return { ...mapUser(u), lastSeenAt: activity?.at || null, lastSeenSource: activity?.source || null };
    }));
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
app.get('/api/standards', auth, async (req, res) => {
  try {
    const [catalog, receipts] = await Promise.all([
      loadStandardsCatalog(),
      loadJsonSetting('standards_read_receipts', {})
    ]);
    const readMap = receipts && typeof receipts === 'object' ? receipts : {};
    const userReads = new Set(readReceiptIds(readMap[req.session.userId]));
    let trackingByStandard = null;
    if (isAdminRole(req.session.role)) {
      const { data: users, error: usersError } = await supabase.from('users').select('id,name,username,active').eq('active', true);
      if (usersError) throw new Error(usersError.message);
      trackingByStandard = new Map(catalog.map(item => [item.id, { read: [], unread: [] }]));
      for (const user of users || []) {
        const seen = new Set(readReceiptIds(readMap[user.id]));
        for (const standard of catalog) {
          const target = seen.has(standard.id) ? 'read' : 'unread';
          trackingByStandard.get(standard.id)?.[target].push({ id: user.id, name: user.name, username: user.username });
        }
      }
    }
    const standards = catalog.map(item => {
      const tracking = trackingByStandard?.get(item.id);
      return {
        ...item,
        read: userReads.has(item.id),
        ...(tracking ? {
          tracking: {
            readCount: tracking.read.length,
            unreadCount: tracking.unread.length,
            readUsers: tracking.read,
            unreadUsers: tracking.unread
          }
        } : {})
      };
    });
    res.json({ standards, unreadCount: standards.filter(item => !item.read).length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/standards/:id/read', auth, async (req, res) => {
  try {
    const catalog = await loadStandardsCatalog();
    const standardId = String(req.params.id || '');
    if (!catalog.some(item => item.id === standardId)) return res.status(404).json({ error: 'Standart bulunamadı.' });
    const receipts = await loadJsonSetting('standards_read_receipts', {});
    const readMap = receipts && typeof receipts === 'object' ? receipts : {};
    addReadReceipt(readMap, req.session.userId, standardId);
    await saveJsonSetting('standards_read_receipts', readMap);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/standards/read-visible', auth, async (req, res) => {
  try {
    const catalog = await loadStandardsCatalog();
    const allowed = new Set(catalog.map(item => item.id));
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String).filter(id => allowed.has(id)).slice(0, 100) : [];
    if (!ids.length) return res.json({ success: true, count: 0 });
    const receipts = await loadJsonSetting('standards_read_receipts', {});
    const readMap = receipts && typeof receipts === 'object' ? receipts : {};
    ids.forEach(id => addReadReceipt(readMap, req.session.userId, id));
    await saveJsonSetting('standards_read_receipts', readMap);
    res.json({ success: true, count: ids.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/standards', auth, admin, async (req, res) => {
  try {
    const title = String(req.body?.title || '').trim().slice(0, 120);
    const category = String(req.body?.category || 'Standart').trim().slice(0, 80);
    const content = String(req.body?.content || '').trim().slice(0, 2000);
    if (!title || !content) return res.status(400).json({ error: 'Başlık ve standart metni gerekli.' });
    const catalog = await loadStandardsCatalog();
    const slug = title.toLocaleLowerCase('tr-TR').replace(/[^a-z0-9çğıöşü]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'standart';
    const id = `${Date.now()}-${slug}`;
    await saveJsonSetting('standards_catalog', [{ id, title, category, content, createdAt: new Date().toISOString() }, ...catalog]);
    res.json({ success: true, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ARCHIVE OPERATIONS SOURCES ─────────────────────────────────────────────
app.get('/api/archive-ops/public-candidates', auth, admin, superAdmin, async (req, res) => {
  try {
    const result = await listArchivePublicCandidates(req.query);
    res.json({ ready: true, counts: result.counts, candidates: result.candidates });
  } catch (e) { res.status(e.statusCode || 500).json({ ready: false, error: e.message }); }
});

app.post('/api/archive-ops/public-candidates/:kind/:id/decision', auth, admin, superAdmin, async (req, res) => {
  try {
    const candidate = await updateArchivePublicCandidateDecision(
      req.params.kind,
      req.params.id,
      req.body?.status,
      req.body?.note,
      req.session?.name || req.session?.username || 'Sistem'
    );
    if (!candidate) return res.status(404).json({ error: 'Aday kayıt bulunamadı.' });
    res.json({ success: true, candidate });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/release-packages', auth, admin, superAdmin, async (req, res) => {
  try {
    const result = await listArchiveReleasePackages(req.query);
    res.json({ ready: true, counts: result.counts, packages: result.packages });
  } catch (e) { res.status(e.statusCode || 500).json({ ready: false, error: e.message }); }
});

app.get('/api/archive-ops/release-packages/:id/output', auth, admin, superAdmin, async (req, res) => {
  try {
    const output = await getArchiveReleasePackageOutput(req.params.id, req.query.format);
    if (!output) return res.status(404).json({ error: 'Yayın paketi bulunamadı.' });
    res.json({ success: true, ...output });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/release-packages', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const pkg = await createArchiveReleasePackage(req.body || {}, actor);
    res.json({ success: true, package: pkg });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.put('/api/archive-ops/release-packages/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const pkg = await updateArchiveReleasePackage(req.params.id, req.body || {}, actor);
    if (!pkg) return res.status(404).json({ error: 'Yayın paketi bulunamadı.' });
    res.json({ success: true, package: pkg });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/release-packages/:id/items/:itemId/review', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const pkg = await updateArchiveReleasePackageItemReview(req.params.id, req.params.itemId, req.body || {}, actor);
    if (!pkg) return res.status(404).json({ error: 'Yayın paketi bulunamadı.' });
    res.json({ success: true, package: pkg });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/release-packages/:id/lock', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const pkg = await lockArchiveReleasePackage(req.params.id, actor);
    if (!pkg) return res.status(404).json({ error: 'Yayın paketi bulunamadı.' });
    res.json({ success: true, package: pkg });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/release-packages/:id/unlock', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const pkg = await unlockArchiveReleasePackage(req.params.id, actor);
    if (!pkg) return res.status(404).json({ error: 'Yayın paketi bulunamadı.' });
    res.json({ success: true, package: pkg });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/release-packages/:id/publication', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const pkg = await updateArchiveReleasePackagePublication(req.params.id, req.body || {}, actor);
    if (!pkg) return res.status(404).json({ error: 'Yayın paketi bulunamadı.' });
    res.json({ success: true, package: pkg });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.delete('/api/archive-ops/release-packages/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const deleted = await deleteArchiveReleasePackage(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Yayın paketi bulunamadı.' });
    res.json({ success: true, deleted });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/sources', auth, admin, superAdmin, async (req, res) => {
  try {
    const list = await listArchiveOpsSources(req.query);
    const sources = list.sources || [];
    const filtered = list.filtered || [];
    const counts = list.counts || {
      total: sources.length,
      filtered: filtered.length,
      byType: {},
      byStatus: {}
    };
    if (!list.counts) {
      for (const source of sources) {
        counts.byType[source.sourceType || 'dokuman'] = (counts.byType[source.sourceType || 'dokuman'] || 0) + 1;
        counts.byStatus[source.status || 'kaynak'] = (counts.byStatus[source.status || 'kaynak'] || 0) + 1;
      }
    }
    res.json({
      storage: list.storage || 'settings',
      counts,
      sources: filtered.slice(0, ARCHIVE_SOURCE_LIST_LIMIT).map(source => publicArchiveSource(source))
    });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/sources', auth, admin, superAdmin, async (req, res) => {
  try {
    const input = req.body || {};
    const actor = req.session.name || req.session.username || 'Sistem';
    const result = await createArchiveOpsSource(input, actor);
    if (result?.conflict) {
      return res.status(409).json({
        error: 'Benzer kaynak bulundu. Kaydetmeden önce mevcut kaydı kontrol edin.',
        conflicts: result.conflicts
      });
    }
    res.json({ success: true, source: publicArchiveSource(result.source, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/sources/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const source = await getArchiveOpsSource(req.params.id);
    if (!source) return res.status(404).json({ error: 'Kaynak kaydı bulunamadı.' });
    res.json({ source: publicArchiveSource(source, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.put('/api/archive-ops/sources/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const input = req.body || {};
    const actor = req.session.name || req.session.username || 'Sistem';
    const result = await updateArchiveOpsSource(req.params.id, input, actor);
    if (!result) return res.status(404).json({ error: 'Kaynak kaydı bulunamadı.' });
    if (result.conflict) {
      return res.status(409).json({
        error: 'Benzer kaynak bulundu. Kaydetmeden önce mevcut kaydı kontrol edin.',
        conflicts: result.conflicts
      });
    }
    res.json({ success: true, source: publicArchiveSource(result.source, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/work-items', auth, admin, superAdmin, async (req, res) => {
  try {
    const list = await listArchiveWorkItems(req.query);
    const items = list.items || [];
    const filtered = list.filtered || [];
    const counts = list.counts || {
      total: items.length,
      filtered: filtered.length,
      byStatus: {},
      byPriority: {}
    };
    if (!list.counts) {
      for (const item of items) {
        counts.byStatus[item.status || 'taslak'] = (counts.byStatus[item.status || 'taslak'] || 0) + 1;
        counts.byPriority[item.priority || 'normal'] = (counts.byPriority[item.priority || 'normal'] || 0) + 1;
      }
    }
    res.json({
      storage: list.storage || 'settings',
      counts,
      items: filtered.slice(0, ARCHIVE_WORK_ITEM_LIMIT).map(item => publicArchiveWorkItem(item))
    });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/work-items', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const item = await createArchiveWorkItem(req.body || {}, actor);
    res.json({ success: true, item: publicArchiveWorkItem(item, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/work-items/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const item = await getArchiveWorkItem(req.params.id);
    if (!item) return res.status(404).json({ error: 'Çalışma kaydı bulunamadı.' });
    res.json({ item: publicArchiveWorkItem(item, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.put('/api/archive-ops/work-items/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const item = await updateArchiveWorkItem(req.params.id, req.body || {}, actor);
    if (!item) return res.status(404).json({ error: 'Çalışma kaydı bulunamadı.' });
    res.json({ success: true, item: publicArchiveWorkItem(item, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.delete('/api/archive-ops/work-items/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const deleted = await deleteArchiveWorkItem(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Çalışma kaydı bulunamadı.' });
    res.json({ success: true, deleted });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/publish-tasks', auth, admin, superAdmin, async (req, res) => {
  try {
    const list = await listArchivePublishTasks(req.query);
    const tasks = list.tasks || [];
    const filtered = list.filtered || [];
    const counts = list.counts || {
      total: tasks.length,
      filtered: filtered.length,
      byStatus: {},
      byPriority: {}
    };
    if (!list.counts) {
      for (const task of tasks) {
        counts.byStatus[task.status || 'planlandi'] = (counts.byStatus[task.status || 'planlandi'] || 0) + 1;
        counts.byPriority[task.priority || 'normal'] = (counts.byPriority[task.priority || 'normal'] || 0) + 1;
      }
    }
    res.json({
      storage: list.storage || 'settings',
      counts,
      tasks: filtered.slice(0, ARCHIVE_PUBLISH_TASK_LIMIT).map(task => publicArchivePublishTask(task))
    });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/publish-tasks', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const task = await createArchivePublishTask(req.body || {}, actor);
    res.json({ success: true, task: publicArchivePublishTask(task, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/publish-tasks/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const task = await getArchivePublishTask(req.params.id);
    if (!task) return res.status(404).json({ error: 'Yayın görevi bulunamadı.' });
    res.json({ task: publicArchivePublishTask(task, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.put('/api/archive-ops/publish-tasks/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const task = await updateArchivePublishTask(req.params.id, req.body || {}, actor);
    if (!task) return res.status(404).json({ error: 'Yayın görevi bulunamadı.' });
    res.json({ success: true, task: publicArchivePublishTask(task, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.delete('/api/archive-ops/publish-tasks/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const deleted = await deleteArchivePublishTask(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Yayın görevi bulunamadı.' });
    res.json({ success: true, deleted });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/import-batches', auth, admin, superAdmin, async (req, res) => {
  try {
    const batches = await listArchiveImportBatches();
    res.json({ ready: true, batches });
  } catch (e) { res.status(e.statusCode || 500).json({ ready: false, error: e.message }); }
});

app.post('/api/archive-ops/import-batches', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const batch = await createArchiveImportBatch(req.body || {}, actor);
    res.json({ success: true, batch });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/archive-ops/import-batches/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const result = await getArchiveImportBatch(req.params.id);
    if (!result) return res.status(404).json({ error: 'İçe aktarım listesi bulunamadı.' });
    res.json({
      batch: result.batch,
      items: result.items.map(item => publicArchiveImportItem(item, { full: true }))
    });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/archive-ops/import-batches/:id/items', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const item = await createArchiveImportItem(req.params.id, req.body || {}, actor);
    if (!item) return res.status(404).json({ error: 'İçe aktarım listesi bulunamadı.' });
    res.json({ success: true, item: publicArchiveImportItem(item, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.put('/api/archive-ops/import-items/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const item = await updateArchiveImportItem(req.params.id, req.body || {}, actor);
    if (!item) return res.status(404).json({ error: 'İçe aktarım dosyası bulunamadı.' });
    res.json({ success: true, item: publicArchiveImportItem(item, { full: true }) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.delete('/api/archive-ops/import-items/:id', auth, admin, superAdmin, async (req, res) => {
  try {
    const actor = req.session.name || req.session.username || 'Sistem';
    const deleted = await deleteArchiveImportItem(req.params.id, actor);
    if (!deleted) return res.status(404).json({ error: 'İçe aktarım dosyası bulunamadı.' });
    res.json({ success: true, deleted });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

// ── CONTENT CORRECTION PACKAGES ────────────────────────────────────────────
app.get('/api/correction-packages', auth, admin, async (req, res) => {
  try {
    const packages = await loadCorrectionPackages();
    res.json({
      logReady: HAS_CONTENT_CORRECTION_LOG,
      packages: packages.map(pkg => publicCorrectionPackage(pkg))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/correction-packages', auth, admin, async (req, res) => {
  try {
    const packages = await loadCorrectionPackages();
    const pkg = normalizeCorrectionPackageInput(req.body || {});
    if (pkg.feedbackIds?.length) {
      const linkedHistoryIds = await fetchFeedbackHistoryIds(pkg.feedbackIds);
      pkg.reportedHistoryIds = normalizeUuidList([...(pkg.reportedHistoryIds || []), ...linkedHistoryIds]);
      pkg.historyScope = normalizeCorrectionHistoryScope(req.body?.historyScope, pkg.reportedHistoryIds.length > 0);
    }
    pkg.createdBy = req.session.name || req.session.username;
    packages.unshift(pkg);
    await saveCorrectionPackages(packages);
    res.json({ success: true, package: publicCorrectionPackage(pkg) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/correction-packages/:id/preview', auth, admin, async (req, res) => {
  try {
    const packages = await loadCorrectionPackages();
    const pkg = packages.find(item => item.id === req.params.id);
    if (!pkg) return res.status(404).json({ error: 'Düzeltme paketi bulunamadı.' });
    const scan = sanitizeCorrectionScan(await scanCorrectionPackage(pkg));
    const nextStatus = pkg.status === 'applied' || pkg.status === 'reverted'
      ? pkg.status
      : 'ready';
    const updated = await updateCorrectionPackage(pkg.id, { lastScan: scan, status: nextStatus });
    res.json({ success: true, logReady: HAS_CONTENT_CORRECTION_LOG, package: publicCorrectionPackage(updated, scan), scan });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/correction-packages/:id/apply', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!HAS_CONTENT_CORRECTION_LOG) {
      return res.status(400).json({
        error: 'Geçmiş içerik düzeltme kayıt defteri hazır değil. schema.sql içindeki content_correction_log bölümünü Supabase SQL Editor’de çalıştırın.'
      });
    }
    const packages = await loadCorrectionPackages();
    const pkg = packages.find(item => item.id === req.params.id);
    if (!pkg) return res.status(404).json({ error: 'Düzeltme paketi bulunamadı.' });
    if (pkg.status === 'applied') {
      return res.json({
        success: true,
        package: publicCorrectionPackage(pkg, pkg.lastScan || null),
        scan: pkg.lastScan || null,
        applied: 0,
        changes: 0,
        alreadyApplied: true
      });
    }
    if (!pkg.lastScan) {
      return res.status(400).json({ error: 'Geçmiş içeriklere uygulamadan önce etki taraması yapılmalı ve örnek kayıtlar kontrol edilmelidir.' });
    }
    if (pkg.status !== 'ready') {
      return res.status(400).json({ error: 'Bu düzeltme henüz son kontrol için hazır değil. Önce etki taraması yapın.' });
    }
    if (req.body?.superAdminApproved !== true) {
      return res.status(400).json({ error: 'Geçmiş düzeltme için süper admin son kontrol onayı gereklidir.' });
    }
    if (pkg.requiresReview && req.body?.confirmReview !== true) {
      return res.status(400).json({ error: 'Bu paket şüpheli durum içeriyor. Uygulamak için ayrıca gözden geçirme onayı gerekir.' });
    }

    const scanWithValues = await scanCorrectionPackage(pkg, { includeValues: true });
    const selectedChangeIds = normalizeCorrectionChangeIds(req.body?.selectedChangeIds);
    const selectedChangeSet = new Set(selectedChangeIds);
    const remainingChanges = scanWithValues.changes.filter(change => !change.alreadyApplied);
    const changesToApply = selectedChangeIds.length
      ? remainingChanges.filter(change => selectedChangeSet.has(change.changeId))
      : remainingChanges;
    if (!scanWithValues.changes.length || !changesToApply.length) {
      const scan = sanitizeCorrectionScan(scanWithValues);
      const updated = await updateCorrectionPackage(pkg.id, { lastScan: scan, status: 'ready' });
      return res.json({ success: true, package: publicCorrectionPackage(updated, scan), scan, applied: 0 });
    }

    const updatesByHistory = new Map();
    const logsByHistory = new Map();
    for (const change of changesToApply) {
      if (!updatesByHistory.has(change.historyId)) updatesByHistory.set(change.historyId, {});
      updatesByHistory.get(change.historyId)[change.field] = change.newValue;
      if (!logsByHistory.has(change.historyId)) logsByHistory.set(change.historyId, []);
      logsByHistory.get(change.historyId).push({
        package_id: pkg.id,
        history_id: change.historyId,
        field_name: change.field,
        old_value: change.oldValue,
        new_value: change.newValue,
        old_hash: textHash(change.oldValue || ''),
        new_hash: textHash(change.newValue || ''),
        status: 'applied',
        created_by: req.session.name || req.session.username
      });
    }

    let appliedRecords = 0;
    let appliedChanges = 0;
    for (const [historyId, update] of updatesByHistory.entries()) {
      const { error: updateError } = await supabase.from('history').update(update).eq('id', historyId);
      if (updateError) throw new Error(updateError.message);
      const logs = logsByHistory.get(historyId) || [];
      await insertCorrectionLogs(logs);
      const sample = scanWithValues.changes.find(change => change.historyId === historyId);
      if (update.corrected_text !== undefined && sample?.userId && ['bekliyor', 'onaylandi'].includes(correctionHistoryStatus(sample))) {
        await markSubmittedCorrectedHash(sample.userId, update.corrected_text || '', historyId, correctionHistoryStatus(sample));
      }
      appliedRecords++;
      appliedChanges += logs.length;
    }

    const scan = sanitizeCorrectionScan(scanWithValues);
    const appliedAtNow = new Date().toISOString();
    const appliedByNow = req.session.name || req.session.username;
    const appliedTargetIds = new Set([...correctionAppliedTargetIds(pkg), ...changesToApply.map(change => change.changeId)]);
    const remainingAfterApply = remainingChanges.filter(change => !appliedTargetIds.has(change.changeId)).length;
    const fullyApplied = remainingAfterApply === 0;
    const updated = await updateCorrectionPackage(pkg.id, {
      lastScan: scan,
      status: fullyApplied ? 'applied' : 'ready',
      appliedTargets: [...appliedTargetIds].map(changeId => ({
        changeId,
        appliedAt: appliedAtNow,
        appliedBy: appliedByNow
      })),
      appliedAt: fullyApplied ? appliedAtNow : pkg.appliedAt,
      appliedBy: fullyApplied ? appliedByNow : pkg.appliedBy,
      partialAppliedAt: fullyApplied ? pkg.partialAppliedAt : appliedAtNow,
      partialAppliedBy: fullyApplied ? pkg.partialAppliedBy : appliedByNow
    });

    const resolutionGroup = `content-correction-${pkg.id}`;
    const resolutionNote = [
      pkg.note || `${pkg.from} -> ${pkg.to}`,
      `Bildirilen metinlerde uygulanan kayit: ${appliedRecords}`,
      `Duzeltme sayisi: ${appliedChanges}`
    ].join('\n');

    const appliedHistoryIds = new Set(changesToApply.map(change => change.historyId));
    const reportedIds = normalizeUuidList(pkg.reportedHistoryIds);
    const reportedWithMatches = new Set(scanWithValues.changes.filter(change => reportedIds.includes(change.historyId)).map(change => change.historyId));
    const reportedResolved = reportedIds.length > 0
      ? reportedWithMatches.size > 0 && [...reportedWithMatches].every(historyId => appliedHistoryIds.has(historyId))
      : fullyApplied;

    if (HAS_ALERT_FEEDBACK_META && Array.isArray(pkg.feedbackIds) && pkg.feedbackIds.length && reportedResolved) {
      await supabase.from('alerts').update({
        feedback_status: 'resolved',
        resolved_at: new Date().toISOString(),
        resolved_by: req.session.name || req.session.username,
        resolution_group: resolutionGroup,
        resolution_note: resolutionNote
      }).eq('type', 'feedback').in('id', pkg.feedbackIds);
    }

    if (HAS_ISSUE_RESOLUTION_LOG) {
      await supabase.from('issue_resolution_log').insert({
        resolution_group: resolutionGroup,
        title: pkg.title,
        summary: [
          pkg.note || `${pkg.from} -> ${pkg.to}`,
          `Etkilenen kayıt: ${appliedRecords}`,
          `Değişim: ${appliedChanges}`
        ].join('\n'),
        status: fullyApplied ? 'applied' : 'partially_applied',
        feedback_count: Array.isArray(pkg.feedbackIds) ? pkg.feedbackIds.length : 0,
        user_count: 0,
        created_by: req.session.name || req.session.username
      });
    }

    res.json({ success: true, package: publicCorrectionPackage(updated, scan), scan, applied: appliedRecords, changes: appliedChanges, partial: !fullyApplied });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/correction-packages/:id/revert', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!HAS_CONTENT_CORRECTION_LOG) {
      return res.status(400).json({ error: 'Geçmiş içerik düzeltme kayıt defteri hazır değil.' });
    }
    const packages = await loadCorrectionPackages();
    const pkg = packages.find(item => item.id === req.params.id);
    if (!pkg) return res.status(404).json({ error: 'Düzeltme paketi bulunamadı.' });

    const logs = await fetchAllPages(() => supabase.from('content_correction_log')
      .select('*')
      .eq('package_id', pkg.id)
      .eq('status', 'applied')
      .order('created_at', { ascending: false }));
    if (!logs.length) return res.status(400).json({ error: 'Geri alınacak uygulanmış kayıt bulunamadı.' });

    const updatesByHistory = new Map();
    logs.forEach(log => {
      if (!updatesByHistory.has(log.history_id)) updatesByHistory.set(log.history_id, {});
      updatesByHistory.get(log.history_id)[log.field_name] = log.old_value || '';
    });
    for (const [historyId, update] of updatesByHistory.entries()) {
      const { error: updateError } = await supabase.from('history').update(update).eq('id', historyId);
      if (updateError) throw new Error(updateError.message);
    }
    const { error: logUpdateError } = await supabase.from('content_correction_log')
      .update({ status: 'reverted' })
      .in('id', logs.map(log => log.id));
    if (logUpdateError) throw new Error(logUpdateError.message);

    const updated = await updateCorrectionPackage(pkg.id, {
      status: 'reverted',
      revertedAt: new Date().toISOString(),
      revertedBy: req.session.name || req.session.username
    });
    res.json({ success: true, package: publicCorrectionPackage(updated), reverted: updatesByHistory.size });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/history', auth, async (req, res) => {
  try {
    const data = await fetchAllPages(() => {
      let q = supabase.from('history').select('*').order('created_at', { ascending: false });
      if (isAdminRole(req.session.role)) q = q.or(`status.is.null,status.not.in.(taslak,${CHUNK_DRAFT_STATUS},${SUBMITTED_PART_STATUS})`);
      else q = q.eq('user_id', req.session.userId).or(`status.is.null,status.not.in.(${CHUNK_DRAFT_STATUS},${SUBMITTED_PART_STATUS})`);
      return q;
    });
    res.json((data || []).map(mapHistory).filter(h => !isHiddenHistoryForRole(h, req.session.role)));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history/approval-board', auth, admin, async (req, res) => {
  try {
    const [pending, approved, rejected] = await Promise.all([
      loadApprovalGroup(q => q.or('status.is.null,status.eq.bekliyor')),
      loadApprovalGroup(q => q.eq('status', 'onaylandi')),
      loadApprovalGroup(q => q.eq('status', 'reddedildi'))
    ]);
    res.json({
      groups: {
        bekliyor: pending,
        onaylandi: approved,
        reddedildi: rejected
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history/:id([0-9a-fA-F-]{36})', auth, async (req, res) => {
  try {
    let query = supabase.from('history').select('*').eq('id', req.params.id);
    if (!isAdminRole(req.session.role)) query = query.eq('user_id', req.session.userId);
    const { data, error } = await query.maybeSingle();
    if (error) throw new Error(error.message);
    if (!data) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    const mapped = mapHistory(data);
    if (data.user_id !== req.session.userId && isHiddenHistoryForRole(mapped, req.session.role)) {
      return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    }
    if (data.user_id === req.session.userId && isHiddenHistoryForRole(mapped, req.session.role)) {
      return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    }
    res.json(mapped);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history/:id([0-9a-fA-F-]{36})/approval-status', auth, async (req, res) => {
  try {
    let query = supabase.from('history')
      .select('id,user_id,status,approved_by,approved_at')
      .eq('id', req.params.id);
    if (!isAdminRole(req.session.role)) query = query.eq('user_id', req.session.userId);
    const { data, error } = await query.maybeSingle();
    if (error) throw new Error(error.message);
    if (!data) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    res.json({
      id: data.id,
      status: data.status || 'bekliyor',
      submitted: historyStatusForApproval(data.status) || data.status === 'onaylandi',
      approvedBy: data.approved_by,
      approvedAt: data.approved_at
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/history/:id([0-9a-fA-F-]{36})/feedback', auth, async (req, res) => {
  try {
    const { reason, note, category, original, fixed, rule } = req.body || {};
    const reasonLabel = FEEDBACK_REASONS[reason] || FEEDBACK_REASONS.other;
    const cleanNote = String(note || '').trim().slice(0, 2000);
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

function safeUuidList(values, limit = 80) {
  const uuidRe = /^[0-9a-fA-F-]{36}$/;
  return [...new Set((Array.isArray(values) ? values : []).map(String).filter(id => uuidRe.test(id)).slice(0, limit))];
}

function countsFromSubmittedCategories(categories) {
  const out = { sozluk: 0, imla: 0, noktalama: 0, etiket: 0, yapi: 0 };
  Object.keys(out).forEach(key => {
    const item = categories?.[key];
    const count = Number.isFinite(Number(item?.count)) ? Number(item.count) : Array.isArray(item?.issues) ? item.issues.length : 0;
    out[key] = Math.max(0, Math.min(5000, Math.round(count)));
  });
  return out;
}

function httpError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function mergedHistoryPayloadFromBody(req, fallbackSummary) {
  const originalText = prepareAnalysisText(req.body?.originalText || '');
  const correctedText = String(req.body?.correctedText || '').normalize('NFC').replace(/\r\n?/g, '\n').trim();
  if (!correctedText) throw httpError('Onaya gönderilecek düzeltilmiş metin bulunamadı.');

  const filename = String(req.body?.filename || 'Metin Girişi').trim().slice(0, 160) || 'Metin Girişi';
  const score = Math.max(0, Math.min(100, Math.round(Number(req.body?.score) || 0)));
  const totalErrors = Math.max(0, Math.min(100000, Math.round(Number(req.body?.totalErrors) || 0)));
  const categories = countsFromSubmittedCategories(req.body?.categories || {});
  const summary = String(req.body?.summary || fallbackSummary).trim().slice(0, 2000);
  const analysisMeta = req.body?.analysisMeta || {};
  const hash = textHash(originalText);

  return { originalText, correctedText, filename, score, totalErrors, categories, summary, analysisMeta, hash };
}

async function loadValidChunkSources(req, sourceIds) {
  if (!sourceIds.length) throw httpError('Sonuç kaydı hazırlanamadı. Lütfen denetimi yeniden başlatın.');
  const { data: sources, error: sourceError } = await supabase.from('history')
    .select('id,user_id,status,filename')
    .eq('user_id', req.session.userId)
    .in('id', sourceIds);
  if (sourceError) throw new Error(sourceError.message);
  if ((sources || []).length !== sourceIds.length) throw httpError('Sonuç kaydı eksik görünüyor. Lütfen denetimi yeniden başlatın.', 404);
  const validSourceStatuses = ['taslak', CHUNK_DRAFT_STATUS];
  if ((sources || []).some(item => !validSourceStatuses.includes(item.status) || !isChunkHistoryRow(item))) {
    throw httpError('Bu sonuç daha önce onaya gönderilmiş olabilir.');
  }
  return sources;
}

async function submittedDuplicateExists(req, hash, excludeId = '') {
  if (!HAS_TEXT_HASH || !hash) return false;
  let q = supabase.from('history')
    .select('id')
    .eq('user_id', req.session.userId)
    .eq('text_hash', hash)
    .or('status.is.null,status.in.(bekliyor,onaylandi)')
    .limit(1);
  if (excludeId) q = q.neq('id', excludeId);
  const { data, error } = await q;
  if (error) { console.warn('Onay tekrar kontrolü uyarısı:', error.message); return false; }
  return !!data?.length;
}

function submittedCorrectedHashKey(userId, correctedText) {
  if (!userId || !normalizeText(correctedText)) return '';
  return `${SUBMITTED_CORRECTED_HASH_PREFIX}${userId}:${textHash(correctedText)}`;
}

function parseSettingJson(value) {
  try { return JSON.parse(value || '{}'); }
  catch { return {}; }
}

function isDuplicateKeyError(error) {
  return error && (error.code === '23505' || /duplicate key/i.test(error.message || ''));
}

function stalePendingCorrectedHash(value = {}) {
  if (value.status !== 'pending' || !value.createdAt) return false;
  const created = Date.parse(value.createdAt);
  return Number.isFinite(created) && Date.now() - created > 20 * 60 * 1000;
}

async function readSubmittedCorrectedHash(userId, correctedText) {
  const key = submittedCorrectedHashKey(userId, correctedText);
  if (!key) return null;
  const { data, error } = await supabase.from('settings').select('key,value').eq('key', key).maybeSingle();
  if (error) {
    console.warn('Duzeltilmis metin kilidi okunamadi:', error.message);
    return null;
  }
  return data ? { key, value: parseSettingJson(data.value) } : null;
}

async function submittedCorrectedDuplicateExists(req, correctedText, excludeId = '') {
  const existing = await readSubmittedCorrectedHash(req.session.userId, correctedText);
  if (!existing) return false;
  const historyId = existing.value?.historyId || '';
  const status = existing.value?.status || 'bekliyor';
  if (stalePendingCorrectedHash(existing.value)) {
    const { error } = await supabase.from('settings').delete().eq('key', existing.key);
    if (error) console.warn('Eski duzeltilmis metin kilidi temizlenemedi:', error.message);
    return false;
  }
  if (excludeId && historyId === excludeId) return false;
  return status !== 'reddedildi';
}

async function reserveSubmittedCorrectedHash(req, correctedText, historyId = '') {
  const key = submittedCorrectedHashKey(req.session.userId, correctedText);
  if (!key) return { reserved: false, duplicate: false, key: '' };
  if (await submittedCorrectedDuplicateExists(req, correctedText, historyId)) {
    return { reserved: false, duplicate: true, key };
  }
  const value = JSON.stringify({
    userId: req.session.userId,
    historyId: historyId || null,
    status: 'pending',
    createdAt: new Date().toISOString()
  });
  const { error } = await supabase.from('settings').insert({ key, value });
  if (isDuplicateKeyError(error)) {
    const existing = await readSubmittedCorrectedHash(req.session.userId, correctedText);
    const sameHistory = historyId && existing?.value?.historyId === historyId;
    const reusable = sameHistory || existing?.value?.status === 'reddedildi' || stalePendingCorrectedHash(existing?.value || {});
    if (reusable) {
      await supabase.from('settings').delete().eq('key', key);
      const retry = await supabase.from('settings').insert({ key, value });
      if (!retry.error) return { reserved: true, duplicate: false, key };
      if (!isDuplicateKeyError(retry.error)) {
        console.warn('Duzeltilmis metin kilidi tekrar olusturulamadi:', retry.error.message);
        return { reserved: false, duplicate: false, key: '' };
      }
    }
    return { reserved: false, duplicate: true, key };
  }
  if (error) {
    console.warn('Duzeltilmis metin kilidi olusturulamadi:', error.message);
    return { reserved: false, duplicate: false, key: '' };
  }
  return { reserved: true, duplicate: false, key };
}

async function markSubmittedCorrectedHash(userId, correctedText, historyId, status = 'bekliyor') {
  const key = submittedCorrectedHashKey(userId, correctedText);
  if (!key) return;
  const value = JSON.stringify({ userId, historyId, status, updatedAt: new Date().toISOString() });
  const { error } = await supabase.from('settings').upsert({ key, value });
  if (error) console.warn('Duzeltilmis metin kilidi guncellenemedi:', error.message);
}

async function releaseSubmittedCorrectedHash(userId, correctedText, historyId = '') {
  const existing = await readSubmittedCorrectedHash(userId, correctedText);
  if (!existing) return;
  if (historyId && existing.value?.historyId && existing.value.historyId !== historyId) return;
  const { error } = await supabase.from('settings').delete().eq('key', existing.key);
  if (error) console.warn('Duzeltilmis metin kilidi kaldirilamadi:', error.message);
}

app.post('/api/history/:id([0-9a-fA-F-]{36})/submit', auth, async (req, res) => {
  let correctedReservation = null;
  let reservationText = '';
  try {
    const { data: history, error } = await supabase.from('history')
      .select('*')
      .eq('id', req.params.id)
      .eq('user_id', req.session.userId)
      .maybeSingle();
    if (error) throw new Error(error.message);
    if (!history) return res.status(404).json({ error: 'Taslak kayıt bulunamadı.' });
    if (isChunkHistoryRow(history)) {
      return res.status(400).json({ error: 'Bu kayıt onaya gönderilemez. Lütfen sonuç ekranındaki Onaya Gönder butonunu kullanın.' });
    }
    if (history.status === 'onaylandi' || history.status === 'reddedildi') {
      return res.status(400).json({ error: 'Bu kayıt zaten onay sürecinden geçmiş.' });
    }
    if (historyStatusForApproval(history.status)) {
      return res.json({ success: true, id: history.id, status: 'bekliyor', alreadySubmitted: true, tags: history.tags || [], questionText: history.question_text || '' });
    }
    if (history.status !== 'taslak') return res.status(400).json({ error: 'Bu kayıt onaya gönderilemez.' });
    const approvalMeta = requireApprovalQuestionAndTags(req.body);
    if (await submittedDuplicateExists(req, history.text_hash, history.id)) {
      return res.status(400).json({ error: 'Bu metnin onaya gönderilmiş bir kaydı zaten var.' });
    }
    reservationText = history.corrected_text || '';
    correctedReservation = await reserveSubmittedCorrectedHash(req, reservationText, history.id);
    if (correctedReservation.duplicate) {
      return res.status(400).json({ error: 'Bu düzeltilmiş metnin onaya gönderilmiş veya onaylanmış bir kaydı zaten var.' });
    }
    const updateRow = { status: 'bekliyor', approved_by: null, approved_at: null };
    updateRow.tags = approvalMeta.tags;
    updateRow.question_text = approvalMeta.questionText;
    const { data, error: updateError } = await supabase.from('history')
      .update(updateRow)
      .eq('id', history.id)
      .eq('user_id', req.session.userId)
      .eq('status', 'taslak')
      .select('*')
      .single();
    if (updateError) throw new Error(updateError.message);
    await markSubmittedCorrectedHash(req.session.userId, reservationText, data.id, data.status);
    await maybeCreateLowScoreAlert(req, history.id, history.score, history.filename);
    res.json({ success: true, id: data.id, status: data.status, tags: data.tags || updateRow.tags || [], questionText: data.question_text || updateRow.question_text || '' });
  } catch (e) {
    if (correctedReservation?.reserved) await releaseSubmittedCorrectedHash(req.session.userId, reservationText, req.params.id);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

app.post('/api/history/:id([0-9a-fA-F-]{36})/withdraw', auth, async (req, res) => {
  try {
    const { data: history, error } = await supabase.from('history')
      .select('id,user_id,status,corrected_text')
      .eq('id', req.params.id)
      .eq('user_id', req.session.userId)
      .maybeSingle();
    if (error) throw new Error(error.message);
    if (!history || isChunkHistoryRow(history)) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    if (history.status === 'onaylandi' || history.status === 'reddedildi') {
      return res.status(400).json({ error: 'Bu kayıt artık sonuçlanmış; geri çekilemez.' });
    }
    if (!historyStatusForApproval(history.status)) {
      return res.json({ success: true, id: history.id, status: history.status || 'taslak', alreadyWithdrawn: true });
    }
    const { data, error: updateError } = await supabase.from('history')
      .update({ status: 'taslak', approved_by: null, approved_at: null })
      .eq('id', history.id)
      .eq('user_id', req.session.userId)
      .or('status.is.null,status.eq.bekliyor')
      .select('id,status')
      .single();
    if (updateError) throw new Error(updateError.message);
    await releaseSubmittedCorrectedHash(req.session.userId, history.corrected_text || '', history.id);
    res.json({ success: true, id: data.id, status: data.status });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/history/merged-draft', auth, async (req, res) => {
  try {
    const sourceIds = safeUuidList(req.body?.sourceIds);
    await loadValidChunkSources(req, sourceIds);
    const payload = mergedHistoryPayloadFromBody(req, 'Metin denetlendi ve sonuç hazırlandı.');

    const result = {
      score: payload.score,
      totalErrors: payload.totalErrors,
      categories: payload.categories,
      summary: payload.summary,
      correctedText: payload.correctedText,
      analysisMeta: payload.analysisMeta
    };
    const id = await saveHistory(req, result, payload.filename, payload.hash, payload.originalText, 'taslak');
    const { error: hideError } = await supabase.from('history')
      .update({ status: SUBMITTED_PART_STATUS })
      .eq('user_id', req.session.userId)
      .in('id', sourceIds)
      .in('status', ['taslak', CHUNK_DRAFT_STATUS]);
    if (hideError) throw new Error(hideError.message);
    res.json({ success: true, id, status: 'taslak' });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/history/submit-merged', auth, async (req, res) => {
  let correctedReservation = null;
  let reservationText = '';
  try {
    const sourceIds = safeUuidList(req.body?.sourceIds);
    await loadValidChunkSources(req, sourceIds);
    const payload = mergedHistoryPayloadFromBody(req, 'Metin denetlendi ve sonuç onay sürecine iletildi.');
    const approvalMeta = requireApprovalQuestionAndTags(req.body);
    if (await submittedDuplicateExists(req, payload.hash)) {
      return res.status(400).json({ error: 'Bu metnin onaya gönderilmiş bir kaydı zaten var.' });
    }
    reservationText = payload.correctedText || '';
    correctedReservation = await reserveSubmittedCorrectedHash(req, reservationText);
    if (correctedReservation.duplicate) {
      return res.status(400).json({ error: 'Bu düzeltilmiş metnin onaya gönderilmiş veya onaylanmış bir kaydı zaten var.' });
    }

    const mergedRow = {
      user_id: req.session.userId,
      username: req.session.username,
      name: req.session.name,
      filename: payload.filename,
      score: payload.score,
      total_errors: payload.totalErrors,
      cat_counts: payload.categories,
      summary: payload.summary,
      corrected_text: payload.correctedText,
      status: 'bekliyor'
    };
    mergedRow.tags = approvalMeta.tags;
    mergedRow.question_text = approvalMeta.questionText;
    if (HAS_ORIGINAL_TEXT) mergedRow.original_text = payload.originalText;
    if (HAS_TEXT_HASH) mergedRow.text_hash = payload.hash;
    if (HAS_ANALYSIS_META) {
      mergedRow.prompt_version = payload.analysisMeta?.promptVersion || PROMPT_VERSION;
      mergedRow.rules_hash = payload.analysisMeta?.rulesHash || null;
    }

    const { data, error: insertError } = await supabase.from('history').insert(mergedRow).select('*').single();
    if (insertError) throw new Error(insertError.message);
    await markSubmittedCorrectedHash(req.session.userId, reservationText, data.id, data.status);
    const { error: hideError } = await supabase.from('history')
      .update({ status: SUBMITTED_PART_STATUS })
      .eq('user_id', req.session.userId)
      .in('id', sourceIds)
      .in('status', ['taslak', CHUNK_DRAFT_STATUS]);
    if (hideError) console.warn('Birlesik onay sonrasi parca gizleme uyarisi:', hideError.message);
    await maybeCreateLowScoreAlert(req, data.id, payload.score, payload.filename);
    res.json({ success: true, id: data.id, status: data.status, tags: data.tags || mergedRow.tags || [], questionText: data.question_text || mergedRow.question_text || '' });
  } catch (e) {
    if (correctedReservation?.reserved) await releaseSubmittedCorrectedHash(req.session.userId, reservationText);
    res.status(e.statusCode || 500).json({ error: e.message });
  }
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
  const rows = [['Tarih', 'Kullanıcı', 'Dosya/Metin', 'Skor', 'Toplam Hata', 'Sözlük', 'İmla', 'Noktalama', 'Etiket Hatası', 'Yapı', 'Durum', 'Onaylayan', 'Soru', 'Soru Etiketleri', 'Prompt Sürümü', 'Kural Hash']];
  (data || []).map(mapHistory).filter(h => !isHiddenHistoryForRole(h, ROLES.ADMIN)).forEach(h => {
    rows.push([
      new Date(h.createdAt).toLocaleString('tr-TR'),
      h.name || '', h.filename || '',
      h.score || 0, h.totalErrors || 0,
      h.catCounts?.sozluk || 0, h.catCounts?.imla || 0,
      h.catCounts?.noktalama || 0, h.catCounts?.etiket || 0, h.catCounts?.yapi || 0,
      h.status || 'bekliyor', h.approvedBy || '', h.questionText || '', (h.tags || []).join(', '),
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
    const { data: current, error: currentError } = await supabase.from('history')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();
    if (currentError) throw new Error(currentError.message);
    if (!current || isHiddenHistoryForRole(mapHistory(current), ROLES.ADMIN)) {
      return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    }
    const updateRow = {
      status, approved_by: req.session.name, approved_at: new Date().toISOString()
    };
    if (HAS_HISTORY_TAGS && Object.prototype.hasOwnProperty.call(req.body || {}, 'tags')) {
      updateRow.tags = normalizeHistoryTags(req.body?.tags);
    }
    if (HAS_HISTORY_QUESTION_TEXT && Object.prototype.hasOwnProperty.call(req.body || {}, 'questionText')) {
      updateRow.question_text = normalizeHistoryQuestion(req.body?.questionText);
    }
    const { data, error } = await supabase.from('history').update(updateRow).eq('id', req.params.id).select('*');
    if (error) throw new Error(error.message);
    if (!data?.length) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    if (status === 'reddedildi') await releaseSubmittedCorrectedHash(current.user_id, current.corrected_text || '', current.id);
    if (status === 'onaylandi') await markSubmittedCorrectedHash(current.user_id, current.corrected_text || '', current.id, status);
    res.json({ success: true, history: mapHistory(data[0]) });
  } catch (e) { res.status(500).json({ error: e.message }); }
}
app.post('/api/history/:id/approve', auth, admin, (req, res) => setApproval(req, res, 'onaylandi'));
app.post('/api/history/:id/reject',  auth, admin, (req, res) => setApproval(req, res, 'reddedildi'));

app.post('/api/history/:id([0-9a-fA-F-]{36})/tags', auth, admin, async (req, res) => {
  try {
    if (!HAS_HISTORY_TAGS) return res.status(400).json({ error: 'Etiket alanı henüz veritabanında aktif değil.' });
    const tags = normalizeHistoryTags(req.body?.tags);
    const { data, error } = await supabase.from('history')
      .update({ tags })
      .eq('id', req.params.id)
      .select('id,tags')
      .maybeSingle();
    if (error) throw new Error(error.message);
    if (!data) return res.status(404).json({ error: 'Kayıt bulunamadı.' });
    res.json({ success: true, id: data.id, tags: data.tags || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ALERTS ────────────────────────────────────────────────────────────────
function ensureHistoryTagImportReady(res) {
  if (!HAS_HISTORY_TAGS) {
    res.status(400).json({ error: 'Denetim kayıtlarında etiket alanı aktif değil. schema.sql içindeki history.tags SQL satırı uygulanmalı.' });
    return false;
  }
  if (!HAS_HISTORY_TAG_IMPORT_TABLES) {
    res.status(400).json({ error: 'Etiket aktarım tabloları aktif değil. schema.sql içindeki history_tag_import tabloları Supabase SQL Editor tarafında uygulanmalı.' });
    return false;
  }
  return true;
}

async function refreshHistoryTagImportBatchCounts(batchId) {
  const matches = await fetchAllPages(() => supabase.from('history_tag_import_matches')
    .select('match_status')
    .eq('batch_id', batchId), 1000);
  const counts = { ready: 0, review: 0, unmatched: 0, applied: 0, skipped: 0 };
  (matches || []).forEach(row => {
    const key = row.match_status || 'review';
    if (Object.prototype.hasOwnProperty.call(counts, key)) counts[key]++;
  });
  const status = counts.ready + counts.review + counts.unmatched > 0 ? 'preview' : 'completed';
  const { data, error: updateError } = await supabase.from('history_tag_import_batches')
    .update({
      ready_count: counts.ready,
      review_count: counts.review,
      unmatched_count: counts.unmatched,
      applied_count: counts.applied,
      skipped_count: counts.skipped,
      status,
      updated_at: new Date().toISOString()
    })
    .eq('id', batchId)
    .select('*')
    .maybeSingle();
  if (updateError) throw new Error(updateError.message);
  return publicHistoryTagImportBatch(data || {});
}

async function fetchHistoryTagImportHistoryRows() {
  const rows = await fetchAllPages(() => supabase.from('history')
    .select(historyTagImportSelectColumns())
    .order('created_at', { ascending: false }), 1000);
  return (rows || [])
    .map(row => tagImportHistoryCandidate(row))
    .filter(row => !isHiddenHistoryForRole({ status: row.status, filename: row.filename }, ROLES.ADMIN))
    .filter(row => row.correctedText || row.originalText);
}

function buildHistoryTagImportMatches(historyRows, excelItems) {
  const excelIndex = buildTagImportExcelIndex(excelItems);
  return historyRows.map(history => {
    const indexes = tagImportCandidateIndexes(history, excelIndex);
    let bestItem = null;
    let bestScore = { confidence: 0, reason: 'eslesme bulunamadi' };
    for (const index of indexes) {
      const excelItem = excelItems[index];
      const score = scoreTagImportMatch(history, excelItem);
      if (score.confidence > bestScore.confidence) {
        bestScore = score;
        bestItem = excelItem;
      }
      if (score.confidence >= 99) break;
    }
    const status = historyTagImportStatus(bestScore.confidence, history, bestItem);
    return {
      history_id: history.id,
      excel_row: bestItem?.rowNumber || null,
      excel_question: bestItem?.question || '',
      answer_preview: bestItem?.answerPreview || archiveTextPreview(history.correctedText || history.originalText, 320),
      tags: bestItem?.tags || [],
      confidence: bestScore.confidence,
      match_status: status,
      match_reason: bestScore.reason,
      current_tags: history.tags || []
    };
  });
}

async function attachHistoryToTagImportMatches(rows = []) {
  const historyIds = [...new Set((rows || []).map(row => row.history_id).filter(Boolean))];
  if (!historyIds.length) return rows || [];
  const { data, error } = await supabase.from('history')
    .select(historyTagImportSelectColumns())
    .in('id', historyIds);
  if (error) throw new Error(error.message);
  const byId = new Map((data || []).map(row => [row.id, row]));
  return (rows || []).map(row => ({ ...row, history: byId.get(row.history_id) || null }));
}

async function insertHistoryTagImportMatches(batchId, matches = []) {
  for (let i = 0; i < matches.length; i += TAG_IMPORT_INSERT_CHUNK_SIZE) {
    const chunk = matches.slice(i, i + TAG_IMPORT_INSERT_CHUNK_SIZE).map(row => ({ ...row, batch_id: batchId }));
    const { error } = await supabase.from('history_tag_import_matches').insert(chunk);
    if (error) throw new Error(error.message);
  }
}

function tagImportUploadMetaKey(uploadId) {
  return `${TAG_IMPORT_UPLOAD_KEY_PREFIX}:${uploadId}:meta`;
}

function tagImportUploadChunkKey(uploadId, index) {
  return `${TAG_IMPORT_UPLOAD_KEY_PREFIX}:${uploadId}:chunk:${index}`;
}

function createTagImportUploadId() {
  return `tiu-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
}

function isValidTagImportUploadId(uploadId = '') {
  return /^tiu-\d{10,}-[a-f0-9]{12}$/i.test(String(uploadId || ''));
}

async function cleanupTagImportUpload(uploadId, totalChunks = 0) {
  if (!isValidTagImportUploadId(uploadId)) return;
  const keys = [tagImportUploadMetaKey(uploadId)];
  for (let i = 0; i < Number(totalChunks || 0); i++) keys.push(tagImportUploadChunkKey(uploadId, i));
  await deleteSettingsByKeys(keys);
}

async function createHistoryTagImportPreviewFromBuffer(buffer, fileName, actorName) {
  const parsed = parseHistoryTagImportWorkbook(buffer, fileName || 'Etiket dosyası');
  if (!parsed.usableRows) {
    const err = new Error('Dosyada etiketli soru-cevap satırı bulunamadı. Soru, Etiket/Sınıf ve Cevap sütunlarını kontrol edin.');
    err.statusCode = 400;
    throw err;
  }
  const historyRows = await fetchHistoryTagImportHistoryRows();
  const matches = buildHistoryTagImportMatches(historyRows, parsed.items);
  const { data: batch, error: batchError } = await supabase.from('history_tag_import_batches')
    .insert({
      filename: parsed.fileName,
      sheet_name: parsed.sheetName,
      total_rows: parsed.totalRows,
      usable_rows: parsed.usableRows,
      history_count: historyRows.length,
      status: 'preview',
      note: `Excel etiketi ön izlemesi: ${parsed.fileName}`,
      created_by: actorName || ''
    })
    .select('*')
    .single();
  if (batchError) throw new Error(batchError.message);
  if (matches.length) await insertHistoryTagImportMatches(batch.id, matches);
  const refreshed = await refreshHistoryTagImportBatchCounts(batch.id);
  const { data: detailRows, error: detailError } = await supabase.from('history_tag_import_matches')
    .select('*')
    .eq('batch_id', batch.id)
    .order('confidence', { ascending: false })
    .limit(TAG_IMPORT_INITIAL_DETAIL_LIMIT);
  if (detailError) throw new Error(detailError.message);
  const rowsWithHistory = await attachHistoryToTagImportMatches(detailRows || []);
  return { batch: refreshed, matches: rowsWithHistory.map(publicHistoryTagImportMatch) };
}

async function applyHistoryTagImportMatchRow(matchId, actorName, options = {}) {
  const { data: match, error } = await supabase.from('history_tag_import_matches')
    .select('*')
    .eq('id', matchId)
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!match) {
    const err = new Error('Etiket aktarım kaydı bulunamadı.');
    err.statusCode = 404;
    throw err;
  }
  if (match.match_status === 'applied') return match;
  if (!match.history_id) {
    const err = new Error('Bu satır mevcut bir denetim kaydıyla eşleşmemiş.');
    err.statusCode = 400;
    throw err;
  }
  const tags = normalizeHistoryTags(match.tags || []);
  if (!tags.length) {
    const err = new Error('Uygulanacak etiket bulunamadı.');
    err.statusCode = 400;
    throw err;
  }
  const historyUpdate = {};
  if (HAS_HISTORY_TAGS) historyUpdate.tags = tags;
  if (HAS_HISTORY_QUESTION_TEXT) {
    const { data: existingHistory, error: existingHistoryError } = await supabase.from('history')
      .select('question_text')
      .eq('id', match.history_id)
      .maybeSingle();
    if (existingHistoryError) throw new Error(existingHistoryError.message);
    const importedQuestion = normalizeHistoryQuestion(match.excel_question);
    const existingQuestion = normalizeHistoryQuestion(existingHistory?.question_text || '');
    if (!existingQuestion && importedQuestion) historyUpdate.question_text = importedQuestion;
  }
  const { data: updatedHistory, error: historyError } = await supabase.from('history')
    .update(historyUpdate)
    .eq('id', match.history_id)
    .select('*')
    .maybeSingle();
  if (historyError) throw new Error(historyError.message);
  if (!updatedHistory) {
    const err = new Error('Denetim kaydı bulunamadı.');
    err.statusCode = 404;
    throw err;
  }
  const { data: updatedMatch, error: matchError } = await supabase.from('history_tag_import_matches')
    .update({
      current_tags: updatedHistory.tags || tags,
      match_status: 'applied',
      applied_at: new Date().toISOString(),
      applied_by: actorName || ''
    })
    .eq('id', matchId)
    .select('*')
    .maybeSingle();
  if (matchError) throw new Error(matchError.message);
  if (options.refreshBatch !== false) await refreshHistoryTagImportBatchCounts(match.batch_id);
  return updatedMatch || match;
}

function historyTagImportApplyLimit(value) {
  const requested = Number(value || 0);
  if (!Number.isFinite(requested) || requested <= 0) return TAG_IMPORT_APPLY_CHUNK_SIZE;
  return Math.min(TAG_IMPORT_APPLY_CHUNK_SIZE, Math.max(1, Math.floor(requested)));
}

async function applyHistoryTagImportBatchChunk({ batchId, matchStatus, minConfidence, limit, actorName }) {
  const safeLimit = historyTagImportApplyLimit(limit);
  let query = supabase.from('history_tag_import_matches')
    .select('id')
    .eq('batch_id', batchId)
    .eq('match_status', matchStatus)
    .order('confidence', { ascending: false })
    .order('id', { ascending: true })
    .limit(safeLimit);
  if (Number.isFinite(minConfidence)) query = query.gte('confidence', minConfidence);
  const { data: rows, error } = await query;
  if (error) throw new Error(error.message);

  let applied = 0;
  const errors = [];
  for (const row of rows || []) {
    try {
      await applyHistoryTagImportMatchRow(row.id, actorName, { refreshBatch: false });
      applied++;
    } catch (error) {
      errors.push(error.message);
    }
  }

  const batch = await refreshHistoryTagImportBatchCounts(batchId);
  const remaining = matchStatus === 'ready' ? Number(batch.readyCount || 0) : Number(batch.reviewCount || 0);
  return {
    success: errors.length === 0,
    applied,
    errors,
    batch,
    remaining,
    done: remaining === 0,
    limit: safeLimit
  };
}

async function fetchHistoryQuestionRowsByIds(historyIds = []) {
  const out = new Map();
  const ids = [...new Set((historyIds || []).filter(Boolean))];
  for (let i = 0; i < ids.length; i += 250) {
    const chunk = ids.slice(i, i + 250);
    const { data, error } = await supabase.from('history')
      .select('id,question_text')
      .in('id', chunk);
    if (error) throw new Error(error.message);
    (data || []).forEach(row => out.set(row.id, row));
  }
  return out;
}

async function backfillHistoryTagImportQuestionsChunk({ batchId, limit }) {
  if (!HAS_HISTORY_QUESTION_TEXT) {
    const err = new Error('Denetim kayıtlarında soru alanı aktif değil. schema.sql içindeki history.question_text SQL satırı uygulanmalı.');
    err.statusCode = 400;
    throw err;
  }
  const safeLimit = historyTagImportApplyLimit(limit);
  const matches = await fetchAllPages(() => supabase.from('history_tag_import_matches')
    .select('id,batch_id,history_id,excel_question,confidence,match_status')
    .eq('batch_id', batchId)
    .eq('match_status', 'applied')
    .not('history_id', 'is', null)
    .not('excel_question', 'is', null)
    .order('confidence', { ascending: false })
    .order('id', { ascending: true }), 1000);

  const byHistory = new Map();
  for (const match of matches || []) {
    const question = normalizeHistoryQuestion(match.excel_question);
    if (!question || !match.history_id) continue;
    if (!byHistory.has(match.history_id)) byHistory.set(match.history_id, { ...match, question });
  }

  const uniqueMatches = [...byHistory.values()];
  const historyById = await fetchHistoryQuestionRowsByIds(uniqueMatches.map(match => match.history_id));
  const missing = uniqueMatches.filter(match => {
    const current = normalizeHistoryQuestion(historyById.get(match.history_id)?.question_text || '');
    return !current;
  });

  const rows = missing.slice(0, safeLimit);
  let updated = 0;
  const errors = [];
  for (const row of rows) {
    try {
      const { error } = await supabase.from('history')
        .update({ question_text: row.question })
        .eq('id', row.history_id);
      if (error) throw new Error(error.message);
      updated++;
    } catch (error) {
      errors.push(error.message);
    }
  }

  const remaining = Math.max(0, missing.length - updated);
  const batch = await refreshHistoryTagImportBatchCounts(batchId);
  return {
    success: errors.length === 0,
    updated,
    skippedExisting: Math.max(0, uniqueMatches.length - missing.length),
    errors,
    batch,
    remaining,
    totalMissing: missing.length,
    done: remaining === 0,
    limit: safeLimit
  };
}

app.post('/api/history-tags/import/preview', auth, admin, superAdmin, tagImportUpload.single('file'), async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    if (!req.file?.buffer) return res.status(400).json({ error: 'Etiket aktarımı için Excel dosyası seçin.' });
    const payload = await createHistoryTagImportPreviewFromBuffer(
      req.file.buffer,
      req.file.originalname || 'Etiket dosyası',
      req.session.name || req.session.username || ''
    );
    res.json(payload);
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/history-tags/import/upload/start', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const fileName = String(req.body?.fileName || req.body?.filename || 'Etiket dosyası').trim().slice(0, 220) || 'Etiket dosyası';
    const fileSize = Number(req.body?.fileSize || req.body?.size || 0);
    const totalChunks = Number(req.body?.totalChunks || 0);
    if (!Number.isFinite(fileSize) || fileSize <= 0) return res.status(400).json({ error: 'Dosya boyutu okunamadı. Lütfen dosyayı yeniden seçin.' });
    if (fileSize > TAG_IMPORT_MAX_UPLOAD_SIZE) return res.status(413).json({ error: 'Etiket dosyası çok büyük. Lütfen dosyayı sadeleştirip tekrar deneyin.' });
    if (!Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > TAG_IMPORT_MAX_UPLOAD_CHUNKS) return res.status(400).json({ error: 'Dosya parçaları hazırlanamadı. Lütfen sayfayı yenileyip tekrar deneyin.' });
    const uploadId = createTagImportUploadId();
    await saveJsonSetting(tagImportUploadMetaKey(uploadId), {
      uploadId,
      fileName,
      fileSize,
      totalChunks,
      createdBy: req.session.name || req.session.username || '',
      createdAt: new Date().toISOString()
    });
    res.json({ uploadId, totalChunks });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/history-tags/import/upload/chunk', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const uploadId = String(req.body?.uploadId || '').trim();
    const index = Number(req.body?.index);
    const totalChunks = Number(req.body?.totalChunks);
    const chunk = String(req.body?.chunk || '');
    if (!isValidTagImportUploadId(uploadId)) return res.status(400).json({ error: 'Yükleme oturumu bulunamadı. Lütfen dosyayı yeniden seçin.' });
    const meta = await loadJsonSetting(tagImportUploadMetaKey(uploadId), null);
    if (!meta) return res.status(404).json({ error: 'Yükleme oturumu süresi dolmuş. Lütfen dosyayı yeniden seçin.' });
    if (!Number.isInteger(index) || index < 0 || index >= meta.totalChunks) return res.status(400).json({ error: 'Dosya parçası sırası okunamadı.' });
    if (totalChunks !== meta.totalChunks) return res.status(400).json({ error: 'Dosya parça sayısı değişti. Lütfen dosyayı yeniden seçin.' });
    if (!chunk || chunk.length > TAG_IMPORT_MAX_CHUNK_BASE64_LENGTH) return res.status(413).json({ error: 'Dosya parçası çok büyük. Lütfen sayfayı yenileyip tekrar deneyin.' });
    await saveJsonSetting(tagImportUploadChunkKey(uploadId, index), { index, chunk, receivedAt: new Date().toISOString() });
    res.json({ success: true, index, received: index + 1, totalChunks: meta.totalChunks });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/history-tags/import/upload/complete', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const uploadId = String(req.body?.uploadId || '').trim();
    if (!isValidTagImportUploadId(uploadId)) return res.status(400).json({ error: 'Yükleme oturumu bulunamadı. Lütfen dosyayı yeniden seçin.' });
    const meta = await loadJsonSetting(tagImportUploadMetaKey(uploadId), null);
    if (!meta) return res.status(404).json({ error: 'Yükleme oturumu süresi dolmuş. Lütfen dosyayı yeniden seçin.' });
    const totalChunks = Number(meta.totalChunks || 0);
    if (!Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > TAG_IMPORT_MAX_UPLOAD_CHUNKS) return res.status(400).json({ error: 'Dosya parça bilgisi okunamadı. Lütfen dosyayı yeniden seçin.' });
    const keys = Array.from({ length: totalChunks }, (_, index) => tagImportUploadChunkKey(uploadId, index));
    const { data, error } = await supabase.from('settings').select('key,value').in('key', keys);
    if (error) throw new Error(error.message);
    const byKey = new Map((data || []).map(row => [row.key, parseJsonSettingValue(row.value, null)]));
    const missing = keys.filter(key => !byKey.get(key)?.chunk);
    if (missing.length) return res.status(400).json({ error: 'Dosyanın bazı parçaları eksik kaldı. Lütfen dosyayı yeniden seçip tekrar deneyin.' });
    const buffer = Buffer.concat(keys.map(key => Buffer.from(String(byKey.get(key).chunk || ''), 'base64')));
    if (meta.fileSize && Math.abs(buffer.length - Number(meta.fileSize)) > 2) {
      return res.status(400).json({ error: 'Dosya eksik aktarılmış görünüyor. Lütfen dosyayı yeniden seçip tekrar deneyin.' });
    }
    const payload = await createHistoryTagImportPreviewFromBuffer(
      buffer,
      meta.fileName || 'Etiket dosyası',
      req.session.name || req.session.username || ''
    );
    await cleanupTagImportUpload(uploadId, totalChunks);
    res.json(payload);
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/history-tags/import-batches', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const { data, error } = await supabase.from('history_tag_import_batches')
      .select('*')
      .order('updated_at', { ascending: false })
      .limit(40);
    if (error) throw new Error(error.message);
    res.json({ batches: (data || []).map(publicHistoryTagImportBatch) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const { data: batch, error } = await supabase.from('history_tag_import_batches')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();
    if (error) throw new Error(error.message);
    if (!batch) return res.status(404).json({ error: 'Etiket aktarım listesi bulunamadı.' });
    const refreshedBatch = await refreshHistoryTagImportBatchCounts(req.params.id);
    const status = String(req.query.status || '').trim();
    const q = String(req.query.q || '').trim().toLocaleLowerCase('tr-TR');
    let query = supabase.from('history_tag_import_matches')
      .select('*')
      .eq('batch_id', req.params.id)
      .order('confidence', { ascending: false })
      .limit(500);
    if (status) query = query.eq('match_status', status);
    const { data: rows, error: rowsError } = await query;
    if (rowsError) throw new Error(rowsError.message);
    const rowsWithHistory = await attachHistoryToTagImportMatches(rows || []);
    let matches = rowsWithHistory.map(publicHistoryTagImportMatch);
    if (q) {
      matches = matches.filter(item => [
        item.question,
        item.answerPreview,
        item.reason,
        item.status,
        item.history?.name,
        item.history?.username,
        item.history?.filename,
        item.history?.summary,
        ...(item.tags || []),
        ...(item.currentTags || [])
      ].join(' ').toLocaleLowerCase('tr-TR').includes(q));
    }
    res.json({ batch: refreshedBatch, matches });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const { data: batch, error: batchError } = await supabase.from('history_tag_import_batches')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();
    if (batchError) throw new Error(batchError.message);
    if (!batch) return res.status(404).json({ error: 'Etiket aktarım listesi bulunamadı.' });

    const { error: matchesError } = await supabase.from('history_tag_import_matches')
      .delete()
      .eq('batch_id', req.params.id);
    if (matchesError) throw new Error(matchesError.message);

    const { error: deleteError } = await supabase.from('history_tag_import_batches')
      .delete()
      .eq('id', req.params.id);
    if (deleteError) throw new Error(deleteError.message);

    res.json({ success: true, batch: publicHistoryTagImportBatch(batch) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/history-tags/import-matches/:id([0-9a-fA-F-]{36})/apply', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const updated = await applyHistoryTagImportMatchRow(req.params.id, req.session.name || req.session.username || '');
    const { data: match, error } = await supabase.from('history_tag_import_matches')
      .select('*')
      .eq('id', updated.id || req.params.id)
      .maybeSingle();
    if (error) throw new Error(error.message);
    const [rowWithHistory] = await attachHistoryToTagImportMatches([match || updated]);
    res.json({ success: true, match: publicHistoryTagImportMatch(rowWithHistory) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/history-tags/import-matches/:id([0-9a-fA-F-]{36})/skip', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const { data: current, error: currentError } = await supabase.from('history_tag_import_matches')
      .select('id,batch_id')
      .eq('id', req.params.id)
      .maybeSingle();
    if (currentError) throw new Error(currentError.message);
    if (!current) return res.status(404).json({ error: 'Etiket aktarım kaydı bulunamadı.' });
    const { data, error } = await supabase.from('history_tag_import_matches')
      .update({ match_status: 'skipped' })
      .eq('id', req.params.id)
      .select('*')
      .maybeSingle();
    if (error) throw new Error(error.message);
    await refreshHistoryTagImportBatchCounts(current.batch_id);
    const [rowWithHistory] = await attachHistoryToTagImportMatches([data]);
    res.json({ success: true, match: publicHistoryTagImportMatch(rowWithHistory) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/apply-ready', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const result = await applyHistoryTagImportBatchChunk({
      batchId: req.params.id,
      matchStatus: 'ready',
      minConfidence: 86,
      limit: req.body?.limit,
      actorName: req.session.name || req.session.username || ''
    });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/apply-review', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const result = await applyHistoryTagImportBatchChunk({
      batchId: req.params.id,
      matchStatus: 'review',
      limit: req.body?.limit,
      actorName: req.session.name || req.session.username || ''
    });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/history-tags/import-batches/:id([0-9a-fA-F-]{36})/backfill-questions', auth, admin, superAdmin, async (req, res) => {
  try {
    if (!ensureHistoryTagImportReady(res)) return;
    const result = await backfillHistoryTagImportQuestionsChunk({
      batchId: req.params.id,
      limit: req.body?.limit
    });
    res.json(result);
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/alerts', auth, admin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('alerts').select('*').order('created_at', { ascending: false }).limit(300);
    if (error) throw new Error(error.message);
    const userIds = [...new Set((data || []).map(a => a.user_id).filter(Boolean))];
    const usersById = new Map();
    if (userIds.length) {
      const { data: users, error: usersError } = await supabase.from('users')
        .select('id,name,username')
        .in('id', userIds);
      if (usersError) throw new Error(usersError.message);
      (users || []).forEach(u => usersById.set(u.id, u));
    }
    const feedbackSimilarities = feedbackSimilarityMap((data || []).filter(a => a.type === 'feedback'));
    res.json((data || []).map(row => {
      const user = usersById.get(row.user_id);
      return {
        ...mapAlert(row),
        userName: user?.name || user?.username || '',
        userUsername: user?.username || '',
        ...(feedbackSimilarities.get(row.id) || {})
      };
    }));
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
    const responseMap = await loadJsonSetting(RESOLUTION_RESPONSE_KEY, {});

    const grouped = new Map();
    for (const n of notices || []) {
      const key = `${n.type}::${n.message}`;
      if (!grouped.has(key)) grouped.set(key, { total: 0, read: [], unread: [] });
      const group = grouped.get(key);
      const user = usersById.get(n.user_id);
      const item = { id: n.user_id, name: user?.name || user?.username || 'Bilinmeyen kullanıcı', username: user?.username || '' };
      group.total++;
      group[n.read ? 'read' : 'unread'].push(item);
    }

    res.json((notices || []).map(n => {
      const user = usersById.get(n.user_id);
      const group = grouped.get(`${n.type}::${n.message}`) || { total: 1, read: [], unread: [] };
      return {
        ...mapAlert(n),
        recipientName: user?.name || user?.username || 'Bilinmeyen kullanıcı',
        recipientUsername: user?.username || '',
        resolutionResponse: normalizeResolutionResponse(responseMap?.[n.id], n, user),
        delivery: {
          total: group.total,
          readCount: group.read.length,
          unreadCount: group.unread.length,
          readUsers: group.read,
          unreadUsers: group.unread
        }
      };
    }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/resolution-responses', auth, admin, superAdmin, async (req, res) => {
  try {
    const responseMap = await loadJsonSetting(RESOLUTION_RESPONSE_KEY, {});
    const noticeIds = Object.keys(responseMap || {});
    if (!noticeIds.length) return res.json([]);
    const { data: notices, error } = await supabase.from('alerts')
      .select('*')
      .in('id', noticeIds)
      .eq('type', 'feedback_resolution')
      .order('created_at', { ascending: false });
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
    const byNotice = new Map((notices || []).map(n => [n.id, n]));
    res.json(noticeIds.map(id => {
      const notice = byNotice.get(id);
      const user = notice ? usersById.get(notice.user_id) : null;
      return normalizeResolutionResponse(responseMap[id], notice, user);
    }).filter(Boolean).sort((a, b) => new Date(b.respondedAt || 0) - new Date(a.respondedAt || 0)));
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
    if (HAS_ALERT_FEEDBACK_META && alert.feedback_status === 'resolved') {
      return res.status(400).json({ error: 'Bu geri bildirim zaten çözüldü olarak işaretlenmiş.' });
    }

    const message = [
      'Geri bildiriminiz incelendi',
      `Çözüm: ${cleanNote}`,
      `Yanıtlayan: ${SYSTEM_SENDER_NAME}`,
      alert.message ? `İlgili kayıt: ${String(alert.message).split(' | ')[1] || 'Denetim sonucu'}` : ''
    ].filter(Boolean).join(' | ');

    const internalResolutionNote = appendRootCategoryNote(cleanNote, [alert]);
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
      patch.resolution_note = internalResolutionNote;
    }
    const { error: updateError } = await supabase.from('alerts').update(patch).eq('id', alert.id);
    if (updateError) throw new Error(updateError.message);

    if (HAS_ISSUE_RESOLUTION_LOG) {
      await supabase.from('issue_resolution_log').upsert({
        resolution_group: `single-${alert.id}`,
        title: cleanNote.slice(0, 160),
        summary: `${feedbackSummary(alert)}\nKök kategoriler: ${feedbackRootCategorySummary([alert]).map(root => `${root.label} (${root.count})`).join(', ')}`,
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
    const internalResolutionNote = appendRootCategoryNote(cleanNote, feedbacks);
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
          resolution_note: internalResolutionNote
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
      patch.resolution_note = internalResolutionNote;
    }
    const { error: updateError } = await supabase.from('alerts')
      .update(patch)
      .in('id', feedbacks.map(f => f.id));
    if (updateError) throw new Error(updateError.message);

    if (HAS_ISSUE_RESOLUTION_LOG) {
      const sampleItems = feedbacks.slice(0, 8).map(feedbackSummary).join('\n');
      const rootSummary = feedbackRootCategorySummary(feedbacks).map(root => `${root.label} (${root.count})`).join(', ');
      const { error: logError } = await supabase.from('issue_resolution_log').insert({
        resolution_group: groupId,
        title: cleanNote.slice(0, 160),
        summary: `${sampleItems}\nKök kategoriler: ${rootSummary}`,
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
    const responseMap = await loadJsonSetting(RESOLUTION_RESPONSE_KEY, {});
    res.json((data || []).map(row => ({
      ...mapAlert(row),
      resolutionResponse: row.type === 'feedback_resolution' ? normalizeResolutionResponse(responseMap?.[row.id], row, null) : null
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/my-notifications/:id/resolution-response', auth, async (req, res) => {
  try {
    const status = req.body?.status === 'confirmed' ? 'confirmed' : req.body?.status === 'unresolved' ? 'unresolved' : '';
    const note = String(req.body?.note || '').trim().slice(0, 1200);
    if (!status) return res.status(400).json({ error: 'Geçerli bir yanıt seçin.' });
    if (status === 'unresolved' && !note) return res.status(400).json({ error: 'Sorun devam ediyorsa kısa bir not yazın.' });
    const { data: notice, error } = await supabase.from('alerts')
      .select('*')
      .eq('id', req.params.id)
      .eq('user_id', req.session.userId)
      .eq('type', 'feedback_resolution')
      .maybeSingle();
    if (error) throw new Error(error.message);
    if (!notice) return res.status(404).json({ error: 'Çözüm bildirimi bulunamadı.' });

    const responseMap = await loadJsonSetting(RESOLUTION_RESPONSE_KEY, {});
    responseMap[notice.id] = {
      noticeId: notice.id,
      userId: req.session.userId,
      userName: req.session.name || req.session.username,
      username: req.session.username,
      status,
      note,
      respondedAt: new Date().toISOString(),
      message: notice.message
    };
    await saveJsonSetting(RESOLUTION_RESPONSE_KEY, responseMap);
    await supabase.from('alerts').update({ read: true }).eq('id', notice.id);

    if (status === 'unresolved') {
      await supabase.from('alerts').insert({
        type: 'feedback',
        message: [
          'Geri Bildirim: Çözüm sonrası sorun devam ediyor',
          `Not: ${note}`,
          `Kayıt: ${notice.history_id || 'Çözüm bildirimi'}`,
          `Önceki çözüm bildirimi: ${notice.id}`
        ].join(' | '),
        user_id: req.session.userId,
        history_id: notice.history_id,
        score: notice.score,
        read: false,
        ...(HAS_ALERT_FEEDBACK_META ? {
          feedback_status: 'open',
          resolution_group: notice.resolution_group || null
        } : {})
      });
    }

    res.json({ success: true, response: normalizeResolutionResponse(responseMap[notice.id], notice, null) });
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
      histRows,
      { data: userRows, error: uErr },
      alertRows,
      resolutionLogResult
    ] = await Promise.all([
      fetchAllPages(() => supabase.from('history').select('*').order('created_at', { ascending: false })),
      supabase.from('users').select('id,name,username,active'),
      fetchAllPages(() => supabase.from('alerts').select('*').order('created_at', { ascending: false })),
      HAS_ISSUE_RESOLUTION_LOG
        ? supabase.from('issue_resolution_log').select('*').order('created_at', { ascending: false }).limit(12)
        : Promise.resolve({ data: [], error: null })
    ]);
    if (uErr) throw new Error(uErr.message);
    if (resolutionLogResult.error) throw new Error(resolutionLogResult.error.message);

    const hist = (histRows || []).map(mapHistory).filter(h => !isHiddenHistoryForRole(h, ROLES.ADMIN));
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

  const hist = (histRows || []).map(mapHistory).filter(h => !isHiddenHistoryForRole(h, ROLES.ADMIN));
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
  const d = await fetchOpenAIChatCompletion({
    model: AI_REPORT_MODEL,
    temperature: 0.2,
    max_tokens: 1800,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: 'Sen Arşiv Kontrol AI yönetim panelinin operasyon analisti asistanısın. Verilen metrikleri kısa, somut ve yönetime uygun Türkçe rapora dönüştür. Halüsinasyon yapma; yalnızca verilen veriye dayan. Asla ham obje, [object Object], JSON parçası veya teknik veri yapısı yazma; activitySummary ve feedbackSummary mutlaka düz Türkçe cümle olmalı. Akademik referans, eğitim programı veya dış kaynak önerme; yalnızca sistem kalitesi, geri bildirim çözümü, denetim tutarlılığı ve operasyon takibi için uygulanabilir öneriler ver. JSON döndür: title, executiveSummary, activitySummary, feedbackSummary, risks(array), recommendations(array), nextActions(array).' },
      { role: 'user', content: JSON.stringify(snapshot).slice(0, 24000) }
    ]
  }, 'operasyon raporu');
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
    const period = ['daily', 'weekly', 'monthly', 'yearly'].includes(req.query.period) ? req.query.period : '';
    const date = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.date || '')) ? String(req.query.date) : '';
    let query = supabase.from('ai_reports').select('*').order('created_at', { ascending: false }).limit(80);
    if (period) query = query.eq('period', period);
    if (date) {
      const start = new Date(`${date}T00:00:00+03:00`);
      const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
      query = query.lt('period_start', end.toISOString()).gt('period_end', start.toISOString());
    }
    const { data, error } = await query;
    if (error) throw new Error(error.message);
    res.json((data || []).map(mapAiReport));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ai/reports/generate', auth, admin, async (req, res) => {
  try {
    const period = ['daily', 'weekly', 'monthly', 'yearly'].includes(req.body?.period) ? req.body.period : 'daily';
    const report = await createAiReport(period, req.session.name || req.session.username);
    res.json({ success: true, report: mapAiReport(report) });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/ai/insight', auth, admin, async (req, res) => {
  try {
    const question = String(req.body?.question || '').trim().slice(0, 1200);
    if (!question) return res.status(400).json({ error: 'Soru gerekli.' });
    const period = ['daily', 'weekly', 'monthly', 'yearly'].includes(req.body?.period) ? req.body.period : 'weekly';
    const snapshot = await collectOperationalSnapshot(period);
    if (!OPENAI_API_KEY) return res.json({ answer: fallbackReport(snapshot).executiveSummary, model: 'fallback' });
    const d = await fetchOpenAIChatCompletion({
      model: AI_REPORT_MODEL,
      temperature: 0.2,
      max_tokens: 1200,
      messages: [
        { role: 'system', content: 'Sen Arşiv Kontrol AI admin panelinde çalışan veri analisti asistansın. Veriye dayan, kısa ve uygulanabilir Türkçe cevap ver.' },
        { role: 'user', content: `Soru: ${question}\n\nVeri:\n${JSON.stringify(snapshot).slice(0, 22000)}` }
      ]
    }, 'admin ai insight');
    res.json({ answer: d.choices[0].message.content, model: AI_REPORT_MODEL });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

function fallbackHelperResponse(task, text, result, question) {
  const len = String(text || '').trim().length;
  const totalErrors = Number(result?.totalErrors || 0);
  const score = Number(result?.score || 0);
  const cats = result?.categories || {};
  const suggestions = [];
  if (len && len < MIN_ANALYSIS_TEXT_CHARS) suggestions.push('Metin çok kısa; daha sağlıklı kontrol için birkaç cümlelik bağlam ekleyin.');
  if (len > 18000) suggestions.push('Metin uzun görünüyor; denetim biraz daha uzun sürebilir.');
  if (String(text || '').includes('\t')) suggestions.push('Tablo veya sütun düzeni olabilir; denetim sonrası düzen karşılaştırmasını mutlaka kontrol edin.');
  if (/^\s*\d{1,3}\./m.test(String(text || ''))) suggestions.push('Numaralı satırlar var; sıra numaralarının metin standardıyla karışmadığını kontrol edin.');
  if (String(text || '').split('\n').filter(Boolean).length > 18) suggestions.push('Çok satırlı bir yapı var; paragraf, slayt veya tablo düzeni denetim sonrası karşılaştırılmalı.');
  if (result && totalErrors === 0) suggestions.push('Sonuç temiz görünüyor; yine de düzeltilmiş metin kaynak metinle aynı mı kontrol edin.');
  if (result && totalErrors > 0) suggestions.push(`Sistem ${totalErrors} bulgu göstermiş. Önce anlamı etkileyen düzeltmeleri ve şüpheli kelime dönüşümlerini kontrol edin.`);
  if (result && score < 60) suggestions.push('Skor düşük olduğu için düzeltilmiş metin verilmemiş olabilir; metni bölerek yeniden denemek faydalı olabilir.');
  const heavyCat = Object.entries(cats).map(([key, value]) => ({ key, count: Number(value?.count || 0) })).sort((a, b) => b.count - a.count)[0];
  if (heavyCat?.count > 0) suggestions.push(`En yoğun alan ${heavyCat.key}; önce bu kategorideki bulguları inceleyin.`);
  if (!suggestions.length) suggestions.push('Metin denetime hazır görünüyor. Denetim sonrası şüpheli bulguları geri bildirimle işaretleyebilirsiniz.');
  const taskTitles = {
    report: 'AI Denetim Raporu',
    feedback: 'Geri Bildirim Taslağı',
    explain: 'Sonuç Yorumu',
    suspect: 'Şüpheli Bulgu Kontrolü',
    copycheck: 'Kopyalama Kontrolü',
    prepare: 'Denetim Hazırlığı',
    ask: 'Denetim Yardımcısı'
  };
  const riskLevel = result && score < 60 ? 'high' : totalErrors > 0 ? 'medium' : 'low';
  const shouldDraft = ['report', 'feedback'].includes(task) && riskLevel !== 'low';
  return {
    title: taskTitles[task] || 'Denetim Yardımcısı',
    summary: task === 'report'
      ? (riskLevel === 'low' ? 'AI raporu sonucu düşük riskli gördü; ekibe bildirim gerekmiyor.' : 'AI raporu bazı noktaların kontrol edilmesini öneriyor; gerekirse ekibe bildirim gönderilebilir.')
      : question ? `Sorunuz için mevcut veriye göre kısa değerlendirme hazırlandı: ${question}` : suggestions[0],
    steps: ['Metin yapısı kontrol edildi.', 'Mevcut denetim sonucu değerlendirildi.', 'Kullanıcı için uygulanabilir öneriler çıkarıldı.'],
    suggestions,
    checks: [
      len ? `${len.toLocaleString('tr-TR')} karakterlik metin okundu.` : 'Metin girişi yok.',
      result ? `Son skor ${score}/100 ve ${totalErrors} bulgu üzerinden yorumlandı.` : 'Henüz denetim sonucu yok.',
      'Kural veya metin üzerinde otomatik değişiklik yapılmadı.'
    ],
    nextActions: riskLevel === 'low'
      ? ['Düzeltilmiş metni kopyalamadan önce son kez karşılaştırma bölümünü gözden geçirin.']
      : ['Şüpheli bulgu varsa açılan geri bildirim alanını kullanın.', 'Düzeltilmiş metni kopyalamadan önce karşılaştırma bölümünü kontrol edin.'],
    feedbackDraft: shouldDraft ? 'Bu sonuçta kontrol edilmesi gereken nokta: ... Doğru olması gerektiğini düşündüğüm yazım/bağlam: ...' : '',
    riskLevel
  };
}

function sanitizeHelperAnswer(answer) {
  const cleanLine = value => String(value || '').replace(/.*akademik\s+referans.*$/giu, '').trim();
  const cleanList = value => (Array.isArray(value) ? value : []).map(cleanLine).filter(Boolean);
  const out = { ...(answer || {}) };
  out.steps = cleanList(out.steps);
  out.suggestions = cleanList(out.suggestions);
  out.checks = cleanList(out.checks);
  out.nextActions = cleanList(out.nextActions);
  out.feedbackDraft = cleanLine(out.feedbackDraft);
  return out;
}

app.post('/api/ai/helper', auth, async (req, res) => {
  try {
    const task = ['report', 'prepare', 'explain', 'feedback', 'suspect', 'copycheck'].includes(req.body?.task) ? req.body.task : 'report';
    const text = String(req.body?.text || '').slice(0, 12000);
    const question = '';
    const result = req.body?.result && typeof req.body.result === 'object' ? req.body.result : null;
    if (!text.trim() && !result) return res.status(400).json({ error: 'Yardımcı için metin veya denetim sonucu gerekli.' });
    if (!OPENAI_API_KEY) return res.json({ answer: sanitizeHelperAnswer(fallbackHelperResponse(task, text, result, question)), model: 'assistant' });

    const d = await fetchOpenAIChatCompletion({
      model: AI_REPORT_MODEL,
      temperature: 0.15,
      max_tokens: 1100,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: `Sen Arşiv Kontrol AI içinde çalışan Denetim Yardımcısısın. Kullanıcı tarafında tek ana görevin AI Denetim Raporu üretmektir: sonucu sade açıkla, şüpheli bulguları yakala, kopyalama/karşılaştırma güvenliğini kontrol et ve ekibe bildirim gerekip gerekmediğini risk seviyesine göre belirt. Metni kendi başına düzeltme, kural değiştirme, dini/içerik yorumu yapma, kullanıcı adına onay/red verme. Akademik referans, kaynakça, dış kaynak, ilave akademik çalışma veya akademik öneri isteme; bu sistem yalnızca arşiv denetim standardına göre çalışır. Sadece sistem kullanımı, denetim kalitesi, şüpheli bulgular, kopyalama güvenliği ve geri bildirim netliği konusunda yardımcı ol. Pozitif/düşük riskli sonuçlarda ekibe bildirim önermemelisin; yalnızca riskli veya kontrol gerektiren sonuçlarda feedbackDraft üret. Yanıtların her seferinde bağlama özel olsun; aynı kalıp cümleleri tekrar etme. JSON döndür: title, summary, steps(array), suggestions(array), checks(array), nextActions(array), feedbackDraft, riskLevel(low|medium|high). Model adından bahsetme.` },
        { role: 'user', content: JSON.stringify({ task, question, text, result }).slice(0, 24000) }
      ]
    }, 'denetim yardımcısı');
    let answer;
    try { answer = JSON.parse(d.choices[0].message.content); }
    catch { answer = { ...fallbackHelperResponse(task, text, result, question), summary: d.choices[0].message.content }; }
    res.json({ answer: sanitizeHelperAnswer(answer), model: 'assistant' });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.get('/api/cron/daily-report', async (req, res) => {
  try {
    const cronSecret = process.env.CRON_SECRET;
    const provided = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query.secret;
    if (!cronSecret) return res.status(500).json({ error: 'CRON_SECRET tanımlı değil.' });
    if (provided !== cronSecret) return res.status(401).json({ error: 'Yetkisiz.' });
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
- "din" ailesi şapkasızdır: din, dinde, dinimizin, dinsiz gibi kullanımları dîn/dînde/dînimizin/dînsiz yapma.
- "dini" kelimesi din + i eki olarak geçiyorsa "dinî" yapma; şapka anlamı değiştirebilir.
- Özel kaynak/kitap adlarında özgün yazımı koru: "İhyâ’u Ulûmi’d-dîn" veya "İhya’u Ulumi’d-dîn" içindeki "dîn" kelimesini "din" yapma.
- "yakîn" Efendimizin sözlüğündeki özel kullanımdır; bunu "yakın" yapma.
- "faziletler" kelimesini "fazlalar" yapma. "fazılla" kullanımı bağlamında "fazl ile" diye bölme.
- "sure de" bağlaç olan de ise "surede" yapma.
- "Tabiatıyla" kelimesini "Tabiî ki" diye değiştirme.
- "Tabi ki" / "Tabii ki" ifadesini "Tabiatıyla" diye değiştirme.
- "Allah (cc.)" ifadesini "Allah (A.S)" yapma; (A.S) peygamber isimleri içindir.
- "ahlaki" sıfatını "ahlakı" diye değiştirme.
- "ardarda" ve "aciz" kullanımları geri bildirim kararına göre bu bağlamlarda korunur.
- "hayydırlar" gibi hayy köklü ifadeleri "diridirler" veya benzeri Türkçe açıklamaya çevirme.
- "lâzımgelen" arşiv kullanımında bitişik geçebilir; bunu otomatik "lâzım gelen" yapma.
- "herşey" doğru yazımdır; ekli biçimleri de birleşik kalır: herşey, herşeye, herşeydir. Metinde "her şey" varsa "herşey" olarak düzelt.
- "birşey" ile "herşey" anlamca farklıdır; birini diğerine dönüştürme.
- "bir şey" ayrı yazılır; bunu "birşey" yapma. Özel birleşik yazım kararı sadece "her şey" → "herşey" içindir.
- MULK-8 âyetindeki "Oraya herbir grup" yazımı birleşik korunur; bunu "her bir grup" yapma.
- "6 tane, 7 tane âyet-i kerime var." gibi sayı alternatifi içeren cümleleri sadeleştirme veya açıklama ekleyerek değiştirme. "6 tane, 7 tane" ifadesi aynen korunur.
- "surette" doğru yazımdır; özellikle "mutlak surette" ifadesini "sürette" veya "sûrette" yapma.
- "suretiyle" doğru ve ayrı bir kullanımdır; bunu "surette" yapma.
- "keyfe meaşadır / keyfe meşadır" görülürse doğru standart "keyfe mâ yeşâdır" olmalıdır.
- "Allah arasındadır" ifadesinde Allah kelimesine kesme eki ekleme; "Allah'a arasındadır" yanlıştır.
- "kaadirdir" ve "halifesi" yazımlarını "kâdirdir/halîfesi" yapma.
- "şekli şemali/şekli şemalinize" gibi ifadelerde "şekli" ekini düşürme; "şekil şemalinize" yapma.
- "(S.A.V:" gibi kapanmamış parantezleri gerçek noktalama hatası say; parantezi kapatıp "(S.A.V):" olarak düzelt. S.A.V kısaltmasının harflerini veya nokta yapısını bozma.
- "vücut" doğru yazımdır; "vücud" veya "vücût" görürsen "vücut" olarak düzelt. "vücut/vücuttan" gibi doğru kullanımları "vücud/vücuddan" yapma.
- "Hadîs-i Şerif" standardında Hadîs kelimesinde î vardır, Şerif kelimesindeki i şapkasızdır. "HADİS-İ ŞERİF" varsa "HADÎS-İ ŞERİF" yap; "ŞERÎF" yapma.
- "Hazreti İsa" ifadesi her zaman "Hazreti İsa (A.S)" olmalıdır.
- Çıplak "İsa" kelimesine otomatik "(A.S)" ekleme. Özellikle âyet, meal, Arapça okunuş/transliterasyon veya referans satırlarında "İsa" kaynakta nasılsa korunur. "(A.S)" standardı sadece açık "Hazreti İsa" ifadesi içindir.
- "Resûlullah'ın" gibi ekli kullanıma (S.A.V) eklenecekse kısaltma isimden sonra gelir: "Resûlullah (S.A.V)'in". "Resûlullah'ın (S.A.V)" yazma.
- "şerr", "arif" ve "cahiliye" yazımları doğru kabul edilir; bunları "şer", "ârif" veya "câhiliye" biçimine çevirme.
- "şer" yalnız bağımsız kelimeyse "şerr" yapılır. "şeriat", "ŞERİAT", "şerh", "ŞERH", "Şerif", "HADÎS-İ ŞERİF" veya zaten "şerr" olan kelimelerin içine girme; "şerrr" üretme.
- "Nefret" kelimesini hiçbir bağlamda "nefs" yapma.
- "beka" ve "Mehdi" doğru arşiv yazımıdır; bunları "bekâ" veya "mehdî" yapma.
- "ilim" kelimesini kendi başına "Kur'ân ilmi" diye genişletme; kaynakta yalnız "ilim" varsa yalnız "ilim" kalmalıdır.
- "münezzehtir" ifadesini "Sûbhân'dır/Sübhan'dır" diye değiştirme; anlam açıklaması veya çeviri ekleme.
- "lânetle lânetle" gibi âyet/alıntı tekrarlarını yazım tekrarı sanıp silme; kaynak tekrar korunur.
- "Allah ile bile olursanız" ifadesindeki "bile" kelimesini silme.
- "hadîsi/hadîsin/hadîste" gibi ekli kullanımları köke kırpma; "hadîsi" kelimesini "hadîs" yapma.
- "derecat" ailesindeki a harfini şapkalama; derecata/derecatı/derecatlar gibi yazımlar derecât yapılmaz.
- "afet" ailesindeki a harfini şapkalama; AFETİ/afetleri/afetinden gibi yazımlar ÂFET/âfet yapılmaz.
- "Felak" sure adında a harfi şapkasızdır; Felâk yapma.
- "nefisleri/nefisleriyle" kullanımı arşiv standardında "nefsleri/nefsleriyle" olarak düzeltilir; ancak âyet/kaynak satırında özellikle "nefislerinin" geçiyorsa bunu "nefslerinin" yapma.
- "fedakarlık" ailesi "fedakârlık" olarak düzeltilir ve aynı metindeki tüm tekrarlar uygulanır.
- "Kur'an/Kur’an" yazımı "Kur'ân" olarak düzeltilir; metnin başında veya başlıkta büyük harf düzeni korunur.
- "Şura suresinin" gibi kullanımlarda doğru yazım "Şûrâ Suresinin" olmalıdır; Suresinin/Suresini kelimelerini apostrofla "Suresi'nin/Suresi'ni" yapma.
- "Âli İmrân" doğru yazımdır; "Âlî", "Âl-i" veya "Ali-İmran" yapma. Câsiye, Yûnus, Hûd, Fâtır, Hacc ve A'râf sure adlarında şapka/apostrof standardını uygula.
- "Yunus Emre", "Yunus diyor", "Yunus ne diyor" gibi kişi adı veya konuşma bağlamlarını "Yûnus" sure adı gibi düzeltme. Sadece "Yunus Suresi", "10/Yunus-7", "Yunus-7", "Yunus 7, 8’de" gibi açık sure/referans bağlamlarında "Yûnus" standardını uygula.
- "Mumtehine" sure adında i harfi noktalıdır; bunu "Mumtehıne" veya benzeri noktasız ı varyantına çevirme.
- "şer" kelimesi arşiv standardında "şerr" olarak düzeltilir; "şerr" kelimesindeki çift r korunur. Bu kural kelime içindeki harf dizisine uygulanmaz; "ŞERİF", "şeriat" ve "şerh" gibi kelimeler bu sebeple değiştirilmez.
- "tevbe" kelimesi normal metinde "tövbe" olarak düzeltilir ve aynı metindeki tüm tekrarlar uygulanır. Fakat "TEVBE" sure adı, "TEVBE-..." referansı veya "Tevbe 69" gibi sure/âyet referansıysa sure adı korunur.
- "Sebîlel gayy" ve "Sebîlel rüşd" ifadeleri bu şekilde korunur; bunları "Sebîli gayy" / "Sebîli rüşd" yapma.
- "MUSIBET/MUSİBET/musibet" yazımı "MUSÎBET/musîbet" olmalıdır. "VELI" başlığı "VELÎ" olur. "zahit" yazımı "zahid" olmalıdır.
- "(S.AV.)" veya "(S.A.V.)" gibi bozuk kısaltmaları "(S.A.V)" standardına getir.
- Kaynak referans parantezlerinde eksik kapanış varsa kapat; örnek: "(Araf 175.." → "(Araf 175)".
- "tavsiye" kelimesini "tâbî" veya başka bir kelimeye dönüştürme.
- "hayy/hayydırlar" gibi kullanımları "hayat/hayattadırlar" diye sadeleştirme.
- "hidayet" kelimesine kaynakta olmayan ek ekleme; "hidayet" kelimesini "hidayete" gibi genişletme. Kaynakta "hidayete/hidayeti/hidayetten" gibi ekli kullanım varsa eki düşürme.
- "hadis no." gibi kaynak/numara ifadelerinde "hadis" kelimesini "hadîs" yapma.
- "Kaynak:", hadis ve bibliyografya satırlarında muhafazakâr davran. Kaynak/kitap adı olabilecek "Fezailül", "Alamet-il" gibi ifadeleri emin olmadan şapka ve apostrofla yeniden yazma.
- "ve, veya, ama, fakat, çünkü" gibi bağlaçları imlâ gerekçesiyle silme.
- Konuşma dilindeki "var ya" ifadesini silme. Sırf biçimsel görünüm için "şeriat kitabı,", "tarikat yoldur varana;", "BAKARA – 139: De ki:" gibi kaynakta olmayan virgül/noktalı virgül/iki nokta ekleme.
- "Yâsîn-60, 61’de:" gibi ardından âyet açıklaması gelen referanslarda iki nokta korunabilir; bunu otomatik silme.
- Kaynakta "Kur'ân'da" geçmiyorsa cümleye "Kur'ân'da" ekleme. Metinde yalnız "Tevrat, İncil’de" deniyorsa Kur'ân'ı açıklama olarak ekleme.
- Alıntı sonrası konuşma fiillerinde tırnak dengesini bozma: doğru biçim örnek olarak "\"Müslümanın dîni ayrı.\" diyor." şeklindedir; sona fazladan tırnak ekleme.
- Bu kararlar mevcut kural metninde ters yönde bir ifade görsen bile daha önceliklidir.

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
15. "Tabiî ki" ve tek başına "tabiî" ifadelerini "tâbî" veya "tabi" yapma. "derecat/derecât" kelimelerini otomatik olarak
   "derece" yapma. "dinlenmeye" kelimesini "dînlenmeye" yapma.
16. "Muhterem Efendimiz" bağlamında geçen Efendimiz'e "(S.A.V)" ekleme; bunu yalnızca açıkça Peygamber Efendimiz
   kastedildiğinde ve kaynak kural gerektiriyorsa uygula.
17. "Tabi/Tabiî" kelimesi konuşma içinde "elbette/doğal olarak" anlamındaysa "tâbî" yapma. "süre" zaman/uzunluk
   anlamındaysa "sûre" yapma. "afet", "zahid", "ahiret", "zülmanî", "Nebîler" ve "nefs" kelimelerini ters yöne
   bozma. "(S.A.V)" kısaltmasına fazladan nokta ekleme.
17a. Allah Resûlü/Peygamber Efendimiz ifadesinden sonra (S.A.V) zaten varsa ikinci kez (S.A.V) ekleme.
18. Slayt, hadîs dökümü, tablo benzeri satır düzenlerini koru. Satır sırası, başlıklar, numaralar ve tırnak dengesi
   düzeltilmiş metinde bozulmamalıdır.
19. Kaynakta şapkalı yazılmış kelimeyi şapkasızlaştırma: manevî, itikâf, daimî, âyet, Allahû Tealâ gibi yazımlar
   metinde doğruysa aynen korunmalıdır. Tek istisna güncel karar gereği dîn/dînin/dîni gibi biçimlerin din/dinin/dini yapılmasıdır.
20. "taktirde" arşiv kullanımında bitişik kabul edilir; "takdirde" veya "taktir de" yapma.
21. "nefsi", "nefsin", "Nefs-i Mutmainne/Mülhime/Levvame/Emmare" gibi kullanımları bağlamından koparıp
   "nefs" veya "nefisin" yapma; ekleri ve özel terkipleri koru.
22. "A.S" ve "S.A.V" kısaltmalarını bağlamdan emin olmadan birbirine çevirme. Efendimiz (A.S) ifadesini
   otomatik olarak Efendimiz (S.A.V) yapma.
23. Kur'ân-ı Kerim, Kur'ân-ı, kelâm-ı, Resûl'ü gibi tamlayan/ekli ifadelerde ek veya ikinci kelimeyi silme;
   "Kur'ân-ı Kerim" ifadesini sadece "Kur'ân" olarak kısaltma.
24. "ve vechini" gibi tekrar sanılan dinî/alıntı ifadelerde kelime silme; "ve" bağlacını emin olmadan kaldırma.
25. NEFSİ EMMÂRE gibi başlıklara kaynakta yoksa iki nokta ekleme.
26. Hadis kaynak numarası, sure adı ve âyet atfı bağlamlarını sözlük kelimesi gibi zorla dönüştürme; Mu'min suresi Mu'minûn değildir, Nur suresi Nûr diye zorlanmaz.
27. Sure/âyet referanslarında sayı-nokta düzenini koru ve sadece boşluğu düzelt: "1 .ENFÂL-29" → "1. ENFÂL-29", "1 .YÛNUS -7" → "1. YÛNUS-7".
28. Kaynakta olmayan cevap, açıklama veya konuşma fiili ekleme. "Evet", "diyor" gibi kelimeler kaynakta zaten yoksa düzeltilmiş metne eklenmez; kaynakta varsa ikinci kez yazılmaz.

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
  const d = await fetchOpenAIChatCompletion({
    model: 'gpt-4o',
    max_tokens: 16000,
    temperature: 0,
    response_format: { type: 'json_object' },   // geçerli JSON garantisi (satır başları escape edilir)
    messages: [
      { role: 'system', content: await buildSystemPrompt(rules) },
      { role: 'user', content: `Metni denetle:\n\n${text}` }
    ]
  }, 'metin denetimi');
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
let HAS_HISTORY_TAGS = false; // startup'ta tespit edilir (history.tags kolonu)
let HAS_HISTORY_QUESTION_TEXT = false; // startup'ta tespit edilir (history.question_text kolonu)
let HAS_ALERT_FEEDBACK_META = false; // startup'ta tespit edilir (alerts feedback çözüm kolonları)
let HAS_ISSUE_RESOLUTION_LOG = false; // startup'ta tespit edilir (çözüm kayıt defteri)
let HAS_CONTENT_CORRECTION_LOG = false; // startup'ta tespit edilir (geçmiş içerik düzeltme kayıt defteri)
let HAS_AI_REPORTS = false; // startup'ta tespit edilir (AI rapor kayıtları)
let HAS_USER_LAST_SEEN = false; // startup'ta tespit edilir (users.last_seen_at kolonu)
let HAS_ARCHIVE_SOURCE_TABLES = false; // startup'ta tespit edilir (kaynak kayıt tabloları)
let HAS_ARCHIVE_IMPORT_TABLES = false; // startup'ta tespit edilir (kalıcı içe aktarım tabloları)
let HAS_ARCHIVE_WORK_TABLES = false; // startup'ta tespit edilir (çalışma kayıtları)
let HAS_ARCHIVE_PUBLISH_TABLES = false; // startup'ta tespit edilir (yayın görevleri)
let HAS_HISTORY_TAG_IMPORT_TABLES = false; // startup'ta tespit edilir (Excel etiket aktarimi)
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

async function maybeCreateLowScoreAlert(req, historyId, score, filename) {
  if ((score || 0) >= LOW_SCORE_THRESHOLD) return;
  await supabase.from('alerts').insert({
    type: 'low_score',
    message: `${req.session.name} tarafından düşük skorlu metin (${score}/100): "${filename || 'Metin Girişi'}"`,
    user_id: req.session.userId,
    history_id: historyId,
    score,
    read: false
  });
}

async function saveHistory(req, result, filename, hash, sourceText = '', status = 'taslak') {
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
    status
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

  if (historyStatusForApproval(status)) await maybeCreateLowScoreAlert(req, entryId, result.score, filename);

  return entryId;
}

app.post('/api/analyze', auth, async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(500).json({ error: 'API anahtarı tanımlı değil.' });
  try {
    await startupReady;
    const text = prepareAnalysisText(req.body?.text);
    const hash = textHash(text);
    const filename = String(req.body?.filename || 'Metin Girisi').trim().slice(0, 160) || 'Metin Girisi';
    const skipDuplicate = req.body?.skipDuplicate === true;
    if (!skipDuplicate && await isDuplicate(req, text)) return res.json({ duplicate: true, message: DUPLICATE_MSG });
    const result = await openaiText(text);
    const status = req.body?.chunkPart === true ? CHUNK_DRAFT_STATUS : 'taslak';
    const id = await saveHistory(req, result, filename, hash, text, status);
    res.json({ ...result, id, originalText: text, filename, status });
  } catch (e) { res.status(e.statusCode || 500).json({ error: e.message }); }
});

app.post('/api/extract-file-text', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Dosya bulunamadı.' });
  try {
    await startupReady;
    const text = prepareAnalysisText(await extractText(req.file.buffer));
    res.json({ text, filename: req.file.originalname, length: text.length });
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
    res.json({ ...result, id, originalText: text, filename: req.file.originalname, status: 'taslak' });
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
      results.push({ filename: file.originalname, success: true, score: result.score, totalErrors: result.totalErrors, id, status: 'taslak' });
    } catch (e) {
      results.push({ filename: file.originalname, success: false, error: e.message });
    }
  }
  res.json({ results });
});

function sendAdminIndex(req, res) {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(__dirname, 'index.html'));
}

if (ADMIN_PARALLEL_ROUTE_ENABLED) {
  app.get(['/admin', '/admin/'], sendAdminIndex);
  app.get('/admin/*', sendAdminIndex);
}

if (process.env.PUBLIC_ARCHIVE_DEMO === '1') {
  const { createPublicArchiveRouter } = require('./public-archive-demo');
  app.use(createPublicArchiveRouter({
    adminFile: path.join(__dirname, 'index.html'),
    cssFile: path.join(__dirname, 'archive-public.css')
  }));
}

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'Dosya en fazla 4 MB olabilir.' });
  }
  if (err) return res.status(500).json({ error: err.message || 'Sunucu hatası.' });
  next();
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
startupReady = process.env.PUBLIC_ARCHIVE_DEMO === '1'
  ? Promise.resolve()
  : seed().catch(e => console.error('Seed hatası:', e.message));

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ Arşiv Kontrol AI: http://localhost:${PORT}`));
}

module.exports = app;
