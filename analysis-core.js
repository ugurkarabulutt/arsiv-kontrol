const crypto = require('crypto');

const LOW_SCORE_THRESHOLD = 60;
const CAT_WEIGHTS = { sozluk: 5, imla: 4, noktalama: 3, etiket: 2, yapi: 4 };
const LOW_SCORE_MSG = 'Bu metin arşiv standartlarının altında kalmaktadır. Lütfen metni gözden geçirip tekrar gönderin.';
const WORD_EDGE = /[\p{L}\p{N}_]/u;
const PROTECTED_PATTERNS = [
  /\bderecat\b/iu,
  /\btabiî\s+ki\b/iu,
  /\bdinlenmeye\b/iu,
  /\bmuhterem\s+efendimiz\b/iu
];
const CANONICAL_WORD_STANDARDS = Object.freeze({
  din: 'din',
  dinde: 'dinde',
  hersey: 'herşey',
  herbir: 'herbir',
  vucut: 'vücut',
  serr: 'şerr',
  derecat: 'derecat',
  afet: 'afet',
  arif: 'arif',
  cahiliye: 'cahiliye',
  ayet: 'âyet',
  daimi: 'daimî',
  teala: 'Tealâ',
  takva: 'takva',
  biraraya: 'biraraya',
  vaad: 'vaad',
  kaadir: 'kaadir',
  halife: 'halife',
  suretiyle: 'suretiyle',
  meyesa: 'mâ yeşâ',
  hristiyan: 'Hristiyan',
  salih: 'salih',
  mustekim: 'mustekîm',
  beka: 'beka',
  mehdi: 'Mehdi',
  fedakarlik: 'fedakârlık',
  kuran: "Kur'ân",
  gayy: 'gayy yolu',
  aliimran: 'Âli İmrân',
  casiye: 'Câsiye',
  yunus: 'Yûnus',
  hud: 'Hûd',
  fatir: 'Fâtır',
  hacc: 'Hacc',
  araf: "A'râf",
  musibet: 'musîbet',
  veli: 'velî',
  zahid: 'zahid'
});
const TURKISH_APOSTROPHE_SUFFIXES = new Set([
  'a', 'e', 'i', 'ı', 'u', 'ü',
  'in', 'ın', 'un', 'ün',
  'im', 'ım', 'um', 'üm',
  'imiz', 'ımız', 'umuz', 'ümüz',
  'de', 'da', 'te', 'ta',
  'den', 'dan', 'ten', 'tan',
  'le', 'la', 'yle', 'yla',
  'dir', 'dır', 'dur', 'dür', 'tir', 'tır', 'tur', 'tür',
  'ye', 'ya', 'nin', 'nın', 'nun', 'nün'
]);
const SURA_NAMES = [
  'FÂTİHA', 'BAKARA', 'ÂLİ İMRÂN', 'NİSÂ', 'MÂİDE', "EN'ÂM", "A'RÂF", 'ENFÂL',
  'TEVBE', 'YÛNUS', 'HÛD', 'YÛSUF', "RA'D", 'İBRÂHÎM', 'HİCR', 'NAHL', 'İSRÂ',
  'KEHF', 'MERYEM', 'TÂHÂ', 'ENBİYÂ', 'HACC', "MU'MİNÛN", 'NÛR', 'FURKÂN',
  'ŞUARÂ', 'NEML', 'KASAS', 'ANKEBÛT', 'RÛM', 'LOKMÂN', 'SECDE', 'AHZÂB',
  'SEBE', 'FÂTIR', 'YÂSÎN', 'SÂFFÂT', 'SÂD', 'ZUMER', "MU'MİN", 'FUSSİLET',
  'ŞÛRÂ', 'ZUHRÛF', 'DUHÂN', 'CÂSİYE', 'AHKÂF', 'MUHAMMED', 'FETİH', 'HUCURÂT',
  'KAF', 'ZÂRİYÂT', 'TÛR', 'NECM', 'KAMER', 'RAHMÂN', 'VÂKIA', 'HADÎD',
  'MUCÂDELE', 'HAŞR', 'MUMTEHİNE', 'SAFF', 'CUMA', 'MUNÂFİKÛN', 'TEGÂBUN',
  'TALÂK', 'TAHRÎM', 'MULK', 'KALEM', 'HÂKKA', 'MEÂRİC', 'NÛH', 'CİNN',
  'MUZZEMMİL', 'MUDDESSİR', 'KIYÂME', 'İNSÂN', 'MURSELÂT', 'NEBE', 'NÂZİÂT',
  'ABESE', 'TEKVÎR', 'İNFİTÂR', 'MUTAFFİFÎN', 'İNŞİKAK', 'BURÛC', 'TÂRIK',
  "A'LÂ", 'GÂŞİYE', 'FECR', 'BELED', 'ŞEMS', 'LEYL', 'DUHÂ', 'İNŞİRÂH',
  'ŞERH', 'TÎN', 'ALAK', 'KADR', 'KADİR', 'BEYYİNE', 'ZİLZÂL', 'ÂDİYÂT',
  'KÂRİA', 'TEKÂSUR', 'ASR', 'HUMEZE', 'FÎL', 'KUREYŞ', 'MÂÛN', 'KEVSER',
  'KÂFİRÛN', 'NASR', 'TEBBET', 'MESED', 'İHLÂS', 'FELAK', 'NÂS'
];
const SURA_NAME_KEYS = new Set(SURA_NAMES.map(suraCaseKey));
const SURA_VARIANT_STANDARDS = [
  {
    title: 'Âli İmrân',
    keys: ['ali imran', 'ali-imran', 'al-i imran', 'âl-i imran', 'âli imran', 'âli imrân', 'âlî imrân']
  },
  { title: 'Câsiye', keys: ['casiye', 'câsiye'] },
  { title: 'Yûnus', keys: ['yunus', 'yûnus'] },
  { title: 'Hûd', keys: ['hud', 'hûd'] },
  { title: 'Fâtır', keys: ['fatir', 'fâtır'] },
  { title: 'Hacc', keys: ['hac', 'hacc'] },
  { title: 'Mumtehine', keys: ['mumtehine'] },
  { title: "A'râf", keys: ['araf', "a'raf", 'a râf'] }
];
const FORBIDDEN_TRANSFORMS = [
  { from: /\bdin\b/iu, to: /\bdîn\b/iu },
  { from: /(?<![\p{L}\p{N}_])din[\p{L}\p{N}_]*/iu, to: /(?<![\p{L}\p{N}_])dîn[\p{L}\p{N}_]*/iu },
  { from: /\bherşey[\p{L}\p{N}_]*/iu, to: /\bher\s+şey[\p{L}\p{N}_]*/iu },
  { from: /\bherbir[\p{L}\p{N}_]*/iu, to: /\bher\s+bir[\p{L}\p{N}_]*/iu },
  { from: /\bvücut[\p{L}\p{N}_]*/iu, to: /\bvüc(?:ud|ûd|ût)[\p{L}\p{N}_]*/iu },
  { from: /\bvücud[\p{L}\p{N}_]*/iu, to: /\bvüc(?:ûd|ût)[\p{L}\p{N}_]*/iu },
  { from: /\bhayy[\p{L}\p{N}_]*/iu, to: /\bhayat[\p{L}\p{N}_]*/iu },
  { from: /\bşerif\b/iu, to: /\bşerîf\b/iu },
  { from: /(?<![\p{L}\p{N}_])şerr[\p{L}\p{N}_]*/iu, to: /(?<![\p{L}\p{N}_])şer[\p{L}\p{N}_]*/iu },
  { from: /(?<![\p{L}\p{N}_])arif(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])ârif(?![\p{L}\p{N}_])/iu },
  { from: /(?<![\p{L}\p{N}_])cahiliye(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])câhiliye(?![\p{L}\p{N}_])/iu },
  { from: /\bve\s+vechini\b/iu, to: /\bvechini\b/iu },
  { from: /\bnefs(?:i)?\s+emmâre\b/iu, to: /\bnefs(?:i)?\s+emmâre:/iu },
  { from: /\bhadis\s+no\b/iu, to: /\bhadîs\s+no\b/iu },
  { from: /(?<![\p{L}\p{N}_])tabi(?:î)?(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])tâbî(?![\p{L}\p{N}_])/iu },
  { from: /(?<![\p{L}\p{N}_])zülmanî(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])zulmanî(?![\p{L}\p{N}_])/iu },
  { from: /(?<![\p{L}\p{N}_])afet(?:ler(?:iyle|in|den|de|i|e)?|leriyle|lerden|lerde|ler|in|den|de|i|e)?(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])âfet/iu },
  { from: /(?<![\p{L}\p{N}_])zahid(?:ler(?:den|de|i|e)?|lerden|lerde|ler|in|den|de|i|e)?(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])zâhid/iu },
  { from: /(?<![\p{L}\p{N}_])süre(?:yi|nin|si|de|den|ler(?:i|in|den|de)?|yle)?(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])sûre/iu },
  { from: /^(?:muhterem\s+)?efendimiz$/iu, to: /^efendimiz\s*\(s\.a\.v\.?\)$/iu },
  { from: /\befendimiz\s*\(s\.a\.v\)(?:'|’)?/iu, to: /\befendimiz\s*\(s\.a\.v\.\)(?:'|’)?/iu },
  { from: /(?<![\p{L}\p{N}_])islâm(?:'|’)?[a-zçğıöşüâîû]*(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])İslâm(?:'|’)?[a-zçğıöşüâîû]*(?![\p{L}\p{N}_])/u },
  { from: /(?<![\p{L}\p{N}_])nebîler(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])nebiler(?![\p{L}\p{N}_])/iu },
  { from: /\bnefs\b/iu, to: /\bnefis\b/iu },
  { from: /(?<![\p{L}\p{N}_])ahiret(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])âhiret(?![\p{L}\p{N}_])/iu },
  { from: /(?<![\p{L}\p{N}_])(?:muminun|m[uü]'?m[iİı]n[uû]n)(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])m[üu]'?m[iİı]n(?![\p{L}\p{N}_])/iu },
  { from: /\bzumer\b/iu, to: /\bzümer\b/iu },
  { from: /\btabiî\s+ki\b/iu, to: /\btâbî\s+ki\b/iu },
  { from: /\bderecat[\p{L}\p{N}_]*/iu, to: /\bderece[\p{L}\p{N}_]*/iu },
  { from: /\bderecât[\p{L}\p{N}_]*/iu, to: /\bderece[\p{L}\p{N}_]*/iu },
  { from: /\bderecat[\p{L}\p{N}_]*/iu, to: /\bderecât[\p{L}\p{N}_]*/iu },
  { from: /\bdinlenmeye\b/iu, to: /\bdînlenmeye\b/iu },
  { from: /\bmuhterem\s+efendimiz\b/iu, to: /\befendimiz\s*\(s\.a\.v\)/iu },
  { from: /\ballah(?:'|’)?ın\s+izniyle\.\s+allah\s+razı\s+olsun\.?/iu, to: /\ballah(?:'|’)?ın\s+izniyle,\s+allah\s+razı\s+olsun\.?/iu },
  { from: /\bnefsi\b/iu, to: /\bnefs\b/iu },
  { from: /\bnefsin\b/iu, to: /\bnefisin\b/iu },
  { from: /\bilim\b/iu, to: /\bkur['’]?ân\s+ilmi\b/iu },
  { from: /(?<![\p{L}\p{N}_])mehdi[\p{L}\p{N}_]*/iu, to: /(?<![\p{L}\p{N}_])mehdî[\p{L}\p{N}_]*/iu },
  { from: /(?<![\p{L}\p{N}_])beka[\p{L}\p{N}_]*/iu, to: /(?<![\p{L}\p{N}_])bekâ[\p{L}\p{N}_]*/iu },
  { from: /(?<![\p{L}\p{N}_])münezzeh[\p{L}\p{N}_]*/iu, to: /\bs[ûü]bhân(?:'|’)?d[ıi]r\b/iu },
  { from: /\ballah\s+ile\s+bile\s+olursan[ıi]z\b/iu, to: /\ballah\s+ile\s+olursan[ıi]z\b/iu },
  { from: /\btaktirde\b/iu, to: /\b(?:takdirde|taktir\s+de)\b/iu },
  { from: /\btaktirde\b/iu, to: /\bo\s+taktirde\b/iu },
  { from: /(?<![\p{L}\p{N}_])takva[\p{L}\p{N}_]*/iu, to: /(?<![\p{L}\p{N}_])takvâ[\p{L}\p{N}_]*/iu },
  { from: /(?<![\p{L}\p{N}_])afet(?:ler(?:iyle|in|den|de|i|e)?|leriyle|lerden|lerde|ler|in|den|de|i|e)?(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])ni'?met/iu },
  { from: /(?<![\p{L}\p{N}_])felak(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])felâk(?![\p{L}\p{N}_])/iu },
  { from: /(?<![\p{L}\p{N}_])hadîs[\p{L}\p{N}_]+(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])hadîs(?![\p{L}\p{N}_])/iu },
  { from: /\bifna\s+olur\b/iu, to: /\bfena\s+bulur\b/iu },
  { from: /\bmürşide(?:\s+tâbiiyet)?\b/iu, to: /\bmürşidin(?:\s+tâbiiyet)?\b/iu },
  { from: /(?<![\p{L}\p{N}_])s\s+\d+(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])s\.\s+\d+(?![\p{L}\p{N}_])/iu },
  { from: /\b(?:a\.s\.?|a\.s)\b/iu, to: /\b(?:s\.a\.v\.?|s\.a\.v)\b/iu },
  { from: /\befendimiz[\s\S]{0,24}\b(?:a\.s\.?|a\.s)\b/iu, to: /\befendimiz[\s\S]{0,24}\b(?:s\.a\.v\.?|s\.a\.v)\b/iu },
  { from: /\bmumin\b/iu, to: /\bmu'?min[uû]n\b/iu },
  { from: /\bmu'?min\b/iu, to: /\bmu'?min[uû]n\b/iu },
  { from: /\ba'?raf\b/iu, to: /\ba'?r[âa]f\b/iu },
  { from: /\bnur\b/iu, to: /\bnûr\b/iu },
  { from: /\bbirr\b/iu, to: /\bbir\b/iu },
  { from: /\bhâdise\b/iu, to: /\bhadîse\b/iu },
  { from: /\bafv-u\b/iu, to: /\baf\s+ve\b/iu },
  { from: /\bmace\b/iu, to: /\bmâce\b/iu },
  { from: /\bkiyame\b/iu, to: /\bkıyâmet\b/iu },
  { from: /[\.\?!]\s+allah\s+razı\s+olsun\.?/iu, to: /,\s+allah\s+razı\s+olsun\.?/iu }
];

function normalizeText(text) {
  return String(text || '').normalize('NFC').replace(/\r\n?/g, '\n').trim();
}

function canonicalText(text) {
  return normalizeText(text)
    .replace(/[\u2018\u2019\u201B\u02BC\u2032\u00B4`]/g, "'")
    .replace(/[\u201C\u201D\u201E\u00AB\u00BB]/g, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

function suraCaseKey(text) {
  return canonicalText(text)
    .replace(/[()]/g, '')
    .toLocaleUpperCase('tr-TR');
}

function foldText(text) {
  return canonicalText(text)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLocaleLowerCase('tr-TR');
}

function asciiFold(text) {
  return foldText(text)
    .replace(/\u0131/g, 'i')
    .replace(/[’']/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function suraVariantKey(text) {
  return asciiFold(text)
    .replace(/[‐‑‒–—]/gu, '-')
    .replace(/\s*-\s*/g, '-')
    .replace(/al-i/g, 'al-i')
    .replace(/âl-i/g, 'al-i')
    .replace(/'/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function isAllCapsLike(text) {
  const letters = String(text || '').replace(/[^\p{L}]/gu, '');
  return !!letters && letters === letters.toLocaleUpperCase('tr-TR');
}

function caseSuraTitleLike(original, title) {
  return isAllCapsLike(original) ? title.toLocaleUpperCase('tr-TR') : title;
}

function normalizeHadisSerifHeading(value) {
  return canonicalText(value)
    .replace(/[‐‑‒–—]/gu, '-')
    .replace(/\s*-\s*/g, '-')
    .replace(/\s+/g, ' ')
    .trim();
}

function isHadisSerifHeading(value) {
  return /^[Hh][Aa][Dd][İiIıÎî][Ss]-[İiIı]\s+[ŞşSs][Ee][Rr]{1,2}[İiIıÎî][Ff]$/u.test(normalizeHadisSerifHeading(value));
}

function isStandardHadisSerifHeading(value) {
  return /^[Hh][Aa][Dd][İiIıÎî][Ss]-[İiIı]\s+[ŞşSs][Ee][Rr][İiIı][Ff]$/u.test(normalizeHadisSerifHeading(value));
}

function isHadisSerifStandardChange(original, fixed) {
  return isHadisSerifHeading(original) && isStandardHadisSerifHeading(fixed);
}

function suraVariantFixed(original) {
  const value = canonicalText(original);
  if (!value) return '';
  const suffixMatch = value.match(/\s+(Suresi(?:nin|ni|nde|nden|ne)?|suresi(?:nin|ni|nde|nden|ne)?)$/u);
  const suffix = suffixMatch ? suffixMatch[1] : '';
  const namePart = suffix ? value.slice(0, -suffixMatch[0].length) : value;
  const key = suraVariantKey(namePart);
  const standard = SURA_VARIANT_STANDARDS.find(item => item.keys.includes(key));
  if (!standard) return '';
  const fixedName = caseSuraTitleLike(namePart, standard.title);
  return suffix ? `${fixedName} ${suffix}` : fixedName;
}

function isAllowedSuraStandardChange(original, fixed) {
  const expected = suraVariantFixed(original);
  return !!expected && canonicalText(expected) === canonicalText(fixed);
}

function isSuraVariantWorsening(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  const expectedFrom = suraVariantFixed(from);
  const expectedTo = suraVariantFixed(to);
  return !!expectedFrom
    && !!expectedTo
    && canonicalText(expectedFrom) === from
    && canonicalText(expectedTo) === from
    && from !== to;
}

function isBareHacToHaccRewrite(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  return foldText(from).toLocaleLowerCase('tr-TR') === 'hac'
    && !isAllCapsLike(from)
    && foldText(to).toLocaleLowerCase('tr-TR') === 'hacc';
}

function hasCircumflex(text) {
  return /[âîûÂÎÛ]/u.test(canonicalText(text));
}

function isSuraCaseOnlyChange(original, fixed) {
  const from = suraCaseKey(original);
  const to = suraCaseKey(fixed);
  return !!from && from === to && SURA_NAME_KEYS.has(to) && canonicalText(original) !== canonicalText(fixed);
}

function isCaseOnlyChange(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  return !!from && !!to && from !== to && from.toLocaleLowerCase('tr-TR') === to.toLocaleLowerCase('tr-TR');
}

function isSourceDiacriticProtected(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (/^dîn(?:ehum|ekum|ihim|ikum|ihi|ehu)$/iu.test(from) && /^din[\p{L}\p{N}_]*$/iu.test(to)) return true;
  if (/^dîn(?:â|en)$/iu.test(from) && /^din(?:â|en)$/iu.test(to)) return true;
  if (/^dîn[\p{L}\p{N}_]*$/iu.test(from) && /^din[\p{L}\p{N}_]*$/iu.test(to)) return false;
  return !!from && !!to && from !== to && hasCircumflex(from) && foldText(from) === foldText(to);
}

function isHadisSuffixDrop(original, fixed) {
  const from = foldText(original);
  const to = foldText(fixed);
  return /^hadis[\p{L}\p{N}_]+$/u.test(from) && to === 'hadis';
}

function isSuresiApostropheRewrite(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ');
  const to = foldText(fixed).replace(/[’']/g, "'").replace(/\s+/g, ' ');
  return /\bsuresi(?:nin|ni|nde|nden|ne)\b/u.test(from)
    && /\bsuresi'/u.test(to);
}

function isAliImranWrongShape(original, fixed) {
  const from = asciiFold(original).replace(/[‐‑‒–—]/gu, '-');
  const to = canonicalText(fixed).toLocaleLowerCase('tr-TR');
  return /\b(?:ali|al-i)[-\s]+imran\b/u.test(from)
    && (/\bâlî\s+imrân\b/u.test(to) || /\bâl-i\s+imrân\b/u.test(to));
}

function isSuspiciousTruncation(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to || to.length >= from.length) return false;
  if (!foldText(from).startsWith(foldText(to))) return false;
  const dropped = from.slice(to.length);
  return /[\s'’-]/u.test(dropped) || dropped.length > 1;
}

function isAllowedContentAddition(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  return foldText(from) === 'hazreti isa' && /^hazreti\s+isa\s*\(a\.s\.?\)$/iu.test(foldText(to));
}

function isSuspiciousContentAddition(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to || from === to || !to.includes(from)) return false;
  if (isAllowedContentAddition(original, fixed)) return false;

  const extra = to.replace(from, ' ').trim();
  if (!extra) return false;
  return /[\p{L}]{2,}/u.test(extra);
}

function isSuspiciousSentenceExpansion(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to || from === to || isAllowedContentAddition(original, fixed)) return false;

  const fromStem = from.replace(/[.!?]\s*$/u, '').trim();
  if (fromStem.length < 20) return false;

  const foldedStem = foldText(fromStem);
  const foldedTo = foldText(to);
  if (foldedTo.startsWith(`${foldedStem}:`) && to.length > fromStem.length + 20) return true;
  if (foldedTo.startsWith(`${foldedStem}.`) && to.length > fromStem.length + 20) return true;
  return false;
}

function isSuspiciousWordExpansion(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to || from.length < 4 || from === to) return false;
  if (isAllowedContentAddition(original, fixed)) return false;
  if (!foldText(to).startsWith(foldText(from))) return false;

  const extra = to.slice(from.length);
  return /^[\p{L}\p{N}_]+$/u.test(extra);
}

function consonantSkeleton(text) {
  return foldText(text).replace(/[aeıiou]/giu, '');
}

function isApostropheFragmentVowelRewrite(original, fixed) {
  const from = canonicalText(original).toLocaleLowerCase('tr-TR');
  const to = canonicalText(fixed).toLocaleLowerCase('tr-TR');
  if (!from || !to || from === to || from.includes(' ') || to.includes(' ')) return false;
  if (!from.includes("'") || !to.includes("'")) return false;

  const fromParts = from.split("'");
  const toParts = to.split("'");
  if (fromParts.length !== 2 || toParts.length !== 2) return false;

  const [fromStem, fromTail] = fromParts;
  const [toStem, toTail] = toParts;
  if (!fromStem || !toStem || !fromTail || !toTail) return false;
  if (foldText(fromStem) !== foldText(toStem)) return false;
  if (fromTail.length > 4 || toTail.length > 4) return false;
  if (!/^[a-zçğıöşüâîû]+$/iu.test(fromTail) || !/^[a-zçğıöşüâîû]+$/iu.test(toTail)) return false;

  const foldedFromTail = foldText(fromTail);
  const foldedToTail = foldText(toTail);
  if (foldedFromTail === foldedToTail) return false;
  if (TURKISH_APOSTROPHE_SUFFIXES.has(foldedFromTail) && TURKISH_APOSTROPHE_SUFFIXES.has(foldedToTail)) return false;

  return consonantSkeleton(fromTail) === consonantSkeleton(toTail);
}

function isUnrelatedTabiRewrite(original, fixed) {
  const foldedFrom = foldText(original).replace(/\s+/g, '');
  const foldedTo = foldText(fixed).replace(/\s+/g, '');
  return foldedTo === 'tabi' && !/^tabii?$/.test(foldedFrom);
}

function isMeaningChangingHerseyRewrite(original, fixed) {
  const foldedFrom = foldText(original).replace(/\s+/g, '');
  const foldedTo = foldText(fixed).replace(/\s+/g, '');
  return foldedTo.startsWith('hersey') && !foldedFrom.startsWith('hersey');
}

function isHerbirSplit(original, fixed) {
  const foldedFrom = foldText(original).replace(/\s+/g, '').trim();
  const foldedTo = foldText(fixed).replace(/\s+/g, ' ').trim();
  return /^herbir[\p{L}\p{N}_]*$/u.test(foldedFrom)
    && /^her bir[\p{L}\p{N}_]*$/u.test(foldedTo);
}

function isNumberTaneAlternativeRewrite(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/\s+/g, ' ').trim();
  const match = from.match(/(?<![\p{L}\p{N}_])(\d+\s+tane\s*,\s*\d+\s+tane)(?![\p{L}\p{N}_])/u);
  return !!match && !to.includes(match[1]);
}

function isLeadingConnectorDeletion(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  const match = from.match(/^(ve|veya|ama|fakat|çünkü|lakin)\s+(.+)$/iu);
  return !!match && foldText(match[2]) === foldText(to);
}

function isRepeatedWordDeletion(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/\s+/g, ' ').trim();
  if (!from || !to || from === to) return false;

  const match = from.match(/(?<![\p{L}\p{N}_])([\p{L}]{4,})\s+\1(?![\p{L}\p{N}_])/u);
  if (!match) return false;

  const collapsed = from.replace(new RegExp(`(?<![\\p{L}\\p{N}_])${escapeRegExp(match[1])}\\s+${escapeRegExp(match[1])}(?![\\p{L}\\p{N}_])`, 'u'), match[1]);
  return collapsed === to;
}

function isAllowedCaseNormalization(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to || foldText(from) !== foldText(to)) return false;
  if (/^Her\s+Resûl$/u.test(from) && to === 'Her resûl') return true;
  if (/^gayy\s+yolu$/iu.test(from) && /^(?:Gayy yolu|GAYY YOLU)$/u.test(to)) return true;
  if (from === 'âyetTE' && to === 'ÂYETTE') return true;
  if (/^nice\s+aşıkların$/iu.test(from) && /^Nice\s+aşıkların$/u.test(to)) return true;
  if (/^bir\s+kâmil\s+mürşide$/iu.test(from) && /^Bir\s+kâmil\s+mürşide$/u.test(to)) return true;
  return false;
}

function sourceProtectsBookTitleDin(sourceText, original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!/^dîn$/iu.test(from) || !/^din$/iu.test(to)) return false;
  const source = asciiFold(sourceText).replace(/[’]/g, "'");
  return /\b(?:ihya'?u\s+)?ulumi'?d-din\b/u.test(source);
}

function sourceProtectsMaideNefislerinin(sourceText, original, fixed) {
  const from = foldText(original);
  const to = foldText(fixed);
  if (from !== 'nefislerinin' || to !== 'nefslerinin') return false;
  return /\bmaide\s*-\s*80\b/u.test(asciiFold(sourceText));
}

function isBareYunusPersonRewrite(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  return /^Yunus$/iu.test(from)
    && /^Yûnus$/iu.test(to)
    && from !== to;
}

function isBareIsaSavAddition(original, fixed) {
  const from = asciiFold(original);
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return from === 'isa' && /^isa\s*\(\s*a\.s\.?\s*\)$/u.test(to);
}

function isNefretToNefsRewrite(original, fixed) {
  return /^nefret[\p{L}\p{N}_]*/u.test(foldText(original))
    && /^nefs[\p{L}\p{N}_]*/u.test(foldText(fixed));
}

function isVarYaDeletion(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/\s+/g, ' ').trim();
  return /\bvar ya\b/u.test(from) && !/\bvar ya\b/u.test(to);
}

function isSimplePunctuationAddition(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  const lowered = from.toLocaleLowerCase('tr-TR').replace(/\s+/g, ' ').trim();
  return lowered === 'şeriat kitabı' && to === `${from},`;
}

function isFazlFamilyFalsePositive(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return (/^fazilet[\p{L}\p{N}_]*$/u.test(from) && /^fazl/u.test(to))
    || (/^fazilla$/u.test(from) && /^fazl\s+ile$/u.test(to));
}

function isAhlakiPossessiveRewrite(original, fixed) {
  const from = canonicalText(original).toLocaleLowerCase('tr-TR');
  const to = canonicalText(fixed).toLocaleLowerCase('tr-TR');
  return from === 'ahlaki' && to === 'ahlakı';
}

function isArdardaSplit(original, fixed) {
  const from = foldText(original).replace(/\s+/g, '').trim();
  const to = foldText(fixed).replace(/\s+/g, ' ').trim();
  return from === 'ardarda' && to === 'ard arda';
}

function isAcizCircumflexInsertion(original, fixed) {
  const from = canonicalText(original).toLocaleLowerCase('tr-TR');
  const to = canonicalText(fixed).toLocaleLowerCase('tr-TR');
  return /^aciz[\p{L}\p{N}_]*$/u.test(from) && /^âciz[\p{L}\p{N}_]*$/u.test(to);
}

function isYakinCircumflexDrop(original, fixed) {
  return /^yakîn$/iu.test(canonicalText(original))
    && /^yakın$/iu.test(canonicalText(fixed));
}

function isDinCircumflexInsertion(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  return /^dini$/iu.test(from) && /^dinî$/iu.test(to);
}

function isSureDeCompaction(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/\s+/g, '').trim();
  return from === 'sure de' && to === 'surede';
}

function isTabiatiylaRewrite(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return from === 'tabiatiyla' && to === 'tabii ki';
}

function isTabiKiToTabiatiylaRewrite(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return /^(?:tabi|tabii|tabiî)\s+ki$/u.test(from) && to === 'tabiatiyla';
}

function isLazimGelenSplitInPhrase(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return from.includes('lazimgelen') && to.includes('lazim gelen');
}

function isAllahCcToAsRewrite(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return /^allah\s*\(\s*c\.?c\.?\s*\)$/u.test(from)
    && /^allah\s*\(\s*a\.?s\.?\s*\)$/u.test(to);
}

function isHayySemanticRewrite(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return /^hayy[\p{L}\p{N}_]*$/u.test(from)
    && /^(?:diri|diridir|hayat|hayatta)[\p{L}\p{N}_]*$/u.test(to);
}

function isSebilelToSebiliRewrite(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  return /^sebilel\s+(?:gayy|rusd)/u.test(from)
    && /^sebili\s+(?:gayy|rusd)/u.test(to);
}

function isYokToYoksaRewrite(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/\s+/g, ' ').trim();
  return /\byok\.$/u.test(from) && /\byoksa\.$/u.test(to);
}

function isQuranContentAddition(original, fixed) {
  const from = asciiFold(original);
  const to = asciiFold(fixed);
  return !/\bkur'?an\b/u.test(from) && /\bkur'?an\b/u.test(to);
}

function isReferenceColonInsertion(original, fixed) {
  const from = canonicalText(original).replace(/[–—]/gu, '-');
  const to = canonicalText(fixed).replace(/[–—]/gu, '-');
  return /^(?:\d+\s*\/\s*)?[A-ZÇĞİÖŞÜÂÎÛ' ]+\s*-\s*\d+\s+De ki:$/u.test(from)
    && to === from.replace(/\s+De ki:$/u, ': De ki:');
}

function isReferenceColonDeletion(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from.endsWith(':') || to !== from.slice(0, -1)) return false;
  return /(?:\d+\s*\/\s*)?[\p{L}'’ÂÎÛâîû]+\s*[-–]\s*\d+/iu.test(from);
}

function isMalformedQuoteDiyorRewrite(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  return /\bdiyor\.$/iu.test(from) && /\bdiyor\."$/iu.test(to);
}

function sourceProtectsTevbeSuraReference(sourceText, original, fixed) {
  const from = foldText(original);
  const to = foldText(fixed);
  if (from !== 'tevbe' || to !== 'tovbe') return false;
  return /\btevbe\s+\d+/u.test(asciiFold(sourceWindow(sourceText, original)));
}

function isBibliographySourceTitleRewrite(original, fixed) {
  const from = asciiFold(original).replace(/\s+/g, ' ').trim();
  const to = asciiFold(fixed).replace(/\s+/g, ' ').trim();
  if (/^fezailul\b/u.test(from) && /^fezailu'?l\b/u.test(to)) return true;
  if (/^alamet-il\b/u.test(from) && /^alamet-i'?l\b/u.test(to)) return true;
  return false;
}

function sourceWindow(sourceText, original) {
  const source = canonicalText(sourceText);
  const needle = canonicalText(original);
  if (!source || !needle) return '';
  const index = source.toLocaleLowerCase('tr-TR').indexOf(needle.toLocaleLowerCase('tr-TR'));
  if (index < 0) return '';
  return source.slice(Math.max(0, index - 220), Math.min(source.length, index + needle.length + 220));
}

function sourceProtectsBareYunusPerson(sourceText, original, fixed) {
  if (!isBareYunusPersonRewrite(original, fixed)) return false;
  const window = asciiFold(sourceWindow(sourceText, original));
  return /\byunus\s+(?:emre|diyor|ne\s+diyor)\b/u.test(window);
}

function sourceProtectsArabicDinLine(sourceText, original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!/^dîn[\p{L}\p{N}_]*$/iu.test(from) || !/^din[\p{L}\p{N}_]*$/iu.test(to)) return false;
  const window = asciiFold(sourceWindow(sourceText, original));
  return /\d+\s*\/\s*[\p{L}' ]+\s*-\s*\d+/u.test(window)
    || /\b(?:tebia|dinekum|dinikum|siratin|siratekel|mustekim|mustekimin|agveyteni|akudenne)\b/u.test(window);
}

function sourceProtectsBibliographyLine(sourceText, original, fixed) {
  if (!isBibliographySourceTitleRewrite(original, fixed)) return false;
  const window = asciiFold(sourceWindow(sourceText, original));
  return /\b(?:kaynak|buhari|muslim|tirmizi|kitab|hadis|hadis-i|hadis)\b/u.test(window);
}

function isAllowedReferencePunctuation(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (/^\(Araf\s+175\.\.$/iu.test(from) && to === '(Araf 175)') return true;
  if (/^\(Bakara\s+129\.151,\s*Âli\s+İmran\s+164,\s*Cuma\s+2\.$/iu.test(from)
    && to === '(Bakara 129.151, Âli İmrân 164, Cuma 2)') return true;
  return false;
}

function isHidayetSuffixDrop(original, fixed) {
  const foldedFrom = foldText(original);
  const foldedTo = foldText(fixed);
  return /^hidayet[\p{L}\p{N}_]+$/u.test(foldedFrom) && foldedTo === 'hidayet';
}

function isSuretteRewrite(original, fixed) {
  const from = canonicalText(original).toLocaleLowerCase('tr-TR');
  const to = canonicalText(fixed).toLocaleLowerCase('tr-TR');
  return /\bsurette\b/u.test(from) && /\bs[üû]rette\b/u.test(to);
}

function isBirSeyCompaction(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/\s+/g, '').trim();
  return /^bir sey\b/u.test(from) && to.startsWith('birsey');
}

function isSekliSemalSuffixTrim(original, fixed) {
  const from = foldText(original);
  const to = foldText(fixed);
  return /^sekli semal/u.test(from) && /^sekil semal/u.test(to);
}

function isKeyfeMeyesaMisspelling(original, fixed) {
  const from = foldText(original).replace(/ı/g, 'i').replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/ı/g, 'i').replace(/\s+/g, ' ').trim();
  return /^(?:keyfe\s+)?measadir$/u.test(from) && /^(?:keyfe\s+)?mesadir$/u.test(to);
}

function isSuretiyleToSurette(original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/\s+/g, ' ').trim();
  return from === 'suretiyle' && to === 'surette';
}

function isNumberedNimetApostropheRewrite(original, fixed) {
  const from = asciiFold(original);
  const to = asciiFold(fixed);
  const fromMatch = from.match(/^(\d+)\.?\s+nimet\b/u);
  const toMatch = to.match(/^(\d+)\.?\s+ni'met\b/u);
  return !!fromMatch && !!toMatch && fromMatch[1] === toMatch[1];
}

function isKuranKerimTruncation(original, fixed) {
  const from = asciiFold(original);
  const to = asciiFold(fixed);
  return /kur'?an-i\s+kerim\b/u.test(from)
    && /kur'?an\b/u.test(to)
    && !/\bkerim\b/u.test(to);
}

function isArabicTransliterationMustekimRewrite(original, fixed) {
  const from = asciiFold(original).replace(/[()]/g, ' ');
  const to = asciiFold(fixed).replace(/[()]/g, ' ');
  return /\bmustekim(?:e)?\b/u.test(from)
    && /\bmustakim(?:in'?e)?\b/u.test(to);
}

function sourceProtectsArabicTransliteration(sourceText, original, fixed) {
  if (!isArabicTransliterationMustekimRewrite(original, fixed)) return false;
  const source = asciiFold(sourceText);
  return /siratekel\s+mustekim(?:\s*\(\s*mustekime\s*\))?/u.test(source)
    || /siratin\s+mustekim(?:\s*\(\s*mustekimin\s*\))?/u.test(source)
    || (/\b(?:kale\s+fe\s+bima|agveyteni|ak'?udenne|lehum)\b/u.test(source) && /\bmustekim(?:e)?\b/u.test(source));
}

function sourceProtectsAllahArasindadir(sourceText, original, fixed) {
  const from = foldText(original).replace(/\s+/g, ' ').trim();
  const to = foldText(fixed).replace(/[’']/g, "'").replace(/\s+/g, ' ').trim();
  if (from !== 'allah' || !/^allah'?a$/u.test(to)) return false;
  return /\ballah\s+aras[ıi]ndad[ıi]r\b/u.test(foldText(sourceText));
}

function sourceAlreadyHasSavAfterIssue(sourceText, original, fixed) {
  const foldedFrom = foldText(original).replace(/\s+/g, ' ').trim();
  const foldedTo = foldText(fixed).replace(/\s+/g, ' ').trim();
  if (!foldedFrom || !foldedTo || !foldedTo.includes('(s.a.v')) return false;
  if (foldedFrom.includes('(s.a.v')) return false;
  if (!foldedTo.startsWith(foldedFrom)) return false;

  const source = foldText(sourceText).replace(/\s+/g, ' ');
  const pattern = new RegExp(`${escapeRegExp(foldedFrom)}\\s*\\(\\s*s\\.a\\.v\\.?\\s*\\)`, 'u');
  return pattern.test(source);
}

function isSourceContextProtectedIssue(sourceText, original, fixed) {
  return sourceProtectsAllahArasindadir(sourceText, original, fixed)
    || sourceProtectsArabicTransliteration(sourceText, original, fixed)
    || sourceAlreadyHasSavAfterIssue(sourceText, original, fixed)
    || sourceProtectsBareYunusPerson(sourceText, original, fixed)
    || sourceProtectsTevbeSuraReference(sourceText, original, fixed)
    || sourceProtectsArabicDinLine(sourceText, original, fixed)
    || sourceProtectsBibliographyLine(sourceText, original, fixed)
    || sourceProtectsBookTitleDin(sourceText, original, fixed)
    || sourceProtectsMaideNefislerinin(sourceText, original, fixed);
}

function isHristiyanVowelInsertion(original, fixed) {
  const from = canonicalText(original).toLocaleLowerCase('tr-TR');
  const to = canonicalText(fixed).toLocaleLowerCase('tr-TR');
  return /^hristiyan[\p{L}\p{N}_]*$/u.test(from)
    && /^h\u0131ristiyan[\p{L}\p{N}_]*$/u.test(to);
}

function isSalihCircumflexRewrite(original, fixed) {
  const from = foldText(original);
  const to = foldText(fixed);
  return /^salih[\p{L}\p{N}_]*$/u.test(from)
    && /^salih[\p{L}\p{N}_]*$/u.test(to)
    && hasCircumflex(fixed);
}

function foldedWordTokens(value) {
  return foldText(value)
    .split(/[^\p{L}\p{N}_]+/u)
    .filter(Boolean);
}

function isAllowedIndependentSerRoot(token) {
  return /^ser(?:dir|le|den|de|in|i|e)?$/u.test(token);
}

function isSerRootInsideWordRewrite(original, fixed) {
  const fromTokens = foldedWordTokens(original);
  const toTokens = foldedWordTokens(fixed);

  return fromTokens.some((fromToken, index) => {
    const toToken = toTokens[index] || '';
    if (!fromToken || !toToken || fromToken === toToken) return false;
    if (/^serr/u.test(fromToken) && /^serrr/u.test(toToken)) return true;
    return /^ser[\p{L}\p{N}_]*/u.test(fromToken)
      && /^serr[\p{L}\p{N}_]*/u.test(toToken)
      && !isAllowedIndependentSerRoot(fromToken);
  });
}

function isDecisionProtectedTransform(original, fixed) {
  const from = canonicalText(original).toLocaleLowerCase('tr-TR');
  const to = canonicalText(fixed).toLocaleLowerCase('tr-TR');
  const foldedFrom = foldText(original);
  const foldedTo = foldText(fixed);

  if (foldedFrom.includes(' ama') && /,\s+ama\b/iu.test(to)) return true;
  if (/^"+/.test(canonicalText(fixed)) || /"+$/.test(canonicalText(fixed))) return true;
  if (foldedFrom.startsWith('dilemeyen') && foldedTo.startsWith('dileyemeyen')) return true;
  if (foldedFrom.startsWith('aheze') && foldedTo.startsWith('ahize')) return true;
  if (foldedFrom.startsWith('zekat') && foldedTo.startsWith('zekat') && hasCircumflex(fixed)) return true;
  if (foldedFrom.startsWith('oluyken') && foldedTo.startsWith('olu iken')) return true;
  if (foldedFrom.startsWith('amenustecibu') && foldedTo.startsWith('amenu stecibu')) return true;
  if (foldedFrom.startsWith('heryeri') && foldedTo.startsWith('herseyi')) return true;
  if (foldedFrom === 'peygamber' && foldedTo === 'nebi') return true;
  if (/^7\s+safha\s+4\s+teslim/i.test(from) && /^7\s+safha,\s+4\s+teslim/i.test(to)) return true;
  if (foldedFrom.startsWith('helal') && foldedTo.startsWith('helal') && hasCircumflex(fixed)) return true;
  if (foldedFrom.startsWith('maddi') && foldedTo.startsWith('maddi') && hasCircumflex(fixed)) return true;
  if (foldedFrom === 'gayret ustune gayret' && foldedTo === 'gayret ustune gayret,') return true;
  if (foldedFrom.startsWith('allah') && foldedTo.startsWith('allahu teala')) return true;
  if (foldedFrom.includes('allah') && foldedTo.includes('allahu teala')) return true;
  if (foldedFrom.startsWith('sergilerse') && foldedTo.startsWith('sergilesin')) return true;
  if (foldedFrom.startsWith('artisi') && foldedTo.startsWith('artisini')) return true;
  if (foldedFrom.startsWith('ahiret') && foldedTo.startsWith('ahiret') && hasCircumflex(fixed)) return true;
  if (foldedFrom.startsWith('tirmizi') && /tirmizi\s*,/iu.test(foldedTo)) return true;
  if (foldedFrom.startsWith('es safi') && /^es-safi/iu.test(foldedTo)) return true;
  if (foldedFrom === 'mumin' && (foldedTo === 'mu min' || /^m[üu]'?min$/iu.test(to))) return true;
  if (/^5\s+dakika\s+10\s+dakikal[ıi]k/iu.test(from) && /^5\s+dakika,\s+10\s+dakikal[ıi]k/iu.test(to)) return true;
  if (/efendimiz\s*\(s\.a\.v\)'dir$/iu.test(from) && /efendimiz\s*\(s\.a\.v\)'dir\.$/iu.test(to)) return true;
  if (foldedFrom.includes('kusluk namaz') && foldedFrom.includes('rekat') && foldedTo.includes('rekat')) return true;
  if (foldedFrom.startsWith('vaad') && foldedTo.startsWith('vaat')) return true;
  if (foldedFrom === '19 tane haslet ruhun' && /^19 tane haslet ruhun\s*[,.;:]$/iu.test(foldedTo)) return true;
  if (/^kitab$/iu.test(from) && /^kitâb$/iu.test(to)) return true;
  if (/^cihad/iu.test(from) && /^cihâd/iu.test(to)) return true;
  if (/^ebu$/iu.test(from) && /^ebû$/iu.test(to)) return true;
  if (/^inşaallah$/iu.test(from) && /^inşallah$/iu.test(to)) return true;
  if (/^kasiyet$/iu.test(from) && /^kasvet$/iu.test(to)) return true;
  if (/^lâzımgelen$/iu.test(from) && /^lâzım\s+gelen$/iu.test(to)) return true;
  if (/^dîn[ie]$/iu.test(from) && /^din[ie]$/iu.test(to)) return true;
  if (/^hz\.\s*isa/iu.test(from) && /^hazreti\s+isa\s*\(a\.s\.?\)/iu.test(to)) return true;
  if (/^[\p{L}'\u2019]+\([\p{L}'\u2019]+\)$/iu.test(from) && new RegExp(`^${escapeRegExp(from.replace('(', ' ('))}$`, 'iu').test(to)) return true;
  if (from.endsWith(';') && to === `${from.slice(0, -1)}:`) return true;
  if (from.includes('. ') && foldText(to) === foldText(from.replace('. ', ', '))) return true;
  if (foldedFrom.length <= 4 && foldedTo.length === foldedFrom.length - 1 && foldedFrom.startsWith(foldedTo)) return true;
  if (foldedFrom.includes('euzu billahi') && foldedTo.replace(/\s+/g, '').startsWith('euzubillahi')) return true;
  if (from.includes("'") && !to.includes("'") && foldText(from.replace(/'/g, '')) === foldText(to)) return true;
  if (/^kadir(?:i|i|\u00ee)?$/iu.test(from) && /^kaadir(?:i|i|\u00ee)?$/iu.test(to)) return true;
  if (/^vel\s+asr$/iu.test(from) && /^vel-asr$/iu.test(to)) return true;
  if (/^\d+\/[\p{L}'\u2019\s]+\s*-\s*\d+$/iu.test(from) && /^\d+\.\s*[\p{L}'\u2019\s]+\s*-\s*\d+$/iu.test(to)) return true;
  if (/^\d+\s+\.\s*[\p{L}'\u2019\s]+\s*-\s*\d+$/iu.test(from) && /^\d+\.\s*[\p{L}'\u2019\s]+\s*-\s*\d+$/iu.test(to)) return true;
  if (/^had\u00eesi$/iu.test(from) && /^had\u00ees-i$/iu.test(to)) return true;
  if (/^allah['\u2019]da$/iu.test(from) && /^allah['\u2019]ta$/iu.test(to)) return true;
  if (/^sagir$/iu.test(from) && /^sa\u011fir$/iu.test(to)) return true;
  if (/^ukba$/iu.test(from) && /^ukb\u00e2$/iu.test(to)) return true;
  if (foldedFrom.startsWith('afet') && foldedTo.startsWith('afet') && hasCircumflex(fixed)) return true;
  if (/^rahmete$/iu.test(from) && /^rahmeti$/iu.test(to)) return true;
  if (/^zur\u00fbf$/iu.test(from) && /^zumer$/iu.test(to)) return true;
  if (from.replace(/…/gu, '...') === to.replace(/…/gu, '...')) return true;
  if (foldedFrom.startsWith('biraraya') && foldedTo.startsWith('bir araya')) return true;
  if (/^la$/iu.test(foldedFrom) && foldedTo.includes('olmuyor')) return true;
  if ((foldedFrom.includes('sinifta -biz') || foldedFrom.includes('s\u0131n\u0131fta -biz'))
    && (/[\u2013\u2014]|--/.test(to) || foldedTo.includes('sinifta biz') || foldedTo.includes('s\u0131n\u0131fta biz'))) return true;
  if (foldedFrom === 'nebi' && foldedTo === 'nebi' && canonicalText(original)[0] !== canonicalText(fixed)[0]) return true;
  if (foldedFrom.startsWith('hersey') && foldedTo.startsWith('her sey')) return true;
  if (foldedFrom.startsWith('vucut') && foldedTo.startsWith('vucud')) return true;
  if (foldedFrom.startsWith('vucud') && foldedTo.startsWith('vucut') && foldedFrom !== 'vucud') return true;
  if (foldedFrom === 'vucud' && foldedTo === 'vucut') return false;
  if (foldedFrom.startsWith('kadir') && foldedTo.startsWith('kadir') && hasCircumflex(fixed)) return true;
  if (foldedFrom.startsWith('kaadir') && foldedTo.startsWith('kadir') && hasCircumflex(fixed)) return true;
  if (foldedFrom.startsWith('halife') && foldedTo.startsWith('halife') && hasCircumflex(fixed)) return true;
  if (foldedFrom === 'tabii' && foldedTo === 'tabi') return true;
  if (foldedFrom.startsWith('hayy') && foldedTo.startsWith('hayat')) return true;
  if (foldedFrom === 'hidayet' && foldedTo.startsWith('hidayet') && foldedTo !== 'hidayet') return true;
  if (isSerRootInsideWordRewrite(original, fixed)) return true;
  if (from.includes('şerif') && to.includes('şerîf')) return true;
  if (isSuretteRewrite(original, fixed)) return true;
  if (isSuretiyleToSurette(original, fixed)) return true;
  if (isKeyfeMeyesaMisspelling(original, fixed)) return true;
  if (isBirSeyCompaction(original, fixed)) return true;
  if (isSekliSemalSuffixTrim(original, fixed)) return true;
  if (isHristiyanVowelInsertion(original, fixed)) return true;
  if (isSalihCircumflexRewrite(original, fixed)) return true;
  if (isNumberedNimetApostropheRewrite(original, fixed)) return true;
  if (isKuranKerimTruncation(original, fixed)) return true;
  return false;
}

function buildResultSummary(cats, total) {
  if (!total) return 'Metinde arşiv standardına göre hata bulunmadı.';
  const labels = {
    sozluk: 'sözlük',
    imla: 'imlâ',
    noktalama: 'noktalama',
    etiket: 'etiket',
    yapi: 'yapı'
  };
  const active = Object.entries(cats || {})
    .filter(([, category]) => (category?.count || 0) > 0)
    .map(([key]) => labels[key])
    .filter(Boolean);
  const list = active.length <= 1
    ? (active[0] || 'denetim')
    : `${active.slice(0, -1).join(', ')} ve ${active[active.length - 1]}`;
  return `Metinde ${list} hataları bulunmaktadır. Düzeltmeler uygulanmıştır.`;
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function needsWordBoundary(ch) {
  return WORD_EDGE.test(ch || '');
}

function sourceContainsIssue(sourceText, original) {
  const source = canonicalText(sourceText);
  const needle = canonicalText(original);
  if (!needle) return false;

  const left = needsWordBoundary(needle[0]) ? '(?<![\\p{L}\\p{N}_])' : '';
  const right = needsWordBoundary(needle[needle.length - 1]) ? '(?![\\p{L}\\p{N}_])' : '';
  const re = new RegExp(`${left}${escapeRegExp(needle)}${right}`, 'iu');
  return re.test(source);
}

function sourceAlreadyHasFixedPunctuation(sourceText, original, fixed) {
  const source = canonicalText(sourceText);
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!source || !from || !to) return false;
  if (!new RegExp(`^${escapeRegExp(from)}[,;:.!?]$`, 'iu').test(to)) return false;
  return sourceContainsIssue(source, to);
}

function isAyetStandardIssue(original, fixed) {
  return foldText(original).replace(/\s+/g, '') === 'ayet'
    && foldText(fixed).replace(/\s+/g, '') === 'ayet'
    && hasCircumflex(fixed);
}

function sourceIssueOccurrenceCount(sourceText, original, fixed = '') {
  const source = canonicalText(sourceText);
  const needle = canonicalText(original);
  if (!needle) return 0;

  const left = needsWordBoundary(needle[0]) ? '(?<![\\p{L}\\p{N}_])' : '';
  const right = needsWordBoundary(needle[needle.length - 1]) ? '(?![\\p{L}\\p{N}_])' : '';
  const re = new RegExp(`${left}${escapeRegExp(needle)}${right}`, 'giu');
  const matches = [...source.matchAll(re)];
  if (isAyetStandardIssue(original, fixed)) {
    return matches.filter(match => match[0] !== match[0].toLocaleUpperCase('tr-TR')).length;
  }
  return matches.length;
}

function equivalentIssue(original, fixed) {
  const a = canonicalText(original);
  const b = canonicalText(fixed);
  if (!a || !b) return false;
  if (a === b) return true;

  const stripInvisibleDiffs = value => value
    .replace(/["']/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return stripInvisibleDiffs(a) === stripInvisibleDiffs(b);
}

function isProtectedChange(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to || from === to) return false;

  if (to === `${from}:`) return true;
  if (isHadisSerifStandardChange(original, fixed)) return false;
  if (isAllowedCaseNormalization(original, fixed)) return false;
  if (isAllowedReferencePunctuation(original, fixed)) return false;
  if (isBareHacToHaccRewrite(original, fixed)) return true;
  if (isBareYunusPersonRewrite(original, fixed)) return true;
  if (isBareIsaSavAddition(original, fixed)) return true;
  if (isNefretToNefsRewrite(original, fixed)) return true;
  if (isVarYaDeletion(original, fixed)) return true;
  if (isSimplePunctuationAddition(original, fixed)) return true;
  if (isFazlFamilyFalsePositive(original, fixed)) return true;
  if (isAhlakiPossessiveRewrite(original, fixed)) return true;
  if (isArdardaSplit(original, fixed)) return true;
  if (isAcizCircumflexInsertion(original, fixed)) return true;
  if (isYakinCircumflexDrop(original, fixed)) return true;
  if (isDinCircumflexInsertion(original, fixed)) return true;
  if (isSureDeCompaction(original, fixed)) return true;
  if (isTabiatiylaRewrite(original, fixed)) return true;
  if (isTabiKiToTabiatiylaRewrite(original, fixed)) return true;
  if (isLazimGelenSplitInPhrase(original, fixed)) return true;
  if (isAllahCcToAsRewrite(original, fixed)) return true;
  if (isHayySemanticRewrite(original, fixed)) return true;
  if (isSebilelToSebiliRewrite(original, fixed)) return true;
  if (isYokToYoksaRewrite(original, fixed)) return true;
  if (isQuranContentAddition(original, fixed)) return true;
  if (isReferenceColonInsertion(original, fixed)) return true;
  if (isReferenceColonDeletion(original, fixed)) return true;
  if (isMalformedQuoteDiyorRewrite(original, fixed)) return true;
  if (isBibliographySourceTitleRewrite(original, fixed)) return true;
  if (isAllowedSuraStandardChange(original, fixed)) return false;
  if (isSuraVariantWorsening(original, fixed)) return true;
  if (isCaseOnlyChange(original, fixed) && !isAllowedCaseNormalization(original, fixed)) return true;
  if (isSuraCaseOnlyChange(original, fixed)) return true;
  if (isSourceDiacriticProtected(original, fixed)) return true;
  if (isHadisSuffixDrop(original, fixed)) return true;
  if (isSuspiciousTruncation(original, fixed)) return true;
  if (isSuspiciousContentAddition(original, fixed)) return true;
  if (isSuspiciousSentenceExpansion(original, fixed)) return true;
  if (isSuspiciousWordExpansion(original, fixed)) return true;
  if (isApostropheFragmentVowelRewrite(original, fixed)) return true;
  if (isUnrelatedTabiRewrite(original, fixed)) return true;
  if (isMeaningChangingHerseyRewrite(original, fixed)) return true;
  if (isHerbirSplit(original, fixed)) return true;
  if (isNumberTaneAlternativeRewrite(original, fixed)) return true;
  if (isLeadingConnectorDeletion(original, fixed)) return true;
  if (isRepeatedWordDeletion(original, fixed)) return true;
  if (isHidayetSuffixDrop(original, fixed)) return true;
  if (isSuresiApostropheRewrite(original, fixed)) return true;
  if (isAliImranWrongShape(original, fixed)) return true;
  if (isDecisionProtectedTransform(original, fixed)) return true;
  if (PROTECTED_PATTERNS.some(pattern => pattern.test(from))) return true;
  return FORBIDDEN_TRANSFORMS.some(pair => pair.from.test(from) && pair.to.test(to));
}

function restoreRejectedChange(text, issue) {
  if (!text || !issue?.original || !issue?.fixed) return text;
  const original = String(issue.original);
  const fixed = String(issue.fixed);
  if (!fixed.trim()) return text;

  return String(text).split(fixed).join(original);
}

function caseLike(original, fixed) {
  const value = String(original || '');
  const replacement = String(fixed || '');
  if (!value || !replacement) return replacement;
  if (value === value.toLocaleUpperCase('tr-TR')) return replacement.toLocaleUpperCase('tr-TR');
  const first = value[0];
  if (first === first.toLocaleUpperCase('tr-TR') && first !== first.toLocaleLowerCase('tr-TR')) {
    return replacement[0].toLocaleUpperCase('tr-TR') + replacement.slice(1);
  }
  return replacement;
}

function hadisSerifStandardFixed(original) {
  const firstSegment = String(original || '').trim().split(/\s+/u)[0] || '';
  return isAllCapsLike(firstSegment) ? 'HADÎS-İ ŞERİF' : caseLike(original, 'Hadîs-i Şerif');
}

function fixAdemSuretiPhrase(original) {
  return String(original || '')
    .replace(/\(\s*A\.S\.?\s*\)/iu, '(A.S)')
    .replace(/sureti/iu, 'z\u00fcrriyeti');
}

function deterministicFixed(original) {
  const rawText = normalizeText(original);
  const text = canonicalText(original);
  if (!text) return '';

  const suraFixed = suraVariantFixed(text);
  if (suraFixed && suraFixed !== text) return suraFixed;
  if (/^tevbe[\p{L}\p{N}_]*$/iu.test(text)) {
    if (text === text.toLocaleUpperCase('tr-TR') && /^TEVBE$/u.test(text)) return '';
    return caseLike(original, text.replace(/^tevbe/iu, 'tövbe'));
  }
  if (/^sebîlel\s+(?:gayy|rüşd)/iu.test(text)) return '';
  if (/^dîn[\p{L}\p{N}_]*$/iu.test(text)) {
    if (/^dîn(?:ehum|ekum|ihim|ikum|ihi|ehu)$/iu.test(text)) return '';
    return caseLike(original, text.replace(/^dîn/iu, 'din'));
  }
  if (/^inşallah$/iu.test(text)) return caseLike(original, 'inşaallah');
  if (/^her\s+şey[\p{L}\p{N}_]*$/iu.test(text)) {
    return caseLike(original, text.replace(/^her\s+şey/iu, 'herşey'));
  }
  if (/^v\u00fcc(?:ud|\u00fbd|\u00fbt)$/iu.test(text)) {
    return caseLike(original, 'v\u00fccut');
  }
  if (/^s\s+\d+$/iu.test(text)) {
    return text.replace(/^s\s+/iu, match => match[0] === 'S' ? 'S.' : 's.');
  }
  if (/^kadirdir$/iu.test(text)) {
    return caseLike(original, text.replace(/^kadir/iu, 'kaadir'));
  }
  if (/^keyfe\s+(?:meaşadır|meşadır)$/iu.test(text)) {
    return caseLike(original, 'keyfe mâ yeşâdır');
  }
  if (/^Zur\u00fbf$/iu.test(text)) return 'Zuhr\u00fbf';
  if (/^ş(?:u|û)ra$/iu.test(text)) return caseLike(original, 'şûrâ');
  if (/^ş(?:u|û)ra\s+suresinin$/iu.test(text)) return caseLike(original, 'Şûrâ Suresinin');
  if (/^ş(?:u|û)ra\s+suresi$/iu.test(text)) return caseLike(original, 'Şûrâ Suresi');
  if (/^19 tane haslet ruhun$/iu.test(text)) return 'Ruhta 19 tane haslet';
  if (/^bir\s+araya$/iu.test(text)) return 'biraraya';
  if (isHadisSerifHeading(text)) return hadisSerifStandardFixed(original);
  if (/^nefisler[\p{L}\p{N}_]*$/iu.test(text)) return caseLike(original, text.replace(/^nefisler/iu, 'nefsler'));
  if (/^fedakarlık[\p{L}\p{N}_]*$/iu.test(text)) return caseLike(original, text.replace(/^fedakarlık/iu, 'fedakârlık'));
  if (/^kur['’]an(?:(?:['’])?[\p{L}\p{N}_]+)?$/iu.test(text)) {
    return caseLike(original, text.replace(/^kur(['’])an/iu, 'Kur$1ân'));
  }
  if (/^şer(?:dir|le|den|de|in|i|e)?$/iu.test(text)) return caseLike(original, text.replace(/^şer/iu, 'şerr'));
  if (/^zahit[\p{L}\p{N}_]*$/iu.test(text)) return caseLike(original, text.replace(/^zahit/iu, 'zahid'));
  if (/^musibet[\p{L}\p{N}_]*$/iu.test(text)) return caseLike(original, text.replace(/^musibet/iu, 'musîbet'));
  if (/^veli$/iu.test(text)) return caseLike(original, 'velî');
  if (/^\(\s*S\.AV\.?\s*\)$/iu.test(text)) return '(S.A.V)';
  if (/^Her\s+Resûl$/u.test(text)) return 'Her resûl';
  if (/^(?:\u00c2dem|Adem)\s*\(\s*A\.S\.?\s*\)\s*['\u2019]?\s*(?:\u0131n|in|un|\u00fcn|n\u0131n|nin|nun|n\u00fcn)?\s+sureti$/iu.test(text)) {
    return fixAdemSuretiPhrase(original);
  }
  if (/^\(Araf\s+175\.\.$/iu.test(text)) return '(Araf 175)';
  if (/^\(Bakara\s+129\.151,\s*Âli\s+İmran\s+164,\s*Cuma\s+2\.$/iu.test(text)) return '(Bakara 129.151, Âli İmrân 164, Cuma 2)';
  if (/^2\.?\s*Gay\s+yolu$/u.test(text)) return '2. Gayy yolu';
  if (/^gayy\s+yolu$/u.test(text)) return 'Gayy yolu';
  if (/^gayy\s+YOLU$/u.test(text)) return 'GAYY YOLU';
  if (text === 'âyetTE') return 'ÂYETTE';
  return '';
}

function isTevbeSuraContext(sourceText, index, length) {
  const text = String(sourceText || '');
  const original = text.slice(index, index + length);
  const before = text.slice(Math.max(0, index - 20), index);
  const after = text.slice(index + length, index + length + 40);
  return /^TEVBE$/u.test(original)
    || /(?:\/|\d+\s*\/)\s*$/u.test(before)
    || /^\s*(?:[-–]\s*\d+|\d+(?:\s*,\s*\d+)?(?:['’]?[a-zçğıöşü]+)?|\bSuresi(?:nin|ni|nde|nden|ne)?\b)/iu.test(after);
}

function isBareYunusSureContext(sourceText, index, length) {
  const text = String(sourceText || '');
  const before = text.slice(Math.max(0, index - 20), index);
  const after = text.slice(index + length, index + length + 40);
  return /(?:\/|\d+\s*\/)\s*$/u.test(before)
    || /^\s*(?:[-–]\s*\d+|\d+(?:\s*,\s*\d+)?(?:['’]?[a-zçğıöşü]+)?|\bSuresi(?:nin|ni|nde|nden|ne)?\b)/iu.test(after);
}

function addDeterministicIssue(cats, seen, original, fixed, rule) {
  if (!original || !fixed || original === fixed) return;
  if (/^[A-Z]\.[A-Z]$/i.test(String(original)) && /^[A-Z]\.\s+[A-Z]$/i.test(String(fixed))) return;
  if (/^(?:[A-Z]\.)+[A-Z]{1,4}$/i.test(String(original)) && /\s/u.test(String(fixed))) return;
  const key = `${canonicalText(original)}=>${canonicalText(fixed)}`;
  seen.set(key, (seen.get(key) || 0) + 1);
  if (!cats.imla) cats.imla = {};
  if (!Array.isArray(cats.imla.issues)) cats.imla.issues = [];
  cats.imla.issues.push({ original, fixed, rule });
}

function applyDeterministicStandards(cats, sourceText) {
  const text = String(sourceText || '');
  if (!text) return cats;

  const seen = new Map();
  Object.values(cats || {}).forEach(category => {
    (category?.issues || []).forEach(issue => {
      const key = `${canonicalText(issue.original)}=>${canonicalText(issue.fixed)}`;
      seen.set(key, (seen.get(key) || 0) + 1);
    });
  });

  const tokenRe = /(?<![\p{L}\p{N}_])(?:tevbe[\p{L}\p{N}_]*|dîn[\p{L}\p{N}_]*|inşallah|her\s+şey[\p{L}\p{N}_]*|vüc(?:ud|ûd|ût)[\p{L}\p{N}_]*|[Hh][Aa][Dd][İiIıÎî][Ss]\s*[-‐‑‒–—]\s*[İiIı]\s+[ŞşSs][Ee][Rr]{1,2}[İiIıÎî][Ff]|nefisler[\p{L}\p{N}_]*|fedakarlık[\p{L}\p{N}_]*|kur['’]an(?:(?:['’])?[\p{L}\p{N}_]+)?)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(tokenRe)) {
    const original = match[0];
    if (/^tevbe[\p{L}\p{N}_]*$/iu.test(original) && isTevbeSuraContext(text, match.index, original.length)) continue;
    addDeterministicIssue(cats, seen, original, deterministicFixed(original), 'Kesin arşiv standardı');
  }

  const kadirRe = /(?<![\p{L}\p{N}_])kadirdir(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(kadirRe)) {
    const original = match[0];
    addDeterministicIssue(cats, seen, original, deterministicFixed(original), 'Kesin ar\u015fiv standard\u0131');
  }

  const keyfeMeyesaRe = /(?<![\p{L}\p{N}_])keyfe\s+(?:meaşadır|meşadır)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(keyfeMeyesaRe)) {
    const original = match[0];
    addDeterministicIssue(cats, seen, original, deterministicFixed(original), 'Efendimizin sözlüğü standardı');
  }

  const zuhrufRe = /(?<![\p{L}\p{N}_])Zur\u00fbf(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(zuhrufRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sure adi standardi');
  }

  const shuraRe = /(?<![\p{L}\p{N}_])Ş(?:u|û)ra(?!\s+suresi(?:nin)?\b)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(shuraRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sure adi standardi');
  }

  const shuraSuresiRe = /(?<![\p{L}\p{N}_])Ş(?:u|û)ra\s+suresi(?:nin)?(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(shuraSuresiRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sure adi standardi');
  }

  const yunusRefRe = /(?<![\p{L}\p{N}_])((?:\d+\s*[\/.]\s*)?)Yunus(\s*[-–]\s*\d+)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(yunusRefRe)) {
    const title = caseSuraTitleLike(match[0], 'Yûnus');
    addDeterministicIssue(cats, seen, match[0], `${match[1]}${title}${match[2]}`, 'Sure adi standardi');
  }

  const yunusLooseRefRe = /(?<![\p{L}\p{N}_])Yunus(\s+\d+(?:\s*,\s*\d+)?(?:['’]?[a-zçğıöşü]+)?)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(yunusLooseRefRe)) {
    addDeterministicIssue(cats, seen, match[0], `Yûnus${match[1]}`, 'Sure adi standardi');
  }

  const tovbeRefRe = /(?<![\p{L}\p{N}_])Tövbe(\s+\d+(?:\s*,\s*\d+)?(?:['’]?[a-zçğıöşü]+)?)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(tovbeRefRe)) {
    addDeterministicIssue(cats, seen, match[0], `Tevbe${match[1]}`, 'Sure referansi standardi');
  }

  const suraVariantRe = /(?<![\p{L}\p{N}_])(?:Ali|Âli|Âl-i|Al-i)[-\s]+(?:İmran|İmrân|Imran|Imrân)(?:\s+Suresi(?:nin|ni|nde|nden|ne)?)?|(?<![\p{L}\p{N}_])(?:Casiye|Yunus|Hud|Fatir|Araf|A'raf|Mumtehıne)(?:\s+Suresi(?:nin|ni|nde|nden|ne)?)?(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(suraVariantRe)) {
    if (/^A'?raf$/iu.test(match[0]) && /^\s+\d/u.test(text.slice(match.index + match[0].length))) continue;
    if (/^Yunus$/iu.test(match[0]) && !isBareYunusSureContext(text, match.index, match[0].length)) continue;
    const fixed = deterministicFixed(match[0]);
    if (fixed) addDeterministicIssue(cats, seen, match[0], fixed, 'Sure adi standardi');
  }

  const sebilelRe = /(?<![\p{L}\p{N}_])sebîlel\s+(?:gayy|rüşd)[\p{L}\p{N}_'’]*(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(sebilelRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sebîli standardı');
  }

  const hacRefRe = /(?<![\p{L}\p{N}_])(\d+\s*\/\s*)Hac(\s*[-–]?\s*\d+)/gu;
  for (const match of text.matchAll(hacRefRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[1]}Hacc${match[2]}`, 'Sure adi standardi');
  }

  const hacListRefRe = /(?<![\p{L}\p{N}_])(\d+\.\s*)Hac(\s*[-–]\s*\d+)/gu;
  for (const match of text.matchAll(hacListRefRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[1]}Hacc${match[2]}`, 'Sure adi standardi');
  }

  const hacSuresiRe = /(?<![\p{L}\p{N}_])Hac(\s+Suresi(?:nin|ni|nde|nden|ne)?)(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(hacSuresiRe)) {
    addDeterministicIssue(cats, seen, match[0], `Hacc${match[1]}`, 'Sure adi standardi');
  }

  const serrRe = /(?<![\p{L}\p{N}_])şer(?:dir|le|den|de|in|i|e)?(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(serrRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sözlük standardı');
  }

  const zahidRe = /(?<![\p{L}\p{N}_])zahit[\p{L}\p{N}_]*(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(zahidRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sözlük standardı');
  }

  const musibetRe = /(?<![\p{L}\p{N}_])musibet[\p{L}\p{N}_]*(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(musibetRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sözlük standardı');
  }

  const veliHeadingRe = /(?<![\p{L}\p{N}_])VELI(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(veliHeadingRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Başlık yazım standardı');
  }

  const savBrokenRe = /\(\s*S\.AV\.?\s*\)/giu;
  for (const match of text.matchAll(savBrokenRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'S.A.V yazım standardı');
  }

  const mulkEightWindows = text.matchAll(/MULK-8[\s\S]{0,420}/giu);
  for (const window of mulkEightWindows) {
    const phrase = window[0].match(/(?<![\p{L}\p{N}_])her\s+bir\s+grup(?![\p{L}\p{N}_])/iu);
    if (phrase) addDeterministicIssue(cats, seen, phrase[0], phrase[0].replace(/her\s+bir/iu, 'herbir'), 'Mulk-8 ayet yazımı');
  }

  const hasletRe = /(?<![\p{L}\p{N}_])19\s+tane\s+haslet\s+ruhun(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(hasletRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Haslet ifade duzeni');
  }

  const birArayaRe = /(?<![\p{L}\p{N}_])bir\s+araya(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(birArayaRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Sozluk standardi');
  }

  const pageReferenceRe = /(?<![\p{L}\p{N}_])s\s+\d+(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(pageReferenceRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Kaynak sayfa standardi');
  }

  const numberedNimetRe = /(^|\n)([ \t]*)(\d+)\s+nimet(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(numberedNimetRe)) {
    addDeterministicIssue(cats, seen, `${match[2]}${match[3]} nimet`, `${match[2]}${match[3]}. nimet`, 'Numarali liste duzeni');
  }

  const hazretiIsaRe = /(?<![\p{L}\p{N}_])Hazreti\s+İsa(?!\s*\(A\.S\.?\))(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(hazretiIsaRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[0]} (A.S)`, 'Nebî isimleri standardı');
  }

  const ademSuretiRe = /(?<![\p{L}\p{N}_])(?:\u00c2dem|Adem)\s*\(\s*A\.S\.?\s*\)\s*['\u2019]?\s*(?:\u0131n|in|un|\u00fcn|n\u0131n|nin|nun|n\u00fcn)?\s+sureti(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(ademSuretiRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Âdem (A.S) zürriyet standardı');
  }

  const herResulRe = /(?<![\p{L}\p{N}_])Her\s+Resûl(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(herResulRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Resûl yazim standardi');
  }

  const arafParenRe = /\(Araf\s+175\.\./giu;
  for (const match of text.matchAll(arafParenRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Kaynak parantez standardi');
  }

  const multiReferenceParenRe = /\(Bakara\s+129\.151,\s*Âli\s+İmran\s+164,\s*Cuma\s+2\./giu;
  for (const match of text.matchAll(multiReferenceParenRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Kaynak parantez standardi');
  }

  const numberedGayRe = /(?<![\p{L}\p{N}_])2\.?\s*Gay\s+yolu(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(numberedGayRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Gayy yolu standardi');
  }

  const sentenceGayyRe = /(^|[.!?]\s+)(gayy\s+yolu)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(sentenceGayyRe)) {
    addDeterministicIssue(cats, seen, match[2], deterministicFixed(match[2]), 'Gayy yolu standardi');
  }

  const headingGayyRe = /(?<![\p{L}\p{N}_])gayy\s+YOLU(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(headingGayyRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Gayy yolu standardi');
  }

  const ayetHeadingRe = /(?<![\p{L}\p{N}_])âyetTE(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(ayetHeadingRe)) {
    addDeterministicIssue(cats, seen, match[0], deterministicFixed(match[0]), 'Baslik buyuk harf standardi');
  }

  const standardLazimRe = /(?<![\p{L}\p{N}_])([\p{L}\p{N}_]+)l\u00e2z\u0131m(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(standardLazimRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[1]} l\u00e2z\u0131m`, 'Biti\u015fik yaz\u0131m d\u00fczeni');
  }

  const malformedQuoteDiyorRe = /([.!?])[”"]diyor\./giu;
  for (const match of text.matchAll(malformedQuoteDiyorRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[1]}" diyor.`, 'Alinti sonrasi konusma duzeni');
  }

  const hzMusaHizirDediRe = /Hz\.\s*Musa['’]ya\s+Hızır['’]a\s+var\s+dedi;/gu;
  for (const match of text.matchAll(hzMusaHizirDediRe)) {
    addDeterministicIssue(cats, seen, match[0], match[0].replace(/;$/u, ','), 'Konusma noktalama standardi');
  }

  const stanzaLowerLineRe = /(^|\n)(nice\s+aşıkların|bir\s+kâmil\s+mürşide)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(stanzaLowerLineRe)) {
    const fixedLine = match[2][0].toLocaleUpperCase('tr-TR') + match[2].slice(1);
    addDeterministicIssue(cats, seen, match[2], fixedLine, 'Dortluk satir basi standardi');
  }

  const standardSentenceSpaceRe = /([\p{L}\p{N}_][\.\?!])([A-Z\u00c7\u011e\u0130\u00d6\u015e\u00dc\u00c2\u00ce\u00db])/gu;
  for (const match of text.matchAll(standardSentenceSpaceRe)) {
    if (/^\d+\.[A-ZÇĞİÖŞÜÂÎÛ]/u.test(match[0])) continue;
    addDeterministicIssue(cats, seen, match[0], `${match[1]} ${match[2]}`, 'C\u00fcmle aras\u0131 bo\u015fluk');
  }

  const fullSentenceSpaceRe = /(?<![\p{L}\p{N}_])([\p{L}\p{N}_]+[\.\?!])([A-Z\u00c7\u011e\u0130\u00d6\u015e\u00dc\u00c2\u00ce\u00db][\p{L}\p{N}_]*)(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(fullSentenceSpaceRe)) {
    if (/^\d+\.[A-ZÇĞİÖŞÜÂÎÛ]/u.test(match[0])) continue;
    addDeterministicIssue(cats, seen, match[0], `${match[1]} ${match[2]}`, 'C\u00fcmle aras\u0131 bo\u015fluk');
  }

  const iradeLabelRe = /(?<![\p{L}\p{N}_])(\u0130rade eksikli\u011fi);\s+([a-z\u00e7\u011f\u0131i\u00f6\u015f\u00fc][\p{L}\p{N}_]*)(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(iradeLabelRe)) {
    const word = match[2][0].toLocaleUpperCase('tr-TR') + match[2].slice(1);
    addDeterministicIssue(
      cats,
      seen,
      match[0],
      `${match[1]}: ${word}`,
      'Ba\u015fl\u0131k sonras\u0131 b\u00fcy\u00fck harf'
    );
  }

  return cats;
}

function stripOuterTextQuotes(text) {
  let value = String(text || '').trim();
  const pairs = [['"', '"'], ['“', '”'], ['‘', '’'], ['«', '»'], ['â€œ', 'â€'], ['â€˜', 'â€™']];
  pairs.push(["'", "'"], ['\u201c', '\u201d'], ['\u2018', '\u2019'], ['\u00ab', '\u00bb']);
  let changed = true;
  while (changed && value.length >= 2) {
    changed = false;
    for (const [open, close] of pairs) {
      if (value.startsWith(open) && value.endsWith(close)) {
        value = value.slice(open.length, -close.length).trim();
        changed = true;
        break;
      }
    }
  }
  return value;
}

function normalizeDoubledQuotes(text) {
  return String(text || '')
    .replace(/"{2,}([^"\n]+)"{2,}/g, '"$1"')
    .replace(/"{2,}/g, '"')
    .replace(/'{2,}([^'\n]+)'{2,}/g, "'$1'")
    .replace(/\u201c{2,}([^\u201d\n]+)\u201d{2,}/gu, '\u201c$1\u201d')
    .replace(/\u201c{2,}/gu, '\u201c')
    .replace(/\u201d{2,}/gu, '\u201d')
    .replace(/\u2018{2,}([^\u2019\n]+)\u2019{2,}/gu, '\u2018$1\u2019')
    .replace(/\u2018{2,}/gu, '\u2018')
    .replace(/\u2019{2,}/gu, '\u2019')
    .replace(/“{2,}([^”\n]+)”{2,}/g, '“$1”')
    .replace(/“{2,}/g, '“')
    .replace(/”{2,}/g, '”')
    .replace(/‘{2,}([^’\n]+)’{2,}/g, '‘$1’')
    .replace(/\s+"$/g, '');
}

function normalizeRepeatedSav(text) {
  return String(text || '').replace(/(\(\s*S\.A\.V\.?\s*\))\s+\(\s*S\.A\.V\.?\s*\)/giu, '$1');
}

function flexibleIssuePattern(original) {
  const needle = canonicalText(original);
  const chars = [...needle];
  let pattern = '';
  for (const ch of chars) {
    if (/\s/u.test(ch)) pattern += '\\s+';
    else if (/['’‘\x60´ʼ]/u.test(ch)) pattern += "['’‘\\x60´ʼ]";
    else if (/["“”«»]/u.test(ch)) pattern += '["“”«»]';
    else if (ch === '…') pattern += '(?:…|\\.\\.\\.)';
    else pattern += escapeRegExp(ch);
  }
  const left = needsWordBoundary(needle[0]) ? '(?<![\\p{L}\\p{N}_])' : '';
  const right = needsWordBoundary(needle[needle.length - 1]) ? '(?![\\p{L}\\p{N}_])' : '';
  return new RegExp(`${left}${pattern}${right}`, 'iu');
}

function exactIssuePattern(original, flags = 'iu') {
  const needle = canonicalText(original);
  if (!needle) return null;
  const left = needsWordBoundary(needle[0]) ? '(?<![\\p{L}\\p{N}_])' : '';
  const right = needsWordBoundary(needle[needle.length - 1]) ? '(?![\\p{L}\\p{N}_])' : '';
  return new RegExp(`${left}${escapeRegExp(needle)}${right}`, flags);
}

function replaceAcceptedIssue(text, original, fixed) {
  const exactSensitive = exactIssuePattern(original, 'u');
  if (exactSensitive?.test(text)) {
    return text.replace(exactSensitive, match => caseLike(match, fixed));
  }

  const exactInsensitive = exactIssuePattern(original, 'iu');
  if (exactInsensitive?.test(text)) {
    return text.replace(exactInsensitive, match => caseLike(match, fixed));
  }

  const flexible = flexibleIssuePattern(original);
  if (flexible.test(text)) {
    return text.replace(flexible, match => caseLike(match, fixed));
  }

  return text;
}

function applyAcceptedIssues(sourceText, issues) {
  const orderedIssues = [...(issues || [])].sort((a, b) => String(b?.original || '').length - String(a?.original || '').length);
  return orderedIssues.reduce((text, issue) => {
    const original = String(issue?.original || '');
    const fixed = String(issue?.fixed || '');
    if (!original || !fixed) return text;
    return replaceAcceptedIssue(text, original, fixed);
  }, sourceText);
}

function normalizeHaccCase(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!/\bhac\b/iu.test(from) || !/\bHACC\b/u.test(to)) return fixed;
  if (/\bHAC\b/u.test(from)) return fixed;
  return String(fixed).replace(/\bHACC\b/gu, 'Hacc');
}

function normalizeSuraFixedCase(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to) return fixed;
  if (from !== from.toLocaleUpperCase('tr-TR')) return fixed;
  if (!SURA_NAME_KEYS.has(suraCaseKey(to))) return fixed;
  return String(fixed).toLocaleUpperCase('tr-TR');
}

function normalizeSavFixed(fixed) {
  return String(fixed || '').replace(/\(\s*S\.AV\.?\s*\)/giu, '(S.A.V)');
}

function normalizeSavPossessiveFixed(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!/^Resûlullah['’](?:ın|in|un|ün)$/iu.test(from)) return fixed;
  if (!/\(\s*S\.A\.V\.?\s*\)/iu.test(to)) return fixed;
  return 'Resûlullah (S.A.V)\'in';
}

function normalizeIssueForStandards(issue) {
  if (!issue || typeof issue !== 'object') return issue;
  const fixed = normalizeSavPossessiveFixed(
    issue.original,
    normalizeSavFixed(normalizeSuraFixedCase(issue.original, normalizeHaccCase(issue.original, issue.fixed)))
  );
  return fixed === issue.fixed ? issue : { ...issue, fixed };
}

function textHash(text) {
  return crypto.createHash('sha256').update(normalizeText(text), 'utf8').digest('hex');
}

// Önceki sürümde kaydedilmiş parmak izleriyle geriye dönük eşleşme.
function legacyTextHash(text) {
  const normalized = normalizeText(text);
  return `${normalized.length}|${normalized.slice(0, 100)}`;
}

function candidateTextHashes(text) {
  return [...new Set([textHash(text), legacyTextHash(text)])];
}

function finalizeResult(result = {}, sourceText = '') {
  const cats = sourceText ? applyDeterministicStandards(result.categories || {}, sourceText) : (result.categories || {});
  let penalty = 0;
  let total = 0;
  const rejectedIssues = [];
  const acceptedIssues = [];
  const acceptedIssueUses = new Map();

  for (const [key, weight] of Object.entries(CAT_WEIGHTS)) {
    const category = cats[key] || {};
    let issues = Array.isArray(category.issues) ? category.issues.map(normalizeIssueForStandards) : [];
    if (sourceText) {
      issues = issues.filter(issue => {
        const originalKey = canonicalText(issue?.original || '');
        const maxOccurrences = sourceIssueOccurrenceCount(sourceText, issue?.original || '', issue?.fixed || '');
        const usedOccurrences = acceptedIssueUses.get(originalKey) || 0;
        const keep = issue
          && !equivalentIssue(issue.original, issue.fixed)
          && maxOccurrences > 0
          && usedOccurrences < maxOccurrences
          && !sourceAlreadyHasFixedPunctuation(sourceText, issue.original, issue.fixed)
          && !isSourceContextProtectedIssue(sourceText, issue.original, issue.fixed)
          && !isProtectedChange(issue.original, issue.fixed);
        if (!keep && issue) rejectedIssues.push(issue);
        if (keep) {
          acceptedIssueUses.set(originalKey, usedOccurrences + 1);
          acceptedIssues.push(issue);
        }
        return keep;
      });
    }
    category.count = issues.length;
    category.issues = issues;
    cats[key] = category;
    penalty += issues.length * weight;
    total += issues.length;
  }

  result.categories = cats;
  if (sourceText) {
    result.correctedText = applyAcceptedIssues(sourceText, acceptedIssues);
  } else if (result.correctedText) {
    result.correctedText = rejectedIssues.reduce((text, issue) => restoreRejectedChange(text, issue), result.correctedText);
  }
  if (result.correctedText) {
    result.correctedText = stripOuterTextQuotes(result.correctedText);
    result.correctedText = normalizeDoubledQuotes(result.correctedText);
    result.correctedText = normalizeRepeatedSav(result.correctedText);
  }
  result.score = Math.max(0, 100 - penalty);
  result.totalErrors = total;
  if (sourceText && total === 0) {
    result.correctedText = sourceText;
  }
  if (result.score < LOW_SCORE_THRESHOLD) {
    result.correctedText = '';
    result.summary = LOW_SCORE_MSG;
  } else {
    result.summary = buildResultSummary(cats, total);
  }
  return result;
}

module.exports = {
  CAT_WEIGHTS,
  CANONICAL_WORD_STANDARDS,
  candidateTextHashes,
  canonicalText,
  equivalentIssue,
  isProtectedChange,
  LOW_SCORE_MSG,
  LOW_SCORE_THRESHOLD,
  finalizeResult,
  legacyTextHash,
  normalizeText,
  sourceContainsIssue,
  textHash
};
