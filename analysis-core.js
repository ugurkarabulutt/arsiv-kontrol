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
  vucut: 'vücut',
  serr: 'şerr',
  arif: 'arif',
  cahiliye: 'cahiliye',
  ayet: 'âyet',
  daimi: 'daimî',
  teala: 'Tealâ'
});
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
const FORBIDDEN_TRANSFORMS = [
  { from: /\bdin\b/iu, to: /\bdîn\b/iu },
  { from: /(?<![\p{L}\p{N}_])din[\p{L}\p{N}_]*/iu, to: /(?<![\p{L}\p{N}_])dîn[\p{L}\p{N}_]*/iu },
  { from: /\bherşey[\p{L}\p{N}_]*/iu, to: /\bher\s+şey[\p{L}\p{N}_]*/iu },
  { from: /\bvücut[\p{L}\p{N}_]*/iu, to: /\bvüc(?:ud|ûd|ût)[\p{L}\p{N}_]*/iu },
  { from: /\bvücud[\p{L}\p{N}_]*/iu, to: /\bvüc(?:ûd|ût)[\p{L}\p{N}_]*/iu },
  { from: /\bhayy[\p{L}\p{N}_]*/iu, to: /\bhayat[\p{L}\p{N}_]*/iu },
  { from: /\bşerif\b/iu, to: /\bşerîf\b/iu },
  { from: /(?<![\p{L}\p{N}_])şerr(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])şer(?![\p{L}\p{N}_])/iu },
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
  { from: /\bdinlenmeye\b/iu, to: /\bdînlenmeye\b/iu },
  { from: /\bmuhterem\s+efendimiz\b/iu, to: /\befendimiz\s*\(s\.a\.v\)/iu },
  { from: /\ballah(?:'|’)?ın\s+izniyle\.\s+allah\s+razı\s+olsun\.?/iu, to: /\ballah(?:'|’)?ın\s+izniyle,\s+allah\s+razı\s+olsun\.?/iu },
  { from: /\bnefsi\b/iu, to: /\bnefs\b/iu },
  { from: /\bnefsin\b/iu, to: /\bnefisin\b/iu },
  { from: /\btaktirde\b/iu, to: /\b(?:takdirde|taktir\s+de)\b/iu },
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
  if (/^dîn[\p{L}\p{N}_]*$/iu.test(from) && /^din[\p{L}\p{N}_]*$/iu.test(to)) return false;
  if (/^dîn(?:in|i|e|den|de)?$/iu.test(from) && /^din(?:in|i|e|den|de)?$/iu.test(to)) return false;
  return !!from && !!to && from !== to && hasCircumflex(from) && foldText(from) === foldText(to);
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

function isSuspiciousWordExpansion(original, fixed) {
  const from = canonicalText(original);
  const to = canonicalText(fixed);
  if (!from || !to || from.length < 4 || from === to) return false;
  if (isAllowedContentAddition(original, fixed)) return false;
  if (!foldText(to).startsWith(foldText(from))) return false;

  const extra = to.slice(from.length);
  return /^[\p{L}\p{N}_]+$/u.test(extra);
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
  if (foldedFrom.startsWith('allah') && foldedTo.startsWith('allahu teala')) return true;
  if (foldedFrom.startsWith('sergilerse') && foldedTo.startsWith('sergilesin')) return true;
  if (foldedFrom.startsWith('artisi') && foldedTo.startsWith('artisini')) return true;
  if (foldedFrom.startsWith('ahiret') && foldedTo.startsWith('ahiret') && hasCircumflex(fixed)) return true;
  if (foldedFrom.startsWith('tirmizi') && /tirmizi\s*,/iu.test(foldedTo)) return true;
  if (foldedFrom.startsWith('es safi') && /^es-safi/iu.test(foldedTo)) return true;
  if (foldedFrom === 'mumin' && (foldedTo === 'mu min' || /^m[üu]'?min$/iu.test(to))) return true;
  if (/^5\s+dakika\s+10\s+dakikal[ıi]k/iu.test(from) && /^5\s+dakika,\s+10\s+dakikal[ıi]k/iu.test(to)) return true;
  if (/efendimiz\s*\(s\.a\.v\)'dir$/iu.test(from) && /efendimiz\s*\(s\.a\.v\)'dir\.$/iu.test(to)) return true;
  if (/^la$/iu.test(foldedFrom) && foldedTo.includes('olmuyor')) return true;
  if ((foldedFrom.includes('sinifta -biz') || foldedFrom.includes('s\u0131n\u0131fta -biz'))
    && (/[\u2013\u2014]|--/.test(to) || foldedTo.includes('sinifta biz') || foldedTo.includes('s\u0131n\u0131fta biz'))) return true;
  if (foldedFrom === 'nebi' && foldedTo === 'nebi' && canonicalText(original)[0] !== canonicalText(fixed)[0]) return true;
  if (foldedFrom.startsWith('hersey') && foldedTo.startsWith('her sey')) return true;
  if (foldedFrom.startsWith('vucut') && foldedTo.startsWith('vucud')) return true;
  if (foldedFrom.startsWith('vucud') && foldedTo.startsWith('vucut') && foldedFrom !== 'vucud') return true;
  if (foldedFrom === 'vucud' && foldedTo === 'vucut') return false;
  if (foldedFrom.startsWith('kadir') && foldedTo.startsWith('kadir') && hasCircumflex(fixed)) return true;
  if (foldedFrom === 'tabii' && foldedTo === 'tabi') return true;
  if (foldedFrom.startsWith('hayy') && foldedTo.startsWith('hayat')) return true;
  if (foldedFrom === 'hidayet' && foldedTo.startsWith('hidayet') && foldedTo !== 'hidayet') return true;
  if (from.includes('şerif') && to.includes('şerîf')) return true;
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

function sourceIssueOccurrenceCount(sourceText, original) {
  const source = canonicalText(sourceText);
  const needle = canonicalText(original);
  if (!needle) return 0;

  const left = needsWordBoundary(needle[0]) ? '(?<![\\p{L}\\p{N}_])' : '';
  const right = needsWordBoundary(needle[needle.length - 1]) ? '(?![\\p{L}\\p{N}_])' : '';
  const re = new RegExp(`${left}${escapeRegExp(needle)}${right}`, 'giu');
  return [...source.matchAll(re)].length;
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
  if (isCaseOnlyChange(original, fixed)) return true;
  if (isSuraCaseOnlyChange(original, fixed)) return true;
  if (isSourceDiacriticProtected(original, fixed)) return true;
  if (isSuspiciousTruncation(original, fixed)) return true;
  if (isSuspiciousContentAddition(original, fixed)) return true;
  if (isSuspiciousWordExpansion(original, fixed)) return true;
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

function deterministicFixed(original) {
  const text = canonicalText(original);
  if (!text) return '';

  if (/^dîn[\p{L}\p{N}_]*$/iu.test(text)) {
    return caseLike(original, text.replace(/^dîn/iu, 'din'));
  }
  if (/^inşallah$/iu.test(text)) return caseLike(original, 'inşaallah');
  if (/^her\s+şey[\p{L}\p{N}_]*$/iu.test(text)) {
    return caseLike(original, text.replace(/^her\s+şey/iu, 'herşey'));
  }
  if (/^v\u00fcc(?:ud|\u00fbd|\u00fbt)$/iu.test(text)) {
    return caseLike(original, 'v\u00fccut');
  }
  if (/^kadir[\p{L}\p{N}_]*$/iu.test(text)) {
    return caseLike(original, text.replace(/^kadir/iu, 'kaadir'));
  }
  if (/^hadis-i\s+şerif$/iu.test(text)) return caseLike(original, 'Hadîs-i Şerif');
  return '';
}

function addDeterministicIssue(cats, seen, original, fixed, rule) {
  if (!original || !fixed || original === fixed) return;
  if (/^[A-Z]\.[A-Z]$/i.test(String(original)) && /^[A-Z]\.\s+[A-Z]$/i.test(String(fixed))) return;
  const key = `${canonicalText(original)}=>${canonicalText(fixed)}`;
  if (seen.has(key)) return;
  seen.add(key);
  if (!cats.imla) cats.imla = {};
  if (!Array.isArray(cats.imla.issues)) cats.imla.issues = [];
  cats.imla.issues.push({ original, fixed, rule });
}

function applyDeterministicStandards(cats, sourceText) {
  const text = String(sourceText || '');
  if (!text) return cats;

  const seen = new Set();
  Object.values(cats || {}).forEach(category => {
    (category?.issues || []).forEach(issue => {
      seen.add(`${canonicalText(issue.original)}=>${canonicalText(issue.fixed)}`);
    });
  });

  const tokenRe = /(?<![\p{L}\p{N}_])(?:dîn[\p{L}\p{N}_]*|inşallah|her\s+şey[\p{L}\p{N}_]*|vüc(?:ud|ûd|ût)[\p{L}\p{N}_]*|hadis-i\s+şerif)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(tokenRe)) {
    const original = match[0];
    addDeterministicIssue(cats, seen, original, deterministicFixed(original), 'Kesin arşiv standardı');
  }

  const kadirRe = /(?<![\p{L}\p{N}_])kadir[\p{L}\p{N}_]*(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(kadirRe)) {
    const original = match[0];
    addDeterministicIssue(cats, seen, original, deterministicFixed(original), 'Kesin ar\u015fiv standard\u0131');
  }

  const hazretiIsaRe = /(?<![\p{L}\p{N}_])Hazreti\s+İsa(?!\s*\(A\.S\.?\))(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(hazretiIsaRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[0]} (A.S)`, 'Nebî isimleri standardı');
  }

  const referenceRe = /(?<![\p{L}\p{N}_])(\d+)\s+\.\s*([A-ZÇĞİÖŞÜÂÎÛ'’]+)\s*-\s*(\d+)(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(referenceRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[1]}. ${match[2]}-${match[3]}`, 'Sure/âyet referans düzeni');
  }

  const standardLazimRe = /(?<![\p{L}\p{N}_])([\p{L}\p{N}_]+)l\u00e2z\u0131m(?![\p{L}\p{N}_])/giu;
  for (const match of text.matchAll(standardLazimRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[1]} l\u00e2z\u0131m`, 'Biti\u015fik yaz\u0131m d\u00fczeni');
  }

  const standardSentenceSpaceRe = /([\p{L}\p{N}_][\.\?!])([A-Z\u00c7\u011e\u0130\u00d6\u015e\u00dc\u00c2\u00ce\u00db])/gu;
  for (const match of text.matchAll(standardSentenceSpaceRe)) {
    addDeterministicIssue(cats, seen, match[0], `${match[1]} ${match[2]}`, 'C\u00fcmle aras\u0131 bo\u015fluk');
  }

  const fullSentenceSpaceRe = /(?<![\p{L}\p{N}_])([\p{L}\p{N}_]+[\.\?!])([A-Z\u00c7\u011e\u0130\u00d6\u015e\u00dc\u00c2\u00ce\u00db][\p{L}\p{N}_]*)(?![\p{L}\p{N}_])/gu;
  for (const match of text.matchAll(fullSentenceSpaceRe)) {
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
  const pairs = [['"', '"'], ['“', '”'], ['‘', '’']];
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

function applyAcceptedIssues(sourceText, issues) {
  return issues.reduce((text, issue) => {
    const original = String(issue?.original || '');
    const fixed = String(issue?.fixed || '');
    if (!original || !fixed) return text;
    if (text.includes(original)) return text.replace(original, fixed);
    return text.replace(new RegExp(escapeRegExp(original), 'iu'), fixed);
  }, sourceText);
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
    let issues = Array.isArray(category.issues) ? category.issues : [];
    if (sourceText) {
      issues = issues.filter(issue => {
        const originalKey = canonicalText(issue?.original || '');
        const maxOccurrences = sourceIssueOccurrenceCount(sourceText, issue?.original || '');
        const usedOccurrences = acceptedIssueUses.get(originalKey) || 0;
        const keep = issue
          && !equivalentIssue(issue.original, issue.fixed)
          && maxOccurrences > 0
          && usedOccurrences < maxOccurrences
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
