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
  vucud: 'vücud',
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
  { from: /\bdin(?:de|den|e|i|in)?\b/iu, to: /\bdîn(?:de|den|e|i|in)?\b/iu },
  { from: /\bherşey\b/iu, to: /\bher\s+şey\b/iu },
  { from: /\bvücud\b/iu, to: /\bvüc[ûu]t\b/iu },
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
  const cats = result.categories || {};
  let penalty = 0;
  let total = 0;
  const rejectedIssues = [];
  const acceptedIssues = [];

  for (const [key, weight] of Object.entries(CAT_WEIGHTS)) {
    const category = cats[key] || {};
    let issues = Array.isArray(category.issues) ? category.issues : [];
    if (sourceText) {
      issues = issues.filter(issue => {
        const keep = issue
          && !equivalentIssue(issue.original, issue.fixed)
          && sourceContainsIssue(sourceText, issue.original)
          && !isProtectedChange(issue.original, issue.fixed);
        if (!keep && issue) rejectedIssues.push(issue);
        if (keep) acceptedIssues.push(issue);
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
