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
const FORBIDDEN_TRANSFORMS = [
  { from: /\bdin\b/iu, to: /\bdîn\b/iu },
  { from: /\bherşey\b/iu, to: /\bher\s+şey\b/iu },
  { from: /(?<![\p{L}\p{N}_])(?:muminun|m[uü]'?m[iİı]n[uû]n)(?![\p{L}\p{N}_])/iu, to: /(?<![\p{L}\p{N}_])m[üu]'?m[iİı]n(?![\p{L}\p{N}_])/iu },
  { from: /\bzumer\b/iu, to: /\bzümer\b/iu },
  { from: /\btabiî\s+ki\b/iu, to: /\btâbî\s+ki\b/iu },
  { from: /\bderecat\b/iu, to: /\bderece\b/iu },
  { from: /\bdinlenmeye\b/iu, to: /\bdînlenmeye\b/iu },
  { from: /\bmuhterem\s+efendimiz\b/iu, to: /\befendimiz\s*\(s\.a\.v\)/iu },
  { from: /\ballah(?:'|’)?ın\s+izniyle\.\s+allah\s+razı\s+olsun\.?/iu, to: /\ballah(?:'|’)?ın\s+izniyle,\s+allah\s+razı\s+olsun\.?/iu }
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
  if (sourceText && result.correctedText && rejectedIssues.length) {
    result.correctedText = rejectedIssues.reduce(restoreRejectedChange, result.correctedText);
  }
  result.score = Math.max(0, 100 - penalty);
  result.totalErrors = total;
  if (result.score < LOW_SCORE_THRESHOLD) {
    result.correctedText = '';
    result.summary = LOW_SCORE_MSG;
  }
  return result;
}

module.exports = {
  CAT_WEIGHTS,
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
