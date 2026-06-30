const crypto = require('crypto');

const LOW_SCORE_THRESHOLD = 60;
const CAT_WEIGHTS = { sozluk: 5, imla: 4, noktalama: 3, etiket: 2, yapi: 4 };
const LOW_SCORE_MSG = 'Bu metin arşiv standartlarının altında kalmaktadır. Lütfen metni gözden geçirip tekrar gönderin.';
const WORD_EDGE = /[\p{L}\p{N}_]/u;

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

  for (const [key, weight] of Object.entries(CAT_WEIGHTS)) {
    const category = cats[key] || {};
    let issues = Array.isArray(category.issues) ? category.issues : [];
    if (sourceText) {
      issues = issues.filter(issue => {
        if (!issue || equivalentIssue(issue.original, issue.fixed)) return false;
        return sourceContainsIssue(sourceText, issue.original);
      });
    }
    category.count = issues.length;
    category.issues = issues;
    cats[key] = category;
    penalty += issues.length * weight;
    total += issues.length;
  }

  result.categories = cats;
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
  LOW_SCORE_MSG,
  LOW_SCORE_THRESHOLD,
  finalizeResult,
  legacyTextHash,
  normalizeText,
  sourceContainsIssue,
  textHash
};
