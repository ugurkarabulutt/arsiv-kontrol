const crypto = require('crypto');

const LOW_SCORE_THRESHOLD = 60;
const CAT_WEIGHTS = { sozluk: 5, imla: 4, noktalama: 3, etiket: 2, yapi: 4 };
const LOW_SCORE_MSG = 'Bu metin arşiv standartlarının altında kalmaktadır. Lütfen metni gözden geçirip tekrar gönderin.';

function normalizeText(text) {
  return String(text || '').normalize('NFC').replace(/\r\n?/g, '\n').trim();
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

function finalizeResult(result = {}) {
  const cats = result.categories || {};
  let penalty = 0;
  let total = 0;

  for (const [key, weight] of Object.entries(CAT_WEIGHTS)) {
    const category = cats[key] || {};
    const issues = Array.isArray(category.issues) ? category.issues : [];
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
  LOW_SCORE_MSG,
  LOW_SCORE_THRESHOLD,
  finalizeResult,
  legacyTextHash,
  normalizeText,
  textHash
};
