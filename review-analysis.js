const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const { LOW_SCORE_THRESHOLD } = require('./analysis-core');
const analysisText = value => String(value ?? '').replace(/\r\n?/g, '\n');
const analysisHash = value => createHash('md5').update(analysisText(value), 'utf8').digest('hex');

function analysisState(row) {
  const receipt = row.workflow_meta?.analysisReceipt;
  if (!receipt || receipt.version !== 1 || receipt.scope !== 'question_and_answer') {
    return { state: 'required', label: 'Soru ve cevap birlikte denetlenmeli' };
  }
  if (receipt.questionHash !== analysisHash(row.question_text) || receipt.answerHash !== analysisHash(row.corrected_text)) {
    return { state: 'stale', label: 'Metin değişti; yeniden denetim gerekli' };
  }
  if (receipt.state !== 'ready' || ![receipt.question?.score,receipt.answer?.score].every(score => Number.isInteger(score) && score >= LOW_SCORE_THRESHOLD && score <= 100)) {
    return { state: 'low_score', label: 'Düzeltme taslağı hazır; yeniden denetim gerekli' };
  }
  return { state: 'ready', label: 'Soru ve cevabın son hâli denetlendi' };
}

async function analyzeReviewPair(analyze, question, answer) {
  const input = { question: analysisText(question), answer: analysisText(answer) };
  if (!input.question.trim() || !input.answer.trim()) throw new Error('REQUIRED_FIELDS');
  if (input.question.length > 20000 || input.answer.length > 200000) throw new Error('CONTENT_TOO_LONG');
  const [q, a] = await Promise.all([analyze(input.question), analyze(input.answer)]);
  return reviewPairResult(input, q, a);
}

function reviewPairResult(input, q, a) {
  if (!q.correctedText?.trim() || !a.correctedText?.trim()) throw new Error('ANALYSIS_OUTPUT_EMPTY');
  if (![q.score,a.score].every(score => Number.isInteger(score) && score >= 0 && score <= 100)) throw new Error('ANALYSIS_OUTPUT_EMPTY');
  const questionText = analysisText(q.correctedText), correctedText = analysisText(a.correctedText);
  const score = Math.min(q.score, a.score);
  const catCounts = Object.fromEntries([...new Set([...Object.keys(q.categories || {}), ...Object.keys(a.categories || {})])]
    .map(key => [key, (q.categories?.[key]?.count || 0) + (a.categories?.[key]?.count || 0)]));
  return {
    questionText, correctedText, score, totalErrors: (q.totalErrors || 0) + (a.totalErrors || 0), catCounts,
    analysisInput: input,
    summary: score < LOW_SCORE_THRESHOLD ? 'Düzeltmeler taslak olarak kaydedildi. Soru ve cevabı yeniden denetleyin.' : 'Soru ve cevap birlikte denetlendi.',
    analysisReceipt: {
      version: 1, scope: 'question_and_answer', state: score < LOW_SCORE_THRESHOLD ? 'low_score' : 'ready',
      questionHash: analysisHash(questionText), answerHash: analysisHash(correctedText), checkedAt: new Date().toISOString(),
      inputQuestionHash: analysisHash(input.question), inputAnswerHash: analysisHash(input.answer),
      question: { score: q.score, totalErrors: q.totalErrors || 0, categories: q.categories || {}, meta: q.analysisMeta || {} },
      answer: { score: a.score, totalErrors: a.totalErrors || 0, categories: a.categories || {}, meta: a.analysisMeta || {} }
    }
  };
}

const REVIEW_PART_SIZE = 4000;
function reviewAnalysisParts(question, answer) {
  const input = { question: analysisText(question), answer: analysisText(answer) };
  if (!input.question.trim() || !input.answer.trim()) throw new Error('REQUIRED_FIELDS');
  if (input.question.length > 20000 || input.answer.length > 200000) throw new Error('CONTENT_TOO_LONG');
  const parts = [];
  for (const field of ['question', 'answer']) {
    let rest = input[field];
    let leading = '';
    while (rest.length) {
      let end = Math.min(rest.length, REVIEW_PART_SIZE);
      if (end < rest.length) {
        const window = rest.slice(0, end);
        const boundary = Math.max(window.lastIndexOf('\n\n'), window.lastIndexOf('\n'), window.lastIndexOf(' '));
        if (boundary > REVIEW_PART_SIZE / 2) end = boundary + 1;
        if (/[\uD800-\uDBFF]/.test(rest[end - 1])) end--;
      }
      const text = rest.slice(0, end);
      rest = rest.slice(end);
      if (!text.trim()) {
        const previous = parts.at(-1);
        if (previous?.field === field) previous.suffix += text;
        else leading += text;
        continue;
      }
      parts.push({ field, text: text.trim(), prefix: leading + text.match(/^\s*/)[0], suffix: text.match(/\s*$/)[0] });
      leading = '';
    }
  }
  return { input, parts };
}

// Signed results survive serverless instance changes without trusting client scores or text.
function analysisPartToken(secret, binding, index, result, now = Date.now()) {
  if (!result.correctedText?.trim() || !Number.isInteger(result.score) || result.score < 0 || result.score > 100) throw new Error('ANALYSIS_OUTPUT_EMPTY');
  const body = Buffer.from(JSON.stringify({ binding, index, result, expires: now + 3600000 })).toString('base64url');
  const signature = createHmac('sha256', secret).update('review-part-v1:' + body).digest('base64url');
  return body + '.' + signature;
}

function readAnalysisPartToken(secret, binding, token, now = Date.now()) {
  try {
    if (typeof token !== 'string' || token.length > 700000) throw new Error();
    const [body, signature, extra] = token.split('.');
    const expected = createHmac('sha256', secret).update('review-part-v1:' + body).digest();
    const actual = Buffer.from(signature || '', 'base64url');
    if (extra || actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error();
    const value = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (value.binding !== binding || value.expires < now) throw new Error();
    return value;
  } catch { throw new Error('ANALYSIS_PARTS_INVALID'); }
}

function completedAnalysisParts(secret, binding, plan, tokens) {
  if (!Array.isArray(tokens) || tokens.length !== plan.parts.length) throw new Error('ANALYSIS_PARTS_INVALID');
  const results = tokens.map(token => readAnalysisPartToken(secret, binding, token));
  if (results.some((part, index) => part.index !== index)) throw new Error('ANALYSIS_PARTS_INVALID');
  function combine(field) {
    const selected = plan.parts.map((part, i) => ({ ...part, result: results[i].result })).filter(part => part.field === field);
    const categories = {};
    for (const { result } of selected) for (const [key, category] of Object.entries(result.categories || {})) {
      const target = categories[key] ||= { count: 0, issues: [] };
      target.count += category.count || 0;
      target.issues.push(...(category.issues || []));
    }
    return {
      correctedText: selected.map(part => part.prefix + analysisText(part.result.correctedText).trim() + part.suffix).join(''),
      score: Math.min(...selected.map(part => part.result.score)),
      totalErrors: selected.reduce((sum, part) => sum + (part.result.totalErrors || 0), 0), categories,
      analysisMeta: { partCount: selected.length, parts: selected.map(part => part.result.analysisMeta || {}) }
    };
  }
  return reviewPairResult(plan.input, combine('question'), combine('answer'));
}

module.exports = { analysisText, analysisHash, analysisState, analyzeReviewPair, REVIEW_PART_SIZE,
  reviewAnalysisParts, analysisPartToken, completedAnalysisParts };
