const { createHash } = require('node:crypto');
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

module.exports = { analysisText, analysisHash, analysisState, analyzeReviewPair };
