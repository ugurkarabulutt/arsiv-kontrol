const { test } = require('node:test');
const assert = require('node:assert/strict');
const { reviewAnalysisParts, analysisPartToken, completedAnalysisParts, analysisState } = require('../review-analysis');
const secret = 'unit-test-only-key';
const binding = 'record-version-actor-content';
const result = text => ({ correctedText: text, score: 100, totalErrors: 0, categories: {} });
const signed = plan => plan.parts.map((part, index) => analysisPartToken(secret, binding, index, result(part.text)));

test('long answers preserve every paragraph, separator and Unicode character', () => {
  for (const answer of ['Paragraf bir.\n\nParagraf iki.\n'.repeat(1700), ' '.repeat(9000)+'Uzun kaynak. '+ 'İ'.repeat(19000), 'a'.repeat(7999)+'😀'+'b'.repeat(9000)]) {
    const plan = reviewAnalysisParts('Muhterem Hocam, soru nedir?', answer);
    assert.ok(plan.parts.every(part => part.text.length <= 8000));
    const merged = completedAnalysisParts(secret, binding, plan, signed(plan));
    assert.equal(merged.correctedText, answer);
    assert.equal(merged.questionText, plan.input.question);
    assert.equal(analysisState({question_text:merged.questionText,corrected_text:merged.correctedText,workflow_meta:{analysisReceipt:merged.analysisReceipt}}).state, 'ready');
  }
});

test('parts cannot be forged, replayed across content or mixed, omitted or reordered', () => {
  const plan = reviewAnalysisParts('Soru?', 'Cevap. '.repeat(3000));
  const tokens = signed(plan);
  for (const invalid of [tokens.slice(1), [...tokens, tokens[0]], [...tokens].reverse(), tokens.map((token,index)=>index?token:token.slice(0,-10)+'fake')]) {
    assert.throws(()=>completedAnalysisParts(secret,binding,plan,invalid), /ANALYSIS_PARTS_INVALID/);
  }
  assert.throws(()=>completedAnalysisParts(secret,'changed-actor-version',plan,tokens), /ANALYSIS_PARTS_INVALID/);
  assert.throws(()=>completedAnalysisParts('wrong-key',binding,plan,tokens), /ANALYSIS_PARTS_INVALID/);
  const expired = plan.parts.map((part,index)=>analysisPartToken(secret,binding,index,result(part.text),Date.now()-3600001));
  assert.throws(()=>completedAnalysisParts(secret,binding,plan,expired), /ANALYSIS_PARTS_INVALID/);
});

test('low score in any part remains a blocking quality receipt', () => {
  const plan=reviewAnalysisParts('Soru?', 'Cevap. '.repeat(3000));
  const tokens=plan.parts.map((part,index)=>analysisPartToken(secret,binding,index,{...result(part.text),score:index===1?49:100}));
  assert.equal(completedAnalysisParts(secret,binding,plan,tokens).analysisReceipt.state,'low_score');
});
