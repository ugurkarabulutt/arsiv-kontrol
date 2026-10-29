'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { restoreReportedChange } = require('../scripts/resolve-open-feedback-20261027');
const {
  SOURCE_FORM: TEZEKKUR_SOURCE_FORM,
  WRONG_FORM: TEZEKKUR_WRONG_FORM,
  buildPlan: buildTezekkurPlan
} = require('../scripts/resolve-tezekkur-tefekkur-20261029');
const { buildPlan: buildVirdPlan } = require('../scripts/resolve-vird-context-20261029');

test('feedback uzlastirmasi ayni kelimenin dogru kullanimlarina dokunmaz', () => {
  const original = 'Âyet içinde hudâ geçer. Açıklamada hidayet yolu ve hidayet kavramı anlatılır.';
  const current = 'Âyet içinde hidayet geçer. Açıklamada hidayet yolu ve hidayet kavramı anlatılır.';
  const result = restoreReportedChange(original, current, 'hudâ', ['hidayet']);

  assert.equal(result.replacements.length, 1);
  assert.equal(result.text, original);
});

test('feedback uzlastirmasi kaynak adedi kadar en yakin yanlis gecisi geri alir', () => {
  const original = 'abdlık birinci kavramdır. abd olmak açıklanır. Sonra abdlık tekrar edilir.';
  const current = 'abd olmak birinci kavramdır. abd olmak açıklanır. Sonra abd olmak tekrar edilir.';
  const result = restoreReportedChange(original, current, 'abdlık', ['abd olmak']);

  assert.equal(result.replacements.length, 2);
  assert.equal(result.text, original);
});

test('feedback uzlastirmasi dogru kaydi idempotent birakir', () => {
  const original = 'Yolun tayin edilmesi açıklanır.';
  const result = restoreReportedChange(original, original, 'tayin', ['tâyin']);

  assert.equal(result.replacements.length, 0);
  assert.equal(result.text, original);
});

test('tezekkur paketi yalniz kesin yanlis cümleyi geri alir', () => {
  const history = {
    id: 'history-1',
    original_text: `${TEZEKKUR_SOURCE_FORM}, vasiyet etti. İnsan ayrıca tefekkür eder.`,
    corrected_text: `${TEZEKKUR_WRONG_FORM}, vasiyet etti. İnsan ayrıca tefekkür eder.`
  };
  const plan = buildTezekkurPlan(history);

  assert.equal(plan.replacements, 1);
  assert.equal(plan.newText, `${TEZEKKUR_SOURCE_FORM}, vasiyet etti. İnsan ayrıca tefekkür eder.`);
});

test('vird paketi yalniz fizik beden teslimi baglamini duzeltir', () => {
  const history = {
    id: 'history-2',
    corrected_text: 'Fizik beden tesliminde verdiğimizi artırmalıyız. Söz verdiğimizi unutmamalıyız.'
  };
  const plan = buildVirdPlan(history);

  assert.equal(plan.replacements, 1);
  assert.equal(plan.newText, 'Fizik beden tesliminde virdimizi artırmalıyız. Söz verdiğimizi unutmamalıyız.');
});
