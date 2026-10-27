'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { restoreReportedChange } = require('../scripts/resolve-open-feedback-20261027');

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
