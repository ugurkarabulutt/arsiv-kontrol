const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { finalizeResult } = require('../analysis-core');

const casesPath = path.join(__dirname, 'fixtures', 'quality-regression-cases.json');
const cases = JSON.parse(fs.readFileSync(casesPath, 'utf8'));

for (const item of cases) {
  test(`kalite regresyonu: ${item.name}`, () => {
    const result = finalizeResult(structuredClone(item.modelResult), item.sourceText);

    assert.equal(result.score, item.expected.score);
    assert.equal(result.totalErrors, item.expected.totalErrors);
    if (Object.hasOwn(item.expected, 'correctedText')) {
      assert.equal(result.correctedText, item.expected.correctedText);
    }
  });
}
