const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadPublicCategoryUiHelpers() {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const rules = html.match(/const PUBLIC_CATEGORY_RULES=\[[\s\S]*?\];/);
  const start = html.indexOf('function parseHistoryTags');
  const end = html.indexOf('function publicCategorySuggestionsHtml', start);
  assert.ok(rules, 'PUBLIC_CATEGORY_RULES bulunamadi');
  assert.ok(start >= 0 && end > start, 'kategori onerisi helper blogu bulunamadi');
  const context = { correctedText: '', currentOriginalText: '' };
  vm.createContext(context);
  vm.runInContext(`${rules[0]}\n${html.slice(start, end)}\nglobalThis.helpers={suggestPublicCategoriesUi,publicCategoryDefaults};`, context);
  return context.helpers;
}

test('selam ifadesi Sevgi kategorisi onermemeli', () => {
  const { suggestPublicCategoriesUi, publicCategoryDefaults } = loadPublicCategoryUiHelpers();
  const text = 'Sevgili kardeşlerimiz,\n\nBugün bu konuyu açıklayalım.';
  const suggestions = suggestPublicCategoriesUi({ correctedText: text, tags: [] });
  assert.equal(suggestions.some(item => item.category === 'Sevgi'), false);
  assert.notEqual(publicCategoryDefaults({ correctedText: text, tags: [] }).category, 'Sevgi');
});

test('acik Sevgi etiketi yine Sevgi kategorisini onermeli', () => {
  const { suggestPublicCategoriesUi, publicCategoryDefaults } = loadPublicCategoryUiHelpers();
  const suggestions = suggestPublicCategoriesUi({ correctedText: 'Konu metni.', tags: ['Sevgi'] });
  assert.equal(suggestions[0]?.category, 'Sevgi');
  assert.equal(suggestions[0]?.score, 120);
  assert.equal(publicCategoryDefaults({ correctedText: 'Konu metni.', tags: ['Sevgi'] }).category, 'Sevgi');
});

test('cevap metnindeki dusuk guvenli eslesmeler bagli kategoriye dusmemeli', () => {
  const { publicCategoryDefaults } = loadPublicCategoryUiHelpers();
  const defaults = publicCategoryDefaults({
    correctedText: 'Sevgili kardeşlerimiz,\n\nBu cevapta zikir ve dua geçiyor.',
    tags: ['Zikir']
  });
  assert.equal(defaults.category, 'Zikir');
  assert.equal(defaults.related.length, 0);
});
