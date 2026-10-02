const assert = require('node:assert/strict');
const test = require('node:test');
const {
  buildPublicQuestionSlugMigrationPlan,
  collectPublicSitemapTaxonomy,
  publicQuestionSlug,
  stripPublicQuestionAddress,
  uniquePublicQuestionSlug
} = require('../public-archive-seo');

test('question URL removes salutation while visible question text can stay unchanged', () => {
  const question = 'Muhterem Hocam, tayy-i mekân ve bast-ı zamanı açıklar mısınız?';
  assert.equal(stripPublicQuestionAddress(question), 'tayy-i mekân ve bast-ı zamanı açıklar mısınız?');
  assert.equal(publicQuestionSlug(question), 'tayy-i-mekan-ve-bast-i-zamani-aciklar-misiniz');
  assert.equal(question, 'Muhterem Hocam, tayy-i mekân ve bast-ı zamanı açıklar mısınız?');
});

test('question URL removes numbered and hyphenated editorial prefixes', () => {
  assert.equal(publicQuestionSlug('Soru 8: Muhterem Hocam, kıyâmet ne zaman kopacaktır?'), 'kiyamet-ne-zaman-kopacaktir');
  assert.equal(publicQuestionSlug('muhterem-hocam-cennete-kimler-girer'), 'cennete-kimler-girer');
  assert.equal(publicQuestionSlug('soru-6-muhterem-hocam-olumden-korkmak-dogal-midir'), 'olumden-korkmak-dogal-midir');
});

test('future question URLs resolve collisions without changing the question', () => {
  const used = new Set(['cennete-kimler-girer']);
  assert.equal(uniquePublicQuestionSlug('Muhterem Hocam, cennete kimler girer?', used), 'cennete-kimler-girer-2');
});

test('migration plan preserves old URLs and creates deterministic clean destinations', () => {
  const plan = buildPublicQuestionSlugMigrationPlan([
    { slug: 'muhterem-hocam-cennete-kimler-girer', source_history_id: 'a' },
    { slug: 'cennete-kimler-girer', source_history_id: 'b' },
    { slug: 'muhterem-hocam-hidayet-nedir', source_history_id: 'c' }
  ]);
  assert.deepEqual(plan, [
    {
      oldSlug: 'muhterem-hocam-cennete-kimler-girer',
      newSlug: 'cennete-kimler-girer-2',
      sourceHistoryId: 'a',
      collisionResolved: true
    },
    {
      oldSlug: 'muhterem-hocam-hidayet-nedir',
      newSlug: 'hidayet-nedir',
      sourceHistoryId: 'c',
      collisionResolved: false
    }
  ]);
});

test('sitemap taxonomy includes main categories and lower topics without double counting', () => {
  const taxonomy = collectPublicSitemapTaxonomy([
    {
      category_slug: 'iman',
      topic_slugs: ['hidayet', 'iman'],
      updated_at: '2026-10-01T00:00:00.000Z'
    },
    {
      category_slug: 'iman',
      topic_slugs: ['hidayet'],
      updated_at: '2026-10-02T00:00:00.000Z'
    }
  ]);
  assert.deepEqual(taxonomy, [
    {
      slug: 'hidayet',
      count: 2,
      lastmod: '2026-10-02T00:00:00.000Z',
      roles: ['topic']
    },
    {
      slug: 'iman',
      count: 2,
      lastmod: '2026-10-02T00:00:00.000Z',
      roles: ['main', 'topic']
    }
  ]);
});
