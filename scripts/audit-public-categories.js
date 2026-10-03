'use strict';

require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');
const {
  PUBLIC_CATEGORY_INDEX_MIN_QUESTIONS,
  PUBLIC_CATEGORY_SEO_SLUGS,
  publicCategorySeoIndexable,
  publicSeoSlug
} = require('../public-archive-seo');

const PAGE_SIZE = 1000;

function requireEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} ortam değişkeni gerekli.`);
  return value;
}

async function fetchAll(buildQuery) {
  const rows = [];
  for (let from = 0; ; from += PAGE_SIZE) {
    const result = await buildQuery().range(from, from + PAGE_SIZE - 1);
    if (result.error) throw new Error(result.error.message);
    rows.push(...(result.data || []));
    if (!result.data || result.data.length < PAGE_SIZE) return rows;
  }
}

function categorySlugs(row = {}) {
  return [...new Set([
    row.category_slug,
    ...(Array.isArray(row.topic_slugs) ? row.topic_slugs : [])
  ].filter(Boolean).map(String))];
}

function countBucket(count) {
  if (count === 0) return '0';
  if (count === 1) return '1';
  if (count <= 4) return '2-4';
  if (count <= 9) return '5-9';
  if (count <= 24) return '10-24';
  return '25+';
}

function summarizeDuplicates(categories, questionSets) {
  const byName = new Map();
  const byQuestions = new Map();
  for (const category of categories) {
    const normalizedName = publicSeoSlug(category.name || category.slug);
    if (!byName.has(normalizedName)) byName.set(normalizedName, []);
    byName.get(normalizedName).push(category.slug);

    const questionKey = [...(questionSets.get(category.slug) || [])].sort().join('|');
    if (!questionKey) continue;
    if (!byQuestions.has(questionKey)) byQuestions.set(questionKey, []);
    byQuestions.get(questionKey).push(category.slug);
  }
  const sameName = [...byName.values()].filter(group => group.length > 1);
  const sameQuestions = [...byQuestions.values()].filter(group => group.length > 1);
  return { sameName, sameQuestions };
}

async function main() {
  const supabase = createClient(requireEnv('SUPABASE_URL'), requireEnv('SUPABASE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const [qaRows, categoryRows] = await Promise.all([
    fetchAll(() => supabase
      .from('public_qa')
      .select('slug,category_slug,topic_slugs,updated_at,published_at')
      .eq('status', 'published')
      .order('slug', { ascending: true })),
    fetchAll(() => supabase
      .from('public_categories')
      .select('slug,name,description,featured,sort_order')
      .order('sort_order', { ascending: true }))
  ]);

  const questionSets = new Map();
  for (const row of qaRows) {
    for (const slug of categorySlugs(row)) {
      if (!questionSets.has(slug)) questionSets.set(slug, new Set());
      questionSets.get(slug).add(row.slug);
    }
  }

  const categoriesBySlug = new Map(categoryRows.map(row => [row.slug, row]));
  for (const slug of questionSets.keys()) {
    if (!categoriesBySlug.has(slug)) categoriesBySlug.set(slug, { slug, name: slug, missing_definition: true });
  }
  const categories = [...categoriesBySlug.values()].map(row => {
    const questionCount = questionSets.get(row.slug)?.size || 0;
    return {
      slug: row.slug,
      name: row.name || row.slug,
      questionCount,
      indexable: publicCategorySeoIndexable(row.slug, questionCount),
      featured: Boolean(row.featured),
      hasDescription: Boolean(String(row.description || '').trim()),
      missingDefinition: Boolean(row.missing_definition)
    };
  });

  const distribution = Object.fromEntries(['0', '1', '2-4', '5-9', '10-24', '25+'].map(key => [key, 0]));
  for (const category of categories) distribution[countBucket(category.questionCount)] += 1;
  const indexable = categories.filter(category => category.indexable);
  const thin = categories.filter(category => category.questionCount > 0 && !category.indexable);
  const orphan = categories.filter(category => category.questionCount === 0);
  const missingDescriptions = indexable.filter(category => !category.hasDescription);
  const duplicates = summarizeDuplicates(categories.filter(category => category.questionCount > 0), questionSets);
  const indexableDuplicates = summarizeDuplicates(indexable, questionSets);

  const report = {
    generatedAt: new Date().toISOString(),
    policy: {
      minimumQuestions: PUBLIC_CATEGORY_INDEX_MIN_QUESTIONS,
      protectedSlugs: [...PUBLIC_CATEGORY_SEO_SLUGS].sort()
    },
    totals: {
      publishedQuestions: qaRows.length,
      definedCategories: categoryRows.length,
      usedCategories: categories.filter(category => category.questionCount > 0).length,
      indexableCategories: indexable.length,
      thinNoindexCategories: thin.length,
      orphanCategories: orphan.length,
      indexableWithoutDescription: missingDescriptions.length,
      missingDefinitions: categories.filter(category => category.missingDefinition).length
    },
    distribution,
    duplicateCandidates: {
      sameNameCount: duplicates.sameName.length,
      sameName: duplicates.sameName.slice(0, 30),
      sameQuestionsCount: duplicates.sameQuestions.length,
      sameQuestions: duplicates.sameQuestions.slice(0, 30),
      indexableSameQuestionsCount: indexableDuplicates.sameQuestions.length,
      indexableSameQuestions: indexableDuplicates.sameQuestions.slice(0, 30)
    },
    samples: {
      thinNoindex: thin.sort((a, b) => b.questionCount - a.questionCount || a.slug.localeCompare(b.slug, 'tr')).slice(0, 30),
      orphan: orphan.slice(0, 30),
      indexableWithoutDescription: missingDescriptions
        .sort((a, b) => b.questionCount - a.questionCount || a.slug.localeCompare(b.slug, 'tr'))
        .slice(0, 30)
    }
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch(error => {
  console.error(error.message || error);
  process.exitCode = 1;
});
