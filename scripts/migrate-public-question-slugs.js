'use strict';

require('dotenv').config({ path: process.env.ENV_FILE || '.env' });

const { createClient } = require('@supabase/supabase-js');
const { buildPublicQuestionSlugMigrationPlan } = require('../public-archive-seo');

const args = new Set(process.argv.slice(2));
const apply = args.has('--apply');
const confirmed = args.has('--confirm=question-url-migration');

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} tanımlı değil.`);
  return value;
}

async function fetchAllPages(buildQuery, pageSize = 1000) {
  const rows = [];
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await buildQuery().range(from, from + pageSize - 1);
    if (error) throw new Error(error.message);
    rows.push(...(data || []));
    if (!data || data.length < pageSize) return rows;
  }
}

async function main() {
  if (apply && !confirmed) {
    throw new Error('Uygulama için --apply --confirm=question-url-migration birlikte verilmelidir.');
  }
  const supabase = createClient(requiredEnv('SUPABASE_URL'), requiredEnv('SUPABASE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const [rows, redirects] = await Promise.all([
    fetchAllPages(() => supabase
      .from('public_qa')
      .select('slug,source_history_id,status,updated_at')
      .order('slug', { ascending: true })),
    fetchAllPages(() => supabase
      .from('public_question_redirects')
      .select('from_slug,to_slug')
      .order('from_slug', { ascending: true }))
  ]);
  const plan = buildPublicQuestionSlugMigrationPlan(rows, {
    reservedSlugs: redirects.map(row => row.from_slug).filter(Boolean)
  });
  const report = {
    mode: apply ? 'apply' : 'dry-run',
    totalQuestions: rows.length,
    redirectsBefore: redirects.length,
    migrationCount: plan.length,
    publishedMigrationCount: plan.filter(item => rows.find(row => row.slug === item.oldSlug)?.status === 'published').length,
    collisionCount: plan.filter(item => item.collisionResolved).length,
    samples: plan.slice(0, 20)
  };
  console.log(JSON.stringify(report, null, 2));
  if (!apply || !plan.length) return;

  const { data, error } = await supabase.rpc('apply_public_question_slug_migration', {
    p_pairs: plan.map(({ oldSlug, newSlug }) => ({ oldSlug, newSlug }))
  });
  if (error) throw new Error(error.message);

  const [remainingRows, redirectsAfter] = await Promise.all([
    fetchAllPages(() => supabase
    .from('public_qa')
    .select('slug,source_history_id,status,updated_at')
    .order('slug', { ascending: true })),
    fetchAllPages(() => supabase
      .from('public_question_redirects')
      .select('from_slug,to_slug')
      .order('from_slug', { ascending: true }))
  ]);
  const remainingPlan = buildPublicQuestionSlugMigrationPlan(remainingRows, {
    reservedSlugs: redirectsAfter.map(row => row.from_slug).filter(Boolean)
  });
  const sampleOldSlugs = plan.slice(0, 20).map(item => item.oldSlug);
  const { data: verifiedRedirects, error: redirectError } = await supabase
    .from('public_question_redirects')
    .select('from_slug,to_slug,redirect_type')
    .in('from_slug', sampleOldSlugs);
  if (redirectError) throw new Error(redirectError.message);
  const complete = remainingPlan.length === 0 && (verifiedRedirects || []).length === sampleOldSlugs.length;
  console.log(JSON.stringify({ complete, result: data, remainingOldSlugs: remainingPlan.length, verifiedRedirects: (verifiedRedirects || []).length }, null, 2));
  if (!complete) process.exitCode = 2;
}

main().catch(error => {
  console.error(`Soru URL migrasyonu hazırlanamadı: ${error.message}`);
  process.exitCode = 1;
});
