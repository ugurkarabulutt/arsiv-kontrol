'use strict';

require('dotenv').config({ path: process.env.ENV_FILE || '.env' });

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const { buildPublicQuestionSlugMigrationPlan } = require('../public-archive-seo');

const args = new Set(process.argv.slice(2));
const apply = args.has('--apply');
const confirmed = args.has('--confirm=question-url-migration');
const backupFileArg = [...args].find(arg => arg.startsWith('--backup-file='));
const backupFile = backupFileArg ? backupFileArg.slice('--backup-file='.length).trim() : '';

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

async function fetchRowsByValues(buildQuery, values, chunkSize = 120) {
  const rows = [];
  const uniqueValues = [...new Set(values.filter(Boolean))];
  for (let index = 0; index < uniqueValues.length; index += chunkSize) {
    const chunk = uniqueValues.slice(index, index + chunkSize);
    rows.push(...await fetchAllPages(() => buildQuery(chunk)));
  }
  return rows;
}

function writeMigrationBackup(fileName, payload) {
  const destination = path.resolve(process.cwd(), fileName);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const contents = `${JSON.stringify(payload, null, 2)}\n`;
  fs.writeFileSync(destination, contents, { encoding: 'utf8', flag: 'wx' });
  return {
    destination,
    bytes: Buffer.byteLength(contents),
    sha256: crypto.createHash('sha256').update(contents).digest('hex')
  };
}

async function main() {
  if (apply && !confirmed) {
    throw new Error('Uygulama için --apply --confirm=question-url-migration birlikte verilmelidir.');
  }
  if (apply && !backupFile) {
    throw new Error('Uygulama için --backup-file=<dosya> zorunludur.');
  }
  const supabase = createClient(requiredEnv('SUPABASE_URL'), requiredEnv('SUPABASE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const [rows, redirects] = await Promise.all([
    fetchAllPages(() => supabase
      .from('public_qa')
      .select('slug,source_history_id,status,updated_at,related_slugs')
      .order('slug', { ascending: true })),
    fetchAllPages(() => supabase
      .from('public_question_redirects')
      .select('from_slug,to_slug,history_id,redirect_type,created_at')
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

  const oldSlugSet = new Set(plan.map(item => item.oldSlug));
  const involvedSlugs = plan.flatMap(item => [item.oldSlug, item.newSlug]);
  const [questionStats, visitEvents] = await Promise.all([
    fetchRowsByValues(chunk => supabase
      .from('public_question_stats')
      .select('slug,read_count,updated_at')
      .in('slug', chunk)
      .order('slug', { ascending: true }), involvedSlugs),
    fetchRowsByValues(chunk => supabase
      .from('public_visit_events')
      .select('id,question_slug')
      .in('question_slug', chunk)
      .order('id', { ascending: true }), involvedSlugs)
  ]);
  const relatedRows = rows
    .filter(row => Array.isArray(row.related_slugs) && row.related_slugs.some(slug => oldSlugSet.has(slug)))
    .map(row => ({ slug: row.slug, relatedSlugs: row.related_slugs }));
  const backup = writeMigrationBackup(backupFile, {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    projectUrl: requiredEnv('SUPABASE_URL'),
    plan,
    sourceQuestions: rows.filter(row => oldSlugSet.has(row.slug)),
    relatedRows,
    redirects,
    questionStats,
    visitEvents
  });
  console.log(JSON.stringify({ backup }, null, 2));

  const { data, error } = await supabase.rpc('apply_public_question_slug_migration', {
    p_pairs: plan.map(({ oldSlug, newSlug }) => ({ oldSlug, newSlug }))
  });
  if (error) throw new Error(error.message);

  const [remainingRows, redirectsAfter] = await Promise.all([
    fetchAllPages(() => supabase
    .from('public_qa')
    .select('slug,source_history_id,status,updated_at,related_slugs')
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
