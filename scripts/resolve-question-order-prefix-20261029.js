'use strict';

const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const { stripQuestionOrderLead, textHash } = require('../analysis-core');
const { buildPublicQuestionSlugMigrationPlan } = require('../public-archive-seo');

const envFile = [
  process.env.ENV_FILE,
  path.resolve(__dirname, '..', '..', '.env'),
  path.resolve(__dirname, '..', '.env')
].filter(Boolean).find(file => fs.existsSync(file));
if (envFile) dotenv.config({ path: envFile });

const PACKAGE_ID = 'question-order-prefix-source-integrity-20261029';
const ACTOR = 'Sistem Bakımı';
const REPORTED_HISTORY_ID = '99e506ea-7c48-40b7-aae0-886a2e4ef947';

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} tanımlı değil.`);
  return value;
}

function applySnapshotGuard(query, row) {
  let guarded = query.eq('id', row.id);
  guarded = row.version == null ? guarded.is('version', null) : guarded.eq('version', row.version);
  return row.updated_at == null ? guarded.is('updated_at', null) : guarded.eq('updated_at', row.updated_at);
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

async function fetchImpactedHistories(supabase) {
  const rows = await fetchAllPages(() => supabase.from('history')
    .select('id,user_id,name,username,status,version,updated_at,question_text,created_at')
    .or('question_text.ilike.%sualim%,question_text.ilike.%sorum%')
    .order('created_at', { ascending: true }));
  return rows.filter(row => stripQuestionOrderLead(row.question_text || '') !== String(row.question_text || ''));
}

function buildPlan(history) {
  const oldText = String(history.question_text || '');
  const newText = stripQuestionOrderLead(oldText);
  if (!newText || newText === oldText) throw new Error(`Kesin soru sıra etiketi bulunamadı: ${history.id}`);
  return { history, oldText, newText };
}

async function loadPublicRows(supabase, historyIds) {
  if (!historyIds.length) return [];
  const { data, error } = await supabase.from('public_qa')
    .select('slug,status,source_history_id,title,question,updated_at')
    .in('source_history_id', historyIds)
    .order('slug', { ascending: true });
  if (error) throw new Error(error.message);
  return data || [];
}

async function applyHistoryCorrection(supabase, plan) {
  const updateQuery = supabase.from('history').update({ question_text: plan.newText });
  const { data, error } = await applySnapshotGuard(updateQuery, plan.history)
    .select('id,version,updated_at')
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!data) throw new Error(`Kayıt işlem sırasında değişti: ${plan.history.id}`);

  const { error: logError } = await supabase.from('content_correction_log').insert({
    package_id: PACKAGE_ID,
    history_id: plan.history.id,
    field_name: 'question_text',
    old_value: plan.oldText,
    new_value: plan.newText,
    old_hash: textHash(plan.oldText),
    new_hash: textHash(plan.newText),
    status: 'applied',
    created_by: ACTOR
  });
  if (!logError) return;

  const rollbackQuery = supabase.from('history').update({ question_text: plan.oldText });
  const { data: rollback, error: rollbackError } = await applySnapshotGuard(rollbackQuery, data)
    .select('id')
    .maybeSingle();
  if (rollbackError || !rollback) throw new Error(`Düzeltme loglanamadı ve kayıt geri alınamadı: ${plan.history.id}`);
  throw new Error(`Düzeltme loglanamadı; kayıt geri alındı: ${logError.message}`);
}

async function refreshPublicRows(supabase, plans, publicBefore) {
  const app = require('../server');
  await app.maintenance.ready();
  const publicHistoryIds = new Set(publicBefore.map(row => row.source_history_id));
  for (const plan of plans.filter(item => item.history.status === 'onaylandi' && publicHistoryIds.has(item.history.id))) {
    await app.maintenance.publishApprovedHistoryRecord(plan.history.id);
  }

  const planByHistoryId = new Map(plans.map(plan => [plan.history.id, plan]));
  for (const row of publicBefore.filter(item => planByHistoryId.get(item.source_history_id)?.history.status !== 'onaylandi')) {
    const plan = planByHistoryId.get(row.source_history_id);
    const { data, error } = await supabase.from('public_qa')
      .update({ question: plan.newText, title: plan.newText.slice(0, 180), updated_at: new Date().toISOString() })
      .eq('slug', row.slug)
      .eq('source_history_id', row.source_history_id)
      .eq('status', row.status)
      .select('slug')
      .maybeSingle();
    if (error) throw new Error(error.message);
    if (!data) throw new Error(`Public kayıt işlem sırasında değişti: ${row.slug}`);
  }
}

async function buildSlugPlan(supabase, impactedHistoryIds) {
  const [rows, redirects] = await Promise.all([
    fetchAllPages(() => supabase.from('public_qa')
      .select('slug,source_history_id,status,updated_at,related_slugs')
      .order('slug', { ascending: true })),
    fetchAllPages(() => supabase.from('public_question_redirects')
      .select('from_slug,to_slug,history_id,redirect_type,created_at')
      .order('from_slug', { ascending: true }))
  ]);
  const impacted = new Set(impactedHistoryIds);
  const migration = buildPublicQuestionSlugMigrationPlan(rows, {
    reservedSlugs: redirects.map(row => row.from_slug).filter(Boolean)
  }).filter(item => impacted.has(item.sourceHistoryId));
  return { rows, redirects, migration };
}

function writeBackup(plans, publicBefore, slugSnapshot) {
  const directory = path.resolve(__dirname, '..', '.tmp-question-order-prefix-20261029');
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, `before-${Date.now()}.json`);
  fs.writeFileSync(file, `${JSON.stringify({
    packageId: PACKAGE_ID,
    createdAt: new Date().toISOString(),
    histories: plans.map(plan => plan.history),
    publicRows: publicBefore,
    migration: slugSnapshot.migration,
    redirects: slugSnapshot.redirects.filter(row => slugSnapshot.migration.some(item => item.oldSlug === row.from_slug))
  }, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  return file;
}

async function notifyEda(supabase, summary) {
  const { data: users, error } = await supabase.from('users')
    .select('id,name,username')
    .or('name.ilike.%Eda Şahinhan%,username.ilike.%Eda Şahinhan%')
    .eq('active', true)
    .limit(2);
  if (error) throw new Error(error.message);
  if ((users || []).length !== 1) return { recipientCount: 0, matchCount: (users || []).length };
  const user = users[0];
  const { data: existing, error: existingError } = await supabase.from('alerts')
    .select('id')
    .eq('type', 'feedback_resolution')
    .eq('resolution_group', PACKAGE_ID)
    .eq('user_id', user.id)
    .limit(1)
    .maybeSingle();
  if (existingError) throw new Error(existingError.message);
  if (!existing) {
    const { error: insertError } = await supabase.from('alerts').insert({
      type: 'feedback_resolution',
      message: 'Bildirdiğiniz soru başındaki “birinci sualim” sıra ifadesi kaldırıldı. Aynı türdeki geçmiş ve canlı başlıklar kontrol edilerek düzeltildi; eski bağlantılar yeni adreslere yönlendirildi.',
      user_id: user.id,
      history_id: REPORTED_HISTORY_ID,
      read: false,
      feedback_status: 'notice',
      resolution_group: PACKAGE_ID,
      resolution_note: summary
    });
    if (insertError) throw new Error(insertError.message);
  }
  return { recipientCount: 1, matchCount: 1 };
}

async function recordResolution(supabase, plans, publicBefore, migration) {
  const publishedCount = publicBefore.filter(row => row.status === 'published').length;
  const hiddenCount = publicBefore.length - publishedCount;
  const summary = `${plans.length} geçmiş soruda baştaki sıra etiketi temizlendi; ${publishedCount} yayımdaki ve ${hiddenCount} gizli public kayıt güncellendi, ${migration.length} eski URL yönlendirmeyle korundu.`;
  const notification = await notifyEda(supabase, summary);

  const { error: resolutionError } = await supabase.from('issue_resolution_log').upsert({
    resolution_group: PACKAGE_ID,
    title: 'Soru başındaki sıra etiketi temizliği',
    summary,
    status: 'applied',
    feedback_count: 1,
    user_count: notification.recipientCount,
    created_by: ACTOR
  }, { onConflict: 'resolution_group' });
  if (resolutionError) throw new Error(resolutionError.message);

  const { data: existing, error: existingError } = await supabase.from('admin_action_log')
    .select('id')
    .eq('action', 'content.question_order_prefix_repaired')
    .eq('target_id', PACKAGE_ID)
    .limit(1)
    .maybeSingle();
  if (existingError) throw new Error(existingError.message);
  if (!existing) {
    const { error: insertError } = await supabase.from('admin_action_log').insert({
      actor_username: 'system-maintenance',
      actor_name: ACTOR,
      actor_role: 'super_admin',
      action: 'content.question_order_prefix_repaired',
      action_label: 'Soru başındaki sıra etiketlerini temizledi',
      target_type: 'history_batch',
      target_id: PACKAGE_ID,
      target_label: 'Soru sıra etiketi kaynak bütünlüğü',
      target_status_before: 'editorial_prefix_visible',
      target_status_after: 'repaired',
      summary,
      metadata: {
        historyIds: plans.map(plan => plan.history.id),
        oldSlugs: migration.map(item => item.oldSlug),
        newSlugs: migration.map(item => item.newSlug),
        reportedHistoryId: REPORTED_HISTORY_ID
      }
    });
    if (insertError) throw new Error(insertError.message);
  }
  return { summary, notification };
}

async function verifyAppliedState(supabase, plans, publicBefore, migration) {
  const historyIds = plans.map(plan => plan.history.id);
  const currentHistories = await fetchImpactedHistories(supabase);
  const remaining = currentHistories.filter(row => historyIds.includes(row.id));
  if (remaining.length) throw new Error(`History doğrulamasında ${remaining.length} sıra etiketi kaldı.`);

  const currentPublic = await loadPublicRows(supabase, historyIds);
  const planByHistoryId = new Map(plans.map(plan => [plan.history.id, plan]));
  for (const row of currentPublic) {
    const plan = planByHistoryId.get(row.source_history_id);
    if (!plan || row.question !== plan.newText || row.title !== plan.newText.slice(0, 180)) {
      throw new Error(`Public başlık doğrulaması başarısız: ${row.slug}`);
    }
    const before = publicBefore.find(item => item.source_history_id === row.source_history_id);
    if (before?.status !== row.status) throw new Error(`Public görünürlük değişti: ${row.slug}`);
  }

  if (migration.length) {
    const { data: redirects, error } = await supabase.from('public_question_redirects')
      .select('from_slug,to_slug')
      .in('from_slug', migration.map(item => item.oldSlug));
    if (error) throw new Error(error.message);
    for (const item of migration) {
      const redirect = (redirects || []).find(row => row.from_slug === item.oldSlug && row.to_slug === item.newSlug);
      if (!redirect) throw new Error(`URL yönlendirmesi doğrulanamadı: ${item.oldSlug}`);
    }
  }
}

async function main() {
  const apply = process.argv.includes('--apply');
  const supabase = createClient(requiredEnv('SUPABASE_URL'), requiredEnv('SUPABASE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const impacted = await fetchImpactedHistories(supabase);
  if (!impacted.length) {
    const { data, error } = await supabase.from('content_correction_log')
      .select('history_id')
      .eq('package_id', PACKAGE_ID);
    if (error) throw new Error(error.message);
    console.log(JSON.stringify({ mode: apply ? 'apply' : 'dry-run', alreadyApplied: Boolean(data?.length), impacted: 0 }));
    return;
  }

  const plans = impacted.map(buildPlan);
  const historyIds = plans.map(plan => plan.history.id);
  const publicBefore = await loadPublicRows(supabase, historyIds);
  const slugSnapshot = await buildSlugPlan(supabase, historyIds);
  console.log(JSON.stringify({
    mode: apply ? 'apply' : 'dry-run',
    impacted: plans.length,
    statuses: plans.reduce((result, plan) => ({ ...result, [plan.history.status]: (result[plan.history.status] || 0) + 1 }), {}),
    publicStatuses: publicBefore.reduce((result, row) => ({ ...result, [row.status]: (result[row.status] || 0) + 1 }), {}),
    slugMigrations: slugSnapshot.migration.length,
    reportedQuestion: plans.find(plan => plan.history.id === REPORTED_HISTORY_ID)?.newText || null,
    samples: plans.slice(0, 5).map(plan => ({ id: plan.history.id, from: plan.oldText, to: plan.newText })),
    urls: slugSnapshot.migration
  }, null, 2));
  if (!apply) return;

  const backupFile = writeBackup(plans, publicBefore, slugSnapshot);
  for (const plan of plans) await applyHistoryCorrection(supabase, plan);
  await refreshPublicRows(supabase, plans, publicBefore);
  if (slugSnapshot.migration.length) {
    const { error } = await supabase.rpc('apply_public_question_slug_migration', {
      p_pairs: slugSnapshot.migration.map(({ oldSlug, newSlug }) => ({ oldSlug, newSlug }))
    });
    if (error) throw new Error(error.message);
  }
  await verifyAppliedState(supabase, plans, publicBefore, slugSnapshot.migration);
  const resolution = await recordResolution(supabase, plans, publicBefore, slugSnapshot.migration);
  console.log(JSON.stringify({
    complete: true,
    changedHistories: plans.length,
    refreshedPublicRecords: publicBefore.length,
    redirectedUrls: slugSnapshot.migration.length,
    backupFile,
    ...resolution.notification
  }));
}

if (require.main === module) {
  main().catch(error => {
    console.error(`Soru sıra etiketi düzeltmesi tamamlanamadı: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { PACKAGE_ID, REPORTED_HISTORY_ID, buildPlan };
