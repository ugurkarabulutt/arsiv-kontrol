'use strict';

const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const { textHash } = require('../analysis-core');
const { restoreReportedChange } = require('./resolve-open-feedback-20261027');

const envFile = [
  process.env.ENV_FILE,
  path.resolve(__dirname, '..', '..', '.env'),
  path.resolve(__dirname, '..', '.env')
].filter(Boolean).find(file => fs.existsSync(file));
if (envFile) dotenv.config({ path: envFile });

const PACKAGE_ID = 'tezekkur-tefekkur-source-integrity-20261029';
const RESOLUTION_GROUP = PACKAGE_ID;
const ACTOR = 'Sistem Bakımı';
const SOURCE_FORM = 'Böylece tezekkür edersiniz diye';
const WRONG_FORM = 'Böylece tefekkür edersiniz diye';

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} tanımlı değil.`);
  return value;
}

async function fetchImpactedHistories(supabase) {
  const rows = [];
  for (let from = 0; ; from += 500) {
    const { data, error } = await supabase.from('history')
      .select('id,user_id,name,username,status,version,updated_at,original_text,corrected_text')
      .ilike('original_text', `%${SOURCE_FORM}%`)
      .ilike('corrected_text', `%${WRONG_FORM}%`)
      .order('created_at', { ascending: true })
      .range(from, from + 499);
    if (error) throw new Error(error.message);
    rows.push(...(data || []));
    if (!data || data.length < 500) break;
  }
  return rows;
}

function buildPlan(history) {
  const result = restoreReportedChange(
    history.original_text || '',
    history.corrected_text || '',
    SOURCE_FORM,
    [WRONG_FORM]
  );
  if (result.replacements.length !== 1) {
    throw new Error(`Beklenen tek kesin dönüşüm bulunamadı: ${history.id} (${result.replacements.length})`);
  }
  return {
    history,
    oldText: history.corrected_text || '',
    newText: result.text,
    replacements: result.replacements.length
  };
}

async function applyHistoryCorrection(supabase, plan) {
  const { data, error } = await supabase.from('history')
    .update({ corrected_text: plan.newText })
    .eq('id', plan.history.id)
    .eq('version', plan.history.version)
    .eq('updated_at', plan.history.updated_at)
    .select('id,updated_at')
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!data) throw new Error(`Kayıt işlem sırasında değişti: ${plan.history.id}`);

  const { error: logError } = await supabase.from('content_correction_log').insert({
    package_id: PACKAGE_ID,
    history_id: plan.history.id,
    field_name: 'corrected_text',
    old_value: plan.oldText,
    new_value: plan.newText,
    old_hash: textHash(plan.oldText),
    new_hash: textHash(plan.newText),
    status: 'applied',
    created_by: ACTOR
  });
  if (!logError) return;

  const { data: rollback, error: rollbackError } = await supabase.from('history')
    .update({ corrected_text: plan.oldText })
    .eq('id', plan.history.id)
    .eq('version', plan.history.version)
    .eq('updated_at', data.updated_at)
    .select('id')
    .maybeSingle();
  if (rollbackError || !rollback) {
    throw new Error(`Düzeltme loglanamadı ve kayıt geri alınamadı: ${plan.history.id}`);
  }
  throw new Error(`Düzeltme loglanamadı; kayıt geri alındı: ${logError.message}`);
}

async function recordResolution(supabase, plans, publicCount) {
  const historyIds = plans.map(plan => plan.history.id);
  const userIds = [...new Set(plans.map(plan => plan.history.user_id).filter(Boolean))];
  const summary = `${plans.length} onaylı kayıtta tezekkür kavramını tefekküre çeviren yanlış dönüşüm kaynak biçimine döndürüldü; ${publicCount} canlı kayıt ve arama belgesi yenilendi.`;

  for (const userId of userIds) {
    const { data: existing, error: existingError } = await supabase.from('alerts')
      .select('id')
      .eq('type', 'feedback_resolution')
      .eq('resolution_group', RESOLUTION_GROUP)
      .eq('user_id', userId)
      .limit(1)
      .maybeSingle();
    if (existingError) throw new Error(existingError.message);
    if (existing) continue;
    const first = plans.find(plan => plan.history.user_id === userId);
    const { error } = await supabase.from('alerts').insert({
      type: 'feedback_resolution',
      message: 'Bildirdiğiniz “tezekkür” kelimesinin “tefekkür” olarak değiştirilmesi incelendi. Kaynak metindeki doğru “tezekkür” ifadesi onaylı kayıt ve canlı soru sayfasında düzeltildi; iki kavramın birbirine dönüştürülmesi gelecek denetimlerde engellendi. Dikkatli bildiriminiz için teşekkür ederiz.',
      user_id: userId,
      history_id: first.history.id,
      read: false,
      feedback_status: 'notice',
      resolution_group: RESOLUTION_GROUP,
      resolution_note: summary
    });
    if (error) throw new Error(error.message);
  }

  const { error: resolutionError } = await supabase.from('issue_resolution_log').upsert({
    resolution_group: RESOLUTION_GROUP,
    title: 'Tezekkür ve tefekkür kavram bütünlüğü',
    summary,
    status: 'applied',
    feedback_count: 1,
    user_count: userIds.length,
    created_by: ACTOR
  }, { onConflict: 'resolution_group' });
  if (resolutionError) throw new Error(resolutionError.message);

  const { data: existingAdminLog, error: existingAdminLogError } = await supabase.from('admin_action_log')
    .select('id')
    .eq('action', 'content.source_integrity_repaired')
    .eq('target_id', RESOLUTION_GROUP)
    .limit(1)
    .maybeSingle();
  if (existingAdminLogError) throw new Error(existingAdminLogError.message);
  if (!existingAdminLog) {
    const { error } = await supabase.from('admin_action_log').insert({
      actor_username: 'system-maintenance',
      actor_name: ACTOR,
      actor_role: 'super_admin',
      action: 'content.source_integrity_repaired',
      action_label: 'Kaynak kavram bütünlüğünü düzeltti',
      target_type: 'history_batch',
      target_id: RESOLUTION_GROUP,
      target_label: 'Tezekkür ve tefekkür kavram bütünlüğü',
      target_status_before: 'incorrect_public_content',
      target_status_after: 'repaired',
      summary,
      metadata: { historyIds, publicCount, sourceForm: SOURCE_FORM, wrongForm: WRONG_FORM }
    });
    if (error) throw new Error(error.message);
  }
}

async function verifyAppliedState(supabase, plans) {
  for (const plan of plans) {
    const { data: history, error: historyError } = await supabase.from('history')
      .select('id,corrected_text')
      .eq('id', plan.history.id)
      .single();
    if (historyError) throw new Error(historyError.message);
    if (!history.corrected_text.includes(SOURCE_FORM) || history.corrected_text.includes(WRONG_FORM)) {
      throw new Error(`History doğrulaması başarısız: ${plan.history.id}`);
    }
    if (plan.history.status !== 'onaylandi') continue;
    const { data: publicRows, error: publicError } = await supabase.from('public_qa')
      .select('slug,status,answer_text')
      .eq('source_history_id', plan.history.id);
    if (publicError) throw new Error(publicError.message);
    for (const row of publicRows || []) {
      if (row.status === 'published' && (!row.answer_text.includes(SOURCE_FORM) || row.answer_text.includes(WRONG_FORM))) {
        throw new Error(`Public doğrulaması başarısız: ${row.slug}`);
      }
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
  console.log(JSON.stringify({
    mode: apply ? 'apply' : 'dry-run',
    impacted: plans.length,
    replacements: plans.reduce((sum, plan) => sum + plan.replacements, 0),
    statuses: plans.reduce((result, plan) => ({ ...result, [plan.history.status]: (result[plan.history.status] || 0) + 1 }), {}),
    historyIds: plans.map(plan => plan.history.id)
  }, null, 2));
  if (!apply) return;

  for (const plan of plans) await applyHistoryCorrection(supabase, plan);
  const app = require('../server');
  await app.maintenance.ready();
  let publicCount = 0;
  for (const plan of plans.filter(item => item.history.status === 'onaylandi')) {
    const result = await app.maintenance.publishApprovedHistoryRecord(plan.history.id);
    if (!result?.skipped) publicCount += 1;
  }
  await verifyAppliedState(supabase, plans);
  await recordResolution(supabase, plans, publicCount);
  console.log(JSON.stringify({ complete: true, changedHistories: plans.length, publicCount }));
}

if (require.main === module) {
  main().catch(error => {
    console.error(`Tezekkür düzeltmesi tamamlanamadı: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { SOURCE_FORM, WRONG_FORM, buildPlan };
