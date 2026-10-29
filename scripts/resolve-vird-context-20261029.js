'use strict';

const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const { textHash } = require('../analysis-core');

const envFile = [
  process.env.ENV_FILE,
  path.resolve(__dirname, '..', '..', '.env'),
  path.resolve(__dirname, '..', '.env')
].filter(Boolean).find(file => fs.existsSync(file));
if (envFile) dotenv.config({ path: envFile });

const PACKAGE_ID = 'physical-body-vird-context-20261029';
const ACTOR = 'Sistem Bakımı';
const WRONG_PATTERN = /(?<![\p{L}\p{N}_])fizik\s+beden\s+tesliminde\s+verdiğimizi(?![\p{L}\p{N}_])/giu;
const WRONG_QUERY = 'fizik beden tesliminde verdiğimizi';

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} tanımlı değil.`);
  return value;
}

async function fetchImpactedHistories(supabase) {
  const rows = [];
  for (let from = 0; ; from += 500) {
    const { data, error } = await supabase.from('history')
      .select('id,user_id,name,username,status,version,updated_at,question_text,original_text,corrected_text')
      .ilike('corrected_text', `%${WRONG_QUERY}%`)
      .order('created_at', { ascending: true })
      .range(from, from + 499);
    if (error) throw new Error(error.message);
    rows.push(...(data || []));
    if (!data || data.length < 500) break;
  }
  return rows;
}

function buildPlan(history) {
  const oldText = String(history.corrected_text || '');
  const matches = [...oldText.matchAll(new RegExp(WRONG_PATTERN.source, WRONG_PATTERN.flags))];
  if (!matches.length) throw new Error(`Kesin bağlam bulunamadı: ${history.id}`);
  const newText = oldText.replace(WRONG_PATTERN, match => match.replace(/verdiğimizi/iu, 'virdimizi'));
  return { history, oldText, newText, replacements: matches.length };
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
  if (rollbackError || !rollback) throw new Error(`Düzeltme loglanamadı ve kayıt geri alınamadı: ${plan.history.id}`);
  throw new Error(`Düzeltme loglanamadı; kayıt geri alındı: ${logError.message}`);
}

async function recordResolution(supabase, plans, publicCount) {
  const historyIds = plans.map(plan => plan.history.id);
  const summary = `${plans.length} kayıtta fizik beden teslimi bağlamındaki verdiğimizi ifadesi virdimizi olarak düzeltildi; ${publicCount} canlı kayıt ve arama belgesi yenilendi.`;
  const { error: resolutionError } = await supabase.from('issue_resolution_log').upsert({
    resolution_group: PACKAGE_ID,
    title: 'Fizik beden teslimi vird kavramı düzeltmesi',
    summary,
    status: 'applied',
    feedback_count: 1,
    user_count: 1,
    created_by: ACTOR
  }, { onConflict: 'resolution_group' });
  if (resolutionError) throw new Error(resolutionError.message);

  const { data: existingAdminLog, error: existingAdminLogError } = await supabase.from('admin_action_log')
    .select('id')
    .eq('action', 'content.source_integrity_repaired')
    .eq('target_id', PACKAGE_ID)
    .limit(1)
    .maybeSingle();
  if (existingAdminLogError) throw new Error(existingAdminLogError.message);
  if (!existingAdminLog) {
    const { error } = await supabase.from('admin_action_log').insert({
      actor_username: 'system-maintenance',
      actor_name: ACTOR,
      actor_role: 'super_admin',
      action: 'content.source_integrity_repaired',
      action_label: 'Bağlamsal kelime hatasını düzeltti',
      target_type: 'history_batch',
      target_id: PACKAGE_ID,
      target_label: 'Fizik beden teslimi vird kavramı',
      target_status_before: 'incorrect_public_content',
      target_status_after: 'repaired',
      summary,
      metadata: { historyIds, publicCount, wrongPhrase: WRONG_QUERY, correctWord: 'virdimizi' }
    });
    if (error) throw new Error(error.message);
  }

  const { data: reporters, error: reporterError } = await supabase.from('users')
    .select('id,name,username')
    .or('name.ilike.%Eda Şahinhan%,username.ilike.%Eda Şahinhan%')
    .eq('active', true)
    .limit(2);
  if (reporterError) throw new Error(reporterError.message);
  if ((reporters || []).length === 1) {
    const reporter = reporters[0];
    const { data: existingNotice, error: noticeLookupError } = await supabase.from('alerts')
      .select('id')
      .eq('type', 'feedback_resolution')
      .eq('resolution_group', PACKAGE_ID)
      .eq('user_id', reporter.id)
      .limit(1)
      .maybeSingle();
    if (noticeLookupError) throw new Error(noticeLookupError.message);
    if (!existingNotice) {
      const { error } = await supabase.from('alerts').insert({
        type: 'feedback_resolution',
        message: 'Bildirdiğiniz “fizik beden tesliminde verdiğimizi” ifadesi incelendi. Doğru kavram “virdimizi” olarak onaylı kayıtta ve canlı soru sayfasında düzeltildi. Aynı bağlamın gelecek denetimlerde atlanmaması için kalıcı kontrol eklendi. Dikkatli bildiriminiz için teşekkür ederiz.',
        user_id: reporter.id,
        history_id: plans[0]?.history.id || null,
        read: false,
        feedback_status: 'notice',
        resolution_group: PACKAGE_ID,
        resolution_note: summary
      });
      if (error) throw new Error(error.message);
    }
  }
  return { reporterCount: (reporters || []).length };
}

async function verifyAppliedState(supabase, plans) {
  for (const plan of plans) {
    const { data: history, error: historyError } = await supabase.from('history')
      .select('id,corrected_text')
      .eq('id', plan.history.id)
      .single();
    if (historyError) throw new Error(historyError.message);
    WRONG_PATTERN.lastIndex = 0;
    if (WRONG_PATTERN.test(history.corrected_text || '')) throw new Error(`History doğrulaması başarısız: ${plan.history.id}`);
    if (plan.history.status !== 'onaylandi') continue;
    const { data: publicRows, error: publicError } = await supabase.from('public_qa')
      .select('slug,status,answer_text')
      .eq('source_history_id', plan.history.id);
    if (publicError) throw new Error(publicError.message);
    for (const row of publicRows || []) {
      WRONG_PATTERN.lastIndex = 0;
      if (row.status === 'published' && WRONG_PATTERN.test(row.answer_text || '')) throw new Error(`Public doğrulaması başarısız: ${row.slug}`);
    }
  }
}

async function main() {
  const apply = process.argv.includes('--apply');
  const supabase = createClient(requiredEnv('SUPABASE_URL'), requiredEnv('SUPABASE_KEY'), { auth: { persistSession: false, autoRefreshToken: false } });
  const impacted = await fetchImpactedHistories(supabase);
  if (!impacted.length) {
    const { data, error } = await supabase.from('content_correction_log').select('history_id').eq('package_id', PACKAGE_ID);
    if (error) throw new Error(error.message);
    console.log(JSON.stringify({ mode: apply ? 'apply' : 'dry-run', alreadyApplied: Boolean(data?.length), impacted: 0 }));
    return;
  }
  const plans = impacted.map(buildPlan);
  console.log(JSON.stringify({
    mode: apply ? 'apply' : 'dry-run',
    impacted: plans.length,
    replacements: plans.reduce((sum, plan) => sum + plan.replacements, 0),
    statuses: plans.reduce((result, plan) => ({ ...result, [plan.history.status]: (result[plan.history.status] || 0) + 1 }), {},),
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
  const resolution = await recordResolution(supabase, plans, publicCount);
  console.log(JSON.stringify({ complete: true, changedHistories: plans.length, publicCount, ...resolution }));
}

if (require.main === module) {
  main().catch(error => {
    console.error(`Vird bağlamı düzeltmesi tamamlanamadı: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { WRONG_PATTERN, WRONG_QUERY, buildPlan };
