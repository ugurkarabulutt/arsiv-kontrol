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

const PACKAGE_ID = 'antimatter-positive-infinity-source-integrity-20261029';
const ACTOR = 'Sistem Bakımı';
const SUBMISSION_ID = '35b3fd86-98a1-4c56-a527-ddad5f79132b';
const WRONG_QUERY = '6 milyona kadar olan kesim yok';
const WRONG_PATTERN = /(?<![\p{L}\p{N}_])(?:0|O)['’]dan\s+6\s+milyona\s+kadar\s+olan\s+kesim\s+yok\.(?![\p{L}\p{N}_])/giu;
const CORRECT_SENTENCE = "0'dan artı sonsuza kadar olan kesim yok.";
const SUBMISSION_ANSWER = `Düzeltme yapıldı. İlgili cümle “${CORRECT_SENTENCE}” şeklinde güncellendi. Aynı hatanın bulunduğu geçmiş ve canlı kayıtlar kontrol edilerek düzeltildi. Bildiriminiz için teşekkür ederiz.`;

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

async function fetchImpactedHistories(supabase) {
  const rows = [];
  for (let from = 0; ; from += 500) {
    const { data, error } = await supabase.from('history')
      .select('id,user_id,name,username,status,version,updated_at,question_text,corrected_text')
      .ilike('corrected_text', `%${WRONG_QUERY}%`)
      .order('created_at', { ascending: true })
      .range(from, from + 499);
    if (error) throw new Error(error.message);
    rows.push(...(data || []).filter(row => {
      WRONG_PATTERN.lastIndex = 0;
      return WRONG_PATTERN.test(row.corrected_text || '');
    }));
    if (!data || data.length < 500) break;
  }
  return rows;
}

function buildPlan(history) {
  const oldText = String(history.corrected_text || '');
  const matches = [...oldText.matchAll(new RegExp(WRONG_PATTERN.source, WRONG_PATTERN.flags))];
  if (!matches.length) throw new Error(`Kesin antimadde bağlamı bulunamadı: ${history.id}`);
  return {
    history,
    oldText,
    newText: oldText.replace(WRONG_PATTERN, CORRECT_SENTENCE),
    replacements: matches.length
  };
}

async function loadPublicSnapshot(supabase, plans) {
  const approvedIds = plans.filter(plan => plan.history.status === 'onaylandi').map(plan => plan.history.id);
  if (!approvedIds.length) return [];
  const { data, error } = await supabase.from('public_qa')
    .select('slug,status,source_history_id,answer_text')
    .in('source_history_id', approvedIds)
    .order('slug', { ascending: true });
  if (error) throw new Error(error.message);
  return data || [];
}

async function applyHistoryCorrection(supabase, plan) {
  const updateQuery = supabase.from('history').update({ corrected_text: plan.newText });
  const { data, error } = await applySnapshotGuard(updateQuery, plan.history)
    .select('id,version,updated_at')
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

  const rollbackQuery = supabase.from('history').update({ corrected_text: plan.oldText });
  const { data: rollback, error: rollbackError } = await applySnapshotGuard(rollbackQuery, data)
    .select('id')
    .maybeSingle();
  if (rollbackError || !rollback) throw new Error(`Düzeltme loglanamadı ve kayıt geri alınamadı: ${plan.history.id}`);
  throw new Error(`Düzeltme loglanamadı; kayıt geri alındı: ${logError.message}`);
}

async function answerReporterSubmission(supabase) {
  const { data: submission, error } = await supabase.from('public_question_submissions')
    .select('id,status,answer_text,updated_at,submitter_name,public_user_id')
    .eq('id', SUBMISSION_ID)
    .maybeSingle();
  if (error) throw new Error(error.message);
  if (!submission) throw new Error('Benan Hanımın bildirim kaydı bulunamadı.');
  if (submission.status === 'answered' && submission.answer_text === SUBMISSION_ANSWER) {
    return { changed: false, publicUserId: submission.public_user_id };
  }
  if (!['new', 'reviewing'].includes(submission.status)) {
    throw new Error(`Bildirim kaydı beklenmeyen durumda: ${submission.status}`);
  }

  const now = new Date().toISOString();
  const { data: updated, error: updateError } = await supabase.from('public_question_submissions')
    .update({
      answer_text: SUBMISSION_ANSWER,
      answered_by: ACTOR,
      answered_at: now,
      user_seen_at: null,
      status: 'answered',
      admin_note: 'İçerik düzeltme bildirimi doğrulandı; aynı yanlış ifade tüm ilgili geçmiş ve public kayıtlarda düzeltildi.',
      updated_at: now
    })
    .eq('id', submission.id)
    .eq('status', submission.status)
    .eq('updated_at', submission.updated_at)
    .select('id,public_user_id,status,answer_text')
    .maybeSingle();
  if (updateError) throw new Error(updateError.message);
  if (!updated) throw new Error('Benan Hanımın bildirimi işlem sırasında değişti.');
  return { changed: true, publicUserId: updated.public_user_id };
}

async function notifyEda(supabase, plans, summary) {
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
      message: `Bildirdiğiniz antimadde cevabındaki ifade incelendi. Yanlış cümle “${CORRECT_SENTENCE}” olarak düzeltildi; aynı hatayı taşıyan geçmiş ve canlı kayıtlar da kontrol edilerek güncellendi.`,
      user_id: user.id,
      history_id: plans.find(plan => plan.history.status === 'onaylandi')?.history.id || plans[0]?.history.id || null,
      read: false,
      feedback_status: 'notice',
      resolution_group: PACKAGE_ID,
      resolution_note: summary
    });
    if (insertError) throw new Error(insertError.message);
  }
  return { recipientCount: 1, matchCount: 1 };
}

async function recordResolution(supabase, plans, publicRows, submissionResult) {
  const historyIds = plans.map(plan => plan.history.id);
  const publishedCount = publicRows.filter(row => row.status === 'published').length;
  const hiddenCount = publicRows.filter(row => row.status === 'content_review_hidden').length;
  const summary = `${plans.length} geçmiş kayıtta antimadde anlatımındaki 6 milyon ifadesi artı sonsuz olarak düzeltildi; ${publishedCount} yayımdaki kayıt yenilendi, ${hiddenCount} gizli kayıt gizli kaldı.`;
  const edaNotification = await notifyEda(supabase, plans, summary);

  const { error: resolutionError } = await supabase.from('issue_resolution_log').upsert({
    resolution_group: PACKAGE_ID,
    title: 'Antimadde artı sonsuz kaynak bütünlüğü',
    summary,
    status: 'applied',
    feedback_count: 1,
    user_count: 1 + edaNotification.recipientCount,
    created_by: ACTOR
  }, { onConflict: 'resolution_group' });
  if (resolutionError) throw new Error(resolutionError.message);

  const { data: existing, error: existingError } = await supabase.from('admin_action_log')
    .select('id')
    .eq('action', 'content.source_integrity_repaired')
    .eq('target_id', PACKAGE_ID)
    .limit(1)
    .maybeSingle();
  if (existingError) throw new Error(existingError.message);
  if (!existing) {
    const { error: insertError } = await supabase.from('admin_action_log').insert({
      actor_username: 'system-maintenance',
      actor_name: ACTOR,
      actor_role: 'super_admin',
      action: 'content.source_integrity_repaired',
      action_label: 'Kaynak anlatımındaki sayısal ifadeyi düzeltti',
      target_type: 'history_batch',
      target_id: PACKAGE_ID,
      target_label: 'Antimadde artı sonsuz kaynak bütünlüğü',
      target_status_before: 'incorrect_public_content',
      target_status_after: 'repaired',
      summary,
      metadata: {
        historyIds,
        publicSlugs: publicRows.map(row => row.slug),
        submissionId: SUBMISSION_ID,
        submissionChanged: submissionResult.changed,
        wrongPhrase: WRONG_QUERY,
        correctSentence: CORRECT_SENTENCE
      }
    });
    if (insertError) throw new Error(insertError.message);
  }
  return { summary, edaNotification };
}

async function verifyAppliedState(supabase, plans, publicBefore) {
  for (const plan of plans) {
    const { data: history, error } = await supabase.from('history')
      .select('id,status,corrected_text')
      .eq('id', plan.history.id)
      .single();
    if (error) throw new Error(error.message);
    WRONG_PATTERN.lastIndex = 0;
    if (WRONG_PATTERN.test(history.corrected_text || '') || !String(history.corrected_text || '').includes(CORRECT_SENTENCE)) {
      throw new Error(`History doğrulaması başarısız: ${history.id}`);
    }
    if (history.status !== plan.history.status) throw new Error(`History durumu değişti: ${history.id}`);
  }

  for (const before of publicBefore) {
    const { data: current, error } = await supabase.from('public_qa')
      .select('slug,status,answer_text')
      .eq('slug', before.slug)
      .single();
    if (error) throw new Error(error.message);
    WRONG_PATTERN.lastIndex = 0;
    if (WRONG_PATTERN.test(current.answer_text || '') || !String(current.answer_text || '').includes(CORRECT_SENTENCE)) {
      throw new Error(`Public doğrulaması başarısız: ${current.slug}`);
    }
    if (current.status !== before.status) throw new Error(`Public görünürlük değişti: ${current.slug}`);
  }

  const { data: submission, error: submissionError } = await supabase.from('public_question_submissions')
    .select('status,answer_text,user_notified_at')
    .eq('id', SUBMISSION_ID)
    .single();
  if (submissionError) throw new Error(submissionError.message);
  if (submission.status !== 'answered' || submission.answer_text !== SUBMISSION_ANSWER) {
    throw new Error('Benan Hanımın bildirim cevabı doğrulanamadı.');
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
  const publicBefore = await loadPublicSnapshot(supabase, plans);
  console.log(JSON.stringify({
    mode: apply ? 'apply' : 'dry-run',
    impacted: plans.length,
    replacements: plans.reduce((sum, plan) => sum + plan.replacements, 0),
    statuses: plans.reduce((result, plan) => ({ ...result, [plan.history.status]: (result[plan.history.status] || 0) + 1 }), {}),
    publicStatuses: publicBefore.reduce((result, row) => ({ ...result, [row.status]: (result[row.status] || 0) + 1 }), {}),
    historyIds: plans.map(plan => plan.history.id),
    publicSlugs: publicBefore.map(row => row.slug)
  }, null, 2));
  if (!apply) return;

  for (const plan of plans) await applyHistoryCorrection(supabase, plan);
  const app = require('../server');
  await app.maintenance.ready();
  for (const plan of plans.filter(item => item.history.status === 'onaylandi')) {
    await app.maintenance.publishApprovedHistoryRecord(plan.history.id);
  }
  const submissionResult = await answerReporterSubmission(supabase);
  await verifyAppliedState(supabase, plans, publicBefore);
  const resolution = await recordResolution(supabase, plans, publicBefore, submissionResult);
  console.log(JSON.stringify({
    complete: true,
    changedHistories: plans.length,
    refreshedPublicRecords: publicBefore.length,
    publishedRecords: publicBefore.filter(row => row.status === 'published').length,
    hiddenRecords: publicBefore.filter(row => row.status === 'content_review_hidden').length,
    submissionChanged: submissionResult.changed,
    ...resolution.edaNotification
  }));
}

if (require.main === module) {
  main().catch(error => {
    console.error(`Antimadde artı sonsuz düzeltmesi tamamlanamadı: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { WRONG_PATTERN, WRONG_QUERY, CORRECT_SENTENCE, buildPlan };
