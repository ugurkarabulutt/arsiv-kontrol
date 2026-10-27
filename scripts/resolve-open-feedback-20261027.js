'use strict';

const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const { textHash } = require('../analysis-core');

const fallbackEnvFiles = [
  process.env.ENV_FILE,
  path.resolve(__dirname, '..', '..', '.env'),
  path.resolve(__dirname, '..', '.env')
].filter(Boolean);
const envFile = fallbackEnvFiles.find(file => fs.existsSync(file));
if (envFile) dotenv.config({ path: envFile });

const PACKAGE_ID = 'feedback-source-integrity-20261027';
const RESOLUTION_GROUP = 'feedback-source-integrity-20261027';
const ACTOR = 'Sistem Bakımı';

const CASES = [
  ['91ff16f0-e9c5-492d-84dc-34389d05ae34', '6e9447d6-cb09-44ed-adbe-8468829429f3', 'hevasına', ['hevâsına']],
  ['a1faffa8-7324-467f-a74b-a0330e6cee05', 'd3b07113-d8f5-4542-aea6-139dfaaf8c89', 'dîni', ['dinî', 'dini']],
  ['c287ba1a-b924-4876-bdb4-8a914b05bc06', '31a92aff-bfee-4530-8906-0eda36918d27', 'abdlık', ['abd olmak']],
  ['a5a8d7e6-2b6c-4c59-ac4d-d70774c18e16', '31a92aff-bfee-4530-8906-0eda36918d27', 'abdlık', ['abd olmak']],
  ['ee5765cf-35fb-4df3-adb6-e0fc715b844d', '95169ba7-261d-42e9-9dc1-18fc83af9f27', 'tayin', ['tâyin']],
  ['5d0c956c-fbc1-4e24-87dd-0022416b10b9', 'f5142ad8-0859-4ae1-9a79-38df58d9ac6c', 'sureden', ['Surenin']],
  ['bc9c57d3-d7e3-4509-a936-70aed500aefe', '2f67568a-7b4b-44d5-b1a7-7ac62c35129e', 'Allah’a ulaşmayı dilemek.', ['Allah’a ulaşmayı dilemek']],
  ['e2419bfb-da6a-415c-a073-0d3f2e7db445', '62ec2c6c-c63d-4109-9e3e-08fd8fa6f9fd', 'hudâ', ['hidayet']],
  ['675310b8-e768-4612-ad20-e152fce05b30', '706373d3-8948-444c-b765-6aad294e2b47', 'Rahîm’dir (rahmet', ['Rahîm’dir. (rahmet']],
  ['82bb785b-7ba3-4bc1-87ca-3546bc72428f', '81041f73-6945-41b1-807e-18a88f468bb4', 'dîninizden', ['dininizden']],
  ['541ce77e-3f44-40a1-a2d1-4b3929d35412', '81041f73-6945-41b1-807e-18a88f468bb4', 'dîninizi', ['dininizi']],
  ['ffc7f41e-c695-4895-aca7-ae4d62b4dd05', '5477b436-5b21-452c-a6e7-335ee24db228', 'teslimi', ['teslim']],
  ['c5a292ef-2b09-476c-9d42-dcf194672f24', '7428be31-2c93-409c-986e-50be6a72829c', 'hakîm(hakîmun).', ['hakîm (hakîmun).']],
  ['d187d3ea-59b3-4328-8ff3-ccf80bce4633', '231b6704-8caf-43db-9744-1a58776403d9', 'tevbetu', ['tövbetu']],
  ['751948fe-0f25-455c-a4f9-4b2dc4a1ce4b', '8b746b9f-6c61-4163-b82f-9d01e4b14598', 'her şeyi', ['herşeyi']],
  ['a2f1ea34-dcf9-40b0-bfe0-61afacbd206c', '1280dedc-a163-4f5f-b9b2-16b4dad1cb5d', 'ardarda', ['art arda']],
  ['a4882657-a5d9-4019-8abc-12b7740fc131', '66b12686-f153-4471-b2c7-88eaa37220ee', 'birşey', ['bir şey']],
  ['9d40dccf-acad-4c45-9f41-ba9188402e04', '9eeb0ca4-aeaa-44a5-9753-a55470a953be', 'Yûnus-7 ve 8’de buyuruluyor:', ['Yûnus-7 ve 8’de buyuruluyor.']],
  ['a23778c7-9730-4954-bace-4eae08cc8c86', 'cdc71d11-6ec7-42f8-97dc-59a4882dd0d5', 'dîninden', ['dininden']],
  ['7a8d4ff6-9296-4a5a-ad1e-2b96d0d905e2', 'a2aacc91-a5a6-4c4b-9af5-191de8716105', 'iman', ['îmân']],
  ['6c23f7cf-758c-4cfb-a83b-79c1f1c5a6be', '63c8be75-5ea0-49a2-bc50-8dacb222a00a', 'vechini', ['vechimizi']],
  ['ff180836-4aa0-4c2d-98e0-504729f292f7', '6a9bb9eb-f48a-4da1-853b-1e7d472b57be', 'Müddessir', ['MUDDESSİR']],
  ['35c0eda1-ed8f-4b2c-a10d-2a15f2d6023c', 'f7d8b2e6-2762-4904-85ac-c36ca4e11ddf', 'hadîs-i şerif', ['Hadîs-i Şerif']],
  ['fdb6ad01-14a9-4f6c-b800-4c2902039504', '1a0eae76-5f33-4b62-8da6-aaaa4adaf9be', 'YEMİN’NİN', ["YEMİN'NİN"]],
  ['a5bc705c-a65b-489b-992c-aadc2ecffd32', '4de31b0c-6774-4be1-ac7d-1500a4be803c', 'Allah ile bile olarak', ['Allah ile olarak', 'Allah ile']],
  ['64e06f14-195c-4582-bb10-541d7352d07f', '761126d0-16f1-4c6e-9420-be0098faaae6', 'rahmânir rahîm', ['rahmânirrahîm']],
  ['594a5b7f-c020-47bd-b791-93b65268e76c', '761126d0-16f1-4c6e-9420-be0098faaae6', 'El hamdu', ['Elhamdu']],
  ['bc77ea87-c702-4f1d-877c-67da3574b365', '761126d0-16f1-4c6e-9420-be0098faaae6', 'Rahmânir rahîm', ['Rahmânirrahîm']],
  ['851bb622-56ae-47be-a1bb-fec78717e6d5', 'a70ea0af-696a-4526-91a3-5eeb1897fbe3', "Mehdi (A.S)'ın", ["Mehdi (A.S)'in"]],
  ['1a907571-d6d2-4ce8-a132-0a36413898cb', '924c7395-f188-469b-8788-0adcaf2b5213', 'Her Resûl', ['Her resûl']],
  ['2753159e-e09e-424a-8c69-07d1a632b7d2', 'c017432a-ad40-4769-b094-5463c18111df', 'acaip', ['acayip']],
  ['63cec153-56a3-422b-89ec-af80bf316d74', 'ec2db5cf-c8f7-4549-8df8-e78062b0687d', 'Keşf’ul Hafâ', ['Keşfü’l Hafa', 'Keşfü’l-Hafa']],
  ['aecfe383-ce8a-4373-8021-252fc62acae6', '38eef799-955e-4e92-8f62-275c92eb5626', 'dîninizi', ['dininizi']],
  ['c97c8c4d-6e8d-4967-928f-a272349230b2', '38eef799-955e-4e92-8f62-275c92eb5626', 'dîninizden', ['dininizden']],
  ['b8580ef9-ba01-4890-9dfc-eba88d375c99', '868aa23c-f661-4e32-81fb-8240f4e07e2c', 'Kur’an', ['Kur’ân']],
  ['742c3010-b6a7-4888-abd2-0866bb0a1ad8', '742f7d8b-65ef-43a1-8db3-e316b4f985f6', 'Sübhan’dır', ['münezzehtir', "Sübhân'dır", 'Sübhân’dır']],
  ['16772d65-7c84-4e55-a4aa-54ee08b6926e', '7c8a6fe1-531e-46d3-92ce-576bf594e93c', 'her şeyden', ['herşeyden']],
  ['96303dcd-6d55-403c-a2d5-3c15848cef81', '666a664b-6cc7-472c-82aa-2a3aa54bf98c', 'her şeyi', ['herşeyi']],
  ['27a0141b-f720-429e-a287-7d7fb211ef5a', '666a664b-6cc7-472c-82aa-2a3aa54bf98c', 'ulü’l elbâbtan', ["ulûl'elbabtan"]],
  ['4a42d584-68cd-40c6-ac03-c5c256638cc4', 'cf571fbf-9965-4416-9375-46ec8c01fbdd', 'derecelerle', ['derecatla']],
  ['39f59629-f119-474b-b6ae-117651f8815e', 'd0142597-e6a9-42c2-b4a0-98f6b3eaa396', 'tâbiiyet', ['tâbîyet']]
].map(([feedbackId, historyId, sourceForm, wrongForms]) => ({ feedbackId, historyId, sourceForm, wrongForms }));

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} tanımlı değil.`);
  return value;
}

function positionsOf(text, needle, { caseInsensitive = false } = {}) {
  const source = caseInsensitive ? String(text).toLocaleLowerCase('tr-TR') : String(text);
  const target = caseInsensitive ? String(needle).toLocaleLowerCase('tr-TR') : String(needle);
  if (!target) return [];
  const positions = [];
  for (let index = 0; index <= source.length - target.length;) {
    const found = source.indexOf(target, index);
    if (found < 0) break;
    positions.push(found);
    index = found + Math.max(1, target.length);
  }
  return positions;
}

function sourcePositions(text, sourceForm) {
  const exact = positionsOf(text, sourceForm);
  return exact.length ? exact : positionsOf(text, sourceForm, { caseInsensitive: true });
}

function candidateWrongPositions(currentText, sourceForm, wrongForms) {
  const candidates = [];
  for (const wrongForm of wrongForms) {
    for (const index of positionsOf(currentText, wrongForm)) {
      const alreadyCorrect = currentText.slice(index, index + sourceForm.length) === sourceForm;
      if (!alreadyCorrect) candidates.push({ index, wrongForm });
    }
  }
  return candidates.sort((a, b) => a.index - b.index || b.wrongForm.length - a.wrongForm.length);
}

function restoreReportedChange(originalText, currentText, sourceForm, wrongForms) {
  const originals = sourcePositions(originalText, sourceForm);
  const candidates = candidateWrongPositions(currentText, sourceForm, wrongForms);
  if (!originals.length || !candidates.length) {
    return { text: currentText, replacements: [], originalCount: originals.length, candidateCount: candidates.length };
  }

  const available = [...candidates];
  const selected = [];
  for (const originalIndex of originals) {
    if (!available.length) break;
    const expectedIndex = Math.round(originalIndex / Math.max(1, originalText.length) * currentText.length);
    let best = 0;
    for (let index = 1; index < available.length; index += 1) {
      if (Math.abs(available[index].index - expectedIndex) < Math.abs(available[best].index - expectedIndex)) best = index;
    }
    selected.push(available.splice(best, 1)[0]);
  }

  let text = currentText;
  for (const item of selected.sort((a, b) => b.index - a.index)) {
    text = `${text.slice(0, item.index)}${sourceForm}${text.slice(item.index + item.wrongForm.length)}`;
  }
  return { text, replacements: selected, originalCount: originals.length, candidateCount: candidates.length };
}

function buildPlans(histories) {
  const historiesById = new Map(histories.map(row => [row.id, row]));
  const byHistory = new Map();
  for (const item of CASES) {
    if (!byHistory.has(item.historyId)) byHistory.set(item.historyId, []);
    byHistory.get(item.historyId).push(item);
  }

  const plans = [];
  for (const [historyId, cases] of byHistory.entries()) {
    const history = historiesById.get(historyId);
    if (!history) throw new Error(`Kayıt bulunamadı: ${historyId}`);
    let nextText = String(history.corrected_text || '');
    const details = [];
    const seenPairs = new Set();
    for (const item of cases) {
      const pairKey = `${item.sourceForm}\u0000${item.wrongForms.join('\u0000')}`;
      if (seenPairs.has(pairKey)) {
        details.push({ ...item, duplicateFeedback: true, replacements: 0 });
        continue;
      }
      seenPairs.add(pairKey);
      const result = restoreReportedChange(history.original_text || '', nextText, item.sourceForm, item.wrongForms);
      nextText = result.text;
      details.push({
        ...item,
        replacements: result.replacements.length,
        originalCount: result.originalCount,
        candidateCount: result.candidateCount
      });
    }
    plans.push({ history, cases, details, oldText: history.corrected_text || '', newText: nextText });
  }
  return plans;
}

async function fetchRows(supabase, table, select, ids, idColumn = 'id') {
  const rows = [];
  for (let index = 0; index < ids.length; index += 100) {
    const { data, error } = await supabase.from(table).select(select).in(idColumn, ids.slice(index, index + 100));
    if (error) throw new Error(error.message);
    rows.push(...(data || []));
  }
  return rows;
}

async function applyPlan(supabase, plan) {
  if (plan.oldText === plan.newText) return false;
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
  if (logError) {
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
  return true;
}

async function closeFeedback(supabase, feedbacks, changedCount, publicCount) {
  const now = new Date().toISOString();
  const resolutionNote = [
    'Kaynak metni değiştiren yanlış AI dönüşümleri engellendi.',
    `${changedCount} kayıt kaynak biçimine kontrollü olarak döndürüldü.`,
    `${publicCount} canlı kayıt ve arama indeksi yenilendi.`,
    'Zaten doğru olan kayıtlar değiştirilmeden doğrulandı.'
  ].join(' ');

  const byUser = new Map();
  for (const feedback of feedbacks) {
    if (!feedback.user_id) continue;
    if (!byUser.has(feedback.user_id)) byUser.set(feedback.user_id, []);
    byUser.get(feedback.user_id).push(feedback);
  }
  const notices = [...byUser.entries()].map(([userId, items]) => ({
    type: 'feedback_resolution',
    message: `Gönderdiğiniz ${items.length} geri bildirim incelendi. Bildirdiğiniz yanlış dönüşümler tekrar oluşmayacak şekilde denetim kurallarına eklendi; ilgili kayıtlar kaynak metinle karşılaştırılarak düzeltildi. Canlı kayıt ve arama indeksi bulunan içerikler de yenilendi. Dikkatli bildiriminiz için teşekkür ederiz.`,
    user_id: userId,
    history_id: items[0].history_id || null,
    score: items[0].score || null,
    read: false,
    feedback_status: 'notice',
    resolution_group: RESOLUTION_GROUP,
    resolution_note: resolutionNote
  }));
  const { data: existingNotices, error: existingNoticeError } = await supabase.from('alerts')
    .select('user_id')
    .eq('type', 'feedback_resolution')
    .eq('resolution_group', RESOLUTION_GROUP);
  if (existingNoticeError) throw new Error(existingNoticeError.message);
  const notifiedUsers = new Set((existingNotices || []).map(item => item.user_id).filter(Boolean));
  const missingNotices = notices.filter(item => !notifiedUsers.has(item.user_id));
  if (missingNotices.length) {
    const { error } = await supabase.from('alerts').insert(missingNotices);
    if (error) throw new Error(error.message);
  }
  const { error: feedbackError } = await supabase.from('alerts').update({
    read: true,
    feedback_status: 'resolved',
    resolved_at: now,
    resolved_by: ACTOR,
    resolution_group: RESOLUTION_GROUP,
    resolution_note: resolutionNote
  }).in('id', feedbacks.map(row => row.id)).eq('type', 'feedback');
  if (feedbackError) throw new Error(feedbackError.message);

  const { data: existingResolution, error: existingResolutionError } = await supabase
    .from('issue_resolution_log')
    .select('id')
    .eq('resolution_group', RESOLUTION_GROUP)
    .limit(1)
    .maybeSingle();
  if (existingResolutionError) throw new Error(existingResolutionError.message);
  if (!existingResolution) {
    const { error: resolutionError } = await supabase.from('issue_resolution_log').insert({
      resolution_group: RESOLUTION_GROUP,
      title: 'Kaynak metin bütünlüğü geri bildirimleri',
      summary: resolutionNote,
      status: 'applied',
      feedback_count: feedbacks.length,
      user_count: byUser.size,
      created_by: ACTOR
    });
    if (resolutionError) throw new Error(resolutionError.message);
  }

  const { data: existingAdminLog, error: existingAdminLogError } = await supabase
    .from('admin_action_log')
    .select('id')
    .eq('action', 'feedback.bulk_resolved')
    .eq('target_id', RESOLUTION_GROUP)
    .limit(1)
    .maybeSingle();
  if (existingAdminLogError) throw new Error(existingAdminLogError.message);
  if (!existingAdminLog) {
    const { error: adminLogError } = await supabase.from('admin_action_log').insert({
      actor_username: 'system-maintenance',
      actor_name: ACTOR,
      actor_role: 'super_admin',
      action: 'feedback.bulk_resolved',
      action_label: 'Geri bildirimleri toplu çözdü',
      target_type: 'feedback_batch',
      target_id: RESOLUTION_GROUP,
      target_label: 'Kaynak metin bütünlüğü geri bildirimleri',
      target_status_before: 'open',
      target_status_after: 'resolved',
      summary: `${feedbacks.length} geri bildirim çözüldü; ${changedCount} kayıt düzeltildi; ${publicCount} canlı kayıt yenilendi.`,
      metadata: {
        feedbackCount: feedbacks.length,
        userCount: byUser.size,
        changedHistoryCount: changedCount,
        refreshedPublicCount: publicCount,
        historyIds: [...new Set(feedbacks.map(row => row.history_id).filter(Boolean))]
      }
    });
    if (adminLogError) throw new Error(adminLogError.message);
  }
}

async function main() {
  const apply = process.argv.includes('--apply');
  const supabase = createClient(requiredEnv('SUPABASE_URL'), requiredEnv('SUPABASE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const historyIds = [...new Set(CASES.map(item => item.historyId))];
  const feedbackIds = CASES.map(item => item.feedbackId);
  const [histories, feedbacks] = await Promise.all([
    fetchRows(supabase, 'history', 'id,original_text,corrected_text,status,version,updated_at', historyIds),
    fetchRows(supabase, 'alerts', 'id,user_id,history_id,score,feedback_status', feedbackIds)
  ]);
  if (histories.length !== historyIds.length) throw new Error(`Beklenen ${historyIds.length} kaydın ${histories.length} tanesi bulundu.`);
  if (feedbacks.length !== feedbackIds.length) throw new Error(`Beklenen ${feedbackIds.length} bildirimin ${feedbacks.length} tanesi bulundu.`);
  const unresolved = feedbacks.filter(row => row.feedback_status !== 'resolved');
  if (!apply && unresolved.length !== CASES.length) throw new Error(`Açık bildirim sayısı değişti: ${unresolved.length}/${CASES.length}`);
  if (apply && !unresolved.length) {
    console.log(JSON.stringify({ mode: 'apply', alreadyApplied: true, feedbacks: feedbacks.length }));
    return;
  }

  const plans = buildPlans(histories);
  const changedPlans = plans.filter(plan => plan.oldText !== plan.newText);
  const unresolvedDetails = plans.flatMap(plan => plan.details).filter(item => !item.duplicateFeedback && item.replacements === 0);
  const report = {
    mode: apply ? 'apply' : 'dry-run',
    feedbacks: feedbacks.length,
    histories: histories.length,
    changedHistories: changedPlans.length,
    replacements: plans.flatMap(plan => plan.details).reduce((sum, item) => sum + Number(item.replacements || 0), 0),
    unchangedOrAlreadyCorrect: unresolvedDetails.length,
    details: plans.flatMap(plan => plan.details).map(item => ({
      feedbackId: item.feedbackId,
      historyId: item.historyId,
      sourceForm: item.sourceForm,
      replacements: item.replacements,
      originalCount: item.originalCount,
      candidateCount: item.candidateCount,
      duplicateFeedback: Boolean(item.duplicateFeedback)
    }))
  };
  console.log(JSON.stringify(report, null, 2));
  if (!apply) return;

  let changedCount = 0;
  for (const plan of changedPlans) {
    if (await applyPlan(supabase, plan)) changedCount += 1;
  }

  const app = require('../server');
  await app.maintenance.ready();
  let publicCount = 0;
  // Önceki bir çalıştırma history güncellemesinden sonra kesilmiş olsa bile public
  // kayıtlar yeniden üretilsin. Yayında olmayan onaylı kayıtlar publisher tarafından atlanır.
  for (const plan of plans.filter(item => item.history.status === 'onaylandi')) {
    const result = await app.maintenance.publishApprovedHistoryRecord(plan.history.id);
    if (!result?.skipped) publicCount += 1;
  }
  await closeFeedback(supabase, unresolved, changedCount, publicCount);
  console.log(JSON.stringify({ complete: true, changedCount, publicCount, resolvedFeedbacks: unresolved.length }));
}

if (require.main === module) {
  main().catch(error => {
    console.error(`Geri bildirim uzlaştırması tamamlanamadı: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = {
  buildPlans,
  candidateWrongPositions,
  positionsOf,
  restoreReportedChange
};
