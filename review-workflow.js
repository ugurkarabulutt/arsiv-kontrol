const express = require('express');
const { randomUUID } = require('node:crypto');
const { analysisState, analyzeReviewPair, analysisHash, REVIEW_PART_SIZE, reviewAnalysisParts, analysisPartToken, completedAnalysisParts } = require('./review-analysis');
const { STATUSES, MEMBER_BUCKETS, UUID, workspaceFor, canReadRecord, recordActions, cleanPayload, memberDisplayStatus, duplicateIdFromError } = require('./review-policy');
const { reviewSearchTerms } = require('./public-search-core');

const ERRORS = {
  OPENAI_API_CREDITS_EXHAUSTED: [503, 'OpenAI API kontrolü gerekli: API bakiyesi veya kullanım limiti tükenmiş görünüyor. Metniniz ve tamamlanan bölümler korunuyor; bakiye yüklendikten sonra yeniden deneyin.'],
  ANALYSIS_PARTS_REQUIRED: [422, 'Uzun metin denetimi için sayfayı güncelleyip yeniden deneyin.'],
  ANALYSIS_PARTS_INVALID: [422, 'Denetim oturumu yenilenmeli. Metniniz korundu; yeniden denetleyin.'],
  ANALYSIS_REQUIRED: [422, 'Soru ve cevabın son hâli denetlenmedi. Soru ve Cevabı Denetle düğmesini kullanın.'],
  ANALYSIS_OUTPUT_EMPTY: [422, 'Denetim kullanılabilir metin üretmedi. Yazdığınız içerik korundu; yeniden deneyin.'],
  VERSION_CONFLICT: [409, 'Kayıt başka bir işlemle değişti. Metninizi koruyun; güncel kaydı açıp karşılaştırın.'],
  FORBIDDEN: [403, 'Bu kayıt için işlem yetkiniz yok.'],
  DRAFT_ONLY: [409, 'Yalnız taslak durumundaki kendi kaydınızı silebilirsiniz.'],
  DRAFT_PROTECTED: [403, 'Bu kaydın düzeltme veya yayın geçmişi var. Ekip üyesi tarafından silinemez.'],
  NOT_FOUND: [404, 'Kayıt bulunamadı.'],
  INVALID_STATUS: [409, 'Kayıt artık bu işleme uygun durumda değil. Güncel kaydı açın.'],
  REQUIRED_FIELDS: [400, 'Onaya göndermek için soru, etiket ve cevap eksiksiz olmalı.'],
  NOTE_REQUIRED: [400, 'İşlemin gerekçesini yazın.'],
  SELF_APPROVAL_FORBIDDEN: [403, 'Kendi gönderinizi başka bir yönetici onaylamalı.'],
  SELF_RETURN_FORBIDDEN: [403, 'Kendi kaydınız için Ekip Üyesi alanındaki Geri Çek işlemini kullanın.'],
  MANAGEMENT_WORKSPACE_REQUIRED: [403, 'Bu işlem Yönetim alanından yapılabilir.'],
  MEMBER_WORKSPACE_REQUIRED: [403, 'Kendi çalışmanızı Ekip Üyesi alanından gönderin.'],
  OWNERSHIP_REVIEW_REQUIRED: [409, 'Sahiplik itirazı yönetici tarafından sonuçlandırılmalı.'],
  EXACT_DUPLICATE: [409, 'Bu soru ve cevap için incelemede veya sonuçlanmış bir kayıt var. Yazdığınız değişiklikler bu ekranda korunuyor.'],
  NOT_EXACT_DUPLICATE: [400, 'Yönlendirme için soru ve cevapların ikisi de birebir aynı olmalı.'],
  DUPLICATE_NOT_PUBLISHED: [400, 'Yönlendirilecek asıl kayıt yayında olmalı.'],
  DUPLICATE_SELECTION_REQUIRED: [400, 'Mükerrer kararı için karşılaştırılan canlı kaydı seçin.'],
  DUPLICATE_NOTE_REQUIRED: [400, 'Mükerrer olarak kapatmak için kontrol notunda veya gerekçede MÜKERRER yazmalı.'],
  INVALID_ASSIGNEE: [400, 'Aktif bir ekip üyesi seçin.'],
  INVALID_CONTENT: [400, 'Gönderilen alanları kontrol edin.'],
  INVALID_TAGS: [400, 'Etiketleri metin olarak girin.'],
  CONTENT_TOO_LONG: [400, 'Metin veya etiket sınırı aşıldı.'],
  NOTE_TOO_LONG: [400, 'Not en fazla 1.200 karakter olabilir.'],
  INVALID_ACTION: [400, 'Geçersiz işlem.'],
  READ_ONLY: [403, 'Bu önizlemede kayıt değişiklikleri kapalı. Canlı kayıtlar korunuyor.'],
};
const LIST_COLUMNS = 'id,user_id,assignee_id,username,name,filename,score,total_errors,status,created_at,updated_at,version,question_text,tags,submission_note,disputed:workflow_meta->disputed,return_note:workflow_meta->>returnNote,analysis_status:workflow_meta->analysisReceipt->>state';
const PREVIEW_COLUMNS = 'id,user_id,username,name,filename,score,total_errors,status,created_at,updated_at,question_text,tags,submission_note';
const QUEUE_COLUMNS = LIST_COLUMNS + ',submitted_at,submitted_by,status_changed_at,status_changed_by,queue_sort_at';
const SUBMITTED_APPROVAL_STATUSES = new Set(['bekliyor','teyit_bekliyor','dergah_sorulari','konferanslar','arsivlendi','onaylandi','reddedildi']);
const CHANGE_SUMMARY_FIELDS = [
  ['question_text', 'Soru'],
  ['corrected_text', 'Cevap'],
  ['tags', 'Etiketler'],
  ['submission_note', 'Ekip üyesi açıklaması']
];

function comparableReviewValue(value) {
  if (Array.isArray(value)) return JSON.stringify(value.map(item => String(item || '').trim()));
  return String(value || '').replace(/\r\n?/g, '\n').trim();
}

function reviewChangeSummary(current, returnedRevision, submittedRevision, actorNames = new Map()) {
  if (!returnedRevision) return { hasReturn: false, changes: [] };
  const returnedSnapshot = returnedRevision.after_data || {};
  const returnMeta = returnedSnapshot.workflow_meta || {};
  const currentMeta = current.workflow_meta || {};
  const resubmitted = Boolean(submittedRevision && submittedRevision.version > returnedRevision.version);
  const comparedSnapshot = resubmitted ? (submittedRevision.after_data || current) : current;
  const changes = CHANGE_SUMMARY_FIELDS.flatMap(([key, label]) => {
    const before = returnedSnapshot[key] ?? (key === 'tags' ? [] : '');
    const after = comparedSnapshot[key] ?? (key === 'tags' ? [] : '');
    return comparableReviewValue(before) === comparableReviewValue(after)
      ? []
      : [{ key, label, before, after }];
  });
  return {
    hasReturn: true,
    resubmitted,
    return: {
      note: returnMeta.returnNote || currentMeta.lastReturnNote || currentMeta.returnNote || '',
      actorName: actorNames.get(returnedRevision.actor_id) || returnMeta.returnedBy || 'Yönetici',
      at: returnedRevision.created_at,
      version: returnedRevision.version
    },
    submission: resubmitted ? {
      actorName: actorNames.get(submittedRevision.actor_id) || 'Ekip üyesi',
      at: submittedRevision.created_at,
      version: submittedRevision.version
    } : null,
    memberNote: comparedSnapshot.submission_note || '',
    changes
  };
}

function createReviewWorkflow({ supabase, mapHistory, loadApprovalReturnNotes, attachApprovalReturnMeta, clearPublicArchiveCaches, analyzeText, analysisRateLimiter, analysisPartRateLimiter = analysisRateLimiter, analysisSigningKey = randomUUID(), loadApprovalFavoriteSet = async () => new Set(), publishApprovedHistoryRecord = async () => null, readOnly = false }) {
  const router = express.Router();
  const userFor = req => ({ id: req.session.userId, role: req.session.role });
  const spaceFor = req => workspaceFor(userFor(req), req.get('X-Review-Workspace') || req.query.workspace);
  async function fail(req, res, error) {
    const code = Object.keys(ERRORS).find(key => error.code === key || String(error.message || error).includes(key));
    const missingMigration = /version|review_history_change|workflow_meta|history_revisions|review_history_queue/.test(error.message || '') && ['42703', 'PGRST202', 'PGRST205', '42P01'].includes(error.code);
    const providerUnavailable = [502,503,504,429].includes(error.statusCode);
    const [status, message] = ERRORS[code] || (providerUnavailable
      ? [error.statusCode, 'Denetim servisi bu bölümü tamamlayamadı. Metniniz ve tamamlanan bölümler korunuyor; yeniden deneyin.']
      : missingMigration
      ? [503, 'İnceleme altyapısı henüz hazır değil. Lütfen yöneticinize bildirin.']
      : [500, 'İşlem tamamlanamadı. Değişikliklerinizi koruyup tekrar deneyin.']);
    if (status === 500) console.error('Review workflow:', error.message);
    let duplicate;
    if (code === 'EXACT_DUPLICATE') {
      const id = duplicateIdFromError(error);
      if (id) {
        try {
          const row = await read(req, id);
          duplicate = { id: row.id, displayStatus: memberDisplayStatus(row.status) };
        } catch { /* A match must never expose a different member's private record. */ }
      }
    }
    return res.status(status).json({ error: message, code: code || (providerUnavailable ? 'ANALYSIS_TEMPORARY_FAILURE' : missingMigration ? 'MIGRATION_REQUIRED' : 'REVIEW_FAILED'), duplicate });
  }
  const handler = fn => async (req, res) => { try { await fn(req, res); } catch (error) { await fail(req, res, error); } };

  async function read(req, id) {
    if (!UUID.test(id || '')) throw new Error('NOT_FOUND');
    const { data, error } = await supabase.from('history').select('*').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!canReadRecord(userFor(req), data, spaceFor(req))) throw new Error('NOT_FOUND');
    return data;
  }
  async function present(req, rows) {
    const ids = rows.map(row => row.id);
    const draftIds = rows.filter(row => row.status === 'taslak').map(row => row.id);
    const protections = !readOnly && draftIds.length
      ? await supabase.rpc('review_draft_protections', { p_ids: draftIds }) : { data: [] };
    if (protections.error) throw protections.error;
    const protectedDrafts = new Map((protections.data || []).map(row => [row.id, row.member_delete_protected]));
    const { data: published, error } = ids.length ? await supabase.from('public_qa').select('slug,status,source_history_id').in('source_history_id', ids) : { data: [] };
    if (error) throw error;
    const publication = new Map((published || []).map(row => [row.source_history_id, row]));
    const notes = await loadApprovalReturnNotes();
    const favorites = spaceFor(req) === 'management' ? await loadApprovalFavoriteSet(req.session.userId) : new Set();
    const assigneeIds = [...new Set(rows.flatMap(row => [row.assignee_id, row.submitted_by]).filter(Boolean))];
    const assignees = assigneeIds.length ? await supabase.from('users').select('id,name').in('id', assigneeIds) : { data: [] };
    if (assignees.error) throw assignees.error;
    const names = new Map((assignees.data || []).map(user => [user.id, user.name]));
    return rows.map(row => {
      const result = attachApprovalReturnMeta(mapHistory(row), notes);
      const meta = row.workflow_meta || { disputed: row.disputed === true, returnNote: row.return_note };
      const quality = Object.hasOwn(row, 'corrected_text') ? analysisState(row) : { state: row.analysis_status || 'required' };
      return { ...result, quality, version: row.version ?? 0, updatedAt: row.updated_at, assigneeId: row.assignee_id, assigneeName: names.get(row.assignee_id) || '',
        submittedAt: row.submitted_at || null, submittedBy: row.submitted_by || null, submittedByName: names.get(row.submitted_by) || '',
        queueAt: row.queue_sort_at || row.updated_at || row.created_at,
        favorite: favorites.has(row.id), workflow: meta, returnNote: row.status === 'geri_gonderildi' ? (meta.returnNote ?? result.returnNote) : '',
        allowedActions: recordActions(userFor(req), { ...row, member_delete_protected: protectedDrafts.get(row.id) ?? true }, spaceFor(req)), publication: publication.get(row.id) || null,
        displayStatus: spaceFor(req) === 'member' ? memberDisplayStatus(row.status) : '' };
    });
  }
  async function change(req, id, action, payload, version) {
    if (readOnly) throw new Error('READ_ONLY');
    if (!UUID.test(id || '')) throw new Error('NOT_FOUND');
    if (!Number.isInteger(version) || version < 0) throw new Error('VERSION_CONFLICT');
    const previous = ['approve','duplicate_clear'].includes(action) ? await read(req, id) : null;
    const { data, error } = await supabase.rpc('review_history_change', {
      p_id: id, p_actor: req.session.userId, p_version: version, p_workspace: spaceFor(req), p_action: action, p_payload: payload
    });
    if (error) throw error;
    if (['approve','duplicate_clear'].includes(action) && data.status === 'onaylandi') {
      try {
        await publishApprovedHistoryRecord(data);
      } catch (publishError) {
        if (previous) {
          await supabase.from('history').update({
            status: previous.status,
            approved_at: previous.approved_at,
            approved_by: previous.approved_by,
            workflow_meta: previous.workflow_meta
          }).eq('id', data.id);
        }
        clearPublicArchiveCaches();
        throw publishError;
      }
    }
    clearPublicArchiveCaches();
    return (await present(req, [data]))[0];
  }

  router.get('/records', handler(async (req, res) => {
    const space = spaceFor(req);
    const status = String(req.query.status || (space === 'management' ? 'bekliyor' : 'todo'));
    const page = Math.max(1, Math.min(10000, parseInt(req.query.page, 10) || 1));
    const pageSize = 25;
    const searchTerms = reviewSearchTerms(req.query.q);
    const memberStatuses = MEMBER_BUCKETS[status];
    if (space === 'member' && !memberStatuses) throw new Error('INVALID_STATUS');
    if (space === 'management' && !['all','disputed','analysis_required'].includes(status) && !STATUSES.includes(status)) throw new Error('INVALID_STATUS');
    const submissionOrder = status === 'bekliyor' && !readOnly;
    let query = supabase.from(readOnly ? 'history' : 'review_history_queue')
      .select(readOnly ? PREVIEW_COLUMNS : QUEUE_COLUMNS, { count: 'exact' })
      .not('status', 'in', '(chunk_draft,submitted_part)');
    if (space === 'member') query = (readOnly ? query.eq('user_id',req.session.userId) : query.or(`user_id.eq.${req.session.userId},assignee_id.eq.${req.session.userId}`)).neq('status', 'copte');
    else query = query.neq('status', 'taslak');
    if (status === 'disputed' && readOnly) return res.json({ items: [], count: 0, page, pageSize, workspace: space });
    if (space === 'member') {
      query = query.in('status', memberStatuses);
      // A reported ownership mismatch remains available to management, but it
      // is no longer an active editing task for the reporting member.
      if (status === 'todo') query = query.or('workflow_meta->>disputed.is.null,workflow_meta->>disputed.neq.true');
    }
    else if (status === 'analysis_required') query = query.in('status', ['bekliyor','teyit_bekliyor','geri_gonderildi','dergah_sorulari','konferanslar'])
      .or('workflow_meta->analysisReceipt.is.null,workflow_meta->analysisReceipt->>state.neq.ready');
    else if (status === 'disputed') query = query.eq('workflow_meta->>disputed', 'true').neq('status', 'copte');
    else if (status !== 'all') query = query.eq('status', status);
    else query = query.neq('status', 'copte');
    for (const term of searchTerms) query = query.ilike('review_search_text', `%${term}%`);
    // Sort the whole filtered queue in PostgreSQL, before selecting a page.
    if (submissionOrder) query = query.order('approval_sort_at', { ascending: false, nullsFirst: false });
    else query = query.order(readOnly ? 'updated_at' : 'queue_sort_at', { ascending: false, nullsFirst: false });
    const { data, error, count } = await query.order('created_at', { ascending: false }).order('id', { ascending: false }).range((page - 1) * pageSize, page * pageSize - 1);
    if (error) throw error;
    res.json({ items: await present(req, data || []), count, page, pageSize, workspace: space });
  }));
  router.get('/assignees', handler(async (req, res) => {
    if (spaceFor(req) !== 'management') throw new Error('FORBIDDEN');
    const { data, error } = await supabase.from('users').select('id,name,username').eq('active', true).order('name');
    if (error) throw error;
    res.json({ items: data || [] });
  }));
  router.get('/:id/revisions', handler(async (req, res) => {
    await read(req, req.params.id);
    if (readOnly) return res.json({ items: [], nextVersion: null, preview: true });
    let query = supabase.from('history_revisions').select('version,action,actor_id,created_at,before_data,after_data')
      .eq('history_id', req.params.id).order('version', { ascending: false }).limit(20);
    const before = parseInt(req.query.beforeVersion, 10);
    if (Number.isInteger(before) && before > 0) query = query.lt('version', before);
    const { data, error } = await query;
    if (error) throw error;
    const actorIds = [...new Set((data || []).map(row => row.actor_id).filter(Boolean))];
    const actors = actorIds.length ? await supabase.from('users').select('id,name').in('id', actorIds) : { data: [] };
    if (actors.error) throw actors.error;
    const names = new Map((actors.data || []).map(user => [user.id, user.name]));
    res.json({ items: (data || []).map(row => ({ ...row, actorName: names.get(row.actor_id) || 'Sistem' })), nextVersion: data?.length === 20 ? data.at(-1).version : null });
  }));
  router.get('/:id/change-summary', handler(async (req, res) => {
    const current = await read(req, req.params.id);
    if (readOnly) return res.json({ hasReturn: false, changes: [], preview: true });
    const revisionFields = 'version,actor_id,created_at,before_data,after_data';
    const [returnedResult, submittedResult] = await Promise.all([
      supabase.from('history_revisions').select(revisionFields).eq('history_id', current.id).eq('action', 'return').order('version', { ascending: false }).limit(1).maybeSingle(),
      supabase.from('history_revisions').select(revisionFields).eq('history_id', current.id).eq('action', 'submit').order('version', { ascending: false }).limit(1).maybeSingle()
    ]);
    if (returnedResult.error) throw returnedResult.error;
    if (submittedResult.error) throw submittedResult.error;
    const actorIds = [...new Set([returnedResult.data?.actor_id, submittedResult.data?.actor_id].filter(Boolean))];
    const actors = actorIds.length ? await supabase.from('users').select('id,name').in('id', actorIds) : { data: [] };
    if (actors.error) throw actors.error;
    const names = new Map((actors.data || []).map(user => [user.id, user.name]));
    res.json(reviewChangeSummary(current, returnedResult.data, submittedResult.data, names));
  }));
  router.get('/:id/duplicates', handler(async (req, res) => {
    if (spaceFor(req) !== 'management') throw new Error('FORBIDDEN');
    await read(req, req.params.id);
    if (readOnly) return res.json({ items: [], preview: true });
    const { data, error } = await supabase.rpc('review_duplicate_candidates', { p_id: req.params.id });
    if (error) throw error;
    res.json({ items: data || [] });
  }));
  router.get('/:id([0-9a-fA-F-]{36})', handler(async (req, res) => res.json((await present(req, [await read(req, req.params.id)]))[0])));
  router.post('/:id([0-9a-fA-F-]{36})/action', handler(async (req, res) => {
    if (req.body?.action === 'reanalyze') throw new Error('INVALID_ACTION');
    const item = await change(req, req.params.id, String(req.body?.action || ''), cleanPayload(req.body), req.body?.version);
    res.json({ success: true, history: item });
  }));
  async function analysisContext(req) {
    if(readOnly)throw new Error('READ_ONLY');
    const current = await read(req, req.params.id);
    if (!recordActions(userFor(req), current, spaceFor(req)).includes('reanalyze')) throw new Error('FORBIDDEN');
    if (current.version !== req.body?.version) throw new Error('VERSION_CONFLICT');
    const payload = cleanPayload(req.body);
    const question = payload.questionText ?? current.question_text;
    const answer = payload.correctedText ?? current.corrected_text;
    const sourceAnswer = !answer?.trim() && req.body?.useOriginalAnswer === true ? current.original_text : answer;
    const plan = reviewAnalysisParts(question, sourceAnswer);
    const binding = JSON.stringify([current.id, current.version, req.session.userId, spaceFor(req),
      req.body?.analysisRequestId, analysisHash(plan.input.question), analysisHash(plan.input.answer)]);
    return { current, payload, plan, binding };
  }
  router.post('/:id([0-9a-fA-F-]{36})/reanalyze-part', analysisPartRateLimiter, handler(async (req, res) => {
    const { plan, binding } = await analysisContext(req);
    const index = req.body?.partIndex;
    if (!Number.isInteger(index) || !plan.parts[index]) throw new Error('INVALID_CONTENT');
    const result = await analyzeText(plan.parts[index].text);
    res.json({ total: plan.parts.length, index, token: analysisPartToken(analysisSigningKey, binding, index, result) });
  }));
  router.post('/:id([0-9a-fA-F-]{36})/reanalyze', analysisRateLimiter, handler(async (req, res) => {
    if(readOnly)return res.status(403).json({error:'Bu önizlemede kayıt değişiklikleri kapalı.'});
    const current = await read(req, req.params.id);
    if (!recordActions(userFor(req), current, spaceFor(req)).includes('reanalyze')) throw new Error('FORBIDDEN');
    if (current.version !== req.body?.version) throw new Error('VERSION_CONFLICT');
    const payload = cleanPayload(req.body);
    const question = payload.questionText ?? current.question_text;
    const answer = payload.correctedText ?? current.corrected_text;
    const sourceAnswer = !answer?.trim() && req.body?.useOriginalAnswer === true ? current.original_text : answer;
    let result;
    if (req.body?.analysisTokens) {
      const { plan, binding } = await analysisContext(req);
      result = completedAnalysisParts(analysisSigningKey, binding, plan, req.body.analysisTokens);
    } else {
      if (question?.length > REVIEW_PART_SIZE || sourceAnswer?.length > REVIEW_PART_SIZE) throw new Error('ANALYSIS_PARTS_REQUIRED');
      result = await analyzeReviewPair(analyzeText, question, sourceAnswer);
    }
    result.analysisReceipt.requestId = UUID.test(req.body?.analysisRequestId || '') ? req.body.analysisRequestId : randomUUID();
    const item = await change(req, current.id, 'reanalyze', { ...payload, ...result }, current.version);
    res.json({ success: true, history: item });
  }));

  // Old open tabs must not bypass the same transition/version rules.
  const legacy = express.Router();
  legacy.get('/:id([0-9a-fA-F-]{36})', handler(async (req, res) => res.json((await present(req, [await read(req, req.params.id)]))[0])));
  legacy.post('/:id([0-9a-fA-F-]{36})/:action(content|submit|withdraw|approve|reject|review|dergah|conference|pending|return|archive|tags)', handler(async (req, res) => {
    const action = { content: 'save', tags: 'save' }[req.params.action] || req.params.action;
    if (action === 'submit') {
      const current = await read(req, req.params.id);
      const status = current.status || 'bekliyor';
      if (SUBMITTED_APPROVAL_STATUSES.has(status)) {
        const item = (await present(req, [current]))[0];
        return res.json({ success: true, id: item.id, status: item.status, alreadySubmitted: true, tags: item.tags, questionText: item.questionText, submissionNote: item.submissionNote, version: item.version, history: item });
      }
    }
    const item = await change(req, req.params.id, action, cleanPayload(req.body), req.body?.version);
    res.json({ success: true, id: item.id, status: item.status, tags: item.tags, questionText: item.questionText, submissionNote: item.submissionNote, version: item.version, history: item });
  }));
  legacy.post('/submit-merged', (_req, res) => res.status(409).json({ error: 'Eski gönderim ekranı açık. Metninizi koruyup sayfayı yenileyin.' }));
  return { router, legacy, change };
}

module.exports = { createReviewWorkflow, reviewChangeSummary };
