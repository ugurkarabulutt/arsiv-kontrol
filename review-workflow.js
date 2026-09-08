const express = require('express');
const { STATUSES, MEMBER_BUCKETS, UUID, workspaceFor, canReadRecord, recordActions, cleanPayload, memberDisplayStatus } = require('./review-policy');

const ERRORS = {
  VERSION_CONFLICT: [409, 'Kayıt başka bir işlemle değişti. Metninizi koruyun; güncel kaydı açıp karşılaştırın.'],
  FORBIDDEN: [403, 'Bu kayıt için işlem yetkiniz yok.'],
  NOT_FOUND: [404, 'Kayıt bulunamadı.'],
  INVALID_STATUS: [409, 'Kayıt artık bu işleme uygun durumda değil. Güncel kaydı açın.'],
  REQUIRED_FIELDS: [400, 'Onaya göndermek için soru, etiket ve cevap eksiksiz olmalı.'],
  NOTE_REQUIRED: [400, 'İşlemin gerekçesini yazın.'],
  SELF_APPROVAL_FORBIDDEN: [403, 'Kendi gönderinizi başka bir yönetici onaylamalı.'],
  SELF_RETURN_FORBIDDEN: [403, 'Kendi kaydınız için Ekip Üyesi alanındaki Geri Çek işlemini kullanın.'],
  MANAGEMENT_WORKSPACE_REQUIRED: [403, 'Bu işlem Yönetim alanından yapılabilir.'],
  MEMBER_WORKSPACE_REQUIRED: [403, 'Kendi çalışmanızı Ekip Üyesi alanından gönderin.'],
  OWNERSHIP_REVIEW_REQUIRED: [409, 'Sahiplik itirazı yönetici tarafından sonuçlandırılmalı.'],
  EXACT_DUPLICATE: [409, 'Soru ve cevabı birebir aynı olan bir kayıt zaten onay sürecinde. Kaydınız korunuyor.'],
  NOT_EXACT_DUPLICATE: [400, 'Yönlendirme için soru ve cevapların ikisi de birebir aynı olmalı.'],
  DUPLICATE_NOT_PUBLISHED: [400, 'Yönlendirilecek asıl kayıt yayında olmalı.'],
  INVALID_ASSIGNEE: [400, 'Aktif bir ekip üyesi seçin.'],
  INVALID_CONTENT: [400, 'Gönderilen alanları kontrol edin.'],
  INVALID_TAGS: [400, 'Etiketleri metin olarak girin.'],
  CONTENT_TOO_LONG: [400, 'Metin veya etiket sınırı aşıldı.'],
  NOTE_TOO_LONG: [400, 'Not en fazla 1.200 karakter olabilir.'],
  INVALID_ACTION: [400, 'Geçersiz işlem.'],
  READ_ONLY: [403, 'Bu önizlemede kayıt değişiklikleri kapalı. Canlı kayıtlar korunuyor.'],
};
const LIST_COLUMNS = 'id,user_id,assignee_id,username,name,filename,score,total_errors,status,created_at,updated_at,version,question_text,tags,submission_note,disputed:workflow_meta->disputed,return_note:workflow_meta->>returnNote';
const PREVIEW_COLUMNS = 'id,user_id,username,name,filename,score,total_errors,status,created_at,updated_at,question_text,tags,submission_note';
const QUEUE_COLUMNS = LIST_COLUMNS + ',submitted_at,submitted_by,status_changed_at,status_changed_by,queue_sort_at';

function createReviewWorkflow({ supabase, mapHistory, loadApprovalReturnNotes, attachApprovalReturnMeta, clearPublicArchiveCaches, analyzeText, analysisRateLimiter, loadApprovalFavoriteSet = async () => new Set(), readOnly = false }) {
  const router = express.Router();
  const userFor = req => ({ id: req.session.userId, role: req.session.role });
  const spaceFor = req => workspaceFor(userFor(req), req.get('X-Review-Workspace') || req.query.workspace);
  function fail(res, error) {
    const code = Object.keys(ERRORS).find(key => String(error.message || error).includes(key));
    const missingMigration = /version|review_history_change|workflow_meta|history_revisions|review_history_queue/.test(error.message || '') && ['42703', 'PGRST202', 'PGRST205', '42P01'].includes(error.code);
    const [status, message] = ERRORS[code] || (missingMigration
      ? [503, 'İnceleme altyapısı henüz hazır değil. Lütfen yöneticinize bildirin.']
      : [500, 'İşlem tamamlanamadı. Değişikliklerinizi koruyup tekrar deneyin.']);
    if (status === 500) console.error('Review workflow:', error.message);
    return res.status(status).json({ error: message, code: code || (missingMigration ? 'MIGRATION_REQUIRED' : 'REVIEW_FAILED') });
  }
  const handler = fn => async (req, res) => { try { await fn(req, res); } catch (error) { fail(res, error); } };

  async function read(req, id) {
    if (!UUID.test(id || '')) throw new Error('NOT_FOUND');
    const { data, error } = await supabase.from('history').select('*').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!canReadRecord(userFor(req), data, spaceFor(req))) throw new Error('NOT_FOUND');
    return data;
  }
  async function present(req, rows) {
    const ids = rows.map(row => row.id);
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
      return { ...result, version: row.version ?? 0, updatedAt: row.updated_at, assigneeId: row.assignee_id, assigneeName: names.get(row.assignee_id) || '',
        submittedAt: row.submitted_at || null, submittedBy: row.submitted_by || null, submittedByName: names.get(row.submitted_by) || '',
        queueAt: row.queue_sort_at || row.updated_at || row.created_at,
        favorite: favorites.has(row.id), workflow: meta, returnNote: row.status === 'geri_gonderildi' ? (meta.returnNote ?? result.returnNote) : '',
        allowedActions: recordActions(userFor(req), row, spaceFor(req)), publication: publication.get(row.id) || null,
        displayStatus: spaceFor(req) === 'member' ? memberDisplayStatus(row.status) : '' };
    });
  }
  async function change(req, id, action, payload, version) {
    if (readOnly) throw new Error('READ_ONLY');
    if (!UUID.test(id || '')) throw new Error('NOT_FOUND');
    if (!Number.isInteger(version) || version < 0) throw new Error('VERSION_CONFLICT');
    const { data, error } = await supabase.rpc('review_history_change', {
      p_id: id, p_actor: req.session.userId, p_version: version, p_workspace: spaceFor(req), p_action: action, p_payload: payload
    });
    if (error) throw error;
    clearPublicArchiveCaches();
    return (await present(req, [data]))[0];
  }

  router.get('/records', handler(async (req, res) => {
    const space = spaceFor(req);
    const status = String(req.query.status || (space === 'management' ? 'bekliyor' : 'todo'));
    const page = Math.max(1, Math.min(10000, parseInt(req.query.page, 10) || 1));
    const pageSize = 25;
    const term = String(req.query.q || '').trim().replace(/[%,()\\]/g, ' ').replace(/\s+/g, ' ').slice(0, 120);
    const memberStatuses = MEMBER_BUCKETS[status];
    if (space === 'member' && !memberStatuses) throw new Error('INVALID_STATUS');
    if (space === 'management' && status !== 'all' && status !== 'disputed' && !STATUSES.includes(status)) throw new Error('INVALID_STATUS');
    const submissionOrder = status === 'bekliyor' && !readOnly;
    let query = supabase.from(readOnly ? 'history' : 'review_history_queue')
      .select(readOnly ? PREVIEW_COLUMNS : QUEUE_COLUMNS, { count: 'exact' })
      .not('status', 'in', '(chunk_draft,submitted_part)');
    if (space === 'member') query = (readOnly ? query.eq('user_id',req.session.userId) : query.or(`user_id.eq.${req.session.userId},assignee_id.eq.${req.session.userId}`)).neq('status', 'copte');
    else query = query.neq('status', 'taslak');
    if (status === 'disputed' && readOnly) return res.json({ items: [], count: 0, page, pageSize, workspace: space });
    if (space === 'member') query = query.in('status', memberStatuses);
    else if (status === 'disputed') query = query.eq('workflow_meta->>disputed', 'true').neq('status', 'copte');
    else if (status !== 'all') query = query.eq('status', status);
    else query = query.neq('status', 'copte');
    if (term) query = query.or(['question_text', 'corrected_text', 'name', 'filename', 'submission_note'].map(field => `${field}.ilike.%${term}%`).join(','));
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
  router.post('/:id([0-9a-fA-F-]{36})/reanalyze', analysisRateLimiter, handler(async (req, res) => {
    if(readOnly)return res.status(403).json({error:'Bu önizlemede kayıt değişiklikleri kapalı.'});
    const current = await read(req, req.params.id);
    if (!recordActions(userFor(req), current, spaceFor(req)).includes('reanalyze')) throw new Error('FORBIDDEN');
    if (current.version !== req.body?.version) throw new Error('VERSION_CONFLICT');
    const payload = cleanPayload(req.body);
    const text = payload.correctedText ?? current.corrected_text;
    if (!text || text.length > 200000) throw new Error('CONTENT_TOO_LONG');
    const result = await analyzeText(text);
    if (!result.correctedText) return res.status(422).json({ error: 'Denetim kullanılabilir bir düzeltilmiş metin üretmedi. Mevcut cevabınız değiştirilmedi.' });
    const item = await change(req, current.id, 'reanalyze', { ...payload, correctedText: result.correctedText,
      analysisInput: text, score: result.score, totalErrors: result.totalErrors,
      catCounts: Object.fromEntries(Object.entries(result.categories || {}).map(([key, value]) => [key, value.count || 0])), summary: result.summary || '' }, current.version);
    res.json({ success: true, history: item });
  }));

  // Old open tabs must not bypass the same transition/version rules.
  const legacy = express.Router();
  legacy.get('/:id([0-9a-fA-F-]{36})', handler(async (req, res) => res.json((await present(req, [await read(req, req.params.id)]))[0])));
  legacy.post('/:id([0-9a-fA-F-]{36})/:action(content|submit|withdraw|approve|reject|review|pending|return|archive|tags)', handler(async (req, res) => {
    const action = { content: 'save', tags: 'save' }[req.params.action] || req.params.action;
    const item = await change(req, req.params.id, action, cleanPayload(req.body), req.body?.version);
    res.json({ success: true, id: item.id, status: item.status, tags: item.tags, questionText: item.questionText, submissionNote: item.submissionNote, version: item.version, history: item });
  }));
  legacy.post('/submit-merged', (_req, res) => res.status(409).json({ error: 'Eski gönderim ekranı açık. Metninizi koruyup sayfayı yenileyin.' }));
  return { router, legacy, change };
}

module.exports = { createReviewWorkflow };
