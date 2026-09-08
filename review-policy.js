const { isAdminRole } = require('./authorization');

const STATUSES = ['taslak', 'bekliyor', 'geri_gonderildi', 'teyit_bekliyor', 'onaylandi', 'reddedildi', 'arsivlendi', 'copte'];
const MEMBER_BUCKETS = {
  todo: ['taslak', 'geri_gonderildi'],
  in_review: ['bekliyor', 'teyit_bekliyor'],
  done: ['onaylandi', 'reddedildi', 'arsivlendi'],
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function workspaceFor(user, requested) {
  return isAdminRole(user?.role) && requested === 'management' ? 'management' : 'member';
}

function canReadRecord(user, row, workspace) {
  if (!row || ['chunk_draft', 'submitted_part'].includes(row.status) || / - Parça \d+\/\d+$/.test(row.filename || '')) return false;
  if (workspaceFor(user, workspace) === 'management') return true;
  return row.status !== 'copte' && (row.user_id === user?.id || row.assignee_id === user?.id);
}

function recordActions(user, row, workspace) {
  if (!canReadRecord(user, row, workspace)) return [];
  const status = row.status || 'bekliyor';
  const disputed = row.workflow_meta?.disputed === true;
  const manager = workspaceFor(user, workspace) === 'management';
  const worker = (row.assignee_id || row.user_id) === user.id;
  if (manager) {
    if (status === 'copte') return ['restore'];
    const actions = ['trash'];
    if (status === 'taslak') return actions;
    if (['bekliyor', 'teyit_bekliyor', 'geri_gonderildi'].includes(status) && !disputed) actions.push('save');
    if (['bekliyor', 'teyit_bekliyor'].includes(status) && user.id !== row.user_id && user.id !== row.assignee_id && !disputed) actions.push('approve');
    if (['bekliyor', 'teyit_bekliyor', 'onaylandi'].includes(status) && !worker) actions.push('return');
    if (disputed) return ['trash','resolve_dispute'];
    actions.push('reject', 'review', 'pending', 'archive');
    return actions.filter(action => ({reject: 'reddedildi', review: 'teyit_bekliyor', pending: 'bekliyor', archive: 'arsivlendi'}[action] !== status));
  }
  if (!worker) return [];
  if (status === 'bekliyor') return ['withdraw'];
  if (status === 'geri_gonderildi' && disputed) return [];
  if (['taslak', 'geri_gonderildi'].includes(status)) return ['save', 'submit', 'reanalyze', ...(status === 'geri_gonderildi' ? ['dispute'] : [])];
  return [];
}

function cleanPayload(input = {}) {
  const payload = {};
  for (const key of ['questionText', 'correctedText', 'submissionNote', 'note']) {
    if (Object.hasOwn(input, key)) {
      if (typeof input[key] !== 'string') throw new Error('INVALID_CONTENT');
      payload[key] = input[key].replace(/\r\n?/g, '\n');
    }
  }
  if (Object.hasOwn(input, 'tags')) {
    if (!Array.isArray(input.tags) || input.tags.some(tag => typeof tag !== 'string')) throw new Error('INVALID_TAGS');
    payload.tags = [...new Set(input.tags.map(tag => tag.trim()).filter(Boolean))];
  }
  for (const key of ['duplicateId', 'assigneeId']) {
    if (input[key]) {
      if (!UUID.test(input[key])) throw new Error('INVALID_CONTENT');
      payload[key] = input[key];
    }
  }
  if (input.reason) payload.reason = String(input.reason).slice(0, 60);
  return payload;
}

function memberDisplayStatus(status) {
  if (MEMBER_BUCKETS.todo.includes(status)) return 'Düzenlenecek';
  if (MEMBER_BUCKETS.in_review.includes(status)) return 'İncelemede';
  if (status === 'onaylandi') return 'Onaylandı';
  if (status === 'reddedildi') return 'Reddedildi';
  if (status === 'arsivlendi') return 'Arşivlendi';
  return status || '';
}

module.exports = { STATUSES, MEMBER_BUCKETS, UUID, workspaceFor, canReadRecord, recordActions, cleanPayload, memberDisplayStatus };
