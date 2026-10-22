const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const UUID_PART = '[0-9a-f-]{36}';

function normalizedApiPath(value = '') {
  return String(value || '').split('?')[0].replace(/\/+$/, '') || '/';
}

function cleanRequiredActionNote(body = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return '';
  for (const key of ['adminActionNote', 'actionNote', 'adminNote', 'note']) {
    if (!Object.prototype.hasOwnProperty.call(body, key)) continue;
    const note = String(body[key] || '').normalize('NFC').replace(/\s+/g, ' ').trim().slice(0, 1200);
    if (note) return note;
  }
  return '';
}

function decodeAdminActionNoteHeader(value = '') {
  const raw = String(value || '').trim();
  if (!raw.startsWith('b64:')) return raw;
  try {
    return Buffer.from(raw.slice(4), 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function isApprovalAction(method, path, body = {}) {
  if (method !== 'POST') return false;
  if (new RegExp(`^/api/history/${UUID_PART}/approve$`, 'i').test(path)) return true;
  return new RegExp(`^/api/review/${UUID_PART}/action$`, 'i').test(path)
    && String(body?.action || '').trim() === 'approve';
}

function isTechnicalReviewAction(method, path) {
  if (method !== 'POST') return false;
  return new RegExp(`^/api/review/${UUID_PART}/reanalyze(?:-part)?$`, 'i').test(path);
}

function isMemberWorkflowAction(method, path, body = {}, context = {}) {
  if (method !== 'POST') return false;

  // These endpoints can only create, submit or withdraw the signed-in
  // person's own work. An admin account using the member workflow must not be
  // treated as if it were making a management decision.
  if (path === '/api/history/merged-draft' || path === '/api/history/submit-merged') return true;
  if (new RegExp(`^/api/history/${UUID_PART}/(?:submit|withdraw)$`, 'i').test(path)) return true;

  const memberWorkspace = context.reviewWorkspacesEnabled === true
    && String(context.workspace || '').trim() === 'member';
  if (!memberWorkspace) return false;
  if (new RegExp(`^/api/history/${UUID_PART}/content$`, 'i').test(path)) return true;
  return new RegExp(`^/api/review/${UUID_PART}/(?:action|reanalyze)$`, 'i').test(path);
}

function requiresAdminActionNote(methodValue, pathValue, body = {}, context = {}) {
  const method = String(methodValue || '').toUpperCase();
  const path = normalizedApiPath(pathValue);
  if (!MUTATING_METHODS.has(method)
    || isApprovalAction(method, path, body)
    || isTechnicalReviewAction(method, path)
    || isMemberWorkflowAction(method, path, body, context)) return false;

  if (/^\/api\/users(?:\/|$)/.test(path)) return true;
  if (/^\/api\/rules(?:\/|$)/.test(path)) return true;
  if (method === 'POST' && path === '/api/standards') return true;
  if (/^\/api\/public-archive(?:\/|$)/.test(path)) return true;
  if (/^\/api\/archive-ops(?:\/|$)/.test(path)) return true;
  if (/^\/api\/newsletter\/admin(?:\/|$)/.test(path)) return true;
  if (/^\/api\/correction-packages(?:\/|$)/.test(path)) return true;
  if (/^\/api\/history-tags(?:\/|$)/.test(path)) return true;
  if (new RegExp(`^/api/review/${UUID_PART}/action$`, 'i').test(path)) return true;
  if (new RegExp(`^/api/history/${UUID_PART}/(?:content|reject|review|dergah|conference|pending|return|archive|tags)$`, 'i').test(path)) return true;
  if (/^\/api\/alerts\/(?:[^/]+\/respond|resolve-bulk)$/.test(path)) return true;
  if (method === 'POST' && path === '/api/ai/reports/generate') return true;
  return false;
}

function validAdminActionNote(note) {
  const cleaned = String(note || '').normalize('NFC').replace(/\s+/g, ' ').trim();
  return cleaned.length >= 3 && /[\p{L}\p{N}]/u.test(cleaned);
}

module.exports = {
  cleanRequiredActionNote,
  decodeAdminActionNoteHeader,
  isApprovalAction,
  isTechnicalReviewAction,
  isMemberWorkflowAction,
  normalizedApiPath,
  requiresAdminActionNote,
  validAdminActionNote
};
