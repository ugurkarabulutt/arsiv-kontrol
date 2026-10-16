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

function isApprovalAction(method, path, body = {}) {
  if (method !== 'POST') return false;
  if (new RegExp(`^/api/history/${UUID_PART}/approve$`, 'i').test(path)) return true;
  return new RegExp(`^/api/review/${UUID_PART}/action$`, 'i').test(path)
    && String(body?.action || '').trim() === 'approve';
}

function requiresAdminActionNote(methodValue, pathValue, body = {}) {
  const method = String(methodValue || '').toUpperCase();
  const path = normalizedApiPath(pathValue);
  if (!MUTATING_METHODS.has(method) || isApprovalAction(method, path, body)) return false;

  if (/^\/api\/users(?:\/|$)/.test(path)) return true;
  if (/^\/api\/rules(?:\/|$)/.test(path)) return true;
  if (method === 'POST' && path === '/api/standards') return true;
  if (/^\/api\/public-archive(?:\/|$)/.test(path)) return true;
  if (/^\/api\/archive-ops(?:\/|$)/.test(path)) return true;
  if (/^\/api\/newsletter\/admin(?:\/|$)/.test(path)) return true;
  if (/^\/api\/correction-packages(?:\/|$)/.test(path)) return true;
  if (/^\/api\/history-tags(?:\/|$)/.test(path)) return true;
  if (new RegExp(`^/api/review/${UUID_PART}/(?:action|reanalyze)$`, 'i').test(path)) return true;
  if (path === '/api/history/merged-draft' || path === '/api/history/submit-merged') return true;
  if (new RegExp(`^/api/history/${UUID_PART}/(?:content|submit|withdraw|reject|review|dergah|conference|pending|return|archive|tags)$`, 'i').test(path)) return true;
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
  isApprovalAction,
  normalizedApiPath,
  requiresAdminActionNote,
  validAdminActionNote
};
