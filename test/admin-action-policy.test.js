const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  cleanRequiredActionNote,
  requiresAdminActionNote,
  validAdminActionNote
} = require('../admin-action-policy');

const id = '11111111-1111-4111-8111-111111111111';

test('approval is the only review decision exempt from a required admin note', () => {
  assert.equal(requiresAdminActionNote('POST', `/api/review/${id}/action`, { action: 'approve' }), false);
  assert.equal(requiresAdminActionNote('POST', `/api/history/${id}/approve`, {}), false);
  for (const action of ['save', 'reject', 'review', 'pending', 'return', 'archive', 'trash', 'restore']) {
    assert.equal(requiresAdminActionNote('POST', `/api/review/${id}/action`, { action }), true, action);
  }
});

test('privileged mutations require a note while passive actions do not', () => {
  const required = [
    ['PUT', '/api/users/user-1'],
    ['POST', '/api/users/user-1/notify'],
    ['POST', '/api/rules/reset'],
    ['POST', '/api/standards'],
    ['POST', '/api/public-archive/sync-approved'],
    ['DELETE', '/api/archive-ops/work-items/item-1'],
    ['POST', '/api/correction-packages/pkg-1/apply'],
    ['POST', `/api/history/${id}/reject`],
    ['POST', '/api/history-tags/import/upload/start'],
    ['POST', '/api/alerts/resolve-bulk'],
    ['POST', '/api/ai/reports/generate']
  ];
  required.forEach(([method, path]) => assert.equal(requiresAdminActionNote(method, path, {}), true, `${method} ${path}`));

  const exempt = [
    ['GET', '/api/users'],
    ['POST', `/api/history/${id}/favorite`],
    ['POST', '/api/alerts/read-all'],
    ['POST', '/api/pdf'],
    ['POST', '/api/auth/logout'],
    ['POST', '/api/analyze']
  ];
  exempt.forEach(([method, path]) => assert.equal(requiresAdminActionNote(method, path, {}), false, `${method} ${path}`));
});

test('note extraction accepts explicit note fields and rejects meaningless input', () => {
  assert.equal(cleanRequiredActionNote({ adminActionNote: '  Kullanıcı talebi üzerine  ' }), 'Kullanıcı talebi üzerine');
  assert.equal(cleanRequiredActionNote({ note: 'Satır\nkontrol edildi.' }), 'Satır kontrol edildi.');
  assert.equal(cleanRequiredActionNote({ message: 'Bildirim metni not değildir.' }), '');
  assert.equal(validAdminActionNote('Düzeltme gerekli.'), true);
  assert.equal(validAdminActionNote('..'), false);
  assert.equal(validAdminActionNote('a'), false);
});

test('every privileged mutation route is guarded or intentionally passive', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const routePattern = /app\.(post|put|patch|delete)\('([^']+)'\s*,\s*auth\s*,\s*admin(?:\s*,\s*superAdmin)?/g;
  const passiveOrApproved = new Set([
    'POST /api/history/:id([0-9a-fA-F-]{36})/favorite',
    'POST /api/feedback/work-package.pdf',
    'POST /api/history/:id/approve',
    'POST /api/alerts/:id/read',
    'POST /api/alerts/read-all',
    'POST /api/ai/insight'
  ]);
  const uncovered = [];
  for (const match of source.matchAll(routePattern)) {
    const method = match[1].toUpperCase();
    const route = match[2];
    const samplePath = route
      .replace(/:id\([^)]*\)/g, id)
      .replace(/:id/g, id)
      .replace(/:[A-Za-z]+/g, 'sample');
    if (!requiresAdminActionNote(method, samplePath, { action: 'reject' })
      && !passiveOrApproved.has(`${method} ${route}`)) {
      uncovered.push(`${method} ${route}`);
    }
  }
  assert.deepEqual(uncovered, []);
});
