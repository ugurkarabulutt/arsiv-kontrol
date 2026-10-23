const test = require('node:test');
const assert = require('node:assert/strict');
const {
  ROLES,
  canManagePublicQuestions,
  effectiveRole,
  isAdminRole,
  isAssignableRole,
  isQuestionManagerRole,
  isReservedSuperAdminUsername,
  isSuperAdminRole
} = require('../authorization');

test('admin kullanıcı adı her zaman süper admin olur', () => {
  assert.equal(effectiveRole('admin', ROLES.USER), ROLES.SUPER_ADMIN);
  assert.equal(effectiveRole(' Admin ', ROLES.ADMIN), ROLES.SUPER_ADMIN);
  assert.equal(isReservedSuperAdminUsername('ADMIN'), true);
});

test('admin dışındaki kullanıcı super_admin yetkisi alamaz', () => {
  assert.equal(effectiveRole('yonetici', ROLES.SUPER_ADMIN), ROLES.ADMIN);
  assert.equal(isSuperAdminRole(effectiveRole('yonetici', ROLES.SUPER_ADMIN)), false);
});

test('süper admin tüm admin yetkilerini kapsar', () => {
  assert.equal(isAdminRole(ROLES.ADMIN), true);
  assert.equal(isAdminRole(ROLES.SUPER_ADMIN), true);
  assert.equal(isAdminRole(ROLES.USER), false);
  assert.equal(isAdminRole(ROLES.QUESTION_MANAGER), false);
});

test('soru yöneticisi yalnız public soru taleplerini yönetir', () => {
  assert.equal(effectiveRole('eda', ROLES.QUESTION_MANAGER), ROLES.QUESTION_MANAGER);
  assert.equal(isQuestionManagerRole(ROLES.QUESTION_MANAGER), true);
  assert.equal(canManagePublicQuestions(ROLES.QUESTION_MANAGER), true);
  assert.equal(canManagePublicQuestions(ROLES.ADMIN), true);
  assert.equal(canManagePublicQuestions(ROLES.SUPER_ADMIN), true);
  assert.equal(canManagePublicQuestions(ROLES.USER), false);
});

test('atanabilir roller super admin dışındaki uygulama rolleridir', () => {
  assert.equal(isAssignableRole(ROLES.USER), true);
  assert.equal(isAssignableRole(ROLES.QUESTION_MANAGER), true);
  assert.equal(isAssignableRole(ROLES.ADMIN), true);
  assert.equal(isAssignableRole(ROLES.SUPER_ADMIN), false);
});
