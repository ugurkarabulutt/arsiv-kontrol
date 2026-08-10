const test = require('node:test');
const assert = require('node:assert/strict');
const {
  ROLES,
  effectiveRole,
  isAdminRole,
  isAssignableRole,
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
});

test('yeni kullanıcılara yalnızca user veya admin atanabilir', () => {
  assert.equal(isAssignableRole(ROLES.USER), true);
  assert.equal(isAssignableRole(ROLES.ADMIN), true);
  assert.equal(isAssignableRole(ROLES.SUPER_ADMIN), false);
});
