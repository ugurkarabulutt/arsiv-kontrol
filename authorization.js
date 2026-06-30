const ROLES = Object.freeze({
  USER: 'user',
  ADMIN: 'admin',
  SUPER_ADMIN: 'super_admin'
});

const SUPER_ADMIN_USERNAME = 'admin';

function isReservedSuperAdminUsername(username) {
  return String(username || '').trim().toLowerCase() === SUPER_ADMIN_USERNAME;
}

function effectiveRole(username, storedRole) {
  if (isReservedSuperAdminUsername(username)) return ROLES.SUPER_ADMIN;
  if (storedRole === ROLES.SUPER_ADMIN) return ROLES.ADMIN;
  if (storedRole === ROLES.ADMIN) return ROLES.ADMIN;
  return ROLES.USER;
}

function isAdminRole(role) {
  return role === ROLES.ADMIN || role === ROLES.SUPER_ADMIN;
}

function isSuperAdminRole(role) {
  return role === ROLES.SUPER_ADMIN;
}

function isAssignableRole(role) {
  return role === ROLES.USER || role === ROLES.ADMIN;
}

module.exports = {
  ROLES,
  SUPER_ADMIN_USERNAME,
  effectiveRole,
  isAdminRole,
  isAssignableRole,
  isReservedSuperAdminUsername,
  isSuperAdminRole
};
