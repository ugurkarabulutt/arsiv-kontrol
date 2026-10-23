const ROLES = Object.freeze({
  USER: 'user',
  QUESTION_MANAGER: 'question_manager',
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
  if (storedRole === ROLES.QUESTION_MANAGER) return ROLES.QUESTION_MANAGER;
  return ROLES.USER;
}

function isAdminRole(role) {
  return role === ROLES.ADMIN || role === ROLES.SUPER_ADMIN;
}

function isSuperAdminRole(role) {
  return role === ROLES.SUPER_ADMIN;
}

function isQuestionManagerRole(role) {
  return role === ROLES.QUESTION_MANAGER;
}

function canManagePublicQuestions(role) {
  return isAdminRole(role) || isQuestionManagerRole(role);
}

function isAssignableRole(role) {
  return role === ROLES.USER || role === ROLES.QUESTION_MANAGER || role === ROLES.ADMIN;
}

module.exports = {
  ROLES,
  SUPER_ADMIN_USERNAME,
  canManagePublicQuestions,
  effectiveRole,
  isAdminRole,
  isAssignableRole,
  isQuestionManagerRole,
  isReservedSuperAdminUsername,
  isSuperAdminRole
};
