'use strict';

function approvedPublicUpdatePolicy(existing, options = {}) {
  const hasExisting = Boolean(existing);
  const republishExisting = options.republishExisting === true;
  if (options.refreshExistingContent === true && !republishExisting) {
    return {
      useExistingContent: false,
      status: existing?.status || 'published',
      refreshedExistingContent: hasExisting
    };
  }

  return {
    useExistingContent: hasExisting && !republishExisting,
    status: republishExisting
      ? 'published'
      : (existing?.status && existing.status !== 'published' ? existing.status : 'published'),
    refreshedExistingContent: hasExisting && republishExisting
  };
}

module.exports = { approvedPublicUpdatePolicy };
