'use strict';

function approvedPublicUpdatePolicy(existing, options = {}) {
  const hasExisting = Boolean(existing);
  const republishExisting = options.republishExisting === true;
  return {
    useExistingContent: hasExisting && !republishExisting,
    status: republishExisting
      ? 'published'
      : (existing?.status && existing.status !== 'published' ? existing.status : 'published'),
    refreshedExistingContent: hasExisting && republishExisting
  };
}

module.exports = { approvedPublicUpdatePolicy };
