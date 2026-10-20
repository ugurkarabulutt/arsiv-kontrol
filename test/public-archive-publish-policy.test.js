const { test } = require('node:test');
const assert = require('node:assert/strict');
const { approvedPublicUpdatePolicy } = require('../public-archive-publish-policy');

test('normal approval republishes a previously hidden public record with current content', () => {
  const policy = approvedPublicUpdatePolicy(
    { status: 'content_review_hidden', answer_text: 'Eski cevap.' },
    { republishExisting: true }
  );
  assert.deepEqual(policy, {
    useExistingContent: false,
    status: 'published',
    refreshedExistingContent: true
  });
});

test('normal approval refreshes even an already published record', () => {
  const policy = approvedPublicUpdatePolicy(
    { status: 'published', answer_text: 'Eski cevap.' },
    { republishExisting: true }
  );
  assert.equal(policy.useExistingContent, false);
  assert.equal(policy.status, 'published');
  assert.equal(policy.refreshedExistingContent, true);
});

test('bulk preservation mode keeps existing content and non-public status', () => {
  const policy = approvedPublicUpdatePolicy(
    { status: 'content_review_hidden', answer_text: 'İnceleme bekleyen cevap.' }
  );
  assert.deepEqual(policy, {
    useExistingContent: true,
    status: 'content_review_hidden',
    refreshedExistingContent: false
  });
});

test('a new public record is published without counting as a refresh', () => {
  const policy = approvedPublicUpdatePolicy(null, { republishExisting: true });
  assert.deepEqual(policy, {
    useExistingContent: false,
    status: 'published',
    refreshedExistingContent: false
  });
});
