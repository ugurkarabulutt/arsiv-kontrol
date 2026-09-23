const test = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeNewsletterCampaignInput,
  newsletterCampaignErrors,
  renderNewsletterEmail,
  newsletterEventEmail
} = require('../newsletter-core');

test('newsletter campaign input is normalized and validated', () => {
  const campaign = normalizeNewsletterCampaignInput({
    name: '  Eylül Bülteni  ',
    subject: ' Yeni rehberler ',
    heading: 'Arşivde bu ay',
    bodyText: 'İlk paragraf.\r\n\r\nİkinci paragraf.',
    ctaLabel: 'Rehberleri oku',
    ctaUrl: 'https://arsiv.ibrahimlive.ai/blog'
  });
  assert.equal(campaign.name, 'Eylül Bülteni');
  assert.equal(campaign.bodyText, 'İlk paragraf.\n\nİkinci paragraf.');
  assert.deepEqual(newsletterCampaignErrors(campaign), []);
  assert.match(renderNewsletterEmail(campaign), /\{\{\{RESEND_UNSUBSCRIBE_URL\}\}\}/);
});

test('newsletter email escapes editor content and test mode never exposes unsubscribe placeholder', () => {
  const campaign = {
    name: 'Test',
    subject: '<Deneme>',
    heading: '<script>alert(1)</script>',
    bodyText: 'Güvenli <metin>',
    ctaLabel: 'Oku',
    ctaUrl: 'https://arsiv.ibrahimlive.ai'
  };
  const html = renderNewsletterEmail(campaign, { mode: 'test' });
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /RESEND_UNSUBSCRIBE_URL/);
  assert.match(html, /yalnızca test amacıyla/);
});

test('newsletter campaign requires paired CTA fields and a valid URL', () => {
  const base = { name: 'A', subject: 'B', heading: 'C', bodyText: 'D' };
  assert.equal(newsletterCampaignErrors({ ...base, ctaLabel: 'Oku' }).length, 1);
  assert.equal(newsletterCampaignErrors({ ...base, ctaLabel: 'Oku', ctaUrl: 'javascript:alert(1)' }).length, 1);
});

test('newsletter event email supports contact and delivery payloads', () => {
  assert.equal(newsletterEventEmail({ data: { email: ' USER@EXAMPLE.COM ' } }), 'user@example.com');
  assert.equal(newsletterEventEmail({ data: { to: ['A@EXAMPLE.COM'] } }), 'a@example.com');
});
