const NEWSLETTER_LIMITS = Object.freeze({
  name: 120,
  subject: 150,
  previewText: 180,
  heading: 180,
  bodyText: 12000,
  ctaLabel: 80,
  ctaUrl: 1000
});

function cleanNewsletterText(value, max) {
  return String(value || '').normalize('NFC').replace(/\r\n?/g, '\n').trim().slice(0, max);
}

function normalizeNewsletterCampaignInput(input = {}) {
  return {
    name: cleanNewsletterText(input.name, NEWSLETTER_LIMITS.name),
    subject: cleanNewsletterText(input.subject, NEWSLETTER_LIMITS.subject),
    previewText: cleanNewsletterText(input.previewText ?? input.preview_text, NEWSLETTER_LIMITS.previewText),
    heading: cleanNewsletterText(input.heading, NEWSLETTER_LIMITS.heading),
    bodyText: cleanNewsletterText(input.bodyText ?? input.body_text, NEWSLETTER_LIMITS.bodyText),
    ctaLabel: cleanNewsletterText(input.ctaLabel ?? input.cta_label, NEWSLETTER_LIMITS.ctaLabel),
    ctaUrl: cleanNewsletterText(input.ctaUrl ?? input.cta_url, NEWSLETTER_LIMITS.ctaUrl)
  };
}

function validNewsletterUrl(value = '') {
  if (!value) return true;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

function newsletterCampaignErrors(campaign = {}) {
  const value = normalizeNewsletterCampaignInput(campaign);
  const errors = [];
  if (!value.name) errors.push('Kampanya adı gerekli.');
  if (!value.subject) errors.push('E-posta konusu gerekli.');
  if (!value.heading) errors.push('E-posta başlığı gerekli.');
  if (!value.bodyText) errors.push('E-posta metni gerekli.');
  if ((value.ctaLabel && !value.ctaUrl) || (!value.ctaLabel && value.ctaUrl)) {
    errors.push('Bağlantı metni ve adresi birlikte doldurulmalı.');
  }
  if (!validNewsletterUrl(value.ctaUrl)) errors.push('Bağlantı adresi http veya https ile başlamalı.');
  return errors;
}

function escapeNewsletterHtml(value = '') {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function newsletterParagraphs(value = '') {
  return String(value || '')
    .split(/\n\s*\n/)
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => `<p style="margin:0 0 18px;color:#26332e;font-size:17px;line-height:1.75">${escapeNewsletterHtml(part).replace(/\n/g, '<br>')}</p>`)
    .join('');
}

function renderNewsletterEmail(campaign = {}, options = {}) {
  const value = normalizeNewsletterCampaignInput(campaign);
  const isBroadcast = options.mode !== 'test';
  const unsubscribeUrl = isBroadcast ? '{{{RESEND_UNSUBSCRIBE_URL}}}' : '';
  const cta = value.ctaLabel && value.ctaUrl
    ? `<table role="presentation" cellspacing="0" cellpadding="0" style="margin:28px 0 10px"><tr><td style="background:#1e6a50;border-radius:6px"><a href="${escapeNewsletterHtml(value.ctaUrl)}" style="display:inline-block;padding:14px 22px;color:#ffffff;text-decoration:none;font-size:16px;font-weight:700">${escapeNewsletterHtml(value.ctaLabel)}</a></td></tr></table>`
    : '';
  const footerAction = isBroadcast
    ? `Bu e-postaları almak istemiyorsanız <a href="${unsubscribeUrl}" style="color:#46675b;text-decoration:underline">abonelikten çıkabilirsiniz</a>.`
    : 'Bu e-posta yalnızca test amacıyla size gönderildi; abonelere ulaşmadı.';

  return `<!doctype html>
<html lang="tr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeNewsletterHtml(value.subject)}</title></head>
<body style="margin:0;background:#eef2ef;color:#17201c;font-family:Arial,Helvetica,sans-serif">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${escapeNewsletterHtml(value.previewText || value.heading)}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#eef2ef;padding:28px 12px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;background:#ffffff;border:1px solid #d8e2dc;border-radius:8px;overflow:hidden">
        <tr><td style="padding:20px 28px;background:#10211a;border-bottom:3px solid #c7a961;color:#ffffff">
          <div style="font-family:Georgia,'Times New Roman',serif;font-size:22px;font-weight:700;line-height:1.25">Dini Sorular ve Cevaplar Arşivi</div>
          <div style="margin-top:5px;color:#b9c9c1;font-size:12px;line-height:1.5">Kaynakları ve delilleriyle güvenilir cevaplar</div>
        </td></tr>
        <tr><td style="padding:34px 28px 26px">
          <h1 style="margin:0 0 18px;color:#17201c;font-family:Georgia,'Times New Roman',serif;font-size:32px;line-height:1.2">${escapeNewsletterHtml(value.heading)}</h1>
          ${newsletterParagraphs(value.bodyText)}
          ${cta}
        </td></tr>
        <tr><td style="padding:22px 28px;background:#f5f7f5;border-top:1px solid #d8e2dc;color:#5c6c64;font-size:12px;line-height:1.65">
          <p style="margin:0 0 8px">${footerAction}</p>
          <p style="margin:0"><a href="https://arsiv.ibrahimlive.ai" style="color:#1e6a50;text-decoration:none">arsiv.ibrahimlive.ai</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

function renderNewsletterText(campaign = {}, options = {}) {
  const value = normalizeNewsletterCampaignInput(campaign);
  const lines = [value.heading, '', value.bodyText];
  if (value.ctaLabel && value.ctaUrl) lines.push('', `${value.ctaLabel}: ${value.ctaUrl}`);
  lines.push('', 'Dini Sorular ve Cevaplar Arşivi', 'https://arsiv.ibrahimlive.ai');
  if (options.mode === 'test') lines.push('', 'Bu e-posta yalnızca test amacıyla gönderildi.');
  return lines.join('\n');
}

function newsletterEventEmail(event = {}) {
  const data = event.data || {};
  if (data.email) return String(data.email).trim().toLowerCase();
  if (Array.isArray(data.to) && data.to[0]) return String(data.to[0]).trim().toLowerCase();
  return '';
}

module.exports = {
  NEWSLETTER_LIMITS,
  normalizeNewsletterCampaignInput,
  newsletterCampaignErrors,
  renderNewsletterEmail,
  renderNewsletterText,
  newsletterEventEmail,
  validNewsletterUrl
};
