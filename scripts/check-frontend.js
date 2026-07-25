const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/);
const root = path.join(__dirname, '..');

if (!script) throw new Error('index.html içinde inline script bulunamadı.');
new Function(script[1]);

const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.webmanifest'), 'utf8'));
if (manifest.name !== 'Arşiv AI' || manifest.short_name !== 'Arşiv AI') {
  throw new Error('PWA uygulama adı Arşiv AI olmalı.');
}
function readPngSize(filePath) {
  const png = fs.readFileSync(filePath);
  return `${png.readUInt32BE(16)}x${png.readUInt32BE(20)}`;
}
for (const icon of manifest.icons || []) {
  const iconPath = path.join(root, icon.src.replace(/^\//, ''));
  if (readPngSize(iconPath) !== icon.sizes) {
    throw new Error(`${icon.src} ölçüsü manifest ile eşleşmiyor.`);
  }
}

const favicon16 = path.join(root, 'icons', 'favicon-16.png');
const favicon32 = path.join(root, 'icons', 'favicon-32.png');
const faviconIco = path.join(root, 'icons', 'favicon.ico');
if (readPngSize(favicon16) !== '16x16' || readPngSize(favicon32) !== '32x32') {
  throw new Error('Favicon PNG ölçüleri 16x16 ve 32x32 olmalı.');
}
const ico = fs.readFileSync(faviconIco);
if (ico.readUInt16LE(0) !== 0 || ico.readUInt16LE(2) !== 1 || ico.readUInt16LE(4) < 1) {
  throw new Error('favicon.ico geçerli ICO başlığı taşımıyor.');
}
if (!html.includes('rel="icon" href="/favicon.ico"') || !html.includes('href="/icons/favicon-32.png"')) {
  throw new Error('Masaüstü favicon linkleri eksik.');
}

new Function(fs.readFileSync(path.join(root, 'sw.js'), 'utf8'));

const social = fs.readFileSync(path.join(root, 'icons', 'social-preview.png'));
if (social.readUInt32BE(16) !== 1200 || social.readUInt32BE(20) !== 630) {
  throw new Error('Sosyal paylaşım görseli 1200x630 olmalı.');
}
if (!html.includes('property="og:image"') || !html.includes('name="twitter:card"')) {
  throw new Error('Open Graph/Twitter paylaşım metaları eksik.');
}
if (!html.includes('function friendlyAnalyzeError') || !html.includes('AI servisi geçici olarak yanıt veremedi')) {
  throw new Error('Denetim hata mesajları kullanıcı dostu Türkçe metne bağlanmalı.');
}
if (!html.includes('Denetim tamamlanamadı. Metniniz korunuyor.')) {
  throw new Error('Denetim hatasında metnin korunduğu kullanıcıya belirtilmeli.');
}
console.log('Frontend/PWA doğrulaması: başarılı');
