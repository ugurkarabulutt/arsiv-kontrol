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
for (const icon of manifest.icons || []) {
  const iconPath = path.join(root, icon.src.replace(/^\//, ''));
  const png = fs.readFileSync(iconPath);
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  if (`${width}x${height}` !== icon.sizes) {
    throw new Error(`${icon.src} ölçüsü manifest ile eşleşmiyor.`);
  }
}

new Function(fs.readFileSync(path.join(root, 'sw.js'), 'utf8'));

const social = fs.readFileSync(path.join(root, 'icons', 'social-preview.png'));
if (social.readUInt32BE(16) !== 1200 || social.readUInt32BE(20) !== 630) {
  throw new Error('Sosyal paylaşım görseli 1200x630 olmalı.');
}
if (!html.includes('property="og:image"') || !html.includes('name="twitter:card"')) {
  throw new Error('Open Graph/Twitter paylaşım metaları eksik.');
}
console.log('Frontend/PWA doğrulaması: başarılı');
