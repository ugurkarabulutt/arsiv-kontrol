const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/);

if (!script) throw new Error('index.html içinde inline script bulunamadı.');
new Function(script[1]);
console.log('Frontend JavaScript sözdizimi: başarılı');
