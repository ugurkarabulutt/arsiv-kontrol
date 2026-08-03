const fs = require('fs');
const path = require('path');
const express = require('express');
const { createPublicArchiveRouter } = require('../public-archive-demo');
const { qaEntries, categoryNames, slugify } = require('../data/qa-seed');

const root = path.join(__dirname, '..');
const outDir = path.join(root, 'demo-public-preview');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeRoute(html, outputRoute) {
  const cleanRoute = outputRoute.replace(/^\/+/, '');
  const filePath = cleanRoute
    ? path.join(outDir, cleanRoute, 'index.html')
    : path.join(outDir, 'index.html');
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, html, 'utf8');
}

async function main() {
  fs.rmSync(outDir, { recursive: true, force: true });
  ensureDir(outDir);
  fs.copyFileSync(path.join(root, 'archive-public.css'), path.join(outDir, 'archive-public.css'));
  process.env.PUBLIC_ARCHIVE_BASE_URL = process.env.PUBLIC_ARCHIVE_BASE_URL || 'http://localhost:3001';

  const app = express();
  app.use(createPublicArchiveRouter({
    adminFile: path.join(root, 'index.html'),
    cssFile: path.join(root, 'archive-public.css')
  }));

  const server = app.listen(0, '127.0.0.1');
  const port = await new Promise(resolve => server.once('listening', () => resolve(server.address().port)));
  const base = `http://127.0.0.1:${port}`;

  const routes = [
    { route: '/', outputRoute: '/' },
    { route: '/arama', outputRoute: '/arama' },
    { route: '/arama?q=hidayet', outputRoute: '/arama-hidayet' },
    { route: '/arama?q=mursid', outputRoute: '/arama-mursid' }
  ];

  qaEntries.forEach(entry => {
    routes.push({ route: `/soru/${entry.slug}`, outputRoute: `/soru/${entry.slug}` });
  });

  categoryNames.forEach(name => {
    routes.push({ route: `/kategori/${slugify(name)}`, outputRoute: `/kategori/${slugify(name)}` });
  });

  const topics = new Set();
  qaEntries.forEach(entry => entry.topics.forEach(topic => topics.add(topic)));
  topics.forEach(topic => {
    routes.push({ route: `/konu/${slugify(topic)}`, outputRoute: `/konu/${slugify(topic)}` });
  });

  for (const { route, outputRoute } of routes) {
    const response = await fetch(`${base}${route}`);
    if (!response.ok) throw new Error(`${route} render failed: ${response.status}`);
    writeRoute(await response.text(), outputRoute);
  }

  await new Promise(resolve => server.close(resolve));
  console.log(`Static archive demo ready: ${outDir}`);
  console.log(`File: ${path.join(outDir, 'index.html')}`);
  console.log(`Route count: ${routes.length}`);
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
