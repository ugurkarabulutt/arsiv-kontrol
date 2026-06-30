const test = require('node:test');
const assert = require('node:assert/strict');
const PDFDocument = require('pdfkit');
const {
  LOW_SCORE_MSG,
  candidateTextHashes,
  finalizeResult,
  isProtectedChange,
  legacyTextHash,
  sourceContainsIssue,
  textHash
} = require('../analysis-core');

test('skoru AI alanından değil her issue instanceından hesaplar', () => {
  const result = finalizeResult({
    score: 99,
    correctedText: 'düzeltilmiş',
    categories: {
      sozluk: { count: 1, issues: Array.from({ length: 8 }, () => ({ original: 'ayet', fixed: 'âyet' })) },
      imla: { count: 50, issues: [] }
    }
  });

  assert.equal(result.categories.sozluk.count, 8);
  assert.equal(result.categories.imla.count, 0);
  assert.equal(result.totalErrors, 8);
  assert.equal(result.score, 60);
  assert.equal(result.correctedText, 'düzeltilmiş');
});

test('60 altındaki sonuçta yalnızca istenen uyarıyı ve boş metni döndürür', () => {
  const result = finalizeResult({
    correctedText: 'gösterilmemeli',
    summary: 'AI özeti',
    categories: {
      sozluk: { issues: Array.from({ length: 9 }, () => ({})) }
    }
  });

  assert.equal(result.score, 55);
  assert.equal(result.correctedText, '');
  assert.equal(result.summary, LOW_SCORE_MSG);
  assert.equal(result.categories.sozluk.issues.length, 9);
});

test('SHA-256 parmak izi satır sonlarını ve Unicode biçimini normalize eder', () => {
  assert.equal(textHash(' Kur\u0027a\u0302n\r\nâyet '), textHash("Kur'ân\nâyet"));
  assert.match(textHash('aynı metin'), /^[a-f0-9]{64}$/);
  assert.notEqual(textHash('x'.repeat(100) + 'A'), textHash('x'.repeat(100) + 'B'));
});

test('eski parmak izi geçmiş kayıtlarıyla geriye uyumludur', () => {
  assert.equal(legacyTextHash('  örnek  '), '5|örnek');
  assert.deepEqual(candidateTextHashes('  örnek  '), [textHash('örnek'), '5|örnek']);
});

test('Türkçe karakterleri gömülü fontla gerçek PDF olarak üretir', async () => {
  const fontPath = require.resolve('@fontsource/noto-serif/files/noto-serif-latin-ext-400-normal.woff');
  const doc = new PDFDocument();
  const chunks = [];
  doc.on('data', chunk => chunks.push(chunk));
  const ended = new Promise((resolve, reject) => doc.on('end', resolve).on('error', reject));
  doc.font(fontPath).text("Allahû Tealâ, âyet, Kur'ân, mü'min, îmân, ni'met");
  doc.end();
  await ended;
  const pdf = Buffer.concat(chunks);
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
  assert.ok(pdf.length > 1000);
});

test('kaynak metinde olmayan veya ayni gorunen bulgulari skor disi birakir', () => {
  const result = finalizeResult({
    correctedText: "Allah'a dua edildi. Muminun Suresi okundu.",
    categories: {
      sozluk: {
        issues: [
          { original: 'Allah’a', fixed: "Allah'a", rule: 'apostrof tipi' },
          { original: 'Mumin', fixed: "mü'min", rule: 'kelime ici yanlis eslesme' },
          { original: 'olmayan', fixed: 'olan', rule: 'metinde yok' },
          { original: 'Teala', fixed: 'Allahû Tealâ', rule: 'gercek bulgu' }
        ]
      }
    }
  }, "Allah’a dua edildi. Teala zikredildi. Muminun Suresi okundu.");

  assert.equal(result.categories.sozluk.count, 1);
  assert.deepEqual(result.categories.sozluk.issues.map(i => i.original), ['Teala']);
  assert.equal(result.totalErrors, 1);
  assert.equal(result.score, 95);
});

test('kelime ici parca eslesmesini kaynak bulgusu saymaz', () => {
  assert.equal(sourceContainsIssue('Muminun Suresi', 'Mumin'), false);
  assert.equal(sourceContainsIssue('Mumin kelimesi hatali yazildi', 'Mumin'), true);
});

test('korumali ve yasak donusumleri hem skordan hem duzeltilmis metinden cikarir', () => {
  const source = "Tabiî ki derecat artar. Dinlenmeye geçti. Muhterem Efendimiz anlattı. Allah'ın izniyle. Allah razı olsun.";
  const result = finalizeResult({
    correctedText: "Tâbî ki derece artar. Dînlenmeye geçti. Efendimiz (S.A.V) anlattı. Allah'ın izniyle, Allah razı olsun.",
    categories: {
      sozluk: {
        issues: [
          { original: 'Tabiî ki', fixed: 'Tâbî ki', rule: 'yanlis baglam' },
          { original: 'derecat', fixed: 'derece', rule: 'yanlis baglam' },
          { original: 'Dinlenmeye', fixed: 'Dînlenmeye', rule: 'yanlis kok' },
          { original: 'Muhterem Efendimiz', fixed: 'Efendimiz (S.A.V)', rule: 'yanlis unvan' }
        ]
      },
      yapi: {
        issues: [
          { original: "Allah'ın izniyle. Allah razı olsun.", fixed: "Allah'ın izniyle, Allah razı olsun.", rule: 'yanlis birlestirme' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 0);
  assert.equal(result.score, 100);
  assert.equal(result.correctedText, source);
});

test('korumali ifadeleri degistiren issue gecersiz sayilir', () => {
  assert.equal(isProtectedChange('Mu\'minûn', 'Mü\'minûn'), true);
  assert.equal(isProtectedChange('Muminun Suresi', "mü'min Suresi"), true);
  assert.equal(isProtectedChange('Tabiî ki', 'tâbî ki'), true);
  assert.equal(isProtectedChange('Resul', 'resûl'), false);
});
