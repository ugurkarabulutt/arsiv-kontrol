const test = require('node:test');
const assert = require('node:assert/strict');
const PDFDocument = require('pdfkit');
const {
  CANONICAL_WORD_STANDARDS,
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
  assert.equal(isProtectedChange('Muminun', 'MU\'MİNÛN'), false);
  assert.equal(isProtectedChange('Muzzemmil', 'MUZZEMMİL'), true);
  assert.equal(isProtectedChange('Fâtiha', 'FÂTİHA'), true);
  assert.equal(isProtectedChange('Muminun Suresi', "mü'min Suresi"), true);
  assert.equal(isProtectedChange('Zumer', 'Zümer'), true);
  assert.equal(isProtectedChange('Tabiî ki', 'tâbî ki'), true);
  assert.equal(isProtectedChange('Resul', 'resûl'), false);
});

test('duzeltilmis tam metin korunur ama reddedilen bulgular skor disi kalir', () => {
  const source = 'Ayet yazildi.\n\nManevî metin korunur.\nTablo: 1 | 2';
  const result = finalizeResult({
    correctedText: 'Âyet yazildi.\nManevi metin bozuldu.\nTablo düz metne çevrildi.',
    categories: {
      sozluk: {
        issues: [
          { original: 'Ayet', fixed: 'Âyet', rule: 'Sozluk' },
          { original: 'Manevî', fixed: 'Manevi', rule: 'Yanlis sapka silme' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 1);
  assert.equal(result.correctedText, 'Âyet yazildi.\n\nManevî metin korunur.\nTablo: 1 | 2');
});

test('duzeltilmis metni saran gereksiz dis tirnaklari kaldirir', () => {
  const result = finalizeResult({
    correctedText: '"Âyet yazildi. Metin içindeki "alıntı" korunur."',
    categories: {
      sozluk: { issues: [{ original: 'Ayet', fixed: 'Âyet', rule: 'Sozluk' }] }
    }
  }, 'Ayet yazildi. Metin içindeki "alıntı" korunur.');

  assert.equal(result.correctedText, 'Âyet yazildi. Metin içindeki "alıntı" korunur.');
});

test('canli feedback korumalari yanlis donusumleri skor disi birakir', () => {
  assert.equal(isProtectedChange('nefsi', 'nefs'), true);
  assert.equal(isProtectedChange('nefsin', 'nefisin'), true);
  assert.equal(isProtectedChange('taktirde', 'takdirde'), true);
  assert.equal(isProtectedChange('taktirde', 'taktir de'), true);
  assert.equal(isProtectedChange('A.S', 'S.A.V'), true);
  assert.equal(isProtectedChange('Efendimiz (A.S)', 'Efendimiz (S.A.V)'), true);
  assert.equal(isProtectedChange('derecatlar', 'dereceler'), true);
  assert.equal(isProtectedChange('Kur’ân-ı Kerim', 'Kur’ân'), true);
  assert.equal(isProtectedChange('Resûl’ü', 'Resûl'), true);
  assert.equal(isProtectedChange('manevî', 'manevi'), true);
  assert.equal(isProtectedChange('İnşaallah', 'inşaallah'), true);
  assert.equal(isProtectedChange('birr', 'bir'), true);
  assert.equal(isProtectedChange('hâdise', 'hadîse'), true);
  assert.equal(isProtectedChange('afv-u', 'af ve'), true);
  assert.equal(isProtectedChange('vücud', 'vücût'), true);
  assert.equal(isProtectedChange('şerr', 'şer'), true);
  assert.equal(isProtectedChange('dinde', 'dînde'), true);
  assert.equal(isProtectedChange('arif', 'ârif'), true);
  assert.equal(isProtectedChange('cahiliye', 'câhiliye'), true);
  assert.equal(isProtectedChange('ve vechini', 'vechini'), true);
  assert.equal(isProtectedChange('NEFSİ EMMÂRE', 'NEFSİ EMMÂRE:'), true);
  assert.equal(isProtectedChange('Sahihi Buhari 12. cilt hadis no. 2043', 'Sahihi Buhari 12. cilt hadîs no. 2043'), true);
  assert.equal(isProtectedChange("Mu'min", "Mu'minûn"), true);
  assert.equal(isProtectedChange("A'raf", "A'RÂF"), true);
  assert.equal(isProtectedChange('Nur', 'NÛR'), true);
  assert.equal(isProtectedChange('vücut', 'vücud'), true);
  assert.equal(isProtectedChange('vücuttan', 'vücuddan'), true);
  assert.equal(isProtectedChange('hayydırlar', 'hayattadırlar'), true);
  assert.equal(isProtectedChange('hidayet', 'hidayete'), true);
  assert.equal(isProtectedChange('HADİS-İ ŞERİF', 'HADÎS-İ ŞERÎF'), true);
});

test('canli feedback standart kelimeleri kayitli tutulur', () => {
  assert.equal(CANONICAL_WORD_STANDARDS.vucut, 'vücut');
  assert.equal(CANONICAL_WORD_STANDARDS.serr, 'şerr');
  assert.equal(CANONICAL_WORD_STANDARDS.arif, 'arif');
  assert.equal(CANONICAL_WORD_STANDARDS.cahiliye, 'cahiliye');
  assert.equal(CANONICAL_WORD_STANDARDS.dinde, 'dinde');
});

test('kabul edilen bulgular kaynak metne uygulanir ve modelin duzen bozmasi alinmaz', () => {
  const source = 'Baslik\n\nGelelim fizik beden ve nefs konusuna.\nTablo: A | B';
  const result = finalizeResult({
    correctedText: 'Gelelim fizik beden ve Nefise konusuna. Tablo bozuldu.',
    categories: {
      imla: {
        issues: [
          { original: 'Baslik', fixed: 'Başlık', rule: 'İmla standardı' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 1);
  assert.equal(result.correctedText, 'Başlık\n\nGelelim fizik beden ve nefs konusuna.\nTablo: A | B');
});

test('yonetici kararli 13 vaka regresyonlari uygulanir', () => {
  const source = [
    '1 .ENFÂL-29 ve 1 .YÛNUS -7',
    'dînde dînimizin dînsiz inşallah Hazreti İsa',
    'HADİS-İ ŞERİF herşeydir vücud vücut vücuttan',
    'daimi daimî daimî',
    'tabiî derecât hayydırlar hidayet',
    "KUR'ÂN başlığı korunur",
    'İşte 7 tane âyet-i kerimede her devirde devrin imamı var mı?'
  ].join('\n');

  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          { original: '1 .ENFÂL-29', fixed: '1. ENFÂL-29', rule: 'Referans düzeni' },
          { original: '1 .YÛNUS -7', fixed: '1. YÛNUS-7', rule: 'Referans düzeni' },
          { original: 'dînde', fixed: 'dinde', rule: 'Din standardı' },
          { original: 'dînimizin', fixed: 'dinimizin', rule: 'Din standardı' },
          { original: 'dînsiz', fixed: 'dinsiz', rule: 'Din standardı' },
          { original: 'inşallah', fixed: 'inşaallah', rule: 'İmlâ standardı' },
          { original: 'Hazreti İsa', fixed: 'Hazreti İsa (A.S)', rule: 'Nebî isimleri' },
          { original: 'HADİS-İ ŞERİF', fixed: 'HADÎS-İ ŞERİF', rule: 'Hadîs standardı' },
          { original: 'vücud', fixed: 'vücut', rule: 'Sözlük standardı' },
          { original: 'daimi', fixed: 'daimî', rule: 'İmlâ standardı' },
          { original: 'daimi', fixed: 'daimî', rule: 'Tekrar sayılmamalı' },
          { original: 'tabiî', fixed: 'tabi', rule: 'Yanlış sadeleştirme' },
          { original: 'derecât', fixed: 'derece', rule: 'Yanlış sadeleştirme' },
          { original: "KUR'ÂN", fixed: "Kur'ân", rule: 'Case only' },
          { original: 'herşeydir', fixed: 'her şeydir', rule: 'Yanlış ayırma' },
          { original: 'vücut', fixed: 'vücud', rule: 'Yanlış yön' },
          { original: 'vücuttan', fixed: 'vücuddan', rule: 'Yanlış yön' },
          { original: 'hayydırlar', fixed: 'hayattadırlar', rule: 'Yanlış sadeleştirme' },
          { original: 'hidayet', fixed: 'hidayete', rule: 'Kaynakta olmayan ek' },
          { original: 'HADİS-İ ŞERİF', fixed: 'HADÎS-İ ŞERÎF', rule: 'Şerif yanlış şapka' },
          {
            original: 'İşte 7 tane âyet-i kerimede her devirde devrin imamı var mı?',
            fixed: 'İşte 7 tane âyet-i kerimede her devirde devrin imamı var mı? Evet.',
            rule: 'Kaynakta olmayan cevap'
          }
        ]
      }
    }
  }, source);

  assert.equal(result.categories.imla.issues.map(i => i.original).join('|'), [
    '1 .ENFÂL-29',
    '1 .YÛNUS -7',
    'dînde',
    'dînimizin',
    'dînsiz',
    'inşallah',
    'Hazreti İsa',
    'HADİS-İ ŞERİF',
    'vücud',
    'daimi'
  ].join('|'));
  assert.equal(result.totalErrors, 10);
  assert.equal(result.correctedText, [
    '1. ENFÂL-29 ve 1. YÛNUS-7',
    'dinde dinimizin dinsiz inşaallah Hazreti İsa (A.S)',
    'HADÎS-İ ŞERİF herşeydir vücut vücut vücuttan',
    'daimî daimî daimî',
    'tabiî derecât hayydırlar hidayet',
    "KUR'ÂN başlığı korunur",
    'İşte 7 tane âyet-i kerimede her devirde devrin imamı var mı?'
  ].join('\n'));
});
