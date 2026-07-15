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

test('akilli dis tirnaklar ve cift akilli tirnaklar temizlenir', () => {
  const smart = finalizeResult({
    correctedText: '\u201cD\u00fczeltilmi\u015f metin\u201d',
    categories: {}
  }, '');
  assert.equal(smart.correctedText, 'D\u00fczeltilmi\u015f metin');

  const doubledSmart = finalizeResult({
    correctedText: '\u201c\u201cal\u0131nt\u0131\u201d\u201d',
    categories: {}
  }, '');
  assert.equal(doubledSmart.correctedText, 'al\u0131nt\u0131');
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
    'dînde',
    'dînimizin',
    'dînsiz',
    'inşallah',
    'Hazreti İsa',
    'HADİS-İ ŞERİF',
    'vücud',
    'daimi'
  ].join('|'));
  assert.equal(result.totalErrors, 8);
  assert.equal(result.correctedText, [
    '1 .ENFÂL-29 ve 1 .YÛNUS -7',
    'dinde dinimizin dinsiz inşaallah Hazreti İsa (A.S)',
    'HADÎS-İ ŞERİF herşeydir vücut vücut vücuttan',
    'daimî daimî daimî',
    'tabiî derecât hayydırlar hidayet',
    "KUR'ÂN başlığı korunur",
    'İşte 7 tane âyet-i kerimede her devirde devrin imamı var mı?'
  ].join('\n'));
});

test('yeni acik feedbacklerde net yanlis pozitifler skor disi kalir', () => {
  const source = [
    'Allah\u2019\u0131n yaratt\u0131\u011f\u0131 sistemde hikmet var ama insan acele eder.',
    'dilemeyenler Aheze etme zekat \u00f6l\u00fcyken \u00e2men\u00fbstec\u00eeb\u00fb heryeri peygamber',
    '7 safha 4 teslimi helalinden maddi Allah\u2019\u0131n Allah kat\u0131nda',
    'sergilerse art\u0131\u015f\u0131 ahirette Tirmizi E\u015f \u015eafi la s\u0131n\u0131fta -biz Nebi',
    'Metin i\u00e7inde "al\u0131nt\u0131" vard\u0131r.'
  ].join('\n');

  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          { original: 'var ama', fixed: 'var, ama', rule: 'Virg\u00fcl' },
          { original: 'dilemeyenler', fixed: 'dileyemeyenler', rule: 'Anlam de\u011fi\u015fikli\u011fi' },
          { original: 'Aheze', fixed: 'Ahize', rule: 'Yanl\u0131\u015f s\u00f6zl\u00fck' },
          { original: 'zekat', fixed: 'zek\u00e2t', rule: '\u015eapka' },
          { original: '\u00f6l\u00fcyken', fixed: '\u00f6l\u00fc iken', rule: 'Ayr\u0131 yaz\u0131m' },
          { original: '\u00e2men\u00fbstec\u00eeb\u00fb', fixed: '\u00e2men\u00fb stec\u00eeb\u00fb', rule: 'Bo\u015fluk' },
          { original: 'heryeri', fixed: 'her\u015feyi', rule: 'Yanl\u0131\u015f kelime' },
          { original: 'peygamber', fixed: 'neb\u00ee', rule: 'E\u015f anlaml\u0131 d\u00f6n\u00fc\u015f\u00fcm' },
          { original: '7 safha 4 teslimi', fixed: '7 safha, 4 teslimi', rule: 'Virg\u00fcl' },
          { original: 'helalinden', fixed: 'hel\u00e2linden', rule: '\u015eapka' },
          { original: 'maddi', fixed: 'madd\u00ee', rule: '\u015eapka' },
          { original: 'Allah\u2019\u0131n', fixed: 'Allah\u00fb Teal\u00e2\u2019n\u0131n', rule: 'Eklenen unvan' },
          { original: 'Allah kat\u0131nda', fixed: 'Allah\u00fb Teal\u00e2 kat\u0131nda', rule: 'Eklenen unvan' },
          { original: 'sergilerse', fixed: 'sergilesin', rule: 'Kip de\u011fi\u015fikli\u011fi' },
          { original: 'art\u0131\u015f\u0131', fixed: 'art\u0131\u015f\u0131n\u0131', rule: 'Ek de\u011fi\u015fikli\u011fi' },
          { original: 'ahirette', fixed: '\u00e2hirette', rule: '\u015eapka' },
          { original: 'Tirmizi', fixed: 'Tirmizi,', rule: 'Virg\u00fcl' },
          { original: 'E\u015f \u015eafi', fixed: 'E\u015f-\u015eafi', rule: 'Tire' },
          { original: 'Mumin', fixed: "M\u00fc'min", rule: 'Sure adini kelimeye indirme' },
          { original: 'la', fixed: 'la olmuyor.', rule: 'Kaynakta olmayan ek' },
          { original: 's\u0131n\u0131fta -biz', fixed: 's\u0131n\u0131fta \u2014biz', rule: 'Uzun \u00e7izgi' },
          { original: 'Nebi', fixed: 'neb\u00ee', rule: 'B\u00fcy\u00fck harf kayb\u0131' },
          { original: '"al\u0131nt\u0131"', fixed: '""al\u0131nt\u0131""', rule: 'T\u0131rnak \u00e7o\u011faltma' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 0);
  assert.equal(result.score, 100);
  assert.equal(result.correctedText, source);
});

test('deterministik eksik uygulamalar ve ozet gercek kategorilerden uretilir', () => {
  const source = 'etmesil\u00e2z\u0131m uzakla\u015fman\u0131zl\u00e2z\u0131m dinleyeceksin.Pazar d\u00eenleyip';
  const result = finalizeResult({ correctedText: '', categories: {} }, source);

  assert.equal(result.totalErrors, 4);
  assert.equal(
    result.correctedText,
    'etmesi l\u00e2z\u0131m uzakla\u015fman\u0131z l\u00e2z\u0131m dinleyeceksin. Pazar dinleyip'
  );
  assert.equal(result.summary, 'Metinde iml\u00e2 hatalar\u0131 bulunmaktad\u0131r. D\u00fczeltmeler uygulanm\u0131\u015ft\u0131r.');
});

test('vucut ve kaadir ekli kullanim standartlari dogru uygulanir', () => {
  const source = 'v\u00fccud v\u00fccudunu kadirdir';
  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          { original: 'v\u00fccudunu', fixed: 'v\u00fccutunu', rule: 'Yanlis ekli vucut' },
          { original: 'kadirdir', fixed: 'k\u00e2dirdir', rule: 'Yanlis sapka' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 2);
  assert.equal(result.correctedText, 'v\u00fccut v\u00fccudunu kaadirdir');
  assert.deepEqual(result.categories.imla.issues.map(i => [i.original, i.fixed]), [
    ['v\u00fccud', 'v\u00fccut'],
    ['kadirdir', 'kaadirdir']
  ]);
});

test('kalan acik feedback noktalama vakalari guvenli ele alinir', () => {
  const source = "5 dakika 10 dakikal\u0131k bekledi. Efendimiz (S.A.V)'dir ve \u0130rade eksikli\u011fi; irade burada zay\u0131f.";
  const result = finalizeResult({
    correctedText: '',
    categories: {
      noktalama: {
        issues: [
          { original: '5 dakika 10 dakikal\u0131k', fixed: '5 dakika, 10 dakikal\u0131k', rule: 'Virg\u00fcl' },
          { original: "Efendimiz (S.A.V)'dir", fixed: "Efendimiz (S.A.V)'dir.", rule: 'Nokta' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 1);
  assert.equal(
    result.correctedText,
    "5 dakika 10 dakikal\u0131k bekledi. Efendimiz (S.A.V)'dir ve \u0130rade eksikli\u011fi: \u0130rade burada zay\u0131f."
  );
  assert.deepEqual(result.categories.imla.issues.map(i => [i.original, i.fixed]), [
    ['\u0130rade eksikli\u011fi; irade', '\u0130rade eksikli\u011fi: \u0130rade']
  ]);
});

test('11 Temmuz yeni feedback vakalari kullanici lehine korunur', () => {
  const source = [
    'Feyzu\u2019l-Kadir kaynagi Kadir olarak kalir.',
    'Kadir\u00ee bir tarikat ismidir.',
    "Kur'an'da Vel Asr yaziyor.",
    '39/ZUMER-17 referansi tablo formatinda kalir.',
    'Sadece nereleri Allah gosteriyor kendisine?',
    'Ayet Arapcasinda d\u00eenehum geciyor.',
    "Peygamber Efendimiz'in had\u00eesi soyledir.",
    "Allah'da ifadesi kaynakta boyle yazildi.",
    '6 . C\u00c2S\u0130YE-19 ve 4 . ENF\u00c2L-73 tablo sablonudur.',
    'Efendimizin sohbetlerinde sagir yazimi geciyor.',
    'Ayet icinde rahmete kelimesi degismez.',
    'ukba tdk ve mihr.com kullanimidir.',
    'Zur\u00fbf sure adi aslinda Zuhr\u00fbf olmali.'
  ].join(' ');

  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          { original: 'Kadir', fixed: 'Kaadir', rule: 'Kaynak ismi' },
          { original: 'Kadir\u00ee', fixed: 'Kaadir\u00ee', rule: 'Ozel isim' },
          { original: 'Vel Asr', fixed: 'Vel-Asr', rule: 'Tire' },
          { original: '39/ZUMER-17', fixed: '39. ZUMER-17', rule: 'Referans' },
          { original: 'Sadece nereleri Allah gosteriyor kendisine?', fixed: 'Sadece nereleri Allahu Teala gosteriyor Kendisine?', rule: 'Zamir' },
          { original: 'd\u00eenehum', fixed: 'dinehum', rule: 'Din standardi' },
          { original: 'had\u00eesi', fixed: 'had\u00ees-i', rule: 'Hadis tamlamasi' },
          { original: "Allah'da", fixed: "Allah'ta", rule: 'Ek' },
          { original: '6 . C\u00c2S\u0130YE-19', fixed: '6. C\u00c2S\u0130YE-19', rule: 'Tablo' },
          { original: '4 . ENF\u00c2L-73', fixed: '4. ENF\u00c2L-73', rule: 'Tablo' },
          { original: 'sagir', fixed: 'sa\u011fir', rule: 'Sozluk' },
          { original: 'rahmete', fixed: 'rahmeti', rule: 'Ayet' },
          { original: 'ukba', fixed: 'ukb\u00e2', rule: 'Sozluk' },
          { original: 'Zur\u00fbf', fixed: 'Zumer', rule: 'Sure adi' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 1);
  assert.equal(result.score, 96);
  assert.ok(result.correctedText.includes('Feyzu\u2019l-Kadir kaynagi Kadir olarak kalir.'));
  assert.ok(result.correctedText.includes('Kadir\u00ee bir tarikat ismidir.'));
  assert.ok(result.correctedText.includes('Vel Asr yaziyor.'));
  assert.ok(result.correctedText.includes('39/ZUMER-17 referansi'));
  assert.ok(result.correctedText.includes('Allah gosteriyor kendisine?'));
  assert.ok(result.correctedText.includes('d\u00eenehum geciyor.'));
  assert.ok(result.correctedText.includes('had\u00eesi soyledir.'));
  assert.ok(result.correctedText.includes("Allah'da ifadesi"));
  assert.ok(result.correctedText.includes('6 . C\u00c2S\u0130YE-19'));
  assert.ok(result.correctedText.includes('sagir yazimi'));
  assert.ok(result.correctedText.includes('rahmete kelimesi'));
  assert.ok(result.correctedText.includes('ukba tdk'));
  assert.ok(result.correctedText.includes('Zuhr\u00fbf sure adi'));
  assert.deepEqual(result.categories.imla.issues.map(i => [i.original, i.fixed]), [
    ['Zur\u00fbf', 'Zuhr\u00fbf']
  ]);
});

test('12 Temmuz geri bildirimleri sozluk ve baglam lehine korunur', () => {
  const source = [
    'Kuşluk namazı 4 rekât öğle, 4 rekât ikindi, 3 rekât akşam toplam 11 rekât.',
    'Efendimizin sözlüğünde vaadde ifadesi vaad kökünden gelir.',
    '19 tane haslet ruhun içinde yer alır.',
    'Nefsin afetlerine dikkat edilir.',
    'Sevgi, saygı, güler yüz…',
    'Bir araya gelince hizmet tamamlanır.',
    'biraraya yazımı sözlükte korunur.'
  ].join(' ');

  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          {
            original: 'Kuşluk namazı 4 rekât öğle, 4 rekât ikindi, 3 rekât akşam toplam 11 rekât.',
            fixed: 'Kuşluk namazı 4 rekât, öğle 4 rekât, ikindi 3 rekât, akşam toplam 11 rekât.',
            rule: 'Yanlis namaz dagilimi'
          },
          { original: 'vaadde', fixed: 'vaatte', rule: 'Sozluk' },
          { original: '19 tane haslet ruhun', fixed: '19 tane haslet ruhun,', rule: 'Virgul' },
          { original: 'afetlerine', fixed: 'âfetlerine', rule: 'Sapka' },
          { original: 'Sevgi, saygı, güler yüz…', fixed: 'Sevgi, saygı, güler yüz...', rule: 'Uc nokta' },
          { original: 'biraraya', fixed: 'bir araya', rule: 'Sozluk' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 2);
  assert.equal(result.score, 92);
  assert.ok(result.correctedText.includes('Kuşluk namazı 4 rekât öğle, 4 rekât ikindi, 3 rekât akşam toplam 11 rekât.'));
  assert.ok(result.correctedText.includes('vaadde ifadesi'));
  assert.ok(result.correctedText.includes('Ruhta 19 tane haslet içinde yer alır.'));
  assert.ok(result.correctedText.includes('afetlerine dikkat edilir.'));
  assert.ok(result.correctedText.includes('güler yüz…'));
  assert.ok(result.correctedText.includes('biraraya gelince hizmet tamamlanır.'));
  assert.ok(result.correctedText.includes('biraraya yazımı sözlükte korunur.'));
  assert.deepEqual(result.categories.imla.issues.map(i => [i.original, i.fixed]), [
    ['19 tane haslet ruhun', 'Ruhta 19 tane haslet'],
    ['Bir araya', 'biraraya']
  ]);
});

test('issue bulunduysa apostrof ve bosluk farkina ragmen duzeltilmis metne uygulanir', () => {
  const source = "Allah’a ulaşmayı dileyen kişi her şey için dua eder.";
  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          { original: "Allah'a", fixed: 'Allah’a', rule: 'Apostrof tipi' },
          { original: 'her şey', fixed: 'herşey', rule: 'Sozluk standardi' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 1);
  assert.equal(result.correctedText, 'Allah’a ulaşmayı dileyen kişi herşey için dua eder.');
  assert.deepEqual(result.categories.imla.issues.map(i => [i.original, i.fixed]), [
    ['her şey', 'herşey']
  ]);
});

test('13 Temmuz son feedbackleri nokta sapka ve cok kelimeli referans formatinda korunur', () => {
  const source = [
    'Bu isin yapilmasi l\u00e2z\u0131m.',
    'Ayet mealinde kitab kelimesi geciyor.',
    '3/\u00c2L\u0130 \u0130MR\u00c2N-20 me\u00e2l alintisi olarak kalir.'
  ].join(' ');

  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          { original: 'l\u00e2z\u0131m', fixed: 'l\u00e2z\u0131m.', rule: 'Nokta' },
          { original: 'kitab', fixed: 'kit\u00e2b', rule: 'Sapka' },
          { original: '3/\u00c2L\u0130 \u0130MR\u00c2N-20', fixed: '3. \u00c2L\u0130 \u0130MR\u00c2N-20', rule: 'Referans' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 0);
  assert.equal(result.score, 100);
  assert.equal(result.correctedText, source);
});

test('14 Temmuz acik feedback kokleri tekrar skorlanmaz', () => {
  const source = [
    '\u015eura suresinde eksik sapka vardir.',
    'Arapca ayette gayz(gayzi) ifadesi korunur.',
    'Efendimizin sozlugunde cihad-\u0131 kelimesinde sapka yoktur.',
    'Bu emirlere dikkat edilir.',
    "Ra'd suresi apostrofla yazilir.",
    'Res\u00fbl diyor ki; bu ifade kalabilir.',
    'Allah\u2019a giden yolun giri\u015f kap\u0131s\u0131 do\u011fru olmakt\u0131r. Do\u011fruyu s\u00f6yleyebilmektir.',
    'Ebu kelimesi slaytta boyle gecmistir.',
    'E\u00fbz\u00fc bill\u00e2hi mine\u2019\u015f-\u015feyt\u00e2nirrac\u00eem ayr\u0131 yazilmistir.',
    'in\u015faallah iki a ile korunur.',
    "Allah Res\u00fbl'\u00fc (S.A.V); ifadesi kalabilir.",
    'Metinde kasiyet kelimesi yoktur.',
    'Efendimizin sozlugunde l\u00e2z\u0131mgelen birlesik kullanilir.',
    'Arapca ayette d\u00eeni ve d\u00eene halleri korunur.',
    'Hz. \u0130sa\u2019ya tefsir icinde boyle yazilmistir.'
  ].join(' ');

  const result = finalizeResult({
    correctedText: '',
    categories: {
      imla: {
        issues: [
          { original: 'cihad-\u0131', fixed: 'cih\u00e2d-\u0131', rule: 'Sapka' },
          { original: 'mir', fixed: 'mi', rule: 'Harf silme' },
          { original: "Ra'd", fixed: 'RAD', rule: 'Sure apostrof' },
          { original: 'Ebu', fixed: 'Eb\u00fb', rule: 'Sapka' },
          { original: 'E\u00fbz\u00fc bill\u00e2hi mine\u2019\u015f-\u015feyt\u00e2nirrac\u00eem', fixed: 'E\u00fbzubill\u00e2himine\u015f\u015feyt\u00e2nirrac\u00eem', rule: 'Arapca ifade' },
          { original: 'in\u015faallah', fixed: 'in\u015fallah', rule: 'Ters standart' },
          { original: 'kasiyet', fixed: 'kasvet', rule: 'Metinde olmayan' },
          { original: 'l\u00e2z\u0131mgelen', fixed: 'l\u00e2z\u0131m gelen', rule: 'Sozluk' },
          { original: 'd\u00eeni', fixed: 'dini', rule: 'Ayet Arapcasi' },
          { original: 'd\u00eene', fixed: 'dine', rule: 'Ayet Arapcasi' }
        ]
      },
      noktalama: {
        issues: [
          { original: 'gayz(gayzi)', fixed: 'gayz (gayzi)', rule: 'Parantez' },
          { original: 'diyor ki;', fixed: 'diyor ki:', rule: 'Noktalama' },
          { original: "Allah Res\u00fbl'\u00fc (S.A.V);", fixed: "Allah Res\u00fbl'\u00fc (S.A.V):", rule: 'Noktalama' }
        ]
      },
      yapi: {
        issues: [
          {
            original: 'Allah\u2019a giden yolun giri\u015f kap\u0131s\u0131 do\u011fru olmakt\u0131r. Do\u011fruyu s\u00f6yleyebilmektir.',
            fixed: "Allah'a giden yolun giri\u015f kap\u0131s\u0131 do\u011fru olmakt\u0131r, do\u011fruyu s\u00f6yleyebilmektir.",
            rule: 'Cumle birlestirme'
          },
          { original: 'Hz. \u0130sa\u2019ya', fixed: 'Hazreti \u0130sa (A.S)\u2019ya', rule: 'Nebiler' }
        ]
      }
    }
  }, source);

  assert.equal(result.totalErrors, 1);
  assert.equal(result.score, 96);
  assert.deepEqual(result.categories.imla.issues.map(i => [i.original, i.fixed]), [
    ['\u015eura', '\u015e\u00fbr\u00e2']
  ]);
  assert.ok(result.correctedText.includes('\u015e\u00fbr\u00e2 suresinde'));
  assert.ok(result.correctedText.includes('gayz(gayzi) ifadesi'));
  assert.ok(result.correctedText.includes('cihad-\u0131 kelimesinde'));
  assert.ok(result.correctedText.includes('Bu emirlere dikkat edilir.'));
  assert.ok(result.correctedText.includes("Ra'd suresi"));
  assert.ok(result.correctedText.includes('diyor ki;'));
  assert.ok(result.correctedText.includes('Do\u011fruyu s\u00f6yleyebilmektir.'));
  assert.ok(result.correctedText.includes('in\u015faallah iki a ile korunur.'));
  assert.ok(result.correctedText.includes('l\u00e2z\u0131mgelen birlesik'));
  assert.ok(result.correctedText.includes('d\u00eeni ve d\u00eene halleri korunur.'));
  assert.ok(result.correctedText.includes('Hz. \u0130sa\u2019ya tefsir'));
});

test('modelin ekledigi gereksiz cift tirnaklar temizlenir', () => {
  const result = finalizeResult({
    correctedText: '""Düzeltilmiş metin içinde ""alıntı"" korunur.""',
    categories: {}
  }, '');

  assert.equal(result.correctedText, 'Düzeltilmiş metin içinde "alıntı" korunur.');
});
