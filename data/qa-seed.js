const categoryNames = [
  "Allah'a Ulaşmayı Dilemek",
  "Hidayet",
  "Mürşid",
  "Tâbiiyet",
  "Zikir",
  "Nefs",
  "Ruh",
  "Takva",
  "Teslimler",
  "Dua",
  "Namaz",
  "İman",
  "Kur'ân-ı Kerîm",
  "Peygamberler",
  "Ahiret",
  "İslâm'ın Temel Kavramları"
];

const topicSeeds = [
  ["Allah'a ulaşmayı dilemek", "niyet", "kalp", "dilek"],
  ["hidayet", "istikamet", "doğru yol", "rehberlik"],
  ["mürşid", "irşad", "rehber", "tâbiiyet"],
  ["tâbiiyet", "teslimiyet", "bağlılık", "rehberlik"],
  ["zikir", "dua", "kalp huzuru", "devamlılık"],
  ["nefs", "terbiye", "imtihan", "arınma"],
  ["ruh", "teslim", "manevi gelişim", "emanet"],
  ["takva", "sakınma", "ölçü", "sorumluluk"],
  ["teslimler", "kalp", "ruh", "irade"],
  ["dua", "niyaz", "samimiyet", "yakınlık"],
  ["namaz", "ibadet", "huşû", "devamlılık"],
  ["iman", "kalp", "tasdik", "istikamet"],
  ["Kur'ân-ı Kerîm", "âyet", "ölçü", "rehberlik"],
  ["peygamberler", "örneklik", "tebliğ", "sabır"],
  ["ahiret", "hesap", "sorumluluk", "hazırlık"],
  ["İslâm'ın temel kavramları", "kavram", "ölçü", "anlam"]
];

const questionPatterns = [
  "{topic} nedir ve günlük hayatta nasıl anlaşılmalıdır?",
  "{topic} konusunda dikkat edilmesi gereken temel ölçü nedir?",
  "{topic} ile kalp arasındaki ilişki nasıl açıklanabilir?",
  "{topic} hakkında sıkça karıştırılan nokta nedir?",
  "{topic} kişinin manevi hayatında neden önemlidir?",
  "{topic} konusunda süreklilik nasıl korunur?",
  "{topic} ile sorumluluk bilinci arasında nasıl bir bağ vardır?",
  "{topic} hakkında arşivde hangi bakış öne çıkar?",
  "{topic} bir insanın davranışlarına nasıl yansır?",
  "{topic} konusunda doğru anlamaya nereden başlanmalıdır?"
];

function slugify(value) {
  return String(value)
    .toLocaleLowerCase("tr-TR")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ı/g, "i")
    .replace(/ğ/g, "g")
    .replace(/ü/g, "u")
    .replace(/ş/g, "s")
    .replace(/ö/g, "o")
    .replace(/ç/g, "c")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function sentenceCase(value) {
  const text = String(value || "").trim();
  return text ? text.charAt(0).toLocaleUpperCase("tr-TR") + text.slice(1) : "";
}

function buildAnswer(topic, category, index) {
  const lead = sentenceCase(topic);
  const variants = [
    `${lead}, kişinin yönünü ve niyetini gözden geçirmesine vesile olan temel konulardan biridir. Arşivde bu başlık, kalpteki samimiyet, doğru istikamet ve ibadet hayatındaki devamlılıkla birlikte ele alınır.`,
    `${lead} konusu, sadece teorik bir tarif olarak değil, insanın hayatına yansıyan bir ölçü olarak değerlendirilir. Bu nedenle mesele; niyet, davranış ve sorumluluk bütünlüğü içinde anlaşılmalıdır.`,
    `${lead} hakkında yapılan açıklamalarda asıl vurgu, kavramın doğru anlaşılması ve günlük hayatta karşılığının görülmesidir. Soru bu yönüyle, insanın kendisini muhasebe etmesine yardımcı olur.`,
    `${lead}, kişinin manevi yolculuğunda dikkatle ele alması gereken başlıklardan biridir. Bu konu arşivde, acele hüküm vermeden, kaynaklı anlatımı ve kavram bütünlüğünü koruyarak işlenir.`
  ];
  const close = [
    `Bu çerçevede ${category} başlığı altındaki diğer sorular da konuyu farklı yönleriyle tamamlar.`,
    `Benzer içerikler, aynı kavram ailesindeki soru-cevaplarla birlikte okununca daha bütünlüklü anlaşılır.`,
    `Konuya dair ayrıntılı kavrayış için ilgili kavramlar ve benzer sorular birlikte incelenebilir.`,
    `Bu yaklaşım, konunun sadece kelime anlamıyla değil, hayat içindeki karşılığıyla değerlendirilmesine yardımcı olur.`
  ];
  return `${variants[index % variants.length]}\n\n${close[index % close.length]}`;
}

const entries = [];
let id = 1;

for (let c = 0; c < categoryNames.length; c += 1) {
  const category = categoryNames[c];
  const topics = topicSeeds[c];
  for (let p = 0; p < questionPatterns.length && entries.length < 100; p += 1) {
    const primaryTopic = topics[p % topics.length];
    const question = questionPatterns[p].replace("{topic}", primaryTopic);
    const title = sentenceCase(question.replace(/\?$/, ""));
    const slug = `${slugify(title)}-${id}`;
    const summary = `${sentenceCase(primaryTopic)} konusu ${category} bağlamında kısa ve anlaşılır şekilde ele alınır.`;
    entries.push({
      id: String(id),
      title,
      slug,
      question,
      answer: buildAnswer(primaryTopic, category, id),
      summary,
      category,
      topics: Array.from(new Set([primaryTopic, ...topics.slice(0, 3)])),
      createdAt: new Date(Date.UTC(2026, 6, 1 + (id % 22), 9, id % 60, 0)).toISOString(),
      updatedAt: new Date(Date.UTC(2026, 6, 6 + (id % 18), 12, id % 60, 0)).toISOString(),
      readTime: 2 + (id % 4)
    });
    id += 1;
  }
}

module.exports = {
  qaEntries: entries,
  categoryNames,
  slugify
};
