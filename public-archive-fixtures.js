const publicArchiveFixtures = {
  brand: {
    name: 'Dini Sorular ve Cevaplar Arşivi',
    logoLines: ['Dini Sorular', 've Cevaplar Arşivi'],
    sentence: 'Soru, cevap ve kavramları kaynak bağlamıyla birlikte okuyun.',
    authorName: 'Dr. Abdulcabbar Boran',
    authorLine: 'Sorular Dr. Abdulcabbar Boran tarafından yanıtlanır.',
    answererLabel: 'Yanıtlayan: Dr. Abdulcabbar Boran'
  },
  categories: [
    {
      id: 'cat-allaha-ulasmayi-dilemek',
      slug: 'allaha-ulasmayi-dilemek',
      name: 'Allah’a Ulaşmayı Dilemek',
      description: 'Kalbin Allah’a yönelişi, talep, dua ve başlangıç sorularını bir araya getiren ana kapı.',
      topicSlugs: ['kalbin-yonelisi', 'dua', 'takva'],
      featured: true
    },
    {
      id: 'cat-hidayet',
      slug: 'hidayet',
      name: 'Hidayet',
      description: 'Hidayetin başlangıcı, istikameti ve kulun hayatındaki karşılığı üzerine cevaplar.',
      topicSlugs: ['sirati-mustakim', 'takva', 'rahmet'],
      featured: true
    },
    {
      id: 'cat-mursid',
      slug: 'mursid',
      name: 'Mürşid',
      description: 'Mürşid, tâbiiyet ve manevi yol göstericilikle ilgili temel soru-cevap başlıkları.',
      topicSlugs: ['tabiiyet', 'irsad', 'kalbin-yonelisi'],
      featured: true
    },
    {
      id: 'cat-zikir',
      slug: 'zikir',
      name: 'Zikir',
      description: 'Zikir, daimi zikir, nefs tezkiyesi ve kalbin Allah ile beraberliği üzerine kayıtlar.',
      topicSlugs: ['daimi-zikir', 'nefs', 'nefs-tezkiyesi', 'kalp'],
      featured: true
    },
    {
      id: 'cat-teslimiyet',
      slug: 'teslimiyet',
      name: 'Teslimiyet',
      description: 'Ruhun, vechin, nefsin ve iradenin teslimi etrafında toplanan okuma yolu.',
      topicSlugs: ['teslim', 'ruh', 'irade', 'tevekkul'],
      featured: true
    }
  ],
  topics: [
    {
      id: 'topic-kalbin-yonelisi',
      slug: 'kalbin-yonelisi',
      name: 'Kalbin Yönelişi',
      description: 'Kulun içten talebi, dua ve Allah’a yönelme hâli.',
      categorySlug: 'allaha-ulasmayi-dilemek',
      relatedTopicSlugs: ['dua', 'takva', 'sirati-mustakim'],
      featured: true
    },
    {
      id: 'topic-dua',
      slug: 'dua',
      name: 'Dua',
      description: 'Talebin, niyazın ve Allah’tan istemenin arşivdeki kavram bağlantısı.',
      categorySlug: 'allaha-ulasmayi-dilemek',
      relatedTopicSlugs: ['kalbin-yonelisi', 'rahmet'],
      featured: true
    },
    {
      id: 'topic-takva',
      slug: 'takva',
      name: 'Takva',
      description: 'Korunma, sakınma ve Allah’a yakınlık arayışını açıklayan kavram.',
      categorySlug: 'hidayet',
      relatedTopicSlugs: ['sirati-mustakim', 'teslim'],
      featured: true
    },
    {
      id: 'topic-sirati-mustakim',
      slug: 'sirati-mustakim',
      name: 'Sıratı Mustakîm',
      description: 'Hidayet yolunu ve istikameti anlatan ana kavramlardan biri.',
      categorySlug: 'hidayet',
      relatedTopicSlugs: ['takva', 'tabiiyet'],
      featured: true
    },
    {
      id: 'topic-tabiiyet',
      slug: 'tabiiyet',
      name: 'Tâbiiyet',
      description: 'Mürşide bağlanma, söz alma ve yolun pratiğiyle ilgili başlık.',
      categorySlug: 'mursid',
      relatedTopicSlugs: ['irsad', 'sirati-mustakim'],
      featured: true
    },
    {
      id: 'topic-zikir',
      slug: 'zikir',
      name: 'Zikir',
      description: 'Allah’ı anma, hatırlama ve kalbi bu hatırlayışla diri tutma başlığı.',
      categorySlug: 'zikir',
      relatedTopicSlugs: ['daimi-zikir', 'kalp', 'nefs'],
      featured: true
    },
    {
      id: 'topic-daimi-zikir',
      slug: 'daimi-zikir',
      name: 'Daimi Zikir',
      description: 'Zikrin sürekliliği ve kalpteki dönüşümle bağlantılı kavram.',
      categorySlug: 'zikir',
      relatedTopicSlugs: ['zikir', 'kalp', 'nefs-tezkiyesi'],
      featured: true
    },
    {
      id: 'topic-nefs',
      slug: 'nefs',
      name: 'Nefs',
      description: 'İnsanın iç dünyası, arınma ihtiyacı ve tezkiye süreciyle ilgili kavram.',
      categorySlug: 'zikir',
      relatedTopicSlugs: ['nefs-tezkiyesi', 'takva', 'kalp'],
      featured: true
    },
    {
      id: 'topic-nefs-tezkiyesi',
      slug: 'nefs-tezkiyesi',
      name: 'Nefs Tezkiyesi',
      description: 'Nefsin arınması, tezkiye ve manevi gelişim sorularının kavram bağı.',
      categorySlug: 'zikir',
      relatedTopicSlugs: ['nefs', 'daimi-zikir', 'takva'],
      featured: true
    },
    {
      id: 'topic-teslim',
      slug: 'teslim',
      name: 'Teslim',
      description: 'Allah’a teslimiyetin farklı merhaleleriyle ilgili okuma bağı.',
      categorySlug: 'teslimiyet',
      relatedTopicSlugs: ['tevekkul', 'irade'],
      featured: true
    },
    {
      id: 'topic-ruh',
      slug: 'ruh',
      name: 'Ruh',
      description: 'Ruhun teslimi ve Allah’a yöneliş yolundaki merhalelerle ilgili kavram.',
      categorySlug: 'teslimiyet',
      relatedTopicSlugs: ['teslim', 'irade', 'kalbin-yonelisi'],
      featured: true
    },
    {
      id: 'topic-irsad',
      slug: 'irsad',
      name: 'İrşad',
      description: 'Manevi yol göstericilik ve doğruya çağırma kavramı.',
      categorySlug: 'mursid',
      relatedTopicSlugs: ['tabiiyet', 'kalbin-yonelisi'],
      featured: false
    },
    {
      id: 'topic-kalp',
      slug: 'kalp',
      name: 'Kalp',
      description: 'Zikir, yöneliş ve teslimiyet konularının kesiştiği merkez kavram.',
      categorySlug: 'zikir',
      relatedTopicSlugs: ['kalbin-yonelisi', 'daimi-zikir'],
      featured: false
    },
    {
      id: 'topic-irade',
      slug: 'irade',
      name: 'İrade',
      description: 'Kulun tercihi, gayreti ve teslimiyet yolundaki sorumluluğu.',
      categorySlug: 'teslimiyet',
      relatedTopicSlugs: ['teslim', 'tevekkul'],
      featured: false
    },
    {
      id: 'topic-tevekkul',
      slug: 'tevekkul',
      name: 'Tevekkül',
      description: 'Sebeplere sarılırken sonucu Allah’a bırakma dengesi.',
      categorySlug: 'teslimiyet',
      relatedTopicSlugs: ['teslim', 'dua'],
      featured: false
    },
    {
      id: 'topic-rahmet',
      slug: 'rahmet',
      name: 'Rahmet',
      description: 'Allah’ın rahmeti, mağfiret ve umut başlıklarının kavram bağlantısı.',
      categorySlug: 'hidayet',
      relatedTopicSlugs: ['dua', 'takva'],
      featured: false
    }
  ],
  qa: [
    {
      id: 'qa-ornek-soru',
      slug: 'ornek-soru',
      title: 'Allah’a ulaşmayı dilemek ne demektir?',
      question: 'Allah’a ulaşmayı dilemek hangi niyeti ve hangi yönelişi ifade eder?',
      summary: 'Allah’a ulaşmayı dilemek, kulun kalbinde Allah’a yönelme talebinin bilinçli hâle gelmesidir. Bu talep yalnız sözde kalmaz; dua, tercih ve istikametle desteklenir.',
      answer: [
        'Allah’a ulaşmayı dilemek, insanın hayatının merkezine Allah’a yönelişi almasıdır. Bu yöneliş, kulun iç dünyasında başlayan samimi bir taleptir.',
        'Bu talep yalnız bir cümle olarak kalmamalıdır. Kişi duasında, seçimlerinde ve gündelik davranışlarında bu yönelişi korumaya çalışır.',
        'Arşivde bu başlık hidayet, takva, dua ve teslimiyet kavramlarıyla birlikte okunur. Çünkü mesele yalnız bir bilgi değil, insanın yönünün değişmesidir.',
        'En doğrusunu Allah bilir.'
      ],
      excerpt: 'Kalbin Allah’a yönelme talebi; dua, tercih ve istikametle canlı tutulur.',
      categorySlug: 'allaha-ulasmayi-dilemek',
      topicSlugs: ['kalbin-yonelisi', 'dua', 'takva'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Bu cevap, arşivdeki Allah’a ulaşmayı dilemek, hidayet ve takva bağlantılarını birlikte okumak için hazırlanmış kısa bir kayıttır.'
      },
      publishedAt: '2026-08-01',
      updatedAt: '2026-08-08',
      readTime: 3,
      isFeatured: true,
      relatedSlugs: ['hidayet-yolu-nasil-baslar', 'murside-tabiiyet-nicin-onemlidir']
    },
    {
      id: 'qa-hidayet',
      slug: 'hidayet-yolu-nasil-baslar',
      title: 'Hidayet yolu nasıl başlar?',
      question: 'Bir insan hidayet yoluna girmek istediğinde ilk olarak neye dikkat etmelidir?',
      summary: 'Hidayet, kulun Allah’a yönelme talebiyle başlayan ve istikametle devam eden bir yoldur. Bu yolun ilk adımı samimi talep, dua ve doğru rehberliği aramaktır.',
      answer: [
        'Hidayet yolunun başlangıcında kalbin samimi talebi vardır. İnsan önce yönünü fark eder, sonra Allah’tan yardım ister.',
        'Bu başlangıç, kişinin kendisini yeterli görmeden doğru bilgiye, doğru rehberliğe ve istikamete ihtiyaç duymasını da beraberinde getirir.',
        'Hidayet başlığı arşivde Sıratı Mustakîm, takva, rahmet ve mürşid kavramlarıyla birlikte okunmalıdır.'
      ],
      excerpt: 'Hidayet; samimi talep, dua, istikamet ve doğru rehberlikle birlikte anlaşılır.',
      categorySlug: 'hidayet',
      topicSlugs: ['sirati-mustakim', 'takva', 'rahmet'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Hidayet başlığındaki cevaplar, arşivde yöneliş ve istikamet konularının merkezinde yer alır.'
      },
      publishedAt: '2026-08-02',
      updatedAt: '2026-08-08',
      readTime: 3,
      isFeatured: true,
      relatedSlugs: ['ornek-soru', 'zikir-kalbi-nasil-degistirir']
    },
    {
      id: 'qa-mursid',
      slug: 'murside-tabiiyet-nicin-onemlidir',
      title: 'Mürşide tâbiiyet niçin önemlidir?',
      question: 'Mürşid ve tâbiiyet kavramları hidayet yolunda nasıl anlaşılmalıdır?',
      summary: 'Mürşid, kulun manevi yürüyüşünde yol göstericilik ve istikamet anlamı taşır. Tâbiiyet ise bu rehberliği ciddiye alma ve yola bilinçli girme iradesidir.',
      answer: [
        'Mürşid kavramı, yalnız bilgi veren bir kişi anlamına indirgenmez. Arşivde bu başlık, manevi yol göstericilik ve istikamet bağlamında ele alınır.',
        'Tâbiiyet, kişinin kendi nefsinin dağınıklığı içinde kalmadan, Allah’a götüren yolu ciddiyetle takip etmek istemesidir.',
        'Bu sebeple mürşid başlığı hidayet, Sıratı Mustakîm, irşad ve kalbin yönelişi kavramlarıyla birlikte okunur.'
      ],
      excerpt: 'Tâbiiyet, doğru rehberliği ciddiye alma ve hidayet yoluna bilinçli girme iradesidir.',
      categorySlug: 'mursid',
      topicSlugs: ['tabiiyet', 'irsad', 'sirati-mustakim'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Mürşid ve tâbiiyet kayıtları, arşivde hidayet yolunun pratik karşılığıyla ilişkilendirilir.'
      },
      publishedAt: '2026-08-03',
      updatedAt: '2026-08-08',
      readTime: 3,
      isFeatured: true,
      relatedSlugs: ['hidayet-yolu-nasil-baslar', 'ornek-soru']
    },
    {
      id: 'qa-zikir',
      slug: 'zikir-kalbi-nasil-degistirir',
      title: 'Zikir kalbi nasıl değiştirir?',
      question: 'Zikir yalnız dil ile yapılan bir tekrar mıdır, yoksa kalbin hâline de tesir eder mi?',
      summary: 'Zikir, kulun Allah’ı hatırlaması ve bu hatırlayışı kalpte diri tutmasıdır. Süreklilik kazandıkça kalbin yönü, dikkati ve hassasiyeti değişir.',
      answer: [
        'Zikir yalnız kelimelerin tekrarından ibaret görülmemelidir. Esas olan, kulun kalbini Allah ile beraber tutma gayretidir.',
        'Dil ile başlayan zikir, dikkat ve süreklilik kazandığında kalbin hâline de tesir eder. İnsan neyi çok hatırlarsa kalbi de ona göre şekillenir.',
        'Bu yüzden zikir başlığı, daimi zikir, kalp ve nefs tezkiyesi kavramlarıyla beraber okunur.'
      ],
      excerpt: 'Zikir, hatırlayışı kalpte diri tutar; süreklilik kazandıkça insanın yönünü değiştirir.',
      categorySlug: 'zikir',
      topicSlugs: ['zikir', 'daimi-zikir', 'kalp', 'nefs-tezkiyesi'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Zikir kayıtları, arşivde kalp, nefs tezkiyesi ve teslimiyet başlıklarına bağlanır.'
      },
      publishedAt: '2026-08-04',
      updatedAt: '2026-08-08',
      readTime: 2,
      isFeatured: true,
      relatedSlugs: ['nefs-tezkiyesi-nedir', 'hidayet-yolu-nasil-baslar']
    },
    {
      id: 'qa-teslimiyet',
      slug: 'teslimiyet-hayatta-nasil-yasanir',
      title: 'Teslimiyet günlük hayatta nasıl yaşanır?',
      question: 'Teslimiyet sadece zor zamanlarda söylenen bir söz müdür, yoksa günlük hayatın içinde de yaşanır mı?',
      summary: 'Teslimiyet, kulun Allah’a güvenini kararlarına, sabrına ve gayretine yansıtmasıdır. İnsan çalışır, dua eder ve sonucu Allah’a bırakır.',
      answer: [
        'Teslimiyet pasif bekleyiş değildir. İnsan elinden geleni yapar, doğru sebebe sarılır ve kalbini Allah’a dayandırır.',
        'Günlük hayatta teslimiyet; acele hüküm vermemek, duayı bırakmamak, helal sınırları korumak ve sonucu Allah’a havale etmekle görünür.',
        'Bu başlık arşivde tevekkül, irade ve teslim kavramlarıyla birlikte okunur.'
      ],
      excerpt: 'Teslimiyet; gayreti terk etmeden, kalbi Allah’a güven içinde tutmaktır.',
      categorySlug: 'teslimiyet',
      topicSlugs: ['teslim', 'ruh', 'tevekkul', 'irade'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Teslimiyet başlığındaki kayıtlar, arşivde tevekkül ve irade kavramlarıyla birlikte değerlendirilir.'
      },
      publishedAt: '2026-08-05',
      updatedAt: '2026-08-08',
      readTime: 3,
      isFeatured: false,
      relatedSlugs: ['ornek-soru', 'zikir-kalbi-nasil-degistirir']
    },
    {
      id: 'qa-nefs',
      slug: 'nefs-tezkiyesi-nedir',
      title: 'Nefs tezkiyesi nedir?',
      question: 'Nefs tezkiyesi insanın iç dünyasında hangi değişimi hedefler?',
      summary: 'Nefs tezkiyesi, insanın kötü eğilimlerden arınması ve Allah’a yönelişini güçlendirmesiyle ilgili bir başlıktır. Zikir ve takva kavramlarıyla birlikte okunur.',
      answer: [
        'Nefs tezkiyesi, insanın iç dünyasını başıboş bırakmaması ve yanlış eğilimlerle mücadele etmesidir.',
        'Bu mücadele yalnız irade gücüyle değil; dua, zikir, takva ve doğru istikametle desteklenir.',
        'Arşivde nefs tezkiyesi başlığı zikir, kalp, takva ve teslimiyet kavramlarına bağlanır.'
      ],
      excerpt: 'Nefs tezkiyesi, iç dünyayı Allah’a yönelişle arındırma gayretidir.',
      categorySlug: 'zikir',
      topicSlugs: ['nefs', 'nefs-tezkiyesi', 'takva', 'kalp'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Nefs tezkiyesi kayıtları, zikir ve takva başlıklarıyla birlikte okuma yolu oluşturur.'
      },
      publishedAt: '2026-08-06',
      updatedAt: '2026-08-08',
      readTime: 2,
      isFeatured: false,
      relatedSlugs: ['zikir-kalbi-nasil-degistirir', 'teslimiyet-hayatta-nasil-yasanir']
    }
  ]
};

module.exports = { publicArchiveFixtures };
