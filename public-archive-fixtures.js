const publicArchiveFixtures = {
  brand: {
    name: 'Dini Sorular ve Cevaplar Arşivi',
    logoLines: ['Dini Sorular', 've Cevaplar Arşivi'],
    sentence: 'Sorularınız Kur’ân ışığında cevaplanır.',
    authorName: 'Dr. Abdulcabbar Boran',
    authorLine: 'Sorular Dr. Abdulcabbar Boran tarafından yanıtlanır.',
    answererLabel: 'Yanıtlayan: Dr. Abdulcabbar Boran'
  },
  categories: [
    {
      id: 'cat-ibadet',
      slug: 'ornek-kategori',
      name: 'İbadet',
      description: 'Namaz, oruç, dua ve günlük ibadet hayatına dair kısa ve okunabilir cevaplar.',
      topicSlugs: ['ornek-kavram', 'namaz', 'dua'],
      featured: true
    },
    {
      id: 'cat-iman',
      slug: 'iman',
      name: 'İman',
      description: 'İmanın temel kavramları ve kalbi ilgilendiren sorular.',
      topicSlugs: ['iman', 'tevekkul', 'sabir'],
      featured: true
    },
    {
      id: 'cat-ahlak',
      slug: 'ahlak',
      name: 'Ahlak',
      description: 'Güzel davranış, sabır, şükür ve insan ilişkileri üzerine cevaplar.',
      topicSlugs: ['sabir', 'sukur'],
      featured: true
    },
    {
      id: 'cat-aile',
      slug: 'aile-ve-toplum',
      name: 'Aile ve Toplum',
      description: 'Aile, komşuluk, kul hakkı ve sosyal hayatla ilgili başlıklar.',
      topicSlugs: ['kul-hakki', 'aile'],
      featured: true
    },
    {
      id: 'cat-mali',
      slug: 'mali-konular',
      name: 'Mali Konular',
      description: 'Zekât, sadaka ve kazanç hassasiyeti gibi mali sorular.',
      topicSlugs: ['zekat', 'sadaka'],
      featured: true
    }
  ],
  topics: [
    {
      id: 'topic-tevekkul',
      slug: 'ornek-kavram',
      name: 'Tevekkül',
      description: 'Sebebe sarılırken kalbin Allah’a dayanması ve sonucu O’na bırakması.',
      categorySlug: 'iman',
      relatedTopicSlugs: ['iman', 'sabir', 'dua'],
      featured: true
    },
    {
      id: 'topic-iman',
      slug: 'iman',
      name: 'İman',
      description: 'Kalbin tasdiki, güven ve teslimiyet ekseninde ele alınan temel kavram.',
      categorySlug: 'iman',
      relatedTopicSlugs: ['ornek-kavram', 'sabir'],
      featured: true
    },
    {
      id: 'topic-namaz',
      slug: 'namaz',
      name: 'Namaz',
      description: 'Günlük ibadetin eda, dikkat ve huzur boyutuyla ilgili sorular.',
      categorySlug: 'ornek-kategori',
      relatedTopicSlugs: ['dua', 'ornek-kavram'],
      featured: true
    },
    {
      id: 'topic-dua',
      slug: 'dua',
      name: 'Dua',
      description: 'Kulun yönelişi, niyazı ve günlük hayatındaki manevi dayanışma dili.',
      categorySlug: 'ornek-kategori',
      relatedTopicSlugs: ['ornek-kavram', 'sabir'],
      featured: true
    },
    {
      id: 'topic-sabir',
      slug: 'sabir',
      name: 'Sabır',
      description: 'Zorluk karşısında istikametini korumaya dair temel başlık.',
      categorySlug: 'ahlak',
      relatedTopicSlugs: ['sukur', 'ornek-kavram'],
      featured: true
    },
    {
      id: 'topic-sukur',
      slug: 'sukur',
      name: 'Şükür',
      description: 'Nimeti bilmek, değerini korumak ve kulluk bilincini diri tutmak.',
      categorySlug: 'ahlak',
      relatedTopicSlugs: ['sabir', 'dua'],
      featured: true
    },
    {
      id: 'topic-zekat',
      slug: 'zekat',
      name: 'Zekât',
      description: 'Mali ibadetin ölçüsü ve toplumsal sorumluluk boyutu.',
      categorySlug: 'mali-konular',
      relatedTopicSlugs: ['sadaka'],
      featured: false
    },
    {
      id: 'topic-sadaka',
      slug: 'sadaka',
      name: 'Sadaka',
      description: 'İyilik, paylaşma ve infak bilinciyle ilgili sorular.',
      categorySlug: 'mali-konular',
      relatedTopicSlugs: ['zekat', 'sukur'],
      featured: false
    },
    {
      id: 'topic-kul-hakki',
      slug: 'kul-hakki',
      name: 'Kul Hakkı',
      description: 'İnsan ilişkilerinde hassasiyet, emanet ve sorumluluk bilinci.',
      categorySlug: 'aile-ve-toplum',
      relatedTopicSlugs: ['aile', 'sabir'],
      featured: false
    },
    {
      id: 'topic-aile',
      slug: 'aile',
      name: 'Aile',
      description: 'Aile içi sorumluluk ve nezaketle ilgili başlıklar.',
      categorySlug: 'aile-ve-toplum',
      relatedTopicSlugs: ['kul-hakki'],
      featured: false
    }
  ],
  qa: [
    {
      id: 'qa-ornek-soru',
      slug: 'ornek-soru',
      title: 'Namaz kılarken akla gelen kötü düşünceler namazı bozar mı?',
      question: 'Namaz esnasında istemeden akla gelen kötü düşünceler namazın geçerliliğine zarar verir mi?',
      summary: 'İstem dışı gelen düşünceler, kişi onları bilerek sürdürmediği sürece namazı bozmaz. Esas olan namaza devam edip kalbi yeniden Allah’a yöneltmektir.',
      answer: [
        'Namazda insanın zihnine istemediği düşünceler gelebilir. Bunlar kalbin bilinçli tercihi değilse, ibadetin geçerliliğini tek başına bozmaz.',
        'Böyle bir durumda yapılacak şey düşünceyle uğraşmak yerine namaza dönmek, okunanı ve yapılanı sakin biçimde takip etmektir. Kulun görevi, dikkat dağıldığında yeniden yönelmektir.',
        'Vesvese büyütüldükçe ağırlaşır; önemsenmeden geçildiğinde etkisi azalır. Bu sebeple kişi namazını bozmuş gibi davranmamalı, ibadetini tamamlamalıdır.',
        'En doğrusunu Allah bilir.'
      ],
      excerpt: 'İstem dışı gelen düşünceler namazı bozmaz; kalbi yeniden ibadete yöneltmek yeterlidir.',
      categorySlug: 'ornek-kategori',
      topicSlugs: ['namaz', 'ornek-kavram'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Bu cevap, ibadet başlığı altındaki kısa soru-cevap arşivi üslubunu göstermek için hazırlanmış okunabilir örnek içeriktir.'
      },
      publishedAt: '2026-08-01',
      updatedAt: '2026-08-08',
      readTime: 3,
      isFeatured: true,
      relatedSlugs: ['zekat-kimlere-verilir', 'dua-kabul-olmaz-mi']
    },
    {
      id: 'qa-zekat',
      slug: 'zekat-kimlere-verilir',
      title: 'Zekât kimlere verilir, kimlere verilmez?',
      question: 'Zekât verirken öncelik sırası ve dikkat edilmesi gereken genel ölçüler nelerdir?',
      summary: 'Zekât, ihtiyaç sahibi ve dinen uygun kimselere verilir. Yakın çevredeki ihtiyaç sahipleri gözetilebilir; ancak temel ölçü ehliyet ve ihtiyaçtır.',
      answer: [
        'Zekât mali bir ibadettir ve verilme yeri keyfi değil, dinin belirlediği ölçülere bağlıdır.',
        'Kişi, ihtiyaç sahibi olan ve zekât alabilecek kimseleri araştırmalı; akraba ve yakın çevrede ihtiyaç varsa onları da gözetmelidir.',
        'Zekâtın ibadet bilinciyle, gösterişten uzak ve muhatabı incitmeden verilmesi gerekir.'
      ],
      excerpt: 'Zekât, ihtiyaç ve ehliyet ölçüsü gözetilerek verilir; nezaket ve mahremiyet korunmalıdır.',
      categorySlug: 'mali-konular',
      topicSlugs: ['zekat', 'sadaka'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Mali ibadetler başlığındaki genel açıklama alanıdır; ayrıntılı hükümler için yayınlanmış içerik esas alınır.'
      },
      publishedAt: '2026-08-02',
      updatedAt: '2026-08-08',
      readTime: 2,
      isFeatured: true,
      relatedSlugs: ['sadaka-niyet', 'dua-kabul-olmaz-mi']
    },
    {
      id: 'qa-dua',
      slug: 'dua-kabul-olmaz-mi',
      title: 'Dua hemen kabul olmayınca ne düşünmeliyiz?',
      question: 'Dua ettiğim halde istediğim şey gerçekleşmezse bu nasıl anlaşılmalıdır?',
      summary: 'Duanın karşılığı yalnız istenenin hemen verilmesiyle sınırlı değildir. Kul dua ile Rabbine yönelir; hikmet ve zaman Allah’a aittir.',
      answer: [
        'Dua, kulun Allah’a yönelişidir. Bu yönelişin değeri yalnız sonucu hemen görmekle ölçülmez.',
        'Bazen istenen şey gecikir, bazen farklı bir hayırla karşılık bulur, bazen de kulun kalbine sabır ve teslimiyet olarak döner.',
        'Bu yüzden dua terk edilmemeli; kişi istemeye, iyiye yönelmeye ve sabırla beklemeye devam etmelidir.'
      ],
      excerpt: 'Dua bir yöneliştir; karşılığın zamanı ve şekli kulun değil Allah’ın hikmetindedir.',
      categorySlug: 'ornek-kategori',
      topicSlugs: ['dua', 'sabir', 'ornek-kavram'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Dua ve sabır konularını birlikte okutan kısa arşiv bağlamıdır.'
      },
      publishedAt: '2026-08-03',
      updatedAt: '2026-08-08',
      readTime: 2,
      isFeatured: true,
      relatedSlugs: ['namazda-dusunce', 'tevekkul-yanlis-anlasilir-mi']
    },
    {
      id: 'qa-tevekkul',
      slug: 'tevekkul-yanlis-anlasilir-mi',
      title: 'Tevekkül çalışmayı bırakmak mıdır?',
      question: 'Tevekkül etmek, sebep aramadan beklemek anlamına gelir mi?',
      summary: 'Tevekkül, sebepleri terk etmek değil; gerekeni yaptıktan sonra sonucu Allah’a bırakmaktır.',
      answer: [
        'Tevekkül pasif bekleyiş değildir. İnsan gücü yettiği ölçüde doğru sebebe sarılır, kararını ve emeğini ortaya koyar.',
        'Bundan sonra sonucu kendi elinde görmez; kalbini Allah’a dayandırır. Bu denge hem sorumluluğu hem teslimiyeti korur.',
        'Sebebi terk etmek tevekkül değil ihmal olabilir. Sebebe güvenip Allah’ı unutmak da tevekkülün ruhuna uymaz.'
      ],
      excerpt: 'Tevekkül, emek ve teslimiyetin birlikte korunmasıdır.',
      categorySlug: 'iman',
      topicSlugs: ['ornek-kavram', 'iman'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Kavram açıklaması niteliğindeki kısa arşiv cevabıdır.'
      },
      publishedAt: '2026-08-04',
      updatedAt: '2026-08-08',
      readTime: 3,
      isFeatured: false,
      relatedSlugs: ['dua-kabul-olmaz-mi', 'sabir-zor-zamanda']
    },
    {
      id: 'qa-sabir',
      slug: 'sabir-zor-zamanda',
      title: 'Zor zamanda sabır nasıl korunur?',
      question: 'Sıkıntılı dönemlerde kalbi toparlamak ve sabrı korumak için nasıl bir yol izlenir?',
      summary: 'Sabır, acıyı yok saymak değil; doğru istikameti kaybetmeden dayanabilmektir.',
      answer: [
        'Sabır, insanın zorlanmadığı anlamına gelmez. Zorluk fark edilir; fakat kişi öfke, ümitsizlik ve acele kararlarla yönünü kaybetmemeye çalışır.',
        'Kısa dua, düzenli ibadet, güvenilir yakınlarla konuşmak ve küçük sorumlulukları aksatmamak kalbi toparlamaya yardım eder.',
        'Her hal geçicidir. Kul elinden geleni yapar, neticeyi Allah’a bırakır.'
      ],
      excerpt: 'Sabır, zorluğu yok saymadan doğru istikamette kalabilmektir.',
      categorySlug: 'ahlak',
      topicSlugs: ['sabir', 'ornek-kavram'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Ahlak ve kalp terbiyesi başlıklarını birbirine bağlayan arşiv cevabıdır.'
      },
      publishedAt: '2026-08-05',
      updatedAt: '2026-08-08',
      readTime: 2,
      isFeatured: false,
      relatedSlugs: ['dua-kabul-olmaz-mi', 'tevekkul-yanlis-anlasilir-mi']
    },
    {
      id: 'qa-sadaka',
      slug: 'sadaka-niyet',
      title: 'Sadaka verirken niyet neden önemlidir?',
      question: 'Sadaka verirken gizlilik ve niyet nasıl korunmalıdır?',
      summary: 'Sadakada niyet, verilen şeyin manevi değerini belirleyen temel unsurlardandır.',
      answer: [
        'Sadaka yalnız maddi yardım değildir; kalbin Allah rızasına yönelmesiyle anlam kazanır.',
        'İyilik yapılırken muhatabı incitmemek, gösterişten kaçınmak ve yapılanı büyütmemek gerekir.',
        'Gizlilik, hem verenin niyetini hem alanın mahremiyetini korur.'
      ],
      excerpt: 'Sadakada gizlilik ve temiz niyet, yapılan iyiliğin edebini korur.',
      categorySlug: 'mali-konular',
      topicSlugs: ['sadaka', 'sukur'],
      sourceContext: {
        title: 'Kaynak ve bağlam',
        text: 'Paylaşma ve iyilik başlıkları için kısa arşiv bağlamıdır.'
      },
      publishedAt: '2026-08-06',
      updatedAt: '2026-08-08',
      readTime: 2,
      isFeatured: false,
      relatedSlugs: ['zekat-kimlere-verilir']
    }
  ]
};

module.exports = { publicArchiveFixtures };
