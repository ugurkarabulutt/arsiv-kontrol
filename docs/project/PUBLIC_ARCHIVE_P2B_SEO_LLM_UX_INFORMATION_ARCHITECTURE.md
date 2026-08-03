# Public Archive P2B SEO, LLM, UX and Information Architecture

Date: 2026-08-03
Status: Docs-only architecture and design plan

## A. Product Vision

`arsiv.ibrahimlive.ai` will become the canonical public religious question-answer
archive and knowledge center for IbrahimLive.

Current production state stays unchanged during P2B:

| URL | Current behavior |
| --- | --- |
| `https://arsiv.ibrahimlive.ai/` | Legacy team/admin workspace. |
| `https://arsiv.ibrahimlive.ai/admin` | New production parallel team/admin workspace. |

P2B does not activate the public root. It defines the product, SEO, LLM, UX,
information architecture, data, and publishing direction for the future public
archive.

Public positioning:

- Product name in public UI: `İbrahimLive Soru Cevap Arşivi`.
- Primary homepage H1: `İbrahimLive Soru Cevap Arşivi`.
- Homepage supporting copy: `Merak ettiğiniz konu, kavram veya soruyu arşivde arayın.`
- The site should feel like a serious, warm, modern religious knowledge center.
- It must not feel like a blog, chatbot, random list site, internal tool, or
  technical operations surface.
- It should be easy to cite, easy to scan, and comfortable to read on mobile.

Public-visible language must not include these internal terms:

- `AI`
- `prompt`
- `model`
- `admin`
- `denetim`
- `onay kuyruğu`
- `kalite kontrol`
- `test verisi`

These terms may appear in internal documentation and checks. They must not
appear in public UI, public HTML, public metadata, JSON-LD, sitemap-visible
text, or public API responses.

## B. Workstream Boundaries

This P2B workstream covers:

- Public frontend UX and information architecture.
- Public archive search, detail, topic, category, glossary, and guide pages.
- SEO, LLM sourceability, canonical, sitemap, schema, and noindex strategy.
- Root public cutover planning.
- Super-admin-only public content management needs, only as architecture.

This P2B workstream does not cover:

- General admin panel development.
- Feedback fixes.
- Analysis/quality engine changes.
- Existing admin business logic changes.
- DB migrations.
- Public root activation.
- User question system implementation.

Future public management modules may live under `/admin`, but only as
super-admin-only controls. Normal admins and team users must not see public
publishing, SEO, schema, or public relation graph controls.

## C. Information Architecture

The public archive should be organized as a knowledge center with multiple
connected layers.

Content layers:

| Layer | Purpose | Public value |
| --- | --- | --- |
| Question-answer archive | Canonical answers to specific questions. | Direct answer and citation target. |
| Topic/concept centers | Pages around concepts such as hidayet, tövbe, teslimiyet. | Entity clarity and internal linking. |
| Category centers | Higher-level organization such as ibadet, tasavvuf, Kur'an kavramları. | Browse and discoverability. |
| Guide/knowledge articles | Curated explanations built from published archive records. | Structured learning and topical depth. |
| Glossary terms | Short definitions and concept variations. | Fast lookup and entity disambiguation. |
| Learning paths | Ordered reading journeys for beginners or topic clusters. | Guided progression. |
| Future user questions | Signed-in users submit and track private questions. | Demand capture without chatbot behavior. |

The main public mental model:

1. Search first.
2. Read a short answer.
3. Continue into a detailed answer.
4. Follow related concepts, guides, and categories.
5. If the archive does not answer the need, future signed-in users may submit a
   question.

## D. Route Model

| Route | Purpose | Indexing | Schema | Content type | User intent | SEO/LLM value | MVP |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `/` | Public archive home after root cutover. | Index when `PUBLIC_ARCHIVE_INDEXING=true`. | `WebSite`, `Organization`, `CollectionPage` or `WebPage`, `BreadcrumbList`, optional `ItemList`. | Search hub, topic/category entry, featured content. | Search and discover. | Strong site/entity hub. | Yes, but only after cutover. |
| `/arama?q=...` | Search results. | `noindex,follow`; sitemap excluded. | `WebPage` only if needed. | Published result list. | Find a specific answer. | Lets crawlers follow result links without indexing query URLs. | Yes. |
| `/soru/[slug]` | Canonical question-answer detail. | Index if published. | `WebPage`, `Article`, `BreadcrumbList`. | Question, short answer, detailed answer, related content. | Read and cite an answer. | Primary answer source. | Yes. |
| `/konu/[slug]` | Topic/concept center. | Index if published. | `CollectionPage`, `ItemList`, `BreadcrumbList`, `DefinedTerm`. | Definition, important answers, guides, related concepts. | Understand a concept. | Entity and topic cluster authority. | Yes. |
| `/kategori/[slug]` | Category center. | Index if published. | `CollectionPage`, `ItemList`, `BreadcrumbList`. | Subtopics, featured answers, guides. | Browse a broad subject. | Category-level hub and internal links. | Yes. |
| `/rehber/[slug]` | Guide/knowledge article. | Index if published. | `WebPage`, `Article`, `BreadcrumbList`. | Curated guide connected to archive records. | Learn a theme in context. | Long-form topical depth without blog framing. | Phase 2. |
| `/sozluk/[slug]` | Glossary definition. | Index if published. | `WebPage`, `DefinedTerm`, `BreadcrumbList`. | Short definition, aliases, related answers/guides. | Quick lookup. | Entity disambiguation and internal links. | Phase 2. |
| `/ogrenme-yolu/[slug]` | Ordered reading path. | Index after enough content exists. | `CollectionPage`, `ItemList`, `BreadcrumbList`. | Ordered guide and answer sequence. | Follow a learning journey. | Cluster depth and engagement. | Later. |
| `/giris` | Future user sign-in. | `noindex,nofollow`; sitemap excluded. | None. | Private user entry. | Sign in. | No public SEO value. | P2J or later. |
| `/hesap` | Future account page. | `noindex,nofollow`; sitemap excluded. | None. | Private account. | Manage account. | No public SEO value. | Later. |
| `/soru-gonder` | Future question submission. | `noindex,nofollow`; sitemap excluded. | None. | Private submission form. | Submit a question after seeing similar answers. | Demand capture, not public content. | Later. |
| `/sorularim` | Future private question list. | `noindex,nofollow`; sitemap excluded. | None. | Private list. | Track answers. | No public SEO value. | Later. |
| `/sorularim/[id]` | Future private question detail. | `noindex,nofollow`; sitemap excluded. | None. | Private question and response. | Read own answer. | No public SEO value. | Later. |
| `/admin` | Existing team workspace. | `noindex,nofollow`; sitemap excluded. | None. | Existing admin SPA. | Team operations. | No public SEO value. | Already production. |

Route rules:

- Public routes must read only public publication tables.
- Public routes must never read `history` directly.
- `/api/*` must not be swallowed by public or SPA fallbacks.
- `/admin` and `/admin/*` remain the team workspace and must keep noindex
  protections.
- Public root cutover is a later phase and requires a separate rollout plan.

## E. Public UX Direction

The public experience should feel like a premium knowledge archive:

- Search-centered first screen.
- Calm hierarchy and strong typography.
- Dense enough for repeat use, but not visually crowded.
- Warm and serious rather than decorative.
- Mobile reading must be first-class.
- The site should avoid marketing-style hero sections; the first screen should
  be the usable archive entry.
- Copy should use public archive language: soru-cevap, arşiv, konu, kategori,
  kavram, rehber, son güncelleme, ilgili cevaplar.

Primary public actions:

- Search the archive.
- Open a question-answer detail.
- Browse by topic.
- Browse by category.
- Read a guide.
- Copy/share/print a public answer.
- Later, submit a question only after similar archive answers are shown.

## F. Visual Design Direction

Quality references:

- Apple: clarity, restraint, spacing, typography.
- Linear: refined dark mode and quiet grid.
- Vercel: sharp system feel and fast page confidence.
- Stripe: component polish and detail quality.
- Notion: navigable knowledge-base structure.

Religious content constraints:

- Do not make it look like a neon technology product.
- Do not overuse SaaS dashboards or startup gradients.
- Avoid aggressive motion and decorative visual noise.
- The mood should be dignified, warm, clear, and stable.

Light mode direction:

- Warm off-white page background.
- Cream surfaces.
- Deep anthracite or very dark navy text.
- Deep green primary accent.
- Subtle gold details for dividers, focus, and selected states.

Dark mode direction:

- Deep navy/black background.
- Dark elevated surfaces.
- Cream-white text.
- Deep green and restrained gold accents.
- Very subtle glow, never decorative blobs.

Image and visual assets:

- Public pages should prefer typography, structured content, and subtle
  editorial surfaces.
- If visual assets are added later, they should clarify subjects or reading
  paths, not act as stock decoration.

## G. Light/Dark Theme Tokens

Theme modes:

- `light`
- `dark`
- `system`

Suggested token contract:

| Token group | Light direction | Dark direction |
| --- | --- | --- |
| `background` | Warm off-white, e.g. `#f7f3ea`. | Deep navy/black, e.g. `#0f1412`. |
| `surface` | Cream, e.g. `#fffaf0`. | Dark green-black, e.g. `#171d1a`. |
| `surfaceElevated` | White/cream with low shadow. | Slightly lighter dark surface. |
| `text` | Anthracite/navy. | Cream-white. |
| `textMuted` | Warm gray. | Muted warm gray. |
| `border` | Warm beige-gray. | Dark muted green/gray. |
| `primary` | Deep green. | Softer but still deep green. |
| `accent` | Subtle gold. | Muted gold. |
| `ring` | Green/gold focus ring with enough contrast. | Green/gold focus ring with enough contrast. |
| `shadow` | Very soft, low contrast. | Low, contained dark shadow. |
| `glow` | Almost none; only active search/focus if needed. | Restrained edge glow only. |
| `radius` | 6-8px for cards; 999px only for pills/toggles. | Same. |
| `spacing` | 4/8/12/16/24/32/48/64 scale. | Same. |
| `typography` | System sans plus readable article font. | Same metrics, adjusted contrast. |
| `articleTypography` | 18-20px body, 1.75 line-height. | 18-20px body, 1.8 line-height. |
| `mobileTypography` | 17-18px body, generous line spacing. | Same, slightly higher contrast. |

Additional token rules:

- No negative letter spacing.
- Do not scale font size with viewport width.
- Article content max width should be stable.
- Buttons and fixed controls should have stable height.
- Text must not overflow buttons/cards on mobile.

## H. Component System

| Component | Purpose | Used on | Desktop/mobile behavior | Theme notes | Accessibility |
| --- | --- | --- | --- | --- | --- |
| `PublicHeader` | Public navigation, search entry, theme control. | All public pages. | Desktop horizontal, mobile compact drawer/sheet. | Transparent or solid depending scroll; no admin language. | Semantic nav, visible focus. |
| `ThemeToggle` | Light/dark/system control. | Header/footer/settings. | Compact icon control. | Uses token colors only. | Button label and state announced. |
| `SearchHero` | Main search-first entry. | Home. | Centered desktop; full-width mobile. | Calm surface, high contrast input. | Search landmark and label. |
| `SearchBox` | Query input and submit. | Home, search page, header. | Large on home, compact elsewhere. | Clear focus ring. | Keyboard submit, visible label. |
| `TopicMarquee` | Slow concept flow. | Home/topic hubs. | Desktop calm marquee; mobile scroll chips. | No loud motion. | Pause/stop and reduced-motion support. |
| `TopicCard` | Topic summary and link. | Home, topic lists, guides. | Grid desktop, 1-2 columns mobile. | Subtle border/accent. | Whole card link with clear text. |
| `QuestionCard` | Question result/list item. | Search, category, topic, home. | Dense but readable; mobile stacked. | Summary and metadata muted. | Heading hierarchy preserved. |
| `FeaturedQA` | Highlight important published answer. | Home/category/topic. | Large card or editorial row. | Gentle gold/green accent. | Link text describes target. |
| `LatestQAList` | Recently published answers. | Home/category/topic. | List desktop/mobile. | Minimal dividers. | List semantics. |
| `GuideCard` | Guide preview. | Home, topic, category. | Grid/list hybrid. | Warm editorial surface. | Clear title and description. |
| `CategoryGrid` | Category browsing. | Home/category index. | 3-4 columns desktop, 1-2 mobile. | Distinct icons optional. | Keyboard reachable cards. |
| `Breadcrumb` | Location and hierarchy. | Detail/topic/category/guide/glossary. | Single line desktop, wrap mobile. | Muted text. | `nav aria-label="Breadcrumb"`. |
| `AnswerArticle` | Main answer renderer. | `/soru/[slug]`. | 720-820px content width. | Article tokens, quote blocks. | Semantic article, headings. |
| `SummaryCard` | Short answer/summary. | Detail and guides. | Above detailed answer. | High readability. | Not only color-coded. |
| `RelatedQA` | Related question list. | Detail/topic/guide. | Side rail desktop or below mobile. | Quiet cards. | Ordered/unordered list. |
| `RelatedGuides` | Related guide list. | Detail/topic/category. | Below article or side rail. | Editorial cards. | Clear link names. |
| `TopicMap` | Concept relation graph/list. | Topic pages, guide pages. | Desktop compact map; mobile list. | No complex canvas for MVP. | Text alternative required. |
| `LearningPathCard` | Ordered reading path. | Home/topic/future paths. | Numbered steps. | Calm progress indicator. | Ordered list semantics. |
| `ShareBar` | Share/copy/print actions. | Detail/guide. | Desktop side or top; mobile bottom/inline. | Icon + tooltip. | Buttons with labels. |
| `CopyButton` | Copy canonical URL or selected text. | Detail/guide/cards. | Stable icon button. | Success state token. | Announces copied state. |
| `PrintButton` | Print-friendly action. | Detail/guide. | Optional compact. | Print CSS support. | Button label. |
| `EmptyState` | No results/empty categories. | Search/list pages. | Clear next actions. | No internal process language. | Helpful text. |
| `SkeletonCard` | Loading placeholder. | Search/list if client-enhanced. | Stable dimensions. | Low contrast shimmer; reduced motion. | `aria-busy` where appropriate. |
| `Footer` | Canonical links and simple navigation. | All public pages. | Column desktop/mobile. | Muted. | Semantic footer. |
| `PublicLayout` | Shared public shell. | All public pages. | Defines landmarks. | Applies theme tokens. | Skip link, main landmark. |
| `ArticleLayout` | Reading layout. | Question and guide pages. | Main column plus optional related rail. | Strong type comfort. | Semantic article. |

## I. Motion and Marquee Rules

Motion must be calm and optional:

- Motion is slow and never attention-grabbing.
- Marquee or concept flow pauses on hover.
- Motion pauses when any item receives keyboard focus.
- A visible pause/stop control must exist when motion is continuous.
- `prefers-reduced-motion: reduce` disables non-essential animation.
- Mobile can use horizontal scroll or a static chip list instead of marquee.
- Motion must not move text the user is actively trying to read.
- No fast sliders, auto-advancing cards, or layout-shifting carousel behavior.

## J. Home Page UX

Homepage after public cutover:

- H1: `İbrahimLive Soru Cevap Arşivi`.
- Supporting copy: `Merak ettiğiniz konu, kavram veya soruyu arşivde arayın.`
- Primary element: large central search box.
- Secondary elements: topics, categories, featured answers, latest answers,
  and guides.

Recommended section order:

1. Header with simple nav, theme toggle, and search shortcut.
2. Search-first archive intro.
3. Premium topic/concept flow.
4. Popular topics.
5. Featured question-answers.
6. Latest question-answers.
7. Guide/knowledge articles.
8. Category/concept grid.
9. Short trust-oriented archive explanation.
10. Footer.

The page should not be a marketing landing page. It should open directly as a
usable archive and knowledge center.

## K. Search UX

Search principles:

- Search is the primary interaction.
- Search should support Turkish character and apostrophe variation tolerance.
- Results must only show `published` public records.
- Search result pages are `noindex,follow`.
- Empty results should suggest topics, categories, and future question
  submission only after similar content is shown.

Search phases:

| Phase | Approach | Notes |
| --- | --- | --- |
| Phase 1 | Normalized `ILIKE`. | Good enough for MVP with `search_text_normalized`. |
| Phase 2 | PostgreSQL full-text search. | Weighted title, question, summary, answer. |
| Phase 3 | `pg_trgm` plus aliases. | Typo tolerance and concept variations. |
| Phase 4 | Semantic search/embeddings. | Later, only with strict source and privacy rules. |

Search ranking priorities:

1. Exact title or question match.
2. Topic/category match.
3. Summary match.
4. Answer body match.
5. Alias/trigram match.
6. Recency and editorial featured boost.

## L. Question Detail UX

`/soru/[slug]` is the canonical answer page.

Page structure:

1. Breadcrumb.
2. Category label.
3. H1 title.
4. Short answer or summary.
5. Original public question block.
6. Detailed answer.
7. Related concepts.
8. Similar question-answers.
9. Related guides.
10. Previous/next recommended reading.
11. Share, copy, and print actions.
12. Publish date, last update, and last reviewed date.

Reading comfort:

- Desktop article max width: 720-820px.
- Body text: 18-20px, high line-height.
- Mobile paragraphs get generous spacing.
- Verse, quote, or special blocks use calm indentation and subtle border.
- Related content should not interrupt the answer flow.
- Copy/share/print controls should not cover text on mobile.

LLM/sourceability structure:

- Clear H1.
- Short answer near top.
- Visible question.
- Detailed answer in semantic article HTML.
- Related concepts and internal links.
- Last reviewed date.
- Article JSON-LD aligned with visible content.

## M. Topic/Category/Glossary UX

Topic page structure:

- H1 topic name.
- Short definition.
- Important question-answers.
- Related guides.
- Related concepts.
- Recommended reading order.
- Recently added answers.

Category page structure:

- H1 category name.
- Category description.
- Subtopics.
- Popular concepts.
- Featured guides.
- Featured answers.
- Latest answers in the category.

Glossary page structure:

- H1 term.
- Short definition.
- Detailed explanation.
- Aliases and spelling variations.
- Related question-answers.
- Related guides.
- Related topics/categories.

Glossary pages should solve "what does this concept mean?" quickly, then guide
the reader to full archive answers.

## N. Guide/Rehber Architecture

Use `rehber` or `bilgi yazıları`; do not frame this layer as a blog in public UI.

Route:

- `/rehber/[slug]`

Guide types:

- Main concept guide.
- Relationship guide between concepts.
- Frequently searched topic guide.
- Guide compiled from archive answers.
- Learning path guide.
- Beginner guide.

Initial 20 guide candidates:

| Guide | Main topic/category | Links to |
| --- | --- | --- |
| Allah'a Ulaşmayı Dilemek Nedir? | Hidayet / başlangıç | Hidayet, dua, teslimiyet questions. |
| Hidayet Kavramını Doğru Anlamak | Hidayet | Hidayet topic, related question details, glossary term. |
| Mürşid ve Rehberlik Ne Anlama Gelir? | İrşad / rehberlik | Mürşid, tabiiyet, hidayet answers. |
| Tövbe ve Tevbe Suresi Bağlamı | Tövbe / Kur'an kavramları | Tövbe concept, Tevbe Suresi references, related questions. |
| Zikir: Süreklilik ve Kalp Huzuru | İbadet / zikir | Zikir questions, kalp concept, daily practice guides. |
| Takva: Sakınma ve Sorumluluk Bilinci | Takva | Takva answers, iman and amel topics. |
| Nefs Mertebeleri ve Terbiye | Nefs | Nefs glossary, related QA, learning path. |
| Teslimiyet ve Teslimler | Teslimiyet | Teslim, irade, hidayet answers. |
| Dua: Niyet, Niyaz ve Devamlılık | Dua | Dua topic, zikir relation, answered questions. |
| İman ve Yakîn Arasındaki Bağ | İman / yakîn | İman answers, yakîn glossary, related guides. |
| Ruh, Emanet ve Sorumluluk | Ruh / emanet | Ruh questions, ahiret and sorumluluk categories. |
| Kalp Kavramı ve Manevi Gelişim | Kalp | Kalp glossary, zikir and hidayet questions. |
| İrşad ve Doğru Yol | İrşad | Mürşid, hidayet, tabiiyet links. |
| Kur'ân-ı Kerîm'de Korunmuş Kitap Bilinci | Kur'an kavramları | Korunmuş kitap answers, Hicr 9 references if present. |
| Ahiret Bilinci ve Günlük Hayat | Ahiret | Ahiret answers, amel and sorumluluk topics. |
| Peygamberler ve Örnek Rehberlik | Peygamberler | Prophet-related QA and concept pages. |
| Namaz ve Zikir İlişkisi | İbadet | Namaz, zikir, kalp huzuru links. |
| Tabiiyet ve Bağlılık | Tabiiyet | Mürşid, irşad, hidayet answers. |
| İmtihan Kavramı | İmtihan | Sabır, teslimiyet, dua topics. |
| Yeni Başlayanlar İçin Arşiv Okuma Yolu | Learning path | Ordered beginner sequence across core concepts. |

Each guide must link back to canonical question-answer pages rather than
duplicating full answers unnecessarily.

## O. User Question System Architecture

This is deferred scope and will not be implemented in P2B.

Future user flow:

1. User signs in.
2. User writes a question.
3. The archive first shows similar published answers.
4. User reads the suggested answers.
5. If not sufficient, user chooses to submit the question.
6. The question is stored privately.
7. Team answers behind the scenes.
8. User sees the answer in their account.
9. If suitable, the answer becomes a public archive candidate.
10. It moves to `public_qa` draft.
11. It passes preview and publishing gates.
12. Only then can it become published.

Future routes:

- `/giris`
- `/hesap`
- `/soru-gonder`
- `/sorularim`
- `/sorularim/[id]`

Security rules:

- A user sees only their own private questions.
- Private user questions are not in sitemap.
- Private routes are noindex.
- Public APIs do not return private questions.
- User answers never auto-publish.
- The experience must not look like a chatbot or instant generated-answer UI.

## P. SEO and LLM Architecture

The goal is not to guarantee rankings or LLM citation. The goal is to strengthen
sourceability, crawlability, and semantic clarity.

SEO principles:

- HTML-first/server-rendered public pages.
- Clean canonical URLs.
- Self-canonical indexable pages.
- `/arama` noindex,follow.
- `/admin`, private, preview, draft, review, archived, and API routes excluded
  from public sitemap.
- Sitemap contains only published canonical public URLs.
- Internal links connect questions, topics, categories, glossary, and guides.
- Topic clusters create clear conceptual neighborhoods.
- Last reviewed and modified dates are visible and reflected in schema.
- `ibrahimlive.com` should use summary plus source link, not full duplicate
  content in the first phase.

LLM sourceability principles:

- Clear H1.
- Short answer near the top.
- Explicit question text.
- Detailed answer in semantic HTML.
- Related concepts as linked entities.
- Breadcrumbs.
- JSON-LD aligned with visible content.
- No internal process wording.
- No hidden answer content that differs from the visible article.

Measurement should be treated as learning, not proof. Search Console, internal
search behavior, and page engagement should guide iterative improvements.

## Q. Schema Matrix

| Route | Schema | Notes |
| --- | --- | --- |
| `/` | `WebSite`, `Organization`, `CollectionPage` or `WebPage`, `BreadcrumbList`, optional `ItemList`. | Public archive home after cutover. |
| `/soru/[slug]` | `WebPage`, `Article`, `BreadcrumbList`. | Do not use `QAPage` or random `FAQPage`. |
| `/rehber/[slug]` | `WebPage`, `Article`, `BreadcrumbList`. | Guide content must match visible article. |
| `/konu/[slug]` | `CollectionPage`, `ItemList`, `BreadcrumbList`, `DefinedTerm`. | Topic as concept/entity hub. |
| `/kategori/[slug]` | `CollectionPage`, `ItemList`, `BreadcrumbList`. | Category collection. |
| `/sozluk/[slug]` | `WebPage`, `DefinedTerm`, `BreadcrumbList`. | Glossary entity page. |
| `/arama?q=...` | Optional `WebPage`; `noindex,follow`. | No rich result target. |
| `/admin` and private routes | None; `noindex,nofollow`. | Sitemap excluded. |

Schema builders to centralize:

- `websiteSchema`
- `organizationSchema`
- `breadcrumbSchema`
- `questionArticleSchema`
- `guideArticleSchema`
- `topicCollectionSchema`
- `categoryCollectionSchema`
- `glossaryTermSchema`
- `itemListSchema`

Schema rules:

- JSON-LD must represent visible content.
- Dates must come from public publication fields.
- `Article.author` and `publisher` should use `Organization` for IbrahimLive.
- `QAPage` and opportunistic `FAQPage` are not part of MVP.

## R. Data Model Draft

No migration is created in P2B. This is a draft contract for future DB work.

Core public models:

| Model | Purpose | Key fields |
| --- | --- | --- |
| `public_qa` | Published question-answer records. | `id`, `source_history_id`, `title`, `slug`, `question`, `answer`, `summary`, `category_id`, `status`, `published_at`, `last_reviewed_at`, `canonical_path`, `seo_title`, `seo_description`, `read_time`, `content_hash`, `search_text_normalized`, `search_vector`, `is_featured`, `sort_order`. |
| `public_categories` | Category taxonomy. | `id`, `name`, `slug`, `description`, `parent_id`, `status`, `seo_title`, `seo_description`, `sort_order`. |
| `public_topics` | Topic/concept taxonomy. | `id`, `name`, `slug`, `description`, `aliases`, `status`, `seo_title`, `seo_description`, `sort_order`. |
| `public_qa_topics` | QA-topic many-to-many. | `qa_id`, `topic_id`, `sort_order`. |
| `public_guides` | Guide/knowledge articles. | `id`, `title`, `slug`, `summary`, `body`, `status`, `published_at`, `last_reviewed_at`, `seo_title`, `seo_description`, `canonical_path`. |
| `public_guide_topics` | Guide-topic relation. | `guide_id`, `topic_id`, `sort_order`. |
| `public_guide_related_qa` | Guide to QA relation. | `guide_id`, `qa_id`, `relation_type`, `sort_order`. |
| `public_glossary_terms` | Term definitions. | `id`, `term`, `slug`, `definition_short`, `definition_long`, `aliases`, `status`, `seo_title`, `seo_description`. |
| `public_content_relations` | Generic relation graph. | `source_type`, `source_id`, `target_type`, `target_id`, `relation_type`, `sort_order`. |
| `public_redirects` | Slug/path redirects. | `from_path`, `to_path`, `http_status`, `active`, `reason`. |
| `public_publish_events` | Append-only publication audit. | `entity_type`, `entity_id`, `event_type`, `from_status`, `to_status`, `actor_user_id`, `metadata`, `created_at`. |

Publication rules:

- `public_qa.status='published'` is required for public visibility.
- `history.status='onaylandi'` is only a candidate signal.
- Published slugs should not change unless a redirect is created.
- Sitemap includes only canonical published URLs.
- Public render/API must not expose `source_history_id`, user IDs, internal
  hashes, scoring, workflow status, or source snapshots.

Deferred user system draft:

- `user_profiles`
- `user_questions`
- `user_question_responses`
- `user_question_status_events`

These are P2A/P2J scope, not P2B implementation scope.

## S. Super Admin Only Management Needs

Public management controls may be added under the existing team workspace later,
but only for `super_admin`.

| Module | Purpose | Visible to | Data managed | MVP | Security risk |
| --- | --- | --- | --- | --- | --- |
| Public Arşiv Yönetimi | Manage public QA drafts and published records. | Super admin only. | `public_qa`. | Yes. | Accidental publish/unpublish. |
| Public Preview | View drafts with noindex/private access. | Super admin only. | Draft public records. | Yes. | Draft leakage. |
| Ana Sayfa Bölümleri | Configure homepage sections. | Super admin only. | Featured topics, featured QA, guide slots. | Yes. | Public homepage misconfiguration. |
| Öne Çıkan Cevaplar | Curate highlighted answers. | Super admin only. | `is_featured`, `sort_order`. | Yes. | Wrong content prominence. |
| Konu/Kategori Yönetimi | Manage taxonomy. | Super admin only. | `public_topics`, `public_categories`. | Yes. | Broken internal links. |
| Rehber Yazıları | Create and review guides. | Super admin only. | `public_guides`. | Phase 2. | Duplicate or unsupported content. |
| SEO/Schema Ayarları | Manage SEO overrides and schema validation. | Super admin only. | SEO fields and schema status. | Phase 2. | Indexing/canonical mistakes. |
| Sitemap/Indexing Durumu | See sitemap and noindex health. | Super admin only. | Generated SEO outputs. | Yes before launch. | Drafts entering sitemap. |
| Yayın Gate Kontrolü | Validate public safety gates. | Super admin only. | Gate results. | Yes. | Publishing unsafe content. |
| Public Dil Guard Sonuçları | Show forbidden public-language checks. | Super admin only. | Check results. | Yes. | Internal language leakage. |
| Content Relation Graph | Manage related content. | Super admin only. | `public_content_relations`. | Phase 2. | Bad relation graph. |
| Redirect Yönetimi | Manage slug redirects. | Super admin only. | `public_redirects`. | Yes after first slug changes. | Redirect loops or wrong canonicals. |
| User Questions to Public Candidate | Convert answered private questions into candidates. | Super admin only. | User question to `public_qa` draft. | Later. | Private data leakage. |

All modules need role checks on API and frontend. Hiding a tab in the UI is not
enough.

## T. Publishing Workflow

Question-answer publishing:

```text
history approval
-> public draft
-> preview
-> publish gate
-> published
```

Detailed rules:

1. Existing team workflow produces and approves operational content.
2. Approved `history` records do not auto-publish.
3. A super-admin-only action prepares a public draft.
4. The public draft gets title, slug, question, answer, summary, category,
   topics, SEO fields, related links, and review dates.
5. Preview is noindex and not in sitemap.
6. Publish gates run.
7. Only `published` records are public.

Future user question publishing:

```text
user question
-> similar archive answers shown
-> user submits anyway
-> team answers
-> user sees answer
-> public candidate
-> public_qa draft
-> preview
-> published
```

User question answers never become public automatically.

## U. Public Safety and Quality Gates

Required gates before any public publish:

| Gate | Fail condition |
| --- | --- |
| Public forbidden words | Public HTML/API/metadata/JSON-LD includes internal terms. |
| Source integrity | Religious content is added without source support. |
| Publication layer | Public page reads `history` directly. |
| Status | Record is not `published`. |
| Canonical | Missing, wrong domain, query canonical, or mismatch with sitemap. |
| Slug | Missing, duplicate, unstable, or changed without redirect. |
| Summary | Missing or copied from internal operational summary without edit. |
| Topic/category | Missing required taxonomy. |
| Schema | Invalid JSON-LD or schema not aligned with visible content. |
| Internal links | No related content or broken links. |
| Index/noindex | Draft/private/search/admin routes indexable or sitemap-included. |
| Related content | Private or non-published content linked publicly. |
| Language | Internal process wording appears in public UI. |
| Religious integrity | Any source-unsupported claim, reference distortion, or context shift. |

Most important rule:

> Kaynakta olmayan dini bilgi public içeriğe eklenemez.

## V. Measurement Plan

Measure after launch:

- Search Console indexing status.
- Google query data.
- Internal search queries.
- Zero-result internal searches.
- Most-read question-answer pages.
- Most-read guides.
- Topic and category clicks.
- Copy/share/print actions.
- Related content clicks.
- User question submissions after similar-result suggestions.
- Public candidates created from answered user questions.
- Publish gate failures by type.

Privacy and operations:

- Do not expose personal user data in public analytics surfaces.
- Avoid writing high-frequency page view counters directly to core content rows
  until the write strategy is defined.
- Search and zero-result logs should be reviewed for content planning without
  leaking private user questions.

## W. Implementation Phases

Recommended sequence:

| Phase | Scope | Implementation? |
| --- | --- | --- |
| P2B | SEO/LLM/UX/IA design architecture docs. | This document only. |
| P2C | Public frontend visual design system docs. | Docs-only. |
| P2D | Public preview shell implementation. | Code later, no root cutover. |
| P2E | Home/search/detail/topic/category templates. | Code later. |
| P2F | `public_qa`, guides, topics data integration. | DB/code later with separate approval. |
| P2G | Schema, sitemap, canonical, noindex. | Code later. |
| P2H | Super-admin-only public management shell. | Code later. |
| P2I | User question intake architecture. | Docs-only. |
| P2J | User question MVP. | Code/DB later with separate approval. |
| P2K | Root public cutover plan. | Plan then separate rollout. |

## X. Go / No-Go Criteria

Go for P2C:

- P2B architecture is accepted.
- Public product language is accepted.
- IA, route model, and schema matrix are accepted.
- Public data boundary is preserved: no direct `history` reads.
- Public forbidden-language guard remains required.
- Root cutover remains explicitly deferred.

Go for first public implementation phase:

- Existing `/admin` production route remains stable.
- Team adoption monitoring has no unresolved blocker/critical issue.
- A clean branch/worktree is used.
- Diff boundary is explicit before implementation.
- No admin/feedback/analysis-engine work is mixed into the public frontend patch.
- `PUBLIC_ARCHIVE_ENABLED` and `PUBLIC_ARCHIVE_INDEXING` behavior is defined.
- Rollback plan keeps root legacy available until cutover approval.

No-Go:

- Root `/` is changed to public in the same step as early implementation.
- Public pages read `history` directly.
- Draft/review/private content can appear publicly.
- `/admin` or `/api/*` route behavior is affected.
- Public UI includes forbidden internal terms.
- Public schema/canonical/noindex rules are unclear.
- User question system or feedback fixes are mixed into public frontend work.

## Y. Next Recommended Step

Recommended next step:

1. P2C Public Frontend Visual Design System Docs.
2. Then P2D Public Preview Shell Implementation behind a feature flag, without
   root cutover.

P2C should turn this architecture into concrete visual rules:

- Page layouts.
- Typography scale.
- Color tokens.
- Component variants.
- Mobile reading states.
- Search and article page wireframes.
- Public language examples.

Admin/feedback improvements should continue in a separate workstream and must
not be mixed into P2C/P2D public frontend patches.
