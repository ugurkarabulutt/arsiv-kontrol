# Public Archive P2C Public Frontend Visual Design System

Date: 2026-08-03
Status: Docs-only visual design system plan

## A. Visual North Star

The public archive should communicate trust in the first five seconds:

- This is the official IbrahimLive question-answer archive.
- The page is calm, readable, and serious.
- Search is the primary way to begin.
- The site is modern and premium, but not showy.
- It is a knowledge center, not a marketing page, chat interface, or internal
  operations tool.

Public first impression:

```text
Clear archive entry
-> large search
-> carefully grouped topics
-> readable answers
-> dignified religious knowledge center
```

Reference translation:

| Reference | What to borrow | What not to borrow |
| --- | --- | --- |
| Apple | Space, restraint, typography, confident hierarchy. | Oversized product-marketing hero behavior. |
| Linear | Refined dark mode, quiet borders, polished focus states. | Too much startup tool language. |
| Vercel | Fast, sharp, system-like surfaces. | Stark developer-platform feeling. |
| Stripe | Component polish, subtle depth, high-quality empty/loading states. | Busy gradients and decorative density. |
| Notion | Knowledge access, linked pages, browse/search clarity. | Plain document dump feeling. |

Specific exclusions:

- Neon technology-site look.
- Startup SaaS dashboard feeling.
- Aggressive gradients.
- Fast sliders.
- Heavy animation.
- Crowded landing-page sections.
- Decorative blobs, orbs, bokeh, and purely atmospheric backgrounds.
- Public copy that exposes internal process language.

The visual rule:

> Premium ama gösterişsiz; vakur ama soğuk değil; modern ama moda gösterisi değil.

## B. Color System

The palette uses warm neutral foundations, deep green for trust, subtle gold for
editorial emphasis, and dark navy/green-black for depth. It must not become a
one-note cream page; green, navy, and restrained gold should carry hierarchy.

### Light Mode

| Token | Hex | Usage | Accessibility note | Dark counterpart |
| --- | --- | --- | --- | --- |
| `color.bg` | `#F7F3EA` | Page background. | Soft but not low contrast against text. | `#0D1412` |
| `color.bgSubtle` | `#EFE8DC` | Section bands and quiet separators. | Use with dark text only. | `#101916` |
| `color.surface` | `#FFFDF7` | Cards, search surface, article blocks. | Keep text at `color.text`. | `#121B18` |
| `color.surfaceElevated` | `#FFFFFF` | Raised panels, dropdowns, overlays. | Add border for white-on-cream separation. | `#18231F` |
| `color.articleSurface` | `#FFFCF4` | Long reading surfaces. | Avoid pure white glare. | `#111A17` |
| `color.text` | `#17201C` | Primary text and headings. | Strong contrast on warm backgrounds. | `#F6F0E6` |
| `color.textMuted` | `#66736D` | Descriptions, metadata. | Do not use below 13px. | `#B8C0B8` |
| `color.textSoft` | `#8A7662` | Low-priority labels. | Use sparingly; check contrast. | `#8F9B93` |
| `color.border` | `#DDD2C0` | Card borders and dividers. | Visible on cream surfaces. | `#2C3A34` |
| `color.borderStrong` | `#BBA98F` | Active card border, table outline. | Pair with subtle backgrounds. | `#42544B` |
| `color.primary` | `#145A3A` | Main action, selected topic, important link. | Use white text. | `#79C99E` |
| `color.primaryHover` | `#0F4930` | Hover state for primary controls. | Maintain contrast with white text. | `#9ADDB8` |
| `color.accent` | `#B68A2A` | Gold detail, selected underline, editorial highlight. | Avoid using as small text on light surfaces. | `#D7B35D` |
| `color.focusRing` | `#7FB99A` | Focus ring and active search outline. | At least 2px ring plus offset. | `#9FE3BD` |
| `color.success` | `#177245` | Positive status or copied state. | Pair with pale green background. | `#7BD99F` |
| `color.warning` | `#A86500` | Caution and incomplete state. | Avoid pale yellow text. | `#E4AE55` |
| `color.error` | `#B42318` | Error state. | Use with `#FFF1F0` background if needed. | `#FF8A80` |
| `color.highlight` | `#F5E8C8` | Matched search term, quote highlight. | Do not use for large blocks. | `#2F2A1B` |
| `color.searchGlow` | `#CFE8D9` | Search focus halo. | Decorative only; focus ring remains visible. | `#294D3A` |

### Dark Mode

| Token | Hex | Usage | Accessibility note | Light counterpart |
| --- | --- | --- | --- | --- |
| `color.bg` | `#0D1412` | Page background. | Avoid pure black for reading comfort. | `#F7F3EA` |
| `color.bgSubtle` | `#101916` | Section bands. | Keep separation subtle. | `#EFE8DC` |
| `color.surface` | `#121B18` | Cards and search surface. | Needs visible border. | `#FFFDF7` |
| `color.surfaceElevated` | `#18231F` | Overlays, dropdowns, featured cards. | Use for real elevation only. | `#FFFFFF` |
| `color.articleSurface` | `#111A17` | Article body reading surface. | Body text should be cream-white. | `#FFFCF4` |
| `color.text` | `#F6F0E6` | Primary text and headings. | Strong contrast on dark surfaces. | `#17201C` |
| `color.textMuted` | `#B8C0B8` | Descriptions and metadata. | Good for 14px+ text. | `#66736D` |
| `color.textSoft` | `#8F9B93` | Low-priority metadata. | Do not use for required labels. | `#8A7662` |
| `color.border` | `#2C3A34` | Card borders and dividers. | Keep visible but quiet. | `#DDD2C0` |
| `color.borderStrong` | `#42544B` | Active border and selected card. | Use with green/gold accents. | `#BBA98F` |
| `color.primary` | `#79C99E` | Main action and important link. | Dark text or very dark surface required. | `#145A3A` |
| `color.primaryHover` | `#9ADDB8` | Hover state. | Avoid over-glow. | `#0F4930` |
| `color.accent` | `#D7B35D` | Gold detail and editorial highlight. | Avoid small gold body text. | `#B68A2A` |
| `color.focusRing` | `#9FE3BD` | Focus ring. | 2px minimum with offset. | `#7FB99A` |
| `color.success` | `#7BD99F` | Positive status. | Pair with dark green surface. | `#177245` |
| `color.warning` | `#E4AE55` | Caution status. | Keep text large enough. | `#A86500` |
| `color.error` | `#FF8A80` | Error state. | Do not rely only on color. | `#B42318` |
| `color.glowSubtle` | `#294D3A` | Search and active topic glow. | Low opacity only. | `#CFE8D9` |
| `color.quoteBorder` | `#5B724B` | Quote/verse block edge. | Must not overpower article. | `#C8B27A` |

Color behavior rules:

- Links should use `primary`, not blue by default.
- Gold is for editorial emphasis, not primary actions.
- Search focus can use a soft glow, but visible focus ring is mandatory.
- Error/warning/success states must include icon/text, not color alone.
- Public article pages should favor reading contrast over decorative richness.

## C. Typography System

Typography should feel modern, readable, and mature. It should not feel playful,
ornamental, or trend-driven.

Recommended font stack:

| Role | Preferred option | Alternative | Notes |
| --- | --- | --- | --- |
| UI/headings | `Geist` or `Inter` | `Source Sans 3` | Clean, modern, premium. |
| Body/article | `Source Sans 3` | `Inter`, system sans | Strong Turkish readability. |
| Metadata | `Geist Mono` or system mono sparingly | Sans small caps without mono | Use mono very lightly. |
| Quote/special block | `Noto Serif` optional | Same body font | Only for a dignified accent, not full layout. |

Font evaluation:

- `Inter`: excellent UI clarity, familiar, safe.
- `Geist`: sharp Vercel-like system feeling; strong for headings/search UI.
- `Source Sans 3`: warmer reading quality; good for long Turkish content.
- `IBM Plex Sans`: serious and technical; usable if softened with spacing.
- Serif accents: only for quote/verse/special blocks; avoid decorative fonts.

Recommended type scale:

| Token | Desktop | Mobile | Usage |
| --- | --- | --- | --- |
| `font.hero` | 56px / 1.05 | 36px / 1.12 | Homepage H1 only. |
| `font.h1` | 44px / 1.12 | 32px / 1.18 | Detail/topic/category H1. |
| `font.h2` | 30px / 1.2 | 24px / 1.25 | Section headings. |
| `font.h3` | 22px / 1.3 | 20px / 1.35 | Card groups and article subsections. |
| `font.body` | 17px / 1.7 | 17px / 1.72 | General UI text. |
| `font.article` | 19px / 1.78 | 18px / 1.78 | Main answer and guide body. |
| `font.summary` | 20px / 1.65 | 18px / 1.68 | Short answer card. |
| `font.meta` | 13px / 1.4 | 12px / 1.45 | Dates, read time, labels. |
| `font.button` | 15px / 1.2 | 15px / 1.2 | Buttons and chips. |
| `font.breadcrumb` | 13px / 1.4 | 12px / 1.4 | Breadcrumb. |

Spacing rules:

- Paragraph spacing in articles: `1.0em` to `1.2em`.
- Section spacing: 48-72px desktop, 36-48px mobile.
- Article H2 top spacing: 44px desktop, 34px mobile.
- Quote/verse blocks: 20px vertical padding, 18-20px text, 1.75 line-height.
- Metadata should not compete with article content.

Typography constraints:

- No negative letter spacing.
- No viewport-width font scaling.
- Long Turkish words must wrap without breaking the layout.
- Buttons must never rely on condensed or tiny text.

## D. Layout System

Layout should make information easy to scan and long answers easy to read.

Core dimensions:

| Token | Desktop | Tablet | Mobile |
| --- | --- | --- | --- |
| `layout.max` | 1180-1240px | 92vw | calc(100vw - 32px) |
| `layout.narrow` | 920px | 88vw | calc(100vw - 32px) |
| `layout.article` | 720-820px | 760px max | calc(100vw - 32px) |
| `layout.sideRail` | 280-320px | Hidden or below | Below article |
| `layout.headerHeight` | 72px | 64px | 60px |
| `layout.footerMax` | 1180px | 92vw | calc(100vw - 32px) |

Grid:

- Desktop: 12-column grid, 24px gutters.
- Tablet: 8-column grid, 20px gutters.
- Mobile: single-column, 16px side padding.
- Cards should use stable dimensions and not resize on hover.

Spacing scale:

```text
4, 8, 12, 16, 20, 24, 32, 40, 48, 64, 80
```

Header:

- Sticky at top, but not visually heavy.
- Public header contains brand, search shortcut, topics/guides links, theme
  toggle.
- Mobile header uses a compact menu and search action.
- Header must not obscure anchor targets.

Article layout:

- Desktop: main article column with optional related side rail.
- Side rail should start below the first summary area, not next to the H1.
- Mobile: single column; related content moves below article.
- Optional mobile action bar may include copy/share, but must not cover text.

Footer:

- Simple navigation.
- Topic/category links.
- Source/canonical language.
- No technical operations wording.

Mobile ergonomics:

- Minimum touch target: 44x44px.
- Inputs use 16px+ font to avoid iOS zoom.
- Safe area padding for fixed bottom actions.
- No horizontal page overflow.

## E. Homepage Wireframe

Homepage goal: make the archive immediately searchable and browsable.

Text wireframe:

```text
[PublicHeader]

[SearchHero]
  H1: İbrahimLive Soru Cevap Arşivi
  Text: Merak ettiğiniz konu, kavram veya soruyu arşivde arayın.
  [Large SearchBox]
  Suggested chips: hidayet, tövbe, zikir, teslimiyet, dua

[TopicMarquee / Concept Flow]
  Slow concept chips with pause control

[Popular Topics]
  TopicCard grid

[Featured Question Answers]
  2 large FeaturedQA cards + 3 compact QuestionCards

[Latest Question Answers]
  LatestQAList

[Guide/Rehber Highlights]
  GuideCard row

[Category Grid]
  CategoryCard grid

[Trust/Archive Explanation]
  Short archive explanation and source/canonical note

[Footer]
```

### Section Details

| Section | Purpose | Desktop | Mobile | Components | Example content | Theme notes | SEO/LLM value | Avoid |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PublicHeader | Navigation and search access. | Horizontal nav, compact search trigger. | Brand, search icon/button, menu, theme. | `PublicHeader`, `ThemeToggle`. | Arşiv, Konular, Kategoriler, Rehberler. | Transparent-to-solid on scroll optional. | Clear site structure. | Internal process links. |
| SearchHero | Main entry. | Centered, wide search, topic chips. | Full-width input, chips wrap. | `SearchHero`, `SearchBox`. | H1 and support copy. | Soft search glow only on focus. | Strong H1 and archive intent. | Marketing CTA overload. |
| Concept Flow | Show breadth. | Slow marquee or static row. | Scrollable chip list. | `TopicMarquee`. | hidayet, dua, zikir. | Low contrast border. | Entity discovery. | Fast slider. |
| Popular Topics | Browse by concept. | 3-4 column topic cards. | 1-2 columns. | `TopicCard`. | Hidayet, Tövbe, Teslimiyet. | Green selected accents. | Topic clusters. | Decorative icons only. |
| Featured QA | Editorial highlights. | Large editorial layout. | Stacked cards. | `FeaturedQA`, `QuestionCard`. | Important answers. | Gold border detail. | Internal links to canonical answers. | Random list feel. |
| Latest QA | Freshness. | Compact list. | Compact list. | `LatestQAList`. | Son eklenenler. | Muted metadata. | Crawl paths to new content. | Infinite feed. |
| Guide Highlights | Deep learning. | 3-card guide row. | Stacked guide cards. | `GuideCard`. | Yeni başlayanlar rehberi. | Article-like surfaces. | Supports topic authority. | Blog framing. |
| Category Grid | Broad browse. | Dense grid. | 1-2 column grid. | `CategoryCard`. | İbadet, Kur'an kavramları. | Stable card height. | Category hubs. | Too many cards above fold. |
| Trust Explanation | Explain archive calmly. | Narrow text block. | Short paragraph. | Plain content block. | Arşiv kayıtları düzenli olarak gözden geçirilir. | Quiet surface. | Entity/trust copy. | Guarantees. |
| Footer | Site map. | Multi-column. | Stacked. | `Footer`. | Konular, Rehberler. | Muted. | Crawlable links. | Dense legal clutter. |

## F. Search UX Wireframe

Search appears in three places:

- Home hero search.
- Header compact search.
- `/arama?q=...` full results page.

### Home Search

```text
[SearchBox]
  Placeholder: Arşivde konu, kavram veya soru ara
  Submit: Ara
  Suggested chips below
```

Behavior:

- `Enter` submits.
- Search icon button has an accessible label.
- Focus state uses visible ring plus soft glow.
- Suggested chips are links to topic/search routes.

### Search Results

```text
[PublicHeader]
[SearchBox with current query]
[Result summary]
  "hidayet" için 24 sonuç
[Filters]
  Tümü | Soru-cevap | Rehber | Konu
[Results]
  QuestionCard
  GuideCard
  TopicCard
[Related topics]
[Footer]
```

Result card fields:

- Title.
- Summary.
- Matched excerpt.
- Category.
- Topics.
- Read time.
- Last reviewed.
- Result type: `soru`, `rehber`, `konu`.

### Empty Result

```text
Aradığınız ifadeyle eşleşen bir kayıt bulunamadı.

Önce şu konulara bakabilirsiniz:
[Topic suggestions]

İlgili rehberler:
[Guide suggestions]

Later:
Sorunuzu göndermek isterseniz hesabınızdan takip edebilirsiniz.
```

Rules:

- First show topic suggestions.
- Then guide suggestions.
- Future question submission appears after archive suggestions.
- It must not look like a chatbot.
- Empty state remains calm and useful.

### Loading State

- Skeleton result cards with stable height.
- Search input remains usable.
- Reduced motion disables shimmer and uses static placeholders.

### Typo/Alias Result

Example:

```text
"tovbe" için "tövbe" konusundaki sonuçlar gösteriliyor.
```

Rules:

- Do not over-explain algorithmic matching.
- Show the normalized concept as a helpful public phrase.

### Topic Suggestion

When query maps strongly to a topic:

```text
Öne çıkan konu
[TopicCard: Tövbe]
```

This supports both users and internal linking without indexing search URLs.

## G. Question Detail Wireframe

Question detail page is the primary canonical public source.

Desktop wireframe:

```text
[PublicHeader]

[Breadcrumb]
  Ana sayfa / Kategori / Konu

[ArticleLayout]
  [Main column]
    [Category label]
    H1
    [Meta row: yayın tarihi, son gözden geçirme, okuma süresi]
    [SummaryCard]
    [Question block]
    [AnswerArticle]
      H2 sections if needed
      quote/verse/special blocks
    [Related topics]
    [Related question answers]
    [Related guides]
    [Previous / next reading]

  [Side rail optional]
    [ShareBar]
    [In this answer]
    [Related concepts]

[Footer]
```

Mobile wireframe:

```text
[PublicHeader compact]
[Breadcrumb wraps]
[Category label]
H1
[SummaryCard]
[Question block]
[AnswerArticle single column]
[Related topics]
[Related QAs]
[Related guides]
[Share/copy/print inline or compact sticky]
[Footer]
```

Required fields:

- Breadcrumb.
- Category label.
- H1.
- Summary or short answer card.
- Question block.
- Detailed answer.
- Related topics.
- Related QAs.
- Related guides.
- Previous/next reading.
- Share/copy/print.
- Last updated / last reviewed.

Design rules:

- Article max width: 720-820px.
- H1 should not be squeezed beside side content.
- Summary card should be prominent but not look like an alert.
- Quote/verse blocks use calm border and readable spacing.
- Related content is below the answer on mobile.
- Copy/share/print controls must never cover text.

## H. Topic / Category / Guide / Glossary Wireframes

### Topic Page

```text
[PublicHeader]
[Breadcrumb]
[Topic header]
  H1: Tövbe
  Short definition
  Related aliases/chips
[Core answers]
[Guides]
[Related concepts]
[Recommended reading order]
[Latest additions]
[Footer]
```

Purpose:

- Define a concept.
- Link canonical answers.
- Build entity relationships.

### Category Page

```text
[PublicHeader]
[Breadcrumb]
[Category header]
  H1: Kur'an Kavramları
  Category description
[Subtopics]
[Popular concepts]
[Featured answers]
[Guide highlights]
[Latest in this category]
[Footer]
```

Purpose:

- Broad browsing.
- Category-level internal linking.
- Help users enter a subject area.

### Guide Page

```text
[PublicHeader]
[Breadcrumb]
[Guide article]
  H1
  Intro summary
  Table of contents
  Sections
  Linked archive answers
  Related topics
  Next reading
[Footer]
```

Purpose:

- Curated learning.
- Connect multiple published answers.
- Avoid blog-style chronological framing.

### Glossary Page

```text
[PublicHeader]
[Breadcrumb]
[Term header]
  H1
  Short definition
[Detailed definition]
[Aliases and variations]
[Related answers]
[Related guides]
[Related topics]
[Footer]
```

Purpose:

- Fast concept lookup.
- Disambiguate terms and spelling variants.
- Guide readers into full answers and guides.

## I. Component Variants

Component states must be deliberate and stable. Hover should refine, not
reshape.

| Component | Default | Hover | Focus | Active | Disabled/loading | Light/dark | Mobile |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `PublicHeader` | Brand, nav, search, theme. | Nav underline or text tone shift. | Visible ring on controls. | Current section subtle indicator. | None. | Light solid/transparent; dark elevated. | Compact menu and search button. |
| `ThemeToggle` | Icon or segmented control. | Slight surface lift. | Ring and state label. | Selected state clear. | None. | Uses surface/text tokens. | 44px target. |
| `SearchHero` | Centered H1, text, large search. | None on container. | Search focus glow. | None. | Skeleton not needed. | Soft warm/dark surface. | Full-width, chips wrap. |
| `SearchBox` | Input + submit icon/button. | Border strengthens. | Ring plus glow. | Submit pressed state. | Spinner or disabled submit. | High contrast input. | 16px+ input font. |
| `TopicMarquee` | Slow chip flow. | Pauses. | Pauses on focused chip. | Chip opens topic. | Static if reduced motion. | Low-contrast borders. | Scroll chips/static list. |
| `TopicCard` | Title, short definition, count optional. | Border/accent lift. | Ring, no layout shift. | Selected/pressed state. | Skeleton card. | Green/gold accents. | 1-2 columns. |
| `QuestionCard` | Title, summary, metadata. | Title color shifts, border lift. | Whole card focus ring. | Pressed subtle scale only if no layout shift. | Skeleton. | Article-like surface. | Stacked metadata. |
| `GuideCard` | Title, description, linked topics. | Slight elevated surface. | Ring. | Pressed. | Skeleton. | Warm editorial surface. | Stacked. |
| `CategoryCard` | Category name, description, topic count. | Border/primary accent. | Ring. | Active category state. | Skeleton. | Stable card height. | 1-2 columns. |
| `Breadcrumb` | Muted link trail. | Link underline. | Ring around links. | Current item not linked. | None. | Muted but readable. | Wraps gracefully. |
| `SummaryCard` | Short answer. | No hover if not interactive. | Links inside focusable. | None. | Skeleton possible. | Subtle green/gold left border. | Full width. |
| `AnswerArticle` | Semantic article text. | Links underline. | Focused internal links visible. | Anchor targets highlighted briefly. | None. | Article surface token. | Single column. |
| `RelatedContentCard` | Small linked card. | Border lift. | Ring. | Pressed. | Skeleton. | Quiet surface. | Full-width list. |
| `ShareBar` | Copy/share/print actions. | Icon tone shift. | Ring and tooltip. | Copied state. | Disabled while copying. | Surface or transparent. | Inline or compact sticky. |
| `CopyButton` | Copy URL/text. | Surface lift. | Ring. | Success state. | Spinner if needed. | Success token for copied. | 44px target. |
| `PrintButton` | Print page. | Surface lift. | Ring. | Pressed. | Disabled if unsupported. | Neutral. | Optional inline. |
| `EmptyState` | Helpful message and suggestions. | Links only. | Focus on suggested links. | None. | None. | Warm calm surface. | Shorter text. |
| `SkeletonCard` | Placeholder shape. | None. | None. | None. | Loading state. | Low opacity; no glare. | Static under reduced motion. |
| `Footer` | Links and brief archive note. | Link underline. | Focus visible. | Current section optional. | None. | Muted. | Stacked. |

Variant rules:

- Cards use 8px max border radius unless a specific control needs pill shape.
- Nested cards are avoided.
- Page sections are not floating cards; repeated content cards may be cards.
- Icons should be familiar and named with tooltips or accessible labels.

## J. Motion System

Motion should help orientation and perceived quality. It must not compete with
reading.

Timing:

| Use | Duration | Easing |
| --- | --- | --- |
| Hover color/border | 120-160ms | `ease-out` |
| Surface lift | 140-180ms | `cubic-bezier(.2,.8,.2,1)` |
| Search focus glow | 180-240ms | `ease-out` |
| Page section reveal | 220-320ms | `cubic-bezier(.16,1,.3,1)` |
| Skeleton shimmer | 1200-1600ms loop | Linear, disabled on reduced motion |
| Topic marquee | 50-70s per full loop | Linear, pauseable |

Motion rules:

- Page transitions are subtle fade/translate at most.
- Search focus animation may use a soft glow and border change.
- Topic marquee must pause on hover and focus.
- Reduced motion disables marquee, shimmer, and reveal movement.
- Dark mode glow uses low opacity only.
- No scroll-jacking.
- No heavy JS animation library for MVP.
- No moving text inside active reading areas.
- No fast slider or continuously attention-seeking animation.

## K. Accessibility Requirements

Accessibility is part of the design system, not a later polish task.

Required checks:

- Keyboard navigation for all links, buttons, chips, menus, and forms.
- Visible focus ring on every interactive element.
- Skip link to main content.
- Semantic landmarks: `header`, `nav`, `main`, `article`, `aside`, `footer`.
- Breadcrumb uses `nav aria-label="Breadcrumb"`.
- Search input has a visible or programmatic label.
- Icon buttons have accessible names.
- Color contrast meets WCAG AA for body and controls.
- Reduced motion respected.
- Minimum touch target 44x44px.
- Body text 17px+ on mobile.
- No text embedded only in images.
- Error states include text, not color alone.
- Loading states use `aria-busy` where relevant.
- Menus trap focus only when modal; otherwise normal tab order.
- Mobile bottom actions respect safe area.

Screen reader notes:

- Result cards should expose title, type, and summary in logical order.
- Metadata should not interrupt the main title/summary reading order.
- Copy success should be announced politely.
- Table of contents links should have clear section text.

## L. Public Copy System

Public copy should be warm, simple, and non-technical.

Public allowed tone:

- Clear.
- Sincere.
- Calm.
- Direct.
- Helpful.
- Archive and knowledge centered.

Public forbidden terms:

- `AI`
- `prompt`
- `model`
- `admin`
- `denetim`
- `onay kuyruğu`
- `kalite kontrol`
- `test verisi`

Example public copy:

| Surface | Copy |
| --- | --- |
| Homepage H1 | `İbrahimLive Soru Cevap Arşivi` |
| Homepage support | `Merak ettiğiniz konu, kavram veya soruyu arşivde arayın.` |
| Search placeholder | `Arşivde konu, kavram veya soru ara` |
| Search submit | `Ara` |
| Suggested topics label | `Sık aranan konular` |
| Empty result title | `Bu aramayla eşleşen bir kayıt bulunamadı.` |
| Empty result support | `Benzer konulara ve rehberlere göz atabilirsiniz.` |
| Topic card CTA | `Konuya git` |
| Question card CTA | `Cevabı oku` |
| Summary label | `Kısa cevap` |
| Question block label | `Soru` |
| Detailed answer label | `Cevap` |
| Related topics | `İlgili konular` |
| Related answers | `Benzer soru-cevaplar` |
| Related guides | `İlgili rehberler` |
| Copy button | `Bağlantıyı kopyala` |
| Copy success | `Bağlantı kopyalandı` |
| Share button | `Paylaş` |
| Print button | `Yazdır` |
| Last reviewed | `Son gözden geçirme` |
| Latest section | `Son eklenenler` |
| Guide section | `Rehberler` |

Copy rules:

- Do not promise certainty about search visibility or external ranking.
- Do not expose internal workflow, scoring, or review mechanics.
- Do not describe the site as a chatbot.
- Do not ask users to trust hidden process language.
- Use `arşiv kaydı`, `yayın tarihi`, `son güncelleme`, `son gözden geçirme`,
  `ilgili konular`, and `cevabı oku`.

## M. Super Admin Only Public Management UX

Public management screens are future architecture only. They are not coded in
P2C and must not be mixed with general admin or feedback work.

Visibility rule:

```text
Only super_admin can see and use public management modules.
Normal admin and team users cannot see these modules.
API-level role checks are mandatory later.
```

Management UX modules:

| Module | UX purpose | Primary screen pattern | MVP | Risk |
| --- | --- | --- | --- | --- |
| Public Arşiv Yönetimi | Manage public QA drafts/published records. | Filterable table plus detail drawer. | Yes | Accidental publish/unpublish. |
| Public Preview | Review public page before publish. | Preview page with gate checklist. | Yes | Draft leakage. |
| Ana Sayfa Bölümleri | Curate homepage modules. | Ordered section editor. | Yes | Homepage misconfiguration. |
| Öne Çıkan Cevaplar | Select featured answers. | Search and pin workflow. | Yes | Wrong content prominence. |
| Konu/Kategori Yönetimi | Manage taxonomy. | Tree/list and detail form. | Yes | Broken links or duplicate slugs. |
| Rehber Yazıları | Create guide pages. | Article editor with linked records. | Later | Unsupported claims if unmanaged. |
| SEO/Schema Sağlığı | Inspect canonical/schema status. | Health dashboard. | Yes before indexing | Bad indexing signals. |
| Sitemap/Indexing Durumu | Check sitemap/noindex state. | Status table. | Yes before launch | Draft route leakage. |
| Yayın Gate Kontrolü | Validate publish readiness. | Gate checklist with blocking failures. | Yes | Unsafe content publish. |
| Public Dil Guard Sonuçları | Show public language scan. | Pass/fail list. | Yes | Internal wording leak. |
| Redirect Yönetimi | Manage changed slugs. | Redirect table with loop warning. | Yes after slug changes | Redirect loops. |

UX rules:

- Use clear danger boundaries for publish/unpublish.
- Preview must show what the public sees, plus a private gate panel.
- Gate failures block publish.
- Draft/published status must be visually distinct.
- No public management control is visible to normal roles.

## N. Implementation Readiness For P2D

P2D should implement a public preview shell only. It must not cut over root `/`.

Recommended P2D flags:

| Flag | Meaning |
| --- | --- |
| `PUBLIC_ARCHIVE_PREVIEW_ENABLED` | Enables noindex preview shell route. |
| `PUBLIC_ARCHIVE_ENABLED` | Remains false for root public behavior until later. |
| `PUBLIC_ARCHIVE_INDEXING` | Remains false. |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | True only when public data tables exist and are used. |
| `ADMIN_ROOT_LEGACY_ENABLED` | Remains true until root cutover. |

Preview route suggestion:

```text
/public-preview
/public-preview/soru/[slug]
/public-preview/konu/[slug]
/public-preview/kategori/[slug]
```

P2D route requirements:

- `GET /` remains legacy team/admin shell.
- `GET /admin` remains production team/admin shell.
- `/api/*` remains JSON/non-HTML.
- Preview routes are noindex and sitemap excluded.
- Preview routes do not read `history` directly.
- Public forbidden word guard is present for preview output.
- No public root cutover.

Suggested P2D diff boundary:

- `server.js` for gated preview route registration.
- `vercel.json` only if Vercel needs explicit preview route/header parity.
- New public renderer module, for example `public-archive-renderer.js`.
- New public CSS file, for example `public-archive.css`.
- `scripts/check-frontend.js` for public language, route, and noindex checks.
- Optional focused tests for renderer/schema helpers.

Files not to touch in P2D unless explicitly approved:

- Existing admin business logic.
- Feedback/analysis engine files.
- DB schema/migrations.
- Root admin `index.html` unless the P2D plan specifically requires an isolated
  public asset and the diff boundary is reapproved.

Rollback strategy:

- Turn off `PUBLIC_ARCHIVE_PREVIEW_ENABLED`.
- Revert the isolated P2D patch.
- Keep `/` and `/admin` legacy behavior intact.
- Keep `PUBLIC_ARCHIVE_INDEXING=false`.

## O. Go / No-Go Criteria

Go for P2D planning:

- P2C visual system is accepted.
- P2D preview route is approved.
- Root public cutover remains out of scope.
- Public forbidden word guard is part of the implementation checklist.
- `/admin`, `/admin/*`, `/api/*`, static assets, and service worker behavior
  are explicitly protected.
- Diff boundary is written before code starts.

No-Go:

- The implementation tries to make `/` public immediately.
- Public pages read `history` directly.
- Preview pages can be indexed.
- Public copy includes forbidden internal terms.
- Admin/feedback/analysis work is mixed into public frontend work.
- Vercel route behavior is unclear.
- Rollback path is not defined.

## P. Next Recommended Step

Recommended next step:

```text
P2D Public Preview Shell Implementation Plan
```

Before writing code, P2D should define:

- Exact preview route.
- Exact feature flag values.
- Exact files to touch.
- Exact files not to touch.
- Local smoke matrix.
- Vercel preview smoke matrix.
- Rollback steps.

After that plan is approved, implementation can happen in a clean worktree with
root `/` still preserved as legacy team/admin shell.
