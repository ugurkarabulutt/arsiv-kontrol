alter table public.public_question_submissions
  add column if not exists newsletter_consent boolean not null default false,
  add column if not exists newsletter_consent_version text,
  add column if not exists newsletter_consented_at timestamptz;

comment on column public.public_question_submissions.newsletter_consent is
  'Soru formundaki isteğe bağlı e-posta bülteni kutusunun kullanıcı tarafından işaretlenip işaretlenmediği.';

comment on column public.public_question_submissions.newsletter_consent_version is
  'Kullanıcıya gösterilen isteğe bağlı bülten rıza metninin sürümü.';
