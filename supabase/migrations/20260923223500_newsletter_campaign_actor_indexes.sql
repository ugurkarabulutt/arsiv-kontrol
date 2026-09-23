create index if not exists newsletter_campaigns_created_by_idx
  on public.newsletter_campaigns (created_by);

create index if not exists newsletter_campaigns_updated_by_idx
  on public.newsletter_campaigns (updated_by);
