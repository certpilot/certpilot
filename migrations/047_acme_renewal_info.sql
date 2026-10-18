-- 047_acme_renewal_info.sql
--
-- ACME Renewal Information (RFC 9773) for the ACME server (#140).
--
-- renewalInfo names a certificate by its issuer's key identifier and its
-- serial, so certificates are looked up by serial. An order may say which
-- certificate it replaces, by that identifier, which is what makes "already
-- replaced" answerable, and the record it was in, which each renewal writes
-- over.
begin;

create index if not exists idx_certificates_serial on public.certificates (serial_number);

alter table public.acme_orders
  add column if not exists replaces_certificate_id uuid references public.certificates(id) on delete set null,
  add column if not exists replaces text;

create index if not exists idx_acme_orders_replaces
  on public.acme_orders (replaces) where replaces is not null;

commit;
