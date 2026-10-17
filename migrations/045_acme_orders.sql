-- 045_acme_orders.sql
--
-- Orders for the ACME server (#140), and 'ACME' as a way a certificate can
-- arrive in the inventory.
--
-- There is no authorisation table. Authorisations are pre-authorised by the
-- account's credential, which belongs to one template, so each one is valid
-- from the start and is derived from its order rather than stored. Challenges
-- (HTTP-01, DNS-01) come later, and will need one.
begin;

create table if not exists public.acme_orders (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references public.acme_accounts(id) on delete cascade,
  status text not null check (status in ('pending', 'ready', 'processing', 'valid', 'invalid')),
  identifiers jsonb not null,
  expires_at timestamptz not null,

  -- Set null rather than cascade: deleting a certificate record must not make
  -- an order look as if it never produced one. The order still says valid.
  certificate_id uuid references public.certificates(id) on delete set null,

  -- The problem document that made the order invalid, as the client was told.
  error text,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_acme_orders_account on public.acme_orders (account_id, created_at desc);

-- Same three lines as migrations 012 and 021, one source later.
alter table public.certificates
  drop constraint if exists certificates_discovered_via_check;

alter table public.certificates
  add constraint certificates_discovered_via_check
  check (discovered_via in ('MANUAL', 'SCAN', 'CT_LOG', 'IMPORT', 'REQUESTED', 'CLOUD', 'AGENT', 'ACME'));

commit;
