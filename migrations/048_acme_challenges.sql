-- 048_acme_challenges.sql
--
-- HTTP-01 and DNS-01 for the ACME server (#140), for credentials that require
-- them. A credential that does not keeps its client pre-authorised by the
-- credential and the template's name rules, which is the behaviour before this
-- migration and stays the default.
begin;

alter table public.acme_eab_credentials
  add column if not exists require_challenge boolean not null default false;

-- One per name of an order whose credential requires proof. Orders from other
-- credentials have none, and their authorizations are derived from the order.
create table if not exists public.acme_authorizations (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.acme_orders(id) on delete cascade,
  idx integer not null,
  -- The name to prove, without a wildcard's "*.".
  value text not null,
  wildcard boolean not null default false,
  status text not null check (status in ('pending', 'valid', 'invalid')),
  token text not null,
  expires_at timestamptz not null,
  error text,
  validated_with text check (validated_with in ('http-01', 'dns-01')),
  validated_at timestamptz,
  unique (order_id, idx)
);

commit;
