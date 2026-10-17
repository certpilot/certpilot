-- 044_acme_server.sql
--
-- The tables behind serving ACME (RFC 8555) from the core, so that certbot,
-- acme.sh, win-acme and Caddy can get certificates from CertPilot without the
-- agent (#140).
--
-- Three things are kept. The credentials an administrator hands out, the
-- accounts clients make with them, and the nonces already spent. Orders and
-- authorisations come with the PR that serves them.
begin;

-- Registration is closed: an account can only be made by presenting one of
-- these (External Account Binding). Each belongs to one template, so the
-- account made with it can only ask for what that template allows.
create table if not exists public.acme_eab_credentials (
  id uuid primary key default gen_random_uuid(),
  kid text not null unique,
  name text not null,
  template_id uuid not null references public.certificate_templates(id) on delete cascade,

  -- Sealed, not hashed: the core recomputes an HMAC over the client's account
  -- key to check the binding, so it needs the key itself.
  hmac_key_sealed text not null,

  created_by text,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  revoked_by text
);

create table if not exists public.acme_accounts (
  id uuid primary key default gen_random_uuid(),
  template_id uuid not null references public.certificate_templates(id) on delete cascade,

  -- One credential makes one account. Without this a single leaked credential
  -- could register as many accounts as it liked.
  eab_id uuid not null unique references public.acme_eab_credentials(id) on delete cascade,

  -- RFC 7638. What finds an account when a client has lost its URL.
  jwk_thumbprint text not null,
  jwk text not null,

  status text not null default 'valid' check (status in ('valid', 'deactivated')),
  contacts jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint acme_accounts_key_unique unique (template_id, jwk_thumbprint)
);

-- Nonces are stateless: random, expiring and MACed with a key derived from the
-- KEK, so issuing one writes nothing. Only the ones that were used are kept, so
-- that none is accepted twice.
create table if not exists public.acme_used_nonces (
  nonce_hash bytea primary key,
  expires_at timestamptz not null
);

create index if not exists idx_acme_used_nonces_expiry
  on public.acme_used_nonces (expires_at);

commit;
