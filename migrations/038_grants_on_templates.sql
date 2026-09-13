-- 038_grants_on_templates.sql
--
-- A grant stops describing a certificate and goes back to being permission.
--
-- `agent_grants` has carried two unrelated things since migration 020. The top
-- half is *who may ask* — an agent id or a label selector, and the names they
-- may ask for. The bottom half is *what the certificate looks like* —
-- ca_account_id, min_key_size, allowed_key_types, validity_days,
-- renew_before_days.
--
-- That bottom half is a second, narrower rulebook, reachable only by agents,
-- maintained separately from `policies`, and drifting from it the moment either
-- changes. It is why an agent can obtain a certificate the policy engine would
-- refuse a person: `Issuer.Issue` consults `grant.AllowsKey` and has never
-- consulted the policy engine at all.
--
-- Every system that models this well keeps the two apart — a certificate
-- profile beside an end entity profile, a template beside an ACL on it. This
-- migration does the same: the shape moves to `certificate_templates`, and what
-- is left is a binding.
--
-- Renamed rather than replaced
-- -----------------------------
-- The table is renamed and altered in place, so ids, foreign keys and history
-- survive. The alternative — a new table beside the old one — leaves
-- `agent_grants` sitting there readable and editable while nothing consults it,
-- which is the exact failure this whole line of work exists to remove. An
-- operator who edits a control and sees no effect is worse off than one who
-- cannot find it.
--
-- Behaviour is preserved exactly
-- -------------------------------
-- One template per existing grant, carrying that grant's own rules, named after
-- it. An agent that could request `web-01.example.com` at ECDSA P-256 before
-- this migration can request exactly that after it.
--
-- The key floor is the fiddly part, because `AgentGrant.AllowsKey` did not mean
-- what `min_key_size` looks like it means. It applied that number to RSA only,
-- under a hard floor of 2048 — "nothing below this is worth signing, whatever a
-- grant written years ago happens to say" — and judged every elliptic key
-- against the separate MinEllipticBits constant of 256. So the faithful
-- translation is rsa_min_bits = max(min_key_size, 2048) and no curve
-- restriction at all. Copying min_key_size into a single floor for both would
-- silently start refusing P-256 on every grant that said 2048.
begin;

-- Guarded, like every other statement in this directory, because a migration
-- that has already run must be a no-op the second time. A bare RENAME is the
-- one statement here with no `if exists` form of its own.
--
-- Both halves of the condition are load-bearing. Re-applying the whole
-- directory by hand — which is what somebody does when they are not sure what
-- ran — re-executes migration 020's `create table if not exists agent_grants`,
-- which succeeds against a database where 038 has already moved that table
-- away. Checking only that agent_grants exists would then rename it over the
-- live template_grants and take the estate's grants with it.
do $$
begin
  if exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'agent_grants'
  ) and not exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'template_grants'
  ) then
    alter table public.agent_grants rename to template_grants;
  end if;
end $$;

-- ── The binding gains a subject kind ────────────────────────
--
-- AGENT is what every existing row is. ROLE, TEAM and USER are what let this
-- bound a person's request as well as a host's — the first time CertPilot can
-- say "the payments team may use the internal-mTLS template, for names under
-- payments.internal, and nothing else".
alter table public.template_grants
  add column if not exists subject_kind text not null default 'AGENT'
    check (subject_kind in ('AGENT', 'ROLE', 'TEAM', 'USER')),
  add column if not exists role text,
  add column if not exists team text,
  add column if not exists user_id uuid,
  add column if not exists template_id uuid references public.certificate_templates(id) on delete restrict;

-- ── One template per grant, carrying that grant's rules ─────
--
-- Guarded on the columns still being there. Re-applying the directory by hand
-- runs this file against a database where the first pass already moved the
-- shape onto templates and dropped these columns; PL/pgSQL plans a statement
-- only when its branch is taken, so the unreachable insert is never parsed.
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public'
      and table_name = 'template_grants'
      and column_name = 'ca_account_id'
  ) then
  insert into public.certificate_templates
    (slug, name, description, ca_account_id,
     subject_mode, allowed_key_types, ecdsa_curves, san_rules,
     rsa_min_bits, validity_days, renew_before_days, auto_renew)
  select
    'grant-' || left(replace(g.id::text, '-', ''), 8),
    'Grant: ' || g.name,
    'Generated when grants stopped carrying certificate shape. Carries exactly '
      || 'what grant "' || g.name || '" permitted, so nothing an agent could '
      || 'request before can be refused now.',
    g.ca_account_id,
    'SUPPLIED',
    g.allowed_key_types,
    -- No curve restriction: the old code judged every elliptic key against one
    -- global constant and never against min_key_size.
    '["P-256", "P-384", "P-521"]'::jsonb,
    -- DNS only, which is what the agent path already enforced in code: "only DNS
    -- names are issued to agents: the others are validated differently and a
    -- grant has no way to express them". A template *can* express them, so the
    -- rule moves here — preserved exactly for every existing grant, and
    -- relaxable on a new template that genuinely wants an IP or SPIFFE name.
    '{"types": ["DNS"]}'::jsonb,
    greatest(g.min_key_size, 2048),
    g.validity_days,
    g.renew_before_days,
    -- The core never renewed an agent's certificate — the host holds the key, so
    -- only the host can rotate it, and a sweep that tried would fail forever.
    false
  from public.template_grants g
  where not exists (
    select 1 from public.certificate_templates t
    where t.slug = 'grant-' || left(replace(g.id::text, '-', ''), 8)
  );

  update public.template_grants g
  set template_id = t.id
  from public.certificate_templates t
  where t.slug = 'grant-' || left(replace(g.id::text, '-', ''), 8)
    and g.template_id is null;
  end if;
end $$;

-- ── The shape columns go ────────────────────────────────────
--
-- After the copy above, never before it. Dropping them is the point: a column
-- nothing reads is a rule an operator can still edit.
alter table public.template_grants
  drop column if exists ca_account_id,
  drop column if exists min_key_size,
  drop column if exists allowed_key_types,
  drop column if exists validity_days,
  drop column if exists renew_before_days;

-- ── The target check covers the new subject kinds ───────────
--
-- The old constraint said "an agent id or a label selector", which is right for
-- AGENT and refuses every other kind. A grant matching nothing would sit in the
-- list looking like permission somebody had given, and that is as true of a
-- ROLE grant naming no role as it was of an agent grant naming no agent.
alter table public.template_grants
  drop constraint if exists agent_grants_target_check;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'template_grants_subject_check'
  ) then
    alter table public.template_grants
      add constraint template_grants_subject_check check (
        case subject_kind
          when 'AGENT' then agent_id is not null or label_selector <> '{}'::jsonb
          when 'ROLE'  then role is not null and length(trim(role)) > 0
          when 'TEAM'  then team is not null and length(trim(team)) > 0
          when 'USER'  then user_id is not null
        end
      );
  end if;
end $$;

-- Every grant must name the template it binds to. Nullable above only so the
-- backfill could run; enforced here so a new one cannot be written without.
alter table public.template_grants
  alter column template_id set not null;

create index if not exists idx_template_grants_template
  on public.template_grants (template_id)
  where revoked_at is null;

create index if not exists idx_template_grants_subject
  on public.template_grants (subject_kind)
  where revoked_at is null and is_enabled;

comment on table public.template_grants is
  'Who may use which certificate template, and for which names. The shape lives on the template.';

commit;
