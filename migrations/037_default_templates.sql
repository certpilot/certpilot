-- 037_default_templates.sql
--
-- A template for every CA account that already exists, constraining nothing.
--
-- Migration 036 created the object. This is what makes it safe to put in front
-- of issuance: a request that names no template resolves to its CA account's
-- default, and that default permits exactly what was permitted before templates
-- existed. Every caller written against the old API keeps working, unchanged,
-- and the three-stage path to requiring a template can start.
--
-- Without this row the compatibility path has nothing to resolve to and the
-- first request after the upgrade fails — which is the same outage a migration
-- that deleted somebody's policy would cause, arrived at from the other side.
--
-- The slug is derived from the account id rather than its name. A name can be
-- edited, can repeat, and can contain characters the slug column refuses; the
-- id can do none of those. `default-<first eight hex digits>` is stable,
-- unique, and short enough to type.
--
-- These rows are ordinary templates. An operator may tighten one, and the
-- moment they do it stops being a compatibility shim and becomes the rule for
-- everything issued from that CA.
begin;

insert into public.certificate_templates
  (slug, name, description, ca_account_id,
   subject_mode, allowed_key_types, ecdsa_curves,
   rsa_min_bits, rsa_max_bits, validity_days, max_validity_days,
   renew_before_days, auto_renew)
select
  'default-' || left(replace(a.id::text, '-', ''), 8),
  'Default (' || a.name || ')',
  'Generated when templates were introduced. Constrains nothing, so requests '
    || 'that name no template behave exactly as they did before. Safe to '
    || 'tighten; the estate-wide floor in Policies still applies either way.',
  a.id,
  -- SUPPLIED with no subject_defaults constrains nothing: the subject rule only
  -- has something to say once a template names an organisation. Starting at
  -- CONSTRAINED would record a decision nobody made, and it is the decision
  -- that matters most.
  'SUPPLIED',
  '["RSA", "ECDSA", "Ed25519"]'::jsonb,
  '["P-256", "P-384", "P-521"]'::jsonb,
  -- Zero throughout: the floor belongs in policies, where somebody put it on
  -- purpose. A compatibility template that quietly imposed 2048 would be a rule
  -- nobody wrote, applied to every request that did not name a template.
  0, 0, 0, 0,
  -- The values the request handler defaulted to before this existed.
  30, true
from public.ca_accounts a
where not exists (
  select 1 from public.certificate_templates t
  where t.slug = 'default-' || left(replace(a.id::text, '-', ''), 8)
);

commit;
