-- 040_template_key_usage.sql
--
-- #31: key usage, extended key usage, and extension passthrough.
--
-- Deliberately last of the template columns, and deliberately narrow, for the
-- reason the issue gives: this is the part CertPilot has the least power
-- over. A public CA's profile decides key usage in a way no column here can
-- override, and pretending otherwise with a checkbox that does nothing would
-- be worse than not having the checkbox — a template that looks like a
-- promise and is a wish.
--
-- Where each column is actually enforced, per gateway, is documented in
-- docs/status.md rather than here, because it is a fact about the gateway
-- fleet as it exists today and will change as gateways gain the ability to
-- describe their own profiles.
begin;

alter table public.certificate_templates
  -- Empty means unconstrained, same convention as every other column here:
  -- a template that has never mentioned key usage has not decided about it,
  -- and a non-empty default would be a rule nobody wrote applied to
  -- requests nobody expected it to touch.
  add column if not exists key_usage jsonb not null default '[]'::jsonb,
  add column if not exists extended_key_usage jsonb not null default '[]'::jsonb,

  -- False is the only sane default: a template that silently started minting
  -- CA certificates because a column was added would be the loudest possible
  -- way to fail at issuing certificates.
  add column if not exists basic_constraints_ca boolean not null default false,

  add column if not exists extension_passthrough text not null default 'NONE'
    check (extension_passthrough in ('NONE', 'LISTED', 'ALL')),

  -- Only meaningful under LISTED; empty under NONE and ALL. Not constrained
  -- to be empty when they are, because a template edited from LISTED back to
  -- NONE keeping its old OID list is an operator's decision to reverse, not
  -- a data integrity problem — the list does nothing while passthrough is
  -- NONE, and reappears with its old meaning if passthrough is turned back
  -- on. Losing it silently on a round trip through the UI would be worse.
  add column if not exists passthrough_oids jsonb not null default '[]'::jsonb;

comment on column public.certificate_templates.extension_passthrough is
  'NONE (default): nothing from a CSR''s extensions reaches the certificate. '
  'LISTED: only passthrough_oids. ALL: every extension the CSR carries. '
  'An extension copied out of a CSR is an attacker-controlled field in a '
  'signed certificate — see EJBCA and Google CAS''s own warnings about the '
  'equivalent setting, both of which default it off for the same reason.';

commit;
