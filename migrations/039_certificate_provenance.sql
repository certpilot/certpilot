-- 039_certificate_provenance.sql
--
-- A certificate records the rules it was issued under, so renewal can ask
-- whether they still hold.
--
-- The renewal sweep is the only component that touches every managed
-- certificate on a timer, which makes it the only place a policy change can
-- propagate through an estate. Today it builds its request from the row —
-- `KeyType: cert.KeyType, KeySize: int32(cert.KeySize)` — and consults nothing.
-- So tightening a rule changes what may be requested tomorrow and nothing about
-- what is already issued: an RSA-1024 certificate imported in 2023 renews as
-- RSA-1024 in 2031, on schedule, quietly, showing green.
--
-- Why the version and not just the id
-- ------------------------------------
-- "This certificate violates its template" is unanswerable without "... which
-- has been edited twice since it was issued". A template's rules change; the
-- record of which version governed a particular issuance does not. AD CS and
-- EJBCA both version templates for the same reason.
--
-- All three columns are nullable, and null is a fact rather than a gap
-- ---------------------------------------------------------------------
-- Most of an inventory predates templates: discovered by a scan, found in a CT
-- log, imported from a cloud provider, or issued before migration 036 existed.
-- Backfilling a template onto those would be inventing provenance. Null means
-- "issued before this was recorded", and renewal treats it as it always has —
-- except that the estate-wide floor now applies to it too, which is what makes
-- a policy change reach the whole estate rather than only its newest part.
begin;

alter table public.certificates
  -- Set null rather than cascading: deleting a template does not unmake the
  -- certificates issued under it, and the record that one existed is part of
  -- why the certificate is there. Migration 038 refuses to delete a template a
  -- grant still names; this is the looser rule for the far more numerous side.
  add column if not exists template_id uuid
    references public.certificate_templates(id) on delete set null,

  -- Deliberately not a foreign key to anything. It is the version in force at
  -- issuance, and it has to survive the template being edited — which is the
  -- only reason to record it.
  add column if not exists template_version integer
    check (template_version is null or template_version > 0),

  add column if not exists grant_id uuid
    references public.template_grants(id) on delete set null;

create index if not exists idx_certificates_template
  on public.certificates (template_id)
  where template_id is not null;

comment on column public.certificates.template_id is
  'The template this was issued under. Null means issued before templates existed.';
comment on column public.certificates.template_version is
  'The template version in force at issuance. Survives later edits to the template.';

commit;
