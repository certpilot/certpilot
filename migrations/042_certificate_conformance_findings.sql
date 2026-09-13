-- 042_certificate_conformance_findings.sql
--
-- Where #30's comparison is recorded. A certificate that came back shorter
-- than requested, or carrying an OU nobody asked for, is still a certificate
-- worth keeping — the finding is what keeps that fact visible instead of
-- letting the record imply the CA did exactly what the template said.
--
-- Null and empty are the same "nothing to report" on purpose: every
-- certificate this deployment has ever stored predates this column, and a
-- distinction between "never checked" and "checked, no findings" is not one
-- this migration can make truthfully for a single row of history.
begin;

alter table public.certificates
  add column if not exists conformance_findings jsonb not null default '[]'::jsonb;

comment on column public.certificates.conformance_findings is
  'What #30''s post-issuance check found, if anything: field, severity '
  '(BLOCK or REPORT), and a message. BLOCK here means the finding belongs '
  'to the class core/engine/issuance/conform.go refuses under an ENFORCE '
  'template — a certificate that reached this column with a BLOCK finding '
  'was issued under REPORT, or under a template that has since changed.';

commit;
