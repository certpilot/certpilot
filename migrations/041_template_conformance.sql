-- 041_template_conformance.sql
--
-- #30: CertPilot cannot enforce key usage, extended key usage, validity, or
-- even the requested names on a CA whose own template decides them — ACME's
-- profile and Vault's role are both opaque from here. Sending a request and
-- storing whatever comes back, unchecked, is a control that passes while
-- enforcing nothing: the exact defect this milestone exists to remove,
-- reintroduced at the very last step if issuance stopped at "the gateway
-- said yes".
--
-- The honest answer is issue, then check: parse what actually came back and
-- compare it against what was asked for. This column is the switch that
-- decides what happens when they disagree, and it has to be a property of
-- the template rather than a global setting, because the right strictness
-- differs by CA. ENFORCE suits a private CA under the operator's own
-- control, where a mismatch means the CA is misconfigured. REPORT suits a
-- public CA whose behaviour the operator does not set, where the same
-- mismatch is the CA doing exactly what it always does.
begin;

alter table public.certificate_templates
  add column if not exists conformance text not null default 'REPORT'
    check (conformance in ('ENFORCE', 'REPORT'));

comment on column public.certificate_templates.conformance is
  'ENFORCE: a certificate that does not match what was requested is refused '
  'and, where the gateway supports it, revoked. REPORT: it is recorded '
  'anyway, with the mismatch attached as a finding. Defaults to REPORT so '
  'that adding this column cannot turn a working estate into one where '
  'every renewal against a public CA starts failing overnight; new templates '
  'against a CA this deployment controls are set to ENFORCE by the API '
  'handler, not by this default.';

commit;
