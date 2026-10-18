-- 049_acme_tls_alpn.sql
--
-- TLS-ALPN-01 (RFC 8737) as a third way to prove a name to the ACME server
-- (#140), beside HTTP-01 and DNS-01.
begin;

alter table public.acme_authorizations
  drop constraint if exists acme_authorizations_validated_with_check;

alter table public.acme_authorizations
  add constraint acme_authorizations_validated_with_check
  check (validated_with in ('http-01', 'dns-01', 'tls-alpn-01'));

commit;
