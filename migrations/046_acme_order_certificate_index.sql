-- 046_acme_order_certificate_index.sql
--
-- Revocation over ACME (#140) finds the order that produced a certificate, to
-- check the account asking is the one that ordered it. The index also serves
-- the foreign key: without it, deleting a certificate scans every order to
-- clear the ones that point at it.
create index if not exists idx_acme_orders_certificate
  on public.acme_orders (certificate_id) where certificate_id is not null;
