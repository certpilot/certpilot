-- 043_ca_account_server_name.sql
--
-- Store the TLS server name override a CA account was created with.
--
-- CreateCAAccountInput has accepted server_name since the gateway TLS layer
-- needed one, and Create used it exactly once to register the gateway at
-- account-creation time. It was never written onto the row. Every later
-- reconnect — including the one POST /api/v1/ca-accounts/:id/health
-- performs on demand — had no way to recover it and dialed with an empty
-- override instead, silently falling back to deriving the expected name from
-- the dial address. That fallback is correct for the ordinary case (a
-- hostname address whose certificate names the same hostname) and wrong for
-- exactly the case server_name exists to cover: a gateway dialed by IP or
-- through a service alias whose certificate names something else.
--
-- Empty string is the correct default rather than null: "derive it from the
-- address" is a real, valid choice an operator can make by leaving the field
-- blank, not the absence of one.
begin;

alter table public.ca_accounts
    add column if not exists server_name text not null default '';

commit;
