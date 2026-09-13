-- 036_certificate_templates.sql
--
-- Issuance policy moves from the estate to the certificate.
--
-- `policies` answers "what may this organisation ever issue". It is one flat
-- list evaluated against every request, which is the right shape for a floor
-- and the wrong shape for everything above it: an internal mTLS certificate for
-- a service mesh and a public TLS certificate for a marketing site have almost
-- nothing in common, and a single list of rules that has to be true of both can
-- only contain what they share.
--
-- A template answers the other question — "what does this particular kind of
-- certificate look like" — and every system that does this well keeps the two
-- apart. Google CAS has a CA-pool issuance policy above certificate templates.
-- EJBCA has certificate profiles under a global configuration. AD CS has
-- templates under CA-wide settings. Collapsing them means every template
-- restates the organisation's minimums, and the one that forgets silently
-- permits less than the organisation does.
--
-- The thing a template can do that a policy cannot
-- ------------------------------------------------
-- The policy engine can only constrain: "RSA must be at least 3072". A template
-- also has to be able to *supply* a value the requester cannot touch, and to
-- *pass through* a value the requester decides. Three dispositions, not two —
-- that third axis is the whole reason this table exists.
--
-- The default disposition is supplied by the template. Passthrough is opted
-- into, and `subject_mode` is where that decision is recorded. Microsoft's own
-- hardening guidance and Defender for Identity both flag "Supply in the
-- request" combined with broad enrolment rights, because that is ESC1. It is a
-- default worth not repeating.
--
-- Zero means unconstrained
-- ------------------------
-- Every numeric bound here defaults to 0, and 0 means "this template does not
-- constrain it". A column defaulting to 2048 would look like a safe default and
-- would in fact be a rule nobody wrote, applied to requests nobody expected it
-- to touch. The floor belongs in `policies`, where an operator put it on
-- purpose; a template tightens from there.
--
-- `version` is not decoration
-- ---------------------------
-- Editing a template in place and silently reclassifying every certificate ever
-- issued under it is the mistake the metadata field invariants already prevent:
-- a reworded option must not rewrite history. AD CS and EJBCA both version
-- templates. The certificate row will record the version it was issued under,
-- so "this certificate violates its template" can be answered alongside "...
-- which has been edited twice since".
begin;

create table if not exists public.certificate_templates (
  id uuid primary key default gen_random_uuid(),

  -- The stable machine name. An agent or a CI job names this, not the id, and
  -- not the display name — renaming a template must not break every caller.
  slug text not null unique
    check (slug ~ '^[a-z][a-z0-9-]{0,62}$'),

  name text not null check (length(trim(name)) > 0),
  description text not null default '',

  -- Bumped by the application whenever a rule changes, never by a rename.
  version integer not null default 1 check (version > 0),

  is_enabled boolean not null default true,

  -- Which CA signs what this template describes. Part of the template rather
  -- than chosen by the requester, for the reason agent_grants already gives:
  -- one that could pick its own issuer could pick the cheapest, the least
  -- logged, or the one with the widest trust.
  --
  -- `restrict`, where agent_grants cascades. A grant is permission for one
  -- host and deleting it with its CA account is tidy. A template is a rule
  -- people review, and a rule that silently disappears when somebody removes
  -- an unrelated-looking account is worse than a delete that refuses and says
  -- which templates still point at it.
  ca_account_id uuid not null references public.ca_accounts(id) on delete restrict,

  -- The CA's own template, when it has one: a Vault role, an ACME profile, an
  -- AWS Private CA template ARN. Empty means the account's default, which is
  -- what every request meant before this column existed. Nothing reads it yet.
  ca_profile text not null default '',

  -- ── Subject and names ──────────────────────────────────────────────
  --
  -- SUPPLIED: the template provides the subject and the requester may not set
  -- it. CONSTRAINED: the requester provides it and it is validated. There is
  -- deliberately no third value meaning "anything goes" — that is CONSTRAINED
  -- with no constraints, and it should look as empty as it is.
  subject_mode text not null default 'SUPPLIED'
    check (subject_mode in ('SUPPLIED', 'CONSTRAINED')),

  -- {"O": "Example Ltd", "OU": "Platform", "C": "GB", "L": "...", "ST": "..."}
  subject_defaults jsonb not null default '{}'::jsonb,

  -- {"required": true, "suffixes": ["example.com"], "forbidden_patterns": [...]}
  common_name_rule jsonb not null default '{}'::jsonb,

  -- {"types": ["DNS","IP"], "suffixes": [...], "allow_wildcards": false,
  --  "max_names": 10}
  --
  -- `allow_wildcards` is absent rather than false when unset, the same way the
  -- policy engine's naming rule treats it: a template that never mentioned
  -- wildcards has not decided about them, and a JSON false would silently
  -- become a decision.
  san_rules jsonb not null default '{}'::jsonb,

  -- ── Key ────────────────────────────────────────────────────────────
  allowed_key_types jsonb not null default '["RSA", "ECDSA", "Ed25519"]'::jsonb,

  rsa_min_bits integer not null default 0 check (rsa_min_bits >= 0),
  rsa_max_bits integer not null default 0 check (rsa_max_bits >= 0),

  -- Curves by name, not by bit count. An RSA modulus and an ECDSA curve order
  -- are not comparable numbers, and a single min_key_size column that has to
  -- mean both is how "2048" ends up rejecting P-384.
  ecdsa_curves jsonb not null default '["P-256", "P-384", "P-521"]'::jsonb,

  -- When true, the requester must bring a CSR — CertPilot never holds the key.
  csr_required boolean not null default false,

  -- Who must hold the private key for a certificate issued under this
  -- template. ANY leaves it to the request. The other three are assertions an
  -- operator makes about a class of certificate: a template for host workloads
  -- says AGENT, and a request that would leave the key here is refused rather
  -- than quietly honoured.
  key_custody_required text not null default 'ANY'
    check (key_custody_required in ('ANY', 'CERTPILOT', 'AGENT', 'EXTERNAL')),

  -- ── Lifetime ───────────────────────────────────────────────────────
  --
  -- validity_days is supplied: the requester does not choose. max_validity_days
  -- is the ceiling when they may. Setting both is contradictory unless the
  -- supplied value is under the ceiling, which the check below enforces rather
  -- than leaving for somebody to discover at issuance.
  validity_days integer not null default 0 check (validity_days >= 0),
  max_validity_days integer not null default 0 check (max_validity_days >= 0),

  renew_before_days integer not null default 30 check (renew_before_days > 0),
  auto_renew boolean not null default true,

  -- ── Inventory ──────────────────────────────────────────────────────
  --
  -- Keys from metadata_fields that a request under this template must answer.
  -- Separate from metadata_fields.is_required, which is estate-wide: a change
  -- ticket may be required for production certificates and meaningless for a
  -- short-lived test one, and that is a property of the template.
  require_metadata jsonb not null default '[]'::jsonb,

  default_environment text not null default '',
  default_team text not null default '',
  default_tags jsonb not null default '[]'::jsonb,

  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint certificate_templates_validity_sane
    check (validity_days = 0
           or max_validity_days = 0
           or validity_days <= max_validity_days),

  constraint certificate_templates_rsa_range_sane
    check (rsa_max_bits = 0 or rsa_min_bits = 0 or rsa_max_bits >= rsa_min_bits)
);

create index if not exists idx_certificate_templates_enabled
  on public.certificate_templates (is_enabled, name);

create index if not exists idx_certificate_templates_account
  on public.certificate_templates (ca_account_id);

comment on table public.certificate_templates is
  'What a kind of certificate looks like. The floor everything must clear lives in policies.';

comment on column public.certificate_templates.slug is
  'Stable machine name. What an agent or a CI job names; survives a rename.';

comment on column public.certificate_templates.version is
  'Bumped when a rule changes. Certificates record the version they were issued under.';

commit;
