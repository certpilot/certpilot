# How CertPilot compares

This page puts CertPilot beside three commercial certificate lifecycle
platforms a central PKI team is likely to be weighing:

- Keyfactor Command.
- The product line that began as Venafi TLS Protect.
- DigiCert Trust Lifecycle Manager.

It uses only what each vendor publishes, cites the page every statement comes
from, and says plainly where that material does not answer the question.

It is not a feature-parity table, and it does not rank anything. The commercial
platforms overlap with most of what CertPilot does: outbound agents, discovery,
approval workflows and validation after deployment are all documented by at
least one of them, and none of it is unique to CertPilot. What differs is
maturity, custody, the CAs each one reaches, and who you can call.

**Reviewed 24 September 2026**, against the documentation versions listed under
[Sources](#sources). Vendor documentation changes. `make test-comparison-sources`
fetches every page quoted here and fails when a quoted sentence is no longer on
it, and the weekly documentation run does the same.

## How to read it

- **For CertPilot**, each capability carries the same marker as the
  [implementation status](status.md). These are claims about this repository,
  backed by its CI or by the runs recorded beside them:

  | Marker | Meaning |
  |:--|:--|
  | ✅ | Supported |
  | ⚠️ | Constrained |
  | 🧪 | Unverified: built, but nothing here has run it against the real service |
  | ❌ | Planned |

- **For the commercial platforms**, a row says what the vendor's own
  documentation says, linked to the source.
- **"Not found in the documentation reviewed"** means exactly that: the pages
  under [Sources](#sources) did not answer the question. It is **not** a claim
  that the capability is missing. Ask the vendor.
- **Nothing here is about price, compliance certifications or performance.** None
  of it was reviewed, and none of it is claimed for any product, CertPilot
  included.

## Which fits

### CertPilot fits when

- **You want to evaluate certificate lifecycle management on infrastructure you
  control.** The source is readable, the licence is Apache 2.0, and there is
  nothing to buy. It is early-development software, and its own
  [status page](status.md) says not to run it in production yet.
- **Your CAs are ACME or HashiCorp Vault PKI.** Those gateways exist and have
  issued real certificates. See [Integrations](#integrations).
- **The failure you most need to see coming is an expiring CA.** CertPilot
  monitors the authorities first: expiry thresholds, CRL freshness, and an OCSP
  request whose signature is verified. See [CA health](#ca-health).
- **Private keys have to stay on the host that uses them.** The host agent
  generates keys locally and never sends them, with one known defect. See
  [Key custody](#key-custody).
- **You want to extend it yourself.** Gateways and agents are separate processes
  with published contracts, so adding a CA does not mean changing the core. See
  [writing a gateway](writing-a-gateway.md).

### Another platform fits better when

- **You need it in production now, with a vendor accountable for it.** CertPilot
  has no support contract, no service level and no paid tier. See
  [Support](#support).
- **Your CAs include Microsoft AD CS, AWS Private CA, Google Cloud CAS, DigiCert
  or Sectigo.** CertPilot has no gateway for any of them yet. All three
  commercial platforms document a connection to a Microsoft CA
  ([K7](#sources), [V9](#sources), [D7](#sources)).
- **Certificate requests must be approved before they are issued.** CertPilot
  has no approval workflow
  ([#87](https://github.com/certpilot/certpilot/issues/87),
  [#90](https://github.com/certpilot/certpilot/issues/90)). All three commercial
  platforms document one. See [Governance](#governance).
- **You need notifications, sign-in through your identity provider, or cloud
  inventory that you can rely on today.** CertPilot has built all three, but each
  is 🧪: nothing in this project has run it against a real Slack workspace, mail
  server, identity provider or cloud account.
- **The platform's own keys must be protected by an HSM or a KMS.** CertPilot
  holds its key encryption key in memory, loaded from an environment variable, a
  file or Vault. Delegated unwrapping is not built. See
  [security](security.md#known-gaps).
- **You need certificates for people and devices.** CertPilot issues and deploys
  certificates for servers and services, and it has no enrolment protocol for
  users or devices, such as SCEP or EST. DigiCert, for example, documents
  "private certificate issuance for users, devices, servers, and other IT
  resources" ([D10](#sources)).

## Products compared

| Product | Vendor | Editions and deployment models, as documented | Documentation reviewed |
|:--|:--|:--|:--|
| CertPilot | Open source, Apache 2.0 | Self-hosted only, as containers or binaries. The latest core release is v0.1.1 | This repository at the commit this page was published from |
| Keyfactor Command | Keyfactor | **Keyfactor Command** installed on premises, and **Command SaaS**, "a cloud-based Certificate Lifecycle Management platform" ([K1](#sources)) | On-premises documentation suite v26.2.2, and v25.5.2 for one page; Command SaaS documentation "latest" |
| Next-Generation Trust Security, and Certificate Manager, Self-Hosted | Palo Alto Networks, formerly CyberArk, formerly Venafi | **Next-Generation Trust Security** is the SaaS edition: "the evolution of the SaaS certificate lifecycle management offering previously known as Venafi TLS Protect and, more recently, CyberArk Certificate Manager SaaS" ([V1](#sources)). **Certificate Manager, Self-Hosted** is "built and delivered on the Trust Protection Foundation" ([V2](#sources)). Automated Secure Keypair is "included in Certificate Manager - SaaS premium packages by default" ([V6](#sources)) | Self-Hosted documentation 26.1. The SaaS documentation at docs.venafi.cloud, which still calls it Certificate Manager - SaaS |
| DigiCert Trust Lifecycle Manager | DigiCert | DigiCert ONE, including "a private on-premises DigiCert ONE deployment" ([D2](#sources)) | docs.digicert.com, which is not versioned |

Below, **Keyfactor** means Keyfactor Command, **NGTS** means the Palo Alto
Networks line in both editions, and **DigiCert** means Trust Lifecycle Manager.

## Capability by capability

### CA health

Does it watch the certificate authorities themselves: their own expiry, and
whether their revocation endpoints answer?

| | What is documented |
|:--|:--|
| CertPilot | ✅ A scheduled sweep of every CA: expiry thresholds, CRL freshness, and a real OCSP request whose signature, delegation and subject are verified. ✅ Vault issuers are imported into the CA inventory the moment a CA account connects. 🧪 Delivering the resulting alerts to Slack, a webhook or email is tested against fakes only. See [status](status.md) and [monitoring](monitoring.md) |
| Keyfactor | Revocation Monitoring gives a "Warning of upcoming expiration for a CRL" and a "Notification of expired CRLs" ([K10](#sources)). For OCSP, it "provides only information on whether or not the OCSP endpoint is responsive" ([K3](#sources)) |
| NGTS | Self-Hosted: "Certificate Revocation and CDP Monitoring is a feature that must be enabled when you install Trust Protection Foundation" ([V3](#sources)). SaaS: not found in the documentation reviewed |
| DigiCert | Not found in the documentation reviewed. DigiCert documents creating intermediate CAs and issuing from them ([D1](#sources)), but not monitoring another CA's CRL or OCSP health |

### Key custody

Where the private key is generated, and whether the platform can hold it.

| | What is documented |
|:--|:--|
| CertPilot | ✅ The host agent generates keys on the host and never sends them. The Vault gateway signs CSRs by preference. ✅ Keys CertPilot does generate are sealed with AES-256-GCM envelope encryption before they reach the database. ⚠️ Known defect: renewing an agent-held certificate by hand makes CertPilot generate and hold a key for it ([#107](https://github.com/certpilot/certpilot/issues/107)). The key encryption key lives in the core's memory, with no HSM or KMS unwrapping. See [status](status.md) and [security](security.md) |
| Keyfactor | Both models. PFX enrolment requires "one of the Private Key Retention options" on the template ([K4](#sources)). On-device key generation provides "the ability to enroll for a certificate using a private key" ([K11](#sources)) "generated on the target hosting the certificate store" ([K5](#sources)) |
| NGTS | SaaS, with Automated Secure Keypair: "The VSatellite generates a key pair and a CSR" ([V4](#sources)) in your environment, and "Venafi cannot decrypt private keys that are stored in Certificate Manager - SaaS" ([V5](#sources)). That service is "included in Certificate Manager - SaaS premium packages by default" ([V6](#sources)). Self-Hosted: key storage was not reviewed |
| DigiCert | "An agent can generate a key pair and securely deliver a certificate to a server" ([D3](#sources)). A Recovery manager role exists to "Recover escrowed certificates" ([D5](#sources)) |

### Lifecycle verification

After a certificate is issued and installed, does anything check that the right
one is being served?

| | What is documented |
|:--|:--|
| CertPilot | ✅ Every issuance and renewal is compared against what was asked for: key, names, validity. ✅ After a renewal, the endpoints discovery has seen serving the certificate are probed again, and a renewal that never reached them is reported. ✅ The agent reconnects after installing and rolls back on a mismatch, where a destination sets `verify`. A destination that does not set one has no check. See [status](status.md), [templates](templates.md) and [deployment](deployment.md) |
| Keyfactor | Monitoring scans "inspect previously discovered endpoints to verify certificate presence, health, and expiration status" ([K6](#sources)). A check that the served certificate is the one Keyfactor has just deployed was not found in the documentation reviewed |
| NGTS | Self-Hosted network validation: "When certificate's serial number is retrieved and compared, Trust Protection Foundation can determine if the correct certificate is being used" ([V7](#sources)). SaaS: not found in the documentation reviewed |
| DigiCert | An agent can be set to restart the web server after installing, so "the newly installed certificate can be activated and validated" ([D6](#sources)). With that off, "you will need to manually restart the web server application and select the option to validate the installation" ([D11](#sources)) |

### Integrations

Which CAs it issues from, and where it installs.

| | What is documented |
|:--|:--|
| CertPilot | **CAs:** ✅ ACME, run by hand against Let's Encrypt staging and in the walkthroughs against Pebble. ✅ HashiCorp Vault PKI. ✅ A self-signed CA for evaluation. 🧪 ACME External Account Binding. ❌ No gateway for AD CS, AWS Private CA, Google Cloud CAS, DigiCert or Sectigo; AD CS is first in line on the [roadmap](https://github.com/certpilot/certpilot/blob/main/ROADMAP.md). **Installs:** ✅ The agent installs to ten named platforms, nine tested in containers and IIS on a Windows runner. ✅ A signed webhook. 🧪 AWS ACM, Azure Key Vault and F5 BIG-IP. **Discovery:** ✅ network scans; 🧪 Certificate Transparency and cloud inventory |
| Keyfactor | "a CA may be a Microsoft CA or a Keyfactor gateway to a cloud-based or remote CA" ([K7](#sources)). Command SaaS "is designed to integrate with a third-party Certificate Authority (CA) for certificate issuance" ([K2](#sources)) |
| NGTS | SaaS: Microsoft AD CS, set up "for issuing and importing certificates" ([V9](#sources)) through a VSatellite ([V12](#sources)), and "Connector CAs using the CA Connector Framework" ([V8](#sources)) |
| DigiCert | A Microsoft CA connector to "import, enroll, and manage certificates from private Microsoft certificate authorities (CAs)" ([D7](#sources)). Sensors discover through connectors: "Scans appliances, cloud providers, and CA's using connectors" ([D4](#sources)) |

### Governance

Who may do what, and whether a request can be held for approval.

| | What is documented |
|:--|:--|
| CertPilot | ✅ Four roles, admin, operator, auditor and viewer, enforced per route. ⚠️ A policy engine and certificate templates, applied on all three issuance paths. ❌ No approval workflow: [#87](https://github.com/certpilot/certpilot/issues/87) and [#90](https://github.com/certpilot/certpilot/issues/90). 🧪 Sign-in through an identity provider over OIDC. See [status](status.md) and [templates](templates.md) |
| Keyfactor | Workflows with approval steps, whose "Approvers can be defined by selecting security roles directly or by using tokens that resolve to security roles" ([K8](#sources)) |
| NGTS | "Certificate Approval Workflows offer a structured approach to validating certificate requests" ([V10](#sources)) |
| DigiCert | "Require manual approval by a Trust Lifecycle Manager admin to authenticate enrollment requests" ([D8](#sources)) |

### Operational evidence

What it can show afterwards: an audit trail, and exports a reviewer can use.

| | What is documented |
|:--|:--|
| CertPilot | ✅ A hash-chained audit log, with `GET /audit/verify` walking the chain and counting the entries it does not cover. The chain has no external anchor. ✅ CycloneDX 1.6 CBOM export, and CNSA 2.0 conformance per certificate. ✅ [Compatibility](compatibility.md) with released gateways and agents, measured rather than maintained by hand. See [security](security.md) and [posture](posture.md) |
| Keyfactor | "The Keyfactor Command audit logs are an immutable record of all changes made to the state of the application" ([K9](#sources)) |
| NGTS | SaaS: "The Event Log shows a list of events logged as a result of either user actions or Certificate Manager - SaaS operational activities" ([V11](#sources)) |
| DigiCert | "maintains a comprehensive log of all events including those related to enrollments, certificate lifecycle activities, seats, and connectors" ([D9](#sources)) |

### Support

| | What is documented |
|:--|:--|
| CertPilot | Community only: [issues](https://github.com/certpilot/certpilot/issues), and security reports through [SECURITY.md](https://github.com/certpilot/certpilot/blob/main/SECURITY.md). No support contract, no service level, no paid tier. Early development |
| Keyfactor, NGTS, DigiCert | Commercial products. Support terms are set by contract and were not reviewed |

## What this page does not claim

- **That any capability is unique to CertPilot.** Where a row above says
  CertPilot does something, at least one commercial platform documents something
  comparable, or the row says the documentation reviewed did not answer.
- **That a commercial platform lacks anything.** "Not found in the documentation
  reviewed" is a statement about the pages listed below.
- **Parity, price, compliance or performance** for any product.
- **A migration path** from any of these products to CertPilot, or the reverse.

## Sources

Every page was read on the date shown. The quoted text is copied from the page
exactly, and it is what `make test-comparison-sources` looks for. A row whose
quote has gone is a row to re-read, not one to delete.

| ID | Vendor | Page | Version or date | Reviewed | Quoted |
|:--|:--|:--|:--|:--|:--|
| K1 | Keyfactor | [Command SaaS: Introduction and architecture](https://docs.keyfactor.com/command-saas/latest/introduction-and-architecture) | latest | 2026-09-24 | Command SaaS is a cloud-based Certificate Lifecycle Management platform |
| K2 | Keyfactor | [Command SaaS: Introduction and architecture](https://docs.keyfactor.com/command-saas/latest/introduction-and-architecture) | latest | 2026-09-24 | The platform is designed to integrate with a third-party Certificate Authority (CA) for certificate issuance. |
| K3 | Keyfactor | [Revocation Monitoring](https://software.keyfactor.com/Core-OnPrem/v25.5.2/Content/ReferenceGuide/Revocation%20Monitoring.htm) | v25.5.2 | 2026-09-24 | OCSP monitoring and notification provides only information on whether or not the OCSP endpoint is responsive. |
| K4 | Keyfactor | [PFX Enrollment](https://software.keyfactor.com/Core-OnPrem/v26.2.2/Content/ReferenceGuide/PFX%20Enrollment.htm) | v26.2.2 | 2026-09-24 | you must enable one of the Private Key Retention options in the certificate template details |
| K5 | Keyfactor | [ODKG - On Device Key Generation](https://software.keyfactor.com/Core-OnPrem/v26.2.2/Content/ReferenceGuide/On-Device-Key-Generation.htm) | v26.2.2 | 2026-09-24 | generated on the target hosting the certificate store |
| K6 | Keyfactor | [SSL Discovery](https://software.keyfactor.com/Core-OnPrem/v26.2.2/Content/ReferenceGuide/SSLDiscovery.htm) | v26.2.2 | 2026-09-24 | monitoring scans inspect previously discovered endpoints to verify certificate presence, health, and expiration status |
| K7 | Keyfactor | [PFX Enrollment](https://software.keyfactor.com/Core-OnPrem/v26.2.2/Content/ReferenceGuide/PFX%20Enrollment.htm) | v26.2.2 | 2026-09-24 | a CA may be a Microsoft CA or a Keyfactor gateway to a cloud-based or remote CA |
| K8 | Keyfactor | [Workflow Definition Operations](https://software.keyfactor.com/Core-OnPrem/v26.2.2/Content/ReferenceGuide/WorkflowDefinitionsOperations_1_Simple.htm) | v26.2.2 | 2026-09-24 | Approvers can be defined by selecting security roles directly or by using tokens that resolve to security roles. |
| K9 | Keyfactor | [Audit Log](https://software.keyfactor.com/Core-OnPrem/v26.2.2/Content/ReferenceGuide/Audit%20Log.htm) | v26.2.2 | 2026-09-24 | The Keyfactor Command audit logs are an immutable record of all changes made to the state of the application. |
| K10 | Keyfactor | [Revocation Monitoring](https://software.keyfactor.com/Core-OnPrem/v25.5.2/Content/ReferenceGuide/Revocation%20Monitoring.htm) | v25.5.2 | 2026-09-24 | Warning of upcoming expiration for a CRL. Notification of expired CRLs. |
| K11 | Keyfactor | [ODKG - On Device Key Generation](https://software.keyfactor.com/Core-OnPrem/v26.2.2/Content/ReferenceGuide/On-Device-Key-Generation.htm) | v26.2.2 | 2026-09-24 | The ODKG page provides the ability to enroll for a certificate using a private key |
| V1 | Palo Alto Networks | [Certificate Manager Is Now NGTS](https://www.paloaltonetworks.com/network-security/next-gen-trust-security/certificate-manager) | not shown | 2026-09-24 | Next-Generation Trust Security is the evolution of the SaaS certificate lifecycle management offering previously known as Venafi TLS Protect and, more recently, CyberArk Certificate Manager SaaS. |
| V2 | Palo Alto Networks | [Certificate Manager Is Now NGTS](https://www.paloaltonetworks.com/network-security/next-gen-trust-security/certificate-manager) | not shown | 2026-09-24 | Certificate Manager, Self-Hosted, which is built and delivered on the Trust Protection Foundation |
| V3 | CyberArk | [Enabling CRL Verification](https://docs.venafi.com/Docs/26.1/TopNav/Content/CRL/t-CRL-enablingCRL-Verification.php) | 26.1 | 2026-09-24 | Certificate Revocation and CDP Monitoring is a feature that must be enabled when you install Trust Protection Foundation |
| V4 | CyberArk | [What is Automated Secure Keypair?](https://docs.venafi.cloud/vaas/automated-secure-keypair/what-is-automated-secure-keypair/) | not shown | 2026-09-24 | The VSatellite generates a key pair and a CSR. |
| V5 | CyberArk | [What is Automated Secure Keypair?](https://docs.venafi.cloud/vaas/automated-secure-keypair/what-is-automated-secure-keypair/) | not shown | 2026-09-24 | Venafi cannot decrypt private keys that are stored in Certificate Manager - SaaS. |
| V6 | CyberArk | [What is Automated Secure Keypair?](https://docs.venafi.cloud/vaas/automated-secure-keypair/what-is-automated-secure-keypair/) | not shown | 2026-09-24 | The Automated Secure Keypair service is included in Certificate Manager - SaaS premium packages by default. |
| V7 | CyberArk | [SSL/TLS network validation](https://docs.venafi.com/Docs/26.1/TopNav/Content/Validation/cco-validation-about-tpp.php) | 26.1, topic updated 17 November 2025 | 2026-09-24 | When certificate's serial number is retrieved and compared, Trust Protection Foundation can determine if the correct certificate is being used. |
| V8 | CyberArk | [Adding a certificate authority](https://docs.venafi.cloud/vaas/certificates/ca/adding-a-certificate-authority/) | not shown | 2026-09-24 | Connector CAs using the CA Connector Framework |
| V9 | CyberArk | [Adding a certificate authority](https://docs.venafi.cloud/vaas/certificates/ca/adding-a-certificate-authority/) | not shown | 2026-09-24 | Setting up Microsoft AD CS for issuing and importing certificates |
| V10 | CyberArk | [About certificate approval workflows](https://docs.venafi.cloud/vaas/certificates/workflows/c-about-certificate-approval-workflow/) | not shown | 2026-09-24 | Certificate Approval Workflows offer a structured approach to validating certificate requests. |
| V11 | CyberArk | [Event logging overview](https://docs.venafi.cloud/vaas/logging/c-about-activity-logging/) | not shown | 2026-09-24 | The Event Log shows a list of events logged as a result of either user actions or Certificate Manager - SaaS operational activities. |
| V12 | CyberArk | [Adding a certificate authority](https://docs.venafi.cloud/vaas/certificates/ca/adding-a-certificate-authority/) | not shown | 2026-09-24 | VSatellite Integration with Microsoft AD CS |
| D1 | DigiCert | [Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager.html) | last modified 17 September 2026 | 2026-09-24 | intermediate CA creation and private certificate issuance |
| D2 | DigiCert | [Additional requirements for private on-premises DigiCert ONE users](https://docs.digicert.com/en/trust-lifecycle-manager/client-tools/deploy-and-manage-agents/additional-requirements-for-private-on-premises-digicert-one-users.html) | not shown | 2026-09-24 | Users with a private on-premises DigiCert ONE deployment |
| D3 | DigiCert | [DigiCert agents and sensors](https://docs.digicert.com/en/trust-lifecycle-manager/get-started/overview/agents-and-sensors.html) | last modified 22 September 2026 | 2026-09-24 | An agent can generate a key pair and securely deliver a certificate to a server |
| D4 | DigiCert | [DigiCert agents and sensors](https://docs.digicert.com/en/trust-lifecycle-manager/get-started/overview/agents-and-sensors.html) | last modified 22 September 2026 | 2026-09-24 | Scans appliances, cloud providers, and CA's using connectors. |
| D5 | DigiCert | [User roles](https://docs.digicert.com/en/trust-lifecycle-manager/set-up-your-account/users-and-access/user-roles.html) | not shown | 2026-09-24 | Recovery manager Recover escrowed certificates. |
| D6 | DigiCert | [Configure agents](https://docs.digicert.com/en/trust-lifecycle-manager/build-your-inventory-and-ecosystem/deploy-and-manage-agents/configure-agents.html) | not shown | 2026-09-24 | The web server application gets automatically restarted so the newly installed certificate can be activated and validated. |
| D7 | DigiCert | [Microsoft CA connector](https://docs.digicert.com/en/trust-lifecycle-manager/connectors/certificate-authorities/link-to-microsoft.html) | not shown | 2026-09-24 | to import, enroll, and manage certificates from private Microsoft certificate authorities (CAs) |
| D8 | DigiCert | [Enrollment and authentication methods](https://docs.digicert.com/en/trust-lifecycle-manager/define-policies-to-ensure-compliance/certificate-profiles/enrollment-and-authentication-methods.html) | not shown | 2026-09-24 | Require manual approval by a Trust Lifecycle Manager admin to authenticate enrollment requests. |
| D9 | DigiCert | [Audit logs](https://docs.digicert.com/en/trust-lifecycle-manager/monitor-assets-to-prevent-downtime/reporting-and-auditing/audit-logs.html) | not shown | 2026-09-24 | maintains a comprehensive log of all events including those related to enrollments, certificate lifecycle activities, seats, and connectors |
| D10 | DigiCert | [Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager.html) | last modified 17 September 2026 | 2026-09-24 | private certificate issuance for users, devices, servers, and other IT resources |
| D11 | DigiCert | [Configure agents](https://docs.digicert.com/en/trust-lifecycle-manager/build-your-inventory-and-ecosystem/deploy-and-manage-agents/configure-agents.html) | not shown | 2026-09-24 | you will need to manually restart the web server application and select the option to validate the installation |

## Keeping it true

A vendor rewriting a page is the likeliest way for this one to go wrong without
anybody noticing. Keyfactor's v26.2 documentation suite had already moved one of
the pages quoted here by the time it was reviewed. So the quotes are checked
rather than trusted:

```bash
make test-comparison-sources
```

It fetches each page and fails, naming the row, when the quoted text is no
longer on it or the page no longer answers. Fix a failure by re-reading the
source, correcting the row that depends on it, and updating the version and the
review date. Deleting the quote to make it pass is not a fix.

CertPilot's own rows are checked the same way the rest of the documentation is:
see [documentation checks](documentation-checks.md).
