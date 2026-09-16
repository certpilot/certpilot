# Roadmap

CertPilot is open-source certificate lifecycle management for central PKI and platform teams: the people responsible for issuing CAs, the certificates beneath them, and the services that must keep presenting valid material.

The next priorities are trustworthy pilot adoption and security together. **Now / Next / Later describe sequence, not delivery dates.** They do not promise commercial feature parity or production readiness.

Track the programme in [#77 — Make CertPilot trustworthy to evaluate, operate, and extend](https://github.com/certpilot/certpilot/issues/77). All issues live in this repository; each names the component repositories where implementation belongs. Completion means meeting the issue's acceptance criteria and attaching evidence, not merely merging code.

The [historical implementation record](ROADMAP-HISTORY.md) preserves the earlier phases and their reasoning. It is historical context, not the current support matrix. See [implementation status](docs/status.md) and [compatibility](docs/compatibility.md) alongside the current source when evaluating a release.

## Now: accurate documentation and a complete evaluation journey

The site already has search, generated API references, platform guides and a consistent visual identity. Build on that work. The immediate failure is that a reader can follow synchronised prose that contradicts the product: the operations guide still says revocation has no API, and getting-started describes a removed database prelude.

| Work | Outcome |
|:---|:---|
| [#78 — Correct contradictions between public guides and current behavior](https://github.com/certpilot/certpilot/issues/78) | Correct source-backed contradictions across guides, READMEs and published copies. |
| [#79 — Organize documentation around evaluating, deploying, operating, and extending CertPilot](https://github.com/certpilot/certpilot/issues/79) | Organise Evaluate, Deploy, Operate, Integrate, Reference and Contribute paths; preserve URLs. |
| [#80 — Provide a reproducible first-certificate evaluation](https://github.com/certpilot/certpilot/issues/80) | Exercise the release-pinned container journey from login to verified renewal and cleanup. |
| [#81 — Connect platform guides into complete operational walkthroughs](https://github.com/certpilot/certpilot/issues/81) | Connect Vault/nginx, ACME staging/nginx, Windows/IIS and failure-recovery instructions. |
| [#82 — Standardize component and extension documentation](https://github.com/certpilot/certpilot/issues/82) | Document each component and both extension contracts; add ACME and self-signed guides. |
| [#83 — Test documentation behavior as well as synchronization](https://github.com/certpilot/certpilot/issues/83) | Test executable examples, authenticated API usage, links, anchors and source provenance. |
| [#84 — Publish an evidence-backed evaluation and comparison guide](https://github.com/certpilot/certpilot/issues/84) | Publish sourced, dated, edition-specific comparisons and clear product-fit guidance. |

**Completion gate:** a new evaluator can determine product fit, complete a documented certificate lifecycle, understand limitations and find recovery instructions without undocumented maintainer assistance. Measure evaluation time before advertising it.

Start with the accuracy audit. Navigation, component documentation and the evaluation journey can then progress together; walkthroughs and executable-documentation checks build on them. Detailed dependencies are linked in each issue.

## Next: trustworthy operations and security

Security evidence and recovery exercises are part of adoption, not a later marketing claim. Prepare the review package and compatibility designs before changing sensitive agent or encryption interfaces.

| Work | Outcome |
|:---|:---|
| [#85 — Prove upgrade, backup, restore, and key-recovery procedures](https://github.com/certpilot/certpilot/issues/85) | Prove upgrade and recovery with PostgreSQL, keys, gateway state and host identities. |
| [#86 — Publish a pilot security and maintenance dossier](https://github.com/certpilot/certpilot/issues/86) | Make custody, permissions, limitations, hardening and maintenance policy reviewable. |
| [#87 — Add optional approval before an enrolled agent becomes active](https://github.com/certpilot/certpilot/issues/87) | Add opt-in approval before an enrolled host may obtain certificates. |
| [#88 — Rotate agent identity keys without re-enrolling the host](https://github.com/certpilot/certpilot/issues/88) | Rotate host identity keys safely without losing identity, grants or history. |
| [#89 — Publish operational health and scale evidence](https://github.com/certpilot/certpilot/issues/89) | Exercise failures and scale; publish actual environments, results and limits. |

Prioritise delegated key unwrapping and real-platform deployment evidence alongside this work; retain their existing issues below.

**Completion gate:** pilot operators can recover the system, explain credential custody, identify failures and distinguish demonstrated capabilities from unverified ones. Passing this gate does not independently establish production readiness, certification or compliance.

## Later: targeted enterprise expansion

| Work | Outcome |
|:---|:---|
| [#90 — Define scoped governance for multi-team certificate operations](https://github.com/certpilot/certpilot/issues/90) | Review scoped permissions and approval requirements before implementing multi-team controls. |

Use [#10](https://github.com/certpilot/certpilot/issues/10) for the additional-CA assessment. Start with Microsoft AD CS for this audience, then AWS Private CA and Google Cloud CAS. Prioritise commercial CA integrations when adopter demand and a test environment exist. Require a maintainer, conformance evidence and operational documentation before advertising support.

The governance issue delivers a reviewed design and acceptance tests first. It does not promise tenant isolation. Vendor-specific migration guides and replacement claims follow demonstrated integrations and workflows.

## Existing work

These remain the canonical issues, rather than being duplicated in the new backlog:

| Issue | Roadmap treatment |
|:---|:---|
| [#12 — Delegated KEK unwrapping](https://github.com/certpilot/certpilot/issues/12) | Next, alongside pilot hardening. Preserve existing CPS1 ciphertext and retired-key behaviour; specify failure and migration handling before introducing a delegated envelope. |
| [#11 — Real Azure/F5 deployment validation](https://github.com/certpilot/certpilot/issues/11) | Next. Keep support claims qualified until the relevant environment has been exercised. |
| [#14 — Post-quantum negotiation reporting](https://github.com/certpilot/certpilot/issues/14) | Next. Reconcile the code, tests and remaining issue criteria before changing its status. Key-exchange observation and adoption are distinct from post-quantum certificate issuance. |
| [#10 — Additional CA gateways](https://github.com/certpilot/certpilot/issues/10) | Later. Assess audience demand, maintainer availability and test access before promising an integration. |

Existing container work in [#13](https://github.com/certpilot/certpilot/issues/13), platform documentation in [#35](https://github.com/certpilot/certpilot/issues/35)/[#36](https://github.com/certpilot/certpilot/issues/36), and published extension contracts are foundations for this roadmap, not features to rebuild.

## Evidence and publication rules

- Author component guides in their owning repositories, then synchronise the documentation site. Keep generated API and protocol material generated.
- Preserve guide URLs and anchors or provide compatibility redirects. Test desktop/mobile presentation, keyboard access, search, diagrams, tables and code examples.
- Pin the component versions used for each executable journey. Exercise staging CAs and disposable infrastructure; never use a live estate as a documentation test fixture.
- Separate supported, constrained, unverified and planned capabilities. A skipped check remains a visible limitation.
- Compare named commercial editions using official sources and review dates. Outbound agents and deployment validation are not exclusive to CertPilot: [DigiCert documents outbound agents](https://docs.digicert.com/en/trust-lifecycle-manager/get-started/quick-start-guides/quick-start-guides-for-agents/deploy-a-digicert-agent-windows-version.html), and [Venafi documents installation and validation](https://docs.venafi.com/Docs/25.1PDF/Certificate_Management_Guide.pdf).
- Make the product's case through open source, CA-focused operations, inspectable contracts, clear limits and reproducible evidence. Do not invent exclusivity, compliance, throughput, cost savings, dates or contributor commitments.
- Documentation work does not change runtime interfaces. Future security and operational-health changes require explicit authorisation, compatibility, failure-mode and migration designs in their issues before implementation.

This roadmap was prepared from the repository and published-documentation review on 16 September 2026. It records planned work, not a runtime or security certification.

## Historical phase links

These anchors keep older roadmap bookmarks usable. The linked text describes the implementation at that time.

<details>
<summary>Earlier phases and decisions</summary>

<a id="who-this-is-for"></a>

- [Who this is for](ROADMAP-HISTORY.md#who-this-is-for)

<a id="forcing-function"></a>

- [Forcing function](ROADMAP-HISTORY.md#forcing-function)

<a id="done"></a>

- [Done](ROADMAP-HISTORY.md#done)

<a id="in-progress"></a>

- [In progress](ROADMAP-HISTORY.md#in-progress)

<a id="phase-3--a-monitoring-surface-a-team-can-leave-on-a-screen-"></a>

- [Phase 3 — A monitoring surface a team can leave on a screen ✅](ROADMAP-HISTORY.md#phase-3--a-monitoring-surface-a-team-can-leave-on-a-screen-)

<a id="phase-5--discovery-that-finds-what-nobody-told-you-about"></a>

- [Phase 5 — Discovery that finds what nobody told you about](ROADMAP-HISTORY.md#phase-5--discovery-that-finds-what-nobody-told-you-about)

<a id="phase-4--a-renewal-engine-that-survives-47-day-certificates"></a>

- [Phase 4 — A renewal engine that survives 47-day certificates](ROADMAP-HISTORY.md#phase-4--a-renewal-engine-that-survives-47-day-certificates)

<a id="phase-6--deployment-then-the-agent"></a>

- [Phase 6 — Deployment, then the agent](ROADMAP-HISTORY.md#phase-6--deployment-then-the-agent)

<a id="phase-7--more-cas"></a>

- [Phase 7 — More CAs](ROADMAP-HISTORY.md#phase-7--more-cas)

<a id="phase-8--cryptographic-posture--issuance-deferred"></a>

- [Phase 8 — Cryptographic posture ✅ (issuance deferred)](ROADMAP-HISTORY.md#phase-8--cryptographic-posture--issuance-deferred)

<a id="next"></a>

- [Next](ROADMAP-HISTORY.md#next)

<a id="phase-9--containers-and-proof-that-they-run"></a>

- [Phase 9 — Containers, and proof that they run](ROADMAP-HISTORY.md#phase-9--containers-and-proof-that-they-run)

<a id="phase-10--post-quantum-the-half-that-is-possible"></a>

- [Phase 10 — Post-quantum, the half that is possible](ROADMAP-HISTORY.md#phase-10--post-quantum-the-half-that-is-possible)

<a id="phase-11--the-rest-in-the-order-it-hurts"></a>

- [Phase 11 — The rest, in the order it hurts](ROADMAP-HISTORY.md#phase-11--the-rest-in-the-order-it-hurts)

<a id="phase-12--certificate-templates"></a>

- [Phase 12 — Certificate templates](ROADMAP-HISTORY.md#phase-12--certificate-templates)

<a id="phase-13--x509-shape-and-ca-profiles"></a>

- [Phase 13 — X.509 shape and CA profiles](ROADMAP-HISTORY.md#phase-13--x509-shape-and-ca-profiles)

<a id="phase-14--deploying-to-what-people-actually-run"></a>

- [Phase 14 — Deploying to what people actually run](ROADMAP-HISTORY.md#phase-14--deploying-to-what-people-actually-run)

<a id="known-gaps"></a>

- [Known gaps](ROADMAP-HISTORY.md#known-gaps)

<a id="deliberately-out-of-scope"></a>

- [Deliberately out of scope](ROADMAP-HISTORY.md#deliberately-out-of-scope)

</details>
