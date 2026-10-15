# Design-plan acceptance

This matrix separates implemented repository capabilities from deployment and
organizational outcomes. The original 16-page Detection Signature Management
Uplift Project Plan remains the source of the requested end state. Earlier
all-checked local-capability lists did not mean full operational acceptance.

| Plan area | Repository implementation | Remaining acceptance |
|---|---|---|
| Footprint, defects and migration | Local/runtime guides, issue matrix, query review, backups and rollback procedures | Review against the organization's actual service inventory and ownership |
| Git/YAML authoring independent of ThreatKB | Standalone package/CLI, YAML source, version history, optional web editor and legacy exports | Authoritative content migration/cutover; legacy signature workflow is retained at the user's request |
| Macros | YAML lists, Jinja filters, bounded expansion, regex chunking and compilation checks | Real private macro/rule corpus acceptance |
| Categories, contextual tags and workflow | Category-derived prefixes, full category metadata, rich metadata tags and separate state | Validate customer/product metadata contracts |
| UUIDs and pairings | Immutable identities, staged UUID hook, YAML heater/cooler pairings | Receiving TAC support and migration of existing private pairings |
| Samples and goodware | SHA-256 references, testing strategies, positive/goodware verification and regression history | Representative operational corpora and false-positive acceptance |
| Community collections | Opt-in pinned Git checkouts with severity/confidence and policy selection | Actual collection acquisition/update operations and customer/product selection UX |
| IOC platform | Independent normalization, provenance, assessment, policy, versioned local enrichment, review, quarantine, snapshots and Feedpack export | Live feed connectors, real enrichment datasets and integration into existing TI warehousing |
| Independent content pipelines | Separate CI pack jobs, no cross-pack cancellation, retained checksummed artifacts | Actual private pack format/consumer compatibility |
| Lint, formatting and CI | Python correctness/format checks, frontend type checks, Prettier YAML/config checks, tests, shell syntax and dependency-age gate | Hosting/maintenance ownership and operational monitoring |
| Two-person review and frequent testing releases | Protected branch policy; optional reviewed-merge GitHub testing publisher validates approval/source/bytes and publishes atomically through a draft | Enable publication deliberately; verify a real approved release in the chosen content repository |
| Timed rollout and telemetry | Testing/production channel engine, frozen promotion policy, elapsed-time/rate/error gates, persistent block state and scoped in-app alarms | Ten-minute consumer polling, actual telemetry delivery, production deployment and external escalation routing |
| Release metrics | Monthly counts with 4.5/month baseline and 9/month target | Measure the improvement through real team usage; no achieved doubling is claimed |
| Public/private separation | Generic example pack interfaces; proprietary consumer packaging is not implemented here | Put product-specific packaging/adapters in the appropriate private repositories |

DFI issue #470 is handled by the explicit user-authorized skip. That exception is
not proof of vendor DFI compatibility. GitHub issue resolutions remain in the PR;
upstream issues have not been administratively closed.

Local tests use synthetic data and controlled time where necessary. GitHub
publication tests mock the remote boundary, and no production telemetry, outbound
notifications or deployment results are fabricated. See [verification.md](verification.md)
for measured evidence and [content-delivery.md](content-delivery.md) for activation.
