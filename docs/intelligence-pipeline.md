# Standalone indicator assessment

`python -m threatkb_content evaluate-iocs` runs without Flask, MySQL, Redis or
network enrichment services. It accepts JSON/YAML lists (or an `indicators` list)
and CSV headers. Each observation supplies `type` (`ip` or `domain`), `value` and
a timezone-aware `observed_at`. Optional fields include `expires_at`, confidence,
severity, groups, context tags and candidate/released/retired status.

```sh
.venv/bin/python -m threatkb_content evaluate-iocs \
  --input detections/intelligence/observations.csv --source synthetic \
  --sources detections/intelligence/sources.yaml \
  --policy detections/intelligence/policy.yaml \
  --enrichment detections/intelligence/enrichment.yaml \
  --decisions detections/intelligence/decisions.yaml \
  --output instance/ioc-assessment
```

The explicit source overrides labels supplied by input records. Source configuration
caps confidence, limits groups, sets maximum observation age and can disable a
source. Inputs cannot raise those trust caps. IPs are canonicalized, domains use
lowercase IDNA, and duplicate observations coalesce by stable UUID derived from
type/value. The latest observation from each source controls that source's
retirement and expiration. Conflicting observations from the same source at the
same time are held; input order cannot choose an arbitrary winner.

The policy requires independent review by default, holds low-confidence/stale
observations, and excludes non-global IPs unless explicitly permitted. Allowlists
match CIDR networks and domain suffixes on label boundaries. Context enrichment
comes from versioned local mappings with `network` or `domain_suffix` and a named
provider; it remains separate from authoritative values/scores. The example uses
synthetic, documentation-only addresses and a deliberately long age limit. Replace
those settings with operational policy before processing real intelligence.

The first evaluation produces `assessment.json`, with observations, normalized
identities, provenance, record digests, enrichment, disposition reasons and counts.
A decision file is keyed by indicator UUID:

```yaml
<indicator-uuid>:
  decision: approved
  record_digest: <digest-from-assessment>
  author: analyst-a
  reviewer: analyst-b
```

A self-review or changed observation digest cannot release the record. `rejected`
and `retired` decisions suppress export. These local assertions belong in reviewed
Git changes; typing another analyst's name in a file is not authentication.
Protected hosting/review policy provides that identity boundary.

Only approved, policy-eligible records enter `indicators.yaml`. Expired/retired,
held and malformed observations stay in the assessment. Malformed rows are
quarantined while valid rows are assessed. The default strict CLI exits nonzero
when quarantine is nonempty; `--allow-invalid` explicitly accepts a partial batch.
Use `--previous instance/ioc-assessment/assessment.json` to retain prior source
observations in a later evaluation. Inputs are bounded to 10 MiB and 100,000
observations.

## Feedpack integration

An opt-in `intelligence/pipeline.yaml` declares repository-relative input, sources,
policy, enrichment and decision paths. Builds reject paths outside the repository
and any malformed observations. Feedpack contains released records and the full
assessment/provenance report; Codepack and Sigpack do not run the IOC evaluator.
CSV/JSON inputs participate in the source digest, so changing them invalidates the
corresponding content review. Repositories without pipeline configuration continue
to build from legacy `indicators.yaml`, including existing web exports.

The CLI provides local evaluation/enrichment/validation and a snapshot warehouse.
Live feed connectors, authoritative external enrichment datasets, organizational
reviewer identities and production feed delivery require their actual sources and
credentials. No synthetic mapping is presented as real threat intelligence.
