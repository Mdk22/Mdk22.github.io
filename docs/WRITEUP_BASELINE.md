# Mdk22 write-up publication baseline

This baseline keeps new write-ups compatible with the archive, homepage, and connected-intelligence views without adding claims beyond the verified evidence.

## Required publication metadata

Keep the existing case metadata complete and internally consistent: `case_id`, `case_status`, `case_classification`, `case_family`, `case_evidence`, verification flags, `primary_cwe`, `cwes`, `patterns`, and `methods`.

Use exactly one root-cause CWE as `primary_cwe`. Supporting CWEs describe separately proven consequences or conditions and must not be added merely because they are plausible.

## Optional homepage and archive metadata

```yaml
case_featured: true
case_summary_short: "One evidence-bounded sentence for a compact archive card."
```

- Set `case_featured: true` on only one current case. The homepage uses the newest featured case as its lead record; if none is marked, it falls back to the newest case.
- Keep `case_summary_short` to one plain-language sentence. It must state the confirmed vulnerability and bounded impact, without payloads, credentials, or unverified capability.

## Figure 0 convention

Figure 0 is optional. Use it only when a compact lifecycle, data-flow, or trust-boundary diagram makes the later evidence easier to interpret.

- Label it clearly as explanatory context, not evidence.
- Do not use instance-specific hosts, cookies, credentials, payloads, flags, or reusable exploit syntax.
- Preserve the normal evidence sequence as Figures 1 onward: baseline, sink/oracle, validation differential, bounded impact, and authoritative solved state where available.
- Every figure caption should say what the image proves and what it does not prove.

## Evidence and intelligence rules

- Prefer normal baselines and negative controls before impact claims.
- Redact secrets and objective values; state the boundary of what was not tested.
- Use one primary CWE, a pattern for the observed behavior, and methods for the evidence workflow. These fields drive deterministic related-case matching.
- Before publication, verify that every taxonomy link resolves locally and that the public text does not expose a reusable payload.
