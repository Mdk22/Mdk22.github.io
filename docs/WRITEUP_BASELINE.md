# Mdk22 write-up publication baseline

This baseline keeps the archive, homepage, and connected-intelligence views consistent. It controls the publication system, not the voice or story of an individual case.

## Required publication metadata

Keep the case metadata complete and internally consistent: `case_id`, `case_featured`, `case_summary_short`, `case_status`, `case_classification`, `case_family`, `case_evidence`, verification flags, `primary_cwe`, `cwes`, `patterns`, and `methods`.

Use exactly one root-cause CWE as `primary_cwe`. Supporting CWEs describe separately proven consequences or conditions and must not be added merely because they are plausible.

## Homepage and archive metadata

```yaml
case_featured: true
case_summary_short: "One plain sentence describing the confirmed finding and impact."
```

- Set `case_featured: true` on only one current case. The homepage uses the newest featured case as its lead record; if none is marked, it falls back to the newest case.
- Set `case_featured: false` on every case that is not featured. Do not omit the field.
- Keep `case_summary_short` to one plain sentence. State the confirmed vulnerability and impact without payloads, credentials, or unverified capability.

## Figure 0 convention

Figure 0 is optional. Use it only when a compact lifecycle, data-flow, or trust-boundary diagram makes the later evidence easier to interpret.

- Label it clearly as explanatory context, not evidence.
- Do not use instance-specific hosts, cookies, credentials, payloads, flags, or reusable exploit syntax.
- Preserve the real evidence order as Figures 1 onward. A common sequence is baseline, changed request, control, observed effect, and solved state, but use the order that matches the actual work.
- Explain what each image adds to the chain. Do not repeat the same caption formula under every figure.

## Evidence and intelligence rules

- Prefer normal baselines and useful negative controls before impact claims.
- Redact secrets and objective values; state the boundary of what was not tested.
- Use one primary CWE, a pattern for the observed behavior, and methods for the evidence workflow. These fields drive deterministic related-case matching.
- Keep HTTP requests, commands, payloads, and scripts copyable. A reusable lab payload is allowed when it contains public placeholders instead of credentials, sessions, flags, or another person's private data.
- Before publication, run `scripts/Test-WriteupPublication.ps1`, complete the production Hugo build, and inspect the article in a real browser.

## Keep each case individual

The common system covers metadata, safety, evidence, classification, remediation, and QA. It does not require identical prose or identical headings.

Before writing, identify the case's own story:

1. What looked normal at the start?
2. Which change produced the first useful signal?
3. Which comparison or control separated the finding from a false positive?
4. Which result completed the chain?
5. What makes this case different from the others?

Choose the clearest narrative for the available evidence. A case can be discovery-led, comparison-led, or exploit-chain-led. Include Caido/Burp and Terminal/CLI sections only when those clients were actually used.
