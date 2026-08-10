---
title: "WebVerse Bothered - Second-Order SQL Injection via Stored Username"
date: 2026-08-10T00:00:00+02:00
lastmod: 2026-08-10T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A persisted username reached a later donation-history SQL consumer, producing a verified second-order SQL injection and a bounded objective read."
summary: "A fresh Caido reproduction shows that a self-created account can store a SQL-significant username that is interpreted only by a later authenticated history query. Error, boolean, UNION, and platform-status evidence establish the complete chain."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Bothered"
  - "SQL Injection"
  - "Second-Order SQL Injection"
  - "Stored Input"
  - "Caido"
  - "CWE-89"
platform: "WebVerse"
lab: "Bothered"
difficulty: "Easy"
showToc: true
TocOpen: false
case_id: "CASE-009"
case_status: "SOLVED / VERIFIED"
case_classification: "Second-Order SQL Injection"
case_family: "server-side-injection"
case_evidence:
  - "Caido"
  - "Chromium"
case_verified: true
case_caido: true
case_independent_curl: false
primary_cwe: "CWE-89"
cwes:
  - "CWE-89"
patterns:
  - "SQL Injection"
methods:
  - "Consumer Mapping"
  - "Authoritative Status Check"
---

> **Publication note:** This article documents a fresh reproduction in an authorized WebVerse educational lab. Current-instance hostnames, credentials, session values, exact payload strings, and the literal objective are excluded. The public objective representation is `WEBVERSE{REDACTED}`.

## Executive Summary

Bothered exposed a second-order SQL injection in an authenticated donation-history workflow. A user-controlled username was accepted during normal registration and remained usable for the same account's login. The risk appeared only later, when the server-side history consumer reused that persisted identity in SQL query construction.

A normal self-owned account established the expected registration, login, and history behavior. A separate self-owned stored-input control then produced a PDO/MariaDB syntax error only when the later history page was requested. A syntactically valid boolean control expanded the result set beyond that account's own donation history, including a known row created under a different controlled account. The investigation then used the existing three-field history view for a bounded UNION projection: table names, the relevant column layout, key names, and one redacted objective value only.

The current-instance objective was submitted immediately after the targeted read. WebVerse independently reported **Challenge Solved** and **Flag accepted**. No write, delete, password extraction, filesystem access, or unrelated data collection was tested.

> **CONFIRMED FINDING**
>
> A persisted username becomes executable SQL only when a later authenticated donation-history consumer reuses it in dynamic query construction. The demonstrated impact is cross-record visibility, bounded metadata disclosure, one targeted configuration-value read, and an independently accepted lab objective.

## 1. Stored-Input Lifecycle

![Educational lifecycle diagram showing registration, own-account login, the later history consumer, and SQL execution](Bothered_Figure_00_Stored_Input_Lifecycle.png)

**Figure 0 - Stored-input lifecycle.** This explanatory diagram connects the verified evidence chain. It is not a modified evidence artifact and contains no payload or instance-specific value.

### Why This Is Not Stored XSS

Harmless HTML canaries in the observed public `display_name` and donation-message contexts were HTML-encoded. Those tested browser-side output contexts therefore did not establish stored XSS. The confirmed issue is different: a persisted username reaches a later **server-side** history query and is interpreted as SQL syntax.

## 2. Report Profile

| Field | Verified value |
| --- | --- |
| Platform | WebVerse |
| Lab | Bothered |
| Difficulty | Easy |
| Status | Solved / Verified |
| Stored source | Registration username |
| Later consumer | Authenticated donation-history workflow |
| Observed stack | PHP 8.2.31, PDO, MariaDB |
| Primary weakness | CWE-89 - SQL Injection |
| Evidence | Fresh-instance Caido evidence with Chromium solved-state confirmation |

## 3. Scope and Evidence Boundary

- Every test used a fresh, self-created account; no foreign credentials or historical sessions were reused.
- Each stored control used a separate account, keeping the observed effect attributable to one controlled input.
- One benign donation was created under the baseline account to establish the normal populated history contract and a known cross-account marker.
- Exact payload syntax, session cookies, hostnames, credentials, test-account identifiers, and the literal flag are intentionally omitted.
- The evidence establishes a SELECT-oriented data effect only. It does not establish database write capability, filesystem reads, command execution, password extraction, or access outside the authorized lab.

## 4. Normal Donation-History Baseline

Before introducing SQL-specific input, a normal account completed the expected lifecycle and created one benign donation. The authenticated history view exposed three visible fields: **Amount**, **Message**, and **Date**.

![Normal populated donation-history response with Amount, Message, and Date columns](Bothered_EV01_Normal_History_Baseline.png)

**Figure 1 - Normal baseline.** The normal history response establishes the legitimate three-field projection and a known controlled donation row.

## 5. Persisted Input Reaches a Later SQL Sink

A stored username control completed registration and login normally. The decisive observation happened only when the authenticated donation-history consumer was requested: the server returned a PDO exception with `SQLSTATE[42000]`, identified MariaDB, and disclosed a failure near the query's `ORDER BY created_at DESC` suffix.

The later request contained no new SQL input. This is the essential second-order property: the SQL-significant value was persisted earlier and interpreted later by a different server-side consumer.

![PDO and MariaDB syntax error in the later donation-history consumer](Bothered_EV02_PDO_SQL_Error_Oracle.png)

**Figure 2 - Later SQL sink.** The response ties persisted controlled data to a later SQL parser failure. An error alone is a sink signal, not the final impact proof.

## 6. Boolean Result-Set Differential

A separate account used a syntactically valid stored boolean control. That account had not created any donations of its own, yet its history view returned multiple records. One record was the known baseline `5.00` **Share** donation created under the separate controlled account.

This is a semantic result-set differential, not only a body-length or parser-error difference: the later query returned records beyond the new account's own history.

![Expanded donation-history response containing multiple records and the known Share baseline row](Bothered_EV03_Boolean_Result_Set_Expansion.png)

**Figure 3 - Boolean validation.** The known cross-account marker proves SQL expression control and cross-record visibility in the demonstrated SELECT context.

## 7. Bounded UNION Metadata Mapping

The baseline established a three-field UI projection, allowing the investigation to use compatible numeric, text, and date/time expressions without a broad column-count sweep. Only the existing **Message** field was used for text readback.

First, the controlled projection returned the active schema's table names: `users`, `donations`, and `config`.

![Three-column UNION projection returning users, donations, and config in the Message field](Bothered_EV04_UNION_Table_Names.png)

**Figure 4 - Table mapping.** The Message field returns only current-schema table names; no table contents are read at this stage.

The next bounded step established the relevant `config` structure as `name,value`.

![Controlled projection returning the config column names name and value](Bothered_EV05_Config_Columns.png)

**Figure 5 - Column mapping.** The response confirms the key/value layout needed for a narrowly scoped lookup.

Only configuration key names were then read. The result included `site_flag` without exposing the other configuration values.

![Controlled projection returning configuration key names including site_flag](Bothered_EV06_Config_Key_Names.png)

**Figure 6 - Key mapping.** The objective-oriented key is established before any value is read.

## 8. Targeted Objective Read and Atomic Stop

After the objective-oriented key was established, the final read was constrained to that single value. Figure 7 shows the redacted result in the existing Message field. The preceding metadata projections, rather than this final screenshot alone, establish the compatible UNION alignment and bounded source selection.

The exact current-instance selector remains private. No reusable query or payload is published.

![Redacted WebVerse objective value shown in the Message field](Bothered_EV07_Objective_Read_REDACTED.png)

**Figure 7 - Targeted objective read.** The public-safe response records the redacted result. No additional schema enumeration or value reads followed.

## 9. Independent Solved-State Confirmation

The resulting current-instance objective was submitted to WebVerse immediately after the targeted read. The platform reported **Challenge Solved** and **Flag accepted**, providing an authoritative outcome oracle independent from the application's history response.

![WebVerse challenge solved dialog for Bothered showing Flag accepted](Bothered_EV08_Challenge_Solved.png)

**Figure 8 - Authoritative confirmation.** WebVerse accepted the reproduced objective for Bothered.

## 10. Root Cause and CWE Mapping

The root cause is [CWE-89](https://cwe.mitre.org/data/definitions/89.html): externally influenced data changes SQL structure instead of remaining bound data. Here, the relevant failure occurs in the later read path, not necessarily where the username is first stored.

The verbose PDO/MariaDB error is a confirmed disclosure consequence, but it is not needed as a separate root-cause classification. Likewise, accepting a username at registration does not prove that the registration INSERT was parameterized; the verified issue is unsafe construction of the later history query.

## 11. Impact

Within the authorized lab, the demonstrated impact progressed from SQL parser disclosure to cross-record donation visibility, schema metadata disclosure, targeted configuration metadata disclosure, and one targeted configuration-value read.

The reproduction intentionally did **not** test writes, deletes, filesystem reads, operating-system command execution, password extraction, persistence, or access beyond the current lab instance. Those capabilities must not be inferred from the confirmed evidence.

## 12. Remediation

1. **Parameterize every later query.** Persisted user-controlled values remain untrusted whenever they enter a new SQL context.
2. **Bind history to an immutable server-derived user ID.** Do not construct authorization or history selection from a mutable username.
3. **Suppress user-facing database errors.** Log exceptions internally and return a generic error response without SQLSTATE values, engine details, filesystem paths, source lines, or query fragments.
4. **Apply database least privilege.** The donation-history role should not be able to read secret-bearing configuration values.
5. **Regression-test the lifecycle.** Store a quote/comment-bearing test value, log in normally, and exercise every later consumer. The consumer must return only that account's authorized records and never expose a database exception.

## 13. Minimal Public Reproduction Model

1. Create and authenticate a self-owned normal account; capture the normal history response.
2. Use a separate self-owned account with a bounded stored SQL delimiter/control; then request its authenticated history consumer.
3. Confirm a later SQL-specific oracle even though the history request introduces no new query or body parameter.
4. Use a fresh account with a syntactically valid boolean control and confirm a semantic result-set expansion beyond that account's own records.
5. Use the known three-field projection for a bounded metadata ladder: table names, target columns, target key names, then one approved objective value.
6. Redact the objective, stop immediately after proof, and submit it to the lab platform.

## Conclusion

Bothered demonstrates why persisted input must be treated as untrusted at every later interpreter boundary. The evidence establishes a complete second-order SQL injection chain: normal account lifecycle, later SQL parser error, valid boolean result-set differential, compatible UNION projection, minimal metadata mapping, one targeted objective read, and an independently accepted submission.

The public result is recorded as `WEBVERSE{REDACTED}`. Testing stopped at the confirmed, read-only objective.
