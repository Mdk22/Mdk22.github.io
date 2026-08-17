---
title: "WebVerse Dust Jacket: From Public Migration Debris to Verified Owner Access"
date: 2026-07-29T00:00:00+02:00
lastmod: 2026-08-13T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A public migration backup exposed an `OWNER_KEY` that still worked on `POST /owner.php`."
summary: "An Apache directory listing exposed `config.php.bak` with a reusable `OWNER_KEY`. The owner console rejected an invalid key but accepted the exposed value without Cookie or Authorization headers."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Sensitive File Exposure"
  - "Configuration Disclosure"
  - "Hard-coded Credentials"
  - "Broken Access Control"
  - "Security Misconfiguration"
  - "Reconnaissance"
  - "Apache"
  - "PHP"
  - "WordPress"
  - "Caido"
  - "curl"
  - "CWE-219"
  - "CWE-548"
  - "CWE-798"
  - "OWASP A01"
  - "OWASP A02"
platform: "WebVerse"
lab: "Dust Jacket"
difficulty: "Easy"
showToc: true
TocOpen: false
case_id: "CASE-003"
case_status: "SOLVED / VERIFIED"
case_classification: "Sensitive Backup and Credential Exposure"
case_family: "access-exposure"
case_evidence:
  - "Caido"
  - "curl"
case_verified: true
case_caido: true
case_independent_curl: true
primary_cwe: "CWE-219"
cwes:
  - "CWE-219"
  - "CWE-548"
  - "CWE-798"
patterns:
  - "Public Backup Exposure"
  - "Sensitive Configuration Disclosure"
  - "Hard-Coded Credential Exposure"
  - "Broken Access Control"
  - "Security Misconfiguration"
methods:
  - "Directory Enumeration"
  - "Migration Debris Review"
  - "Source Inspection"
  - "Consumer Mapping"
  - "Invalid-versus-Valid Differential"
  - "Independent curl Verification"
---

> **Publication note:** This article covers an authorized lab reproduction. The flag is shown as `WEBVERSE{REDACTED}`. Database credentials, WordPress keys, the reusable `OWNER_KEY`, Cloudflare clearance values, and raw secret-bearing evidence are not published. Copyable requests use `<LAB_HOST>`, while screenshots keep the non-secret request context.

## Executive Summary

Dust Jacket exposed an Apache directory index under `/archive/` that listed migration artefacts left inside the public document root. The directory README explicitly described the files as migration debris and stated that they should not be linked. The most sensitive artefact, `config.php.bak`, was a legacy WordPress configuration snapshot containing database credentials, authentication keys, and a static `OWNER_KEY` associated with the `/owner` console.

Caido captured the request chain and showed how the owner form submits its key. A correctly formatted invalid key returned the restricted form and a clear validation error. I then repeated the same `POST /owner.php` request and changed only `owner_key` to the value exposed in `config.php.bak`. The response returned `owner: verified` and the lab flag. A second Caido request and a `curl` comparison produced the same result without `Cookie` or `Authorization` headers.

> **Confirmed finding:** An unauthenticated user can retrieve a public configuration backup, extract a reusable static owner credential, and authenticate at the live owner verification endpoint. The directory listing is the discovery accelerator; public configuration disclosure and continued validity of the exposed `OWNER_KEY` create the confirmed security impact.

## Finding Snapshot

| Field | Value |
| --- | --- |
| Vulnerability | Public migration-backup disclosure leading to unauthorized owner-level authentication |
| Exposed directory | `GET /archive/` |
| Critical resource | `GET /archive/config.php.bak` |
| Authentication endpoint | `POST /owner.php` |
| Credential parameter | `owner_key` |
| Authentication state | No `Cookie` or `Authorization` header required; static `OWNER_KEY` only |
| Primary proof | Caido Replay invalid-versus-valid single-variable differential |
| Second client | `curl` reproduction with `Cookie` and `Authorization` explicitly absent |
| Primary classification | `CWE-219`: Storage of File with Sensitive Data Under Web Root |
| Supporting weaknesses | `CWE-548`: Directory Listing; `CWE-798`: Use of Hard-coded Credentials |
| OWASP categories | `A01:2025`: Broken Access Control; `A02:2025`: Security Misconfiguration |
| Result | Owner-level authentication and lab flag returned; public flag redacted |

## 1. Scope and Evidence Basis

Testing stayed inside the active WebVerse Dust Jacket lab. This public version replaces the temporary hostname with `<LAB_HOST>`. Fresh evidence was collected on 29 July 2026. No expired hostname, old cookie, previous response, or earlier flag was used as proof.

### Scope Boundaries

- Read-only inspection of publicly accessible application and archive resources.
- One invalid-key control and one intended valid-key proof against the owner console.
- No database login, WordPress session forgery, credential reuse, archive extraction, or unrelated application testing.
- Testing stopped immediately after owner verification and flag disclosure.

### Evidence Authority

The current Caido and `curl` captures record the active host, routes, request format, authentication state, response behavior, and final result. Older notes were used only as a map so the lab did not need to be rediscovered from scratch.

> **Original discovery context:** During the original solve, focused ffuf content discovery identified `/archive` after manual Apache metadata checks were inconclusive. This fresh reproduction did not repeat broad enumeration; it directly validated the known route and rebuilt the complete claim-to-evidence chain in Caido.

## 2. Application and Attack-Chain Overview

The public site looked like a normal PHP bookstore behind Cloudflare. The shopping flow was not the problem. The same public web root also exposed old migration files.

```text
Public Dust Jacket storefront
  -> GET /archive returns a canonical-directory redirect
  -> GET /archive/ exposes an Apache directory index
  -> README.txt confirms unintended migration debris
  -> config.php.bak exposes DB credentials, WordPress keys, and OWNER_KEY
  -> source comment maps OWNER_KEY to /owner
  -> GET /owner reveals POST /owner.php and owner_key
  -> invalid owner_key returns explicit validation failure
  -> leaked OWNER_KEY returns owner: verified
  -> lab flag is disclosed
```

The evidence was collected in this order so that each claim remained narrower than, and fully supported by, the artefact immediately following it.

## 3. Step-by-Step Reproduction

The steps below keep each request, expected result, screenshot, and conclusion together. Public examples preserve the method and path but replace the temporary hostname and reusable secrets with placeholders. Caido is the main evidence source, and the final `curl` check repeats the same invalid-versus-valid result.

### 3.1 Application Baseline

I opened the root page normally and captured it in Caido before testing any other route. This recorded the active host, request method, and application identity.

**R-01: Root request.**

```http
GET / HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** HTTP 200 with HTML identifying Dust Jacket Books. This is only the starting point and does not prove that an archive is exposed.

![Caido baseline request confirming the active Dust Jacket host and initial GET / navigation](01-caido-baseline-request.png)

*Figure 1: Caido baseline request confirming the active Dust Jacket host and initial GET / navigation.*

The server returned `HTTP 200` with `text/html` content, `X-Powered-By`: `PHP/8.2.31`, and HTML identifying Dust Jacket Books. This bound all later archive, owner-console, and flag evidence to the same fresh instance.

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
X-Powered-By: PHP/8.2.31

<title>Dust Jacket Books - Independent bookseller co-op, Asheville NC</title>
```

![Root response identifying the current Dust Jacket storefront and PHP application baseline](02-caido-root-response.png)

*Figure 2: Root response identifying the current Dust Jacket storefront and PHP application baseline.*

> **Baseline conclusion:** The active application and hostname were confirmed directly from fresh traffic before any known solution route was reproduced.

### 3.2 Canonical Archive Route

The known archive candidate was tested by copying the clean root request into Caido Replay and changing only the path from / to `/archive`. The response was a permanent redirect to the trailing-slash directory form.

**R-02: Archive candidate.**

```http
GET /archive HTTP/1.1
Host: <LAB_HOST>

HTTP/1.1 301 Moved Permanently
Location: http://<LAB_HOST>/archive/
```

![Caido response confirming that /archive is recognized as a directory and canonicalized to /archive/](03-caido-archive-redirect.png)

*Figure 3: Caido response confirming that /archive is recognized as a directory and canonicalized to /archive/.*

The `Location` header used HTTP while the HTML link used HTTPS. That can happen behind a reverse proxy, but the cause was not needed for this finding. What mattered was that Apache recognized `/archive` as a real directory. The redirect alone still did not show any sensitive files.

### 3.3 Public Directory Listing

The canonical path `/archive/` was requested directly. Apache returned `HTTP 200` and an auto-index page titled Index of `/archive`. The listing exposed the complete migration-file inventory.

**R-03: Canonical directory request.**

```http
GET /archive/ HTTP/1.1
Host: <LAB_HOST>

HTTP/1.1 200 OK
<title>Index of /archive</title>

README.txt
config.php.bak
inventory-export-2024-10.csv.bak
site.zip.old
```

![Apache directory index exposing the complete archive inventory, including config.php.bak and site.zip.old](04-caido-archive-directory-index.png)

*Figure 4: Apache directory index exposing the complete archive inventory, including config.php.bak and site.zip.old.*

> **Discovery result:** The directory listing proved unauthenticated file enumeration. It did not yet prove that any listed file contained sensitive or currently useful information.

### 3.4 Migration-Debris Context

`README.txt` was small, publicly accessible, and reviewed in full. It explicitly described the directory as migration debris, stated that it should not be linked, and documented that its contents were scheduled for removal after reconciliation.

**R-04: Public README request.**

```http
GET /archive/README.txt HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** HTTP 200 with the migration-debris, cleanup, and `DO NOT LINK` context for the indexed files.

```text
Migration debris - DO NOT LINK.

This directory holds snapshots taken during the BigCommerce migration...
everything in here should be torn down...

- config.php.bak        legacy WP config (pre-migration)
- inventory-export...  October stock snapshot
- site.zip.old         full file backup; do not unpack on the live box
```

![Public README confirming that the archive contains unintended migration snapshots and should not be linked](05-caido-readme-migration-context.png)

*Figure 5: Public README confirming that the archive contains unintended migration snapshots and should not be linked.*

> **Exposure context:** The application itself documented that the directory was temporary migration material rather than an intentional public download area.

### 3.5 Sensitive Configuration and Consumer Mapping

The critical listed artefact, `config.php.bak`, was retrieved without authentication. The response contained a legacy WordPress configuration snapshot with database connection values, WordPress authentication keys, and a static owner-console key. Reusable secret values are raster-redacted in the figure and represented symbolically below.

**R-05: Listed configuration backup.**

```http
GET /archive/config.php.bak HTTP/1.1
Host: <LAB_HOST>

HTTP/1.1 200 OK
Content-Type: application/x-trash
```

```php
define('DB_PASSWORD', '<REDACTED>');
define('AUTH_KEY', '<REDACTED>');
define('SECURE_AUTH_KEY', '<REDACTED>');
define('LOGGED_IN_KEY', '<REDACTED>');
define('NONCE_KEY', '<REDACTED>');

// Co-op owner console key (used by /owner)
define('OWNER_KEY', '<REDACTED_OWNER_KEY>');
```

![Public config.php.bak response exposing redacted database and WordPress secrets plus the OWNER_KEY-to-/owner mapping](06-caido-config-backup-redacted.png)

*Figure 6: Public config.php.bak response exposing redacted database and WordPress secrets plus the OWNER_KEY-to-/owner mapping.*

The source comment named the credential as `OWNER_KEY` and pointed to `/owner` as its consumer. At this point the key existed in the backup, but it had not yet been tested against the live form.

> **Why the next check mattered:** A credential in a backup may be stale. The next steps first confirmed the live form and then compared an invalid key with the exposed key.

### 3.6 Live Owner-Console Contract

A direct `GET /owner` returned the live owner-console form. Its HTML showed that the key must be sent as `owner_key` in a form-encoded POST.

**R-06: Live consumer request.**

```http
GET /owner HTTP/1.1
Host: <LAB_HOST>

HTTP/1.1 200 OK
<title>Owner console - Dust Jacket Books</title>

<form class="owner-form" method="post" action="/owner.php">
  <input type="text" name="owner_key" autocomplete="off">
</form>
```

![Live owner-console HTML defining POST /owner.php and the owner_key form parameter](07-caido-owner-form-contract.png)

*Figure 7: Live owner-console HTML defining POST /owner.php and the owner_key form parameter.*

| Field | Value |
| --- | --- |
| Method | POST |
| Endpoint | `/owner.php` |
| Content type | `application/x-www-form-urlencoded` |
| Body field | `owner_key` |
| Negative oracle | Restricted HTML form plus explicit validation error |
| Positive oracle | `text/plain` response containing `owner: verified` and `build-flag` |

### 3.7 P-01: Invalid-Key Baseline

The legitimate form was submitted once with a format-correct but invalid value. Capturing the browser-generated request in Caido confirmed the real `Content-Type` and body encoding before any use of the exposed credential.

**P-01: Invalid-key request.**

```http
POST /owner.php HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

owner_key=OWN-0000-0000-0000
```

![Browser-generated invalid-key POST request confirming the exact form-urlencoded contract](08-caido-invalid-owner-key-request.png)

*Figure 8: Browser-generated invalid-key POST request confirming the exact form-urlencoded contract.*

The server returned `HTTP 200`, but the body still contained the restricted form and an explicit validation error. The status code alone could not distinguish rejection from success.

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

Restricted. Enter the owner key on file with the bookkeeper.
That key didn't validate. Try again or contact the bookkeeper.
```

![Negative-control response retaining the restricted form and explicitly rejecting the invalid key](09-caido-invalid-owner-key-response.png)

*Figure 9: Negative-control response retaining the restricted form and explicitly rejecting the invalid key.*

> **Negative-control result:** Both rejected and accepted requests returned `HTTP 200`. Success had to be read from the response body and `Content-Type`, not the status code.

### 3.8 P-02: Exposed `OWNER_KEY` Validation

The invalid request was copied into Replay. Only the `owner_key` value was changed to the value disclosed in `config.php.bak`. `Cookie` and `Authorization` headers were removed so that the proof isolated the static key from browser-session state.

**P-02: Partially redacted proof request.**

```http
POST /owner.php HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

[No Cookie header]
[No Authorization header]
owner_key=<REDACTED_OWNER_KEY>
```

![Cookie-less and authorization-less Caido Replay request using only the redacted OWNER_KEY](10-caido-valid-owner-key-request-redacted.png)

*Figure 10: Cookie-less and authorization-less Caido Replay request using only the redacted OWNER_KEY.*

The valid key produced a different response: `text/plain`, explicit owner verification, and the lab flag. Method, endpoint, host, `Content-Type`, and body field stayed the same. Only the credential value changed.

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8

owner: verified
build-flag: WEBVERSE{REDACTED}
```

![Server-side owner verification and the redacted lab flag returned for the leaked key](11-caido-owner-verified-response-redacted.png)

*Figure 11: The exposed key returns owner verification and the redacted lab flag.*

> **Confirmed credential compromise:** The `OWNER_KEY` retained in the public legacy configuration was accepted by the live owner console without `Cookie` or `Authorization`. This converts a source disclosure into confirmed unauthorized owner-level authentication at the verification endpoint.

### 3.9 Repeating the Comparison with `curl`

A separate command-line workflow reproduced the invalid-versus-valid differential outside both the browser and Caido interface. It explicitly sent empty `Cookie` and `Authorization` headers. The public block preserves the executed request shape while replacing the temporary origin and reusable owner key with placeholders.

**C-01: Executed `curl` request.**

```bash
LAB_ORIGIN='https://<LAB_HOST>'
OWNER_KEY='<REDACTED_OWNER_KEY>'

curl -sS -i \
  -H 'Cookie:' \
  -H 'Authorization:' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'owner_key=OWN-0000-0000-0000' \
  "$LAB_ORIGIN/owner.php"

curl -sS -i \
  -H 'Cookie:' \
  -H 'Authorization:' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "owner_key=$OWNER_KEY" \
  "$LAB_ORIGIN/owner.php"
```

**Expected result:** the invalid request returns `text/html` and the validation error; the exposed-key request returns `text/plain`, `owner: verified`, and `WEBVERSE{REDACTED}`. These commands repeat the comparison but do not replace the Caido evidence that links the backup to the live form.

![curl comparison with invalid key rejected and exposed key accepted](12-curl-owner-key-differential-redacted.png)

*Figure 12: `curl` rejects the invalid key and accepts the exposed key without `Cookie` or `Authorization`.*

The redacted evidence file records the invalid response as `text/html` with a validation error. The valid response is `text/plain` with `owner: verified` and `WEBVERSE{REDACTED}`. Repeating the request outside the browser confirmed that the result was not caused by display state or a browser session.

> **Public evidence handling:** The script contained the live `OWNER_KEY`, and its raw output contained the full flag. Both stay private and are not embedded here.

### 3.10 Final Result and Stop Point

The finding depends on the full chain: discover the public archive, confirm that it contains migration files, retrieve the backup configuration, map `OWNER_KEY` to `/owner`, record an invalid-key response, and repeat the same request with only the exposed key changed.

| Final evidence field | Verified result |
| --- | --- |
| Exposed resource | `GET /archive/config.php.bak` |
| Authentication endpoint | `POST /owner.php` |
| Request state | No `Cookie` or `Authorization` header |
| Negative oracle | HTTP 200, `text/html`, explicit validation failure |
| Positive oracle | HTTP 200, `text/plain`, `owner: verified` |
| Primary weakness | CWE-219 |
| Supporting weaknesses | CWE-548 and CWE-798 |
| Flag | `WEBVERSE{REDACTED}` |
| Status | Solved / Verified |

> **WHERE TESTING STOPPED**
>
> Testing stopped after owner verification, flag disclosure, and the `curl` check. I did not test the database credentials, WordPress keys, unrelated archive files, or any other owner-console capability.

## 4. Technical Root Cause and Classification

The directory index made the migration files easy to enumerate, but indexing alone was not the complete vulnerability. The confirmed chain required four security failures: sensitive artefacts were deployed under the public document root, backup extensions were served directly, reusable secrets remained embedded in a legacy configuration snapshot, and the same static `OWNER_KEY` was still trusted by the current owner console.

| Layer | Observed Role | Security Meaning |
| --- | --- | --- |
| Discovery enabler | Apache auto-index exposed `/archive/` file names. | Converted one route into a complete public inventory. |
| Deployment failure | Migration snapshots remained in the live web root. | Made internal and sensitive files externally retrievable. |
| Secret-management failure | Database, WordPress, and `OWNER_KEY` values remained in `config.php.bak`. | Exposed reusable credentials and authentication material. |
| Authentication design | The owner console trusted a static shared key. | A single leaked value was sufficient for privileged verification. |
| Confirmed consequence | The leaked `OWNER_KEY` returned `owner: verified` and the flag. | Proved current exploitability rather than historical exposure only. |

```text
Observed vulnerable flow:
request -> public /archive/config.php.bak -> extract OWNER_KEY -> POST /owner.php -> owner verified

Required control flow:
deployment pipeline -> reject sensitive artefacts -> secrets manager -> named user authentication -> authorization -> owner resource
```

> **Security boundary:** A hidden or unlinked file is not protected. Static client knowledge, source comments, and obscurity cannot replace web-root hygiene, secret rotation, and server-side identity-based authorization.

**Classification references:** [CWE-219](https://cwe.mitre.org/data/definitions/219.html)  |  [CWE-548](https://cwe.mitre.org/data/definitions/548.html)  |  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  |  [A01:2025](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)  |  [A02:2025](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)

## 5. Evidence Interpretation and False-Positive Controls

| Control | What It Proved | What It Did Not Prove |
| --- | --- | --- |
| `/archive` redirect | Apache recognized a real directory path. | It did not prove that directory contents were accessible. |
| Directory listing | File names and sizes were publicly enumerable. | It did not prove sensitive contents or live credential validity. |
| `README.txt` | The files were unintended migration debris. | It did not prove the configuration snapshot contained real secrets. |
| `config.php.bak` | The backup exposed credentials, auth keys, and `OWNER_KEY`. | It did not prove any disclosed value remained active. |
| Source comment | `OWNER_KEY` was associated with `/owner`. | It did not prove the route existed or define the request transport. |
| `GET /owner` | The live form required `POST /owner.php` and `owner_key`. | It did not prove the exposed key would authenticate. |
| Invalid key | The request contract worked and incorrect credentials were rejected. | `HTTP 200` alone did not indicate access. |
| Valid key | The exposed key produced `owner: verified` and the flag. | It did not prove database or WordPress secrets were active. |
| `Cookie`-less replay | The `OWNER_KEY` worked without session credentials. | It did not test any other owner-console function. |
| `curl` comparison | A second client reproduced the same pass/fail behavior. | It stopped after the lab flag was returned. |

## 6. Impact

In the reproduced lab, any unauthenticated user could enumerate a public migration directory, download a legacy configuration snapshot, obtain a live static owner credential, and receive server-side owner verification and the challenge flag. The same file also disclosed database connection values and WordPress authentication keys, although those additional values were not tested for current validity.

In a production environment, an equivalent chain could expose privileged workflows permitted by the leaked credential, enable database compromise if the disclosed database values remained valid, and undermine WordPress authentication integrity if the exposed keys were still active. Rotating those keys would invalidate existing WordPress authentication cookies; actual user impersonation would require additional user and session material. Credential reuse could also increase lateral-movement risk. Actual severity depends on which disclosed values remain valid and what the privileged console permits.

> **Impact qualification:** Confirmed impact is limited to public secret disclosure, current validity of the `OWNER_KEY`, owner verification, and flag disclosure. Database access, WordPress user impersonation, destructive actions, and broader administrative capabilities were not attempted and are not claimed.

## 7. Remediation

### 7.1 Immediate Containment

- Remove `/archive/` and all migration snapshots from the public document root.
- Rotate `OWNER_KEY`, database credentials, and every WordPress authentication key exposed in the backup.
- Rotate the exposed WordPress authentication keys to invalidate existing authentication cookies, then review access logs for requests to the listed files and privileged endpoint.
- Search the complete deployment for additional .bak, .old, .orig, .save, .zip, .sql, export, and temporary artefacts.

### 7.2 Web-Server Controls

```apache
Options -Indexes

<FilesMatch "\.(bak|old|orig|save|tmp|copy|sql|dump|zip|tar|gz|tgz)$">
    Require all denied
</FilesMatch>

<Directory "/var/www/html/archive">
    Require all denied
</Directory>
```

Extension blocks are defense in depth, not a substitute for removing sensitive files. Backups and migration data should never be deployed under a public web root.

### 7.3 Secret and Authentication Design

- Move secrets to an approved secrets manager or environment-specific protected configuration store.
- Replace the shared static `OWNER_KEY` with named user accounts, strong authentication, MFA, role-based authorization, and auditable server-side sessions.
- Use short-lived administrative credentials and enforce rotation after migrations, incident response, or personnel changes.

### 7.4 Deployment and SDLC Controls

- Add CI/CD deny-list checks for backup, export, archive, and secret-bearing files before release.
- Run post-deployment web-root inventory and unauthenticated content-discovery checks.
- Assign migration-cleanup ownership, a removal deadline, and go-live verification criteria.
- Maintain automated tests confirming that sensitive directories return `403/404` and privileged routes reject anonymous and non-owner identities.

## 8. Lessons Learned

The evidence chain supports six reusable lessons for future authorized web-security testing:

- **Not linked does not mean inaccessible.** Direct routing and content discovery routinely expose forgotten deployment material.
- **Migration debris deserves priority.** Configuration snapshots, exports, archives, and handoff notes frequently preserve the most security-sensitive state.
- **Review small files completely.** A short source comment can map a leaked credential to its exact live consumer.
- **Separate source disclosure from runtime proof.** A secret becomes an active finding only when the live form accepts it.
- **Do not rely on status alone.** Both requests returned `HTTP 200`; the body and `Content-Type` separated rejection from success.
- **Repeat the key comparison.** Caido captured the full HTTP chain, while `curl` confirmed the same result without adding new tests.

## Conclusion

**Discovery.** The Dust Jacket server exposed a real `/archive` directory and an Apache-generated index. The listed README confirmed unintended migration debris, while `config.php.bak` disclosed sensitive configuration material and a static `OWNER_KEY` associated with the owner console.

**Validation and verdict.** The live `/owner` form showed how to send `POST /owner.php`. A correctly formatted invalid key returned an explicit rejection. Replacing only `owner_key` with the value from the public backup, without `Cookie` or `Authorization`, returned `owner: verified` and the lab flag. The same comparison worked with `curl`.

```text
LAB RESULT
Exposed resource: GET /archive/config.php.bak
Authentication endpoint: POST /owner.php
Request state: No Cookie or Authorization header
Primary weakness: CWE-219
Supporting weaknesses: CWE-548 and CWE-798
Flag: WEBVERSE{REDACTED}
Status: SOLVED / VERIFIED
```

### Technical References

**Weakness mapping:** [CWE-219](https://cwe.mitre.org/data/definitions/219.html)  |  [CWE-548](https://cwe.mitre.org/data/definitions/548.html)  |  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

**OWASP Top 10:2025:** [A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)  |  [A02 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)

**WordPress:** [Authentication cookie validation](https://developer.wordpress.org/reference/functions/wp_validate_auth_cookie/)  |  [Security keys and salts](https://developer.wordpress.org/apis/wp-config-php/)
