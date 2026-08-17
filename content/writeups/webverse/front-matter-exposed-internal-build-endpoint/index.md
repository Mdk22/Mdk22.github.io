---
title: "WebVerse Front Matter: From Production HTML Comments to an Exposed Internal Build Endpoint"
date: 2026-07-30T00:00:00+02:00
lastmod: 2026-08-13T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A production HTML comment disclosed `/api/internal/build`, which returned build data and the lab flag without authentication."
summary: "A production comment on the public Colophon page disclosed `/api/internal/build` and said it should remain off-network. Anonymous Caido and curl requests returned HTTP 200, build metadata, status `ok`, and the lab flag."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Sensitive Information Disclosure"
  - "Internal Endpoint Exposure"
  - "HTML Comments"
  - "Broken Access Control"
  - "Security Misconfiguration"
  - "Reconnaissance"
  - "Caido"
  - "curl"
  - "CWE-201"
  - "CWE-615"
  - "CWE-862"
  - "OWASP A01"
  - "OWASP A02"
platform: "WebVerse"
lab: "Front Matter"
difficulty: "Easy"
showToc: true
TocOpen: false
case_id: "CASE-004"
case_status: "SOLVED / VERIFIED"
case_classification: "Internal Endpoint Exposure"
case_family: "access-exposure"
case_evidence:
  - "Caido"
  - "curl"
case_verified: true
case_caido: true
case_independent_curl: true
primary_cwe: "CWE-201"
cwes:
  - "CWE-201"
  - "CWE-615"
  - "CWE-862"
patterns:
  - "Internal Endpoint Exposure"
  - "Sensitive Information Disclosure"
  - "Broken Access Control"
  - "Production Comment Disclosure"
methods:
  - "Source Inspection"
  - "Disclosed Route Follow-Up"
  - "Anonymous Replay"
  - "Independent curl Verification"
  - "Cross-Client Verification"
  - "Authoritative Status Check"
---

> **Publication note:** This article covers an authorized lab reproduction. The flag is shown as `WEBVERSE{REDACTED}`, temporary hosts use `<LAB_HOST>`, and sessions and private raw evidence are not published.

## Executive Summary

The **Front Matter** challenge was solved through focused reconnaissance that followed the application's own public navigation. The storefront linked to a Colophon page whose production HTML contained a build-pipeline comment. That comment disclosed the internal route `/api/internal/build`, stated that the endpoint should remain off-network, and identified the response body as the location of the challenge flag.

I removed all session credentials and requested the disclosed route in Caido Replay. The server returned HTTP `200` and a `text/plain` body with a build ID, status `ok`, and the lab flag. The same request worked with `curl` without cookies or authorization, and WebVerse accepted the flag.

> **Confirmed finding:** The vulnerability was not the HTML comment alone. The complete issue was the combination of a production comment that disclosed an internal route and an access-control/deployment-boundary failure that left the internal endpoint publicly reachable by an anonymous client.

## 1. Report Profile

| Field | Value |
| --- | --- |
| Platform | WebVerse |
| Lab | Front Matter |
| Category | Reconnaissance |
| Difficulty | Easy |
| Status | Solved |
| Date | 30 July 2026 |
| Target | `https://<LAB_HOST>/` |
| Primary issue | Exposed internal endpoint |
| Secondary issue | Sensitive information in production HTML comments |

### Verified Attack Chain

```text
GET /
  -> public storefront exposes /colophon
GET /colophon
  -> production HTML comment discloses /api/internal/build
GET /api/internal/build
  -> anonymous HTTP 200
  -> build metadata and lab flag
curl verification
  -> matching response reproduced in a second client
WebVerse submission
  -> CHALLENGE SOLVED
```

## 2. Preconditions and Test Boundaries

- No user account or privileged role was required.
- No non-`GET` request or explicit mutation payload was sent; every test used `GET`.
- The evidence does not show whether `GET` only returned metadata or also started a build or another server-side action.
- No crawler, directory brute-force, method fuzzing, or unrelated route enumeration was used.
- All dynamic values, responses, and the flag were collected from the fresh current instance.
- The reproduction stopped immediately after WebVerse accepted the flag.

### Evidence Basis

The conclusion uses three evidence sources: Caido History for the normal application flow, Caido Replay for the anonymous request, and `curl` for a portable raw response. WebVerse then accepted the disclosed flag.

## 3. Step-by-Step Reproduction

There was no standalone payload. The important change was the request path, and the access-control check was simple: remove the session before requesting the endpoint named by the application. Each request stays beside its response and conclusion so the path from public page to anonymous response remains easy to follow.

### 3.1 Storefront Baseline

I began with the public storefront instead of copying a route from older notes. The first request recorded the active host and normal application response.

**R-01: Storefront baseline.**

```http
GET / HTTP/1.1
Host: <LAB_HOST>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
```

**Expected result:** HTTP 200 with Front Matter HTML. This step binds the reproduction to the fresh instance; it does not prove sensitive disclosure.

![Storefront request captured in Caido.](01-caido-storefront-baseline-request.png)

*Figure 1: Caido records a normal `GET /` request on the fresh Front Matter host.*

### 3.2 Application-Provided Colophon Discovery

The storefront response identified itself as Front Matter and included a same-origin `/colophon` link. The next route therefore came from intended public navigation rather than crawling or blind enumeration.

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<title>Recent Titles - Front Matter</title>
...
<a href="/colophon">Colophon</a>
```

![Storefront HTML response exposing the public Colophon link.](02-caido-storefront-response-colophon-link.png)

*Figure 2: The storefront confirms its identity and links `/colophon`.*

No relevant HTML comment or flag was identified in the root response. Colophon was prioritized because the challenge briefing emphasized production notes, markup, and producer-left content.

### 3.3 Same-Origin Colophon Request and Response

**R-02: Colophon source request.**

```http
GET /colophon HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** HTTP 200 with the active instance's Colophon HTML.

![Same-origin Colophon navigation request with the browser cookie raster-redacted.](03-caido-colophon-request-redacted.png)

*Figure 3: Colophon request. The same-origin `GET /colophon` follows the storefront link. The browser cookie is redacted because it is unnecessary for the public-page claim.*

The response returned a normal HTML document titled `Colophon - Front Matter` with production notes about typography, paper, binding, and the catalogue build process.

![Colophon response headers and document identity.](04-caido-colophon-response.png)

*Figure 4: Colophon response. HTTP 200, HTML content type, and document title bind the later source comment to the active Front Matter page.*

### 3.4 Production Comment and Testable Route

Raw-source inspection revealed a production build-pipeline comment. The rendered page did not display it, but any unauthenticated client could retrieve it through View Source, an intercepting proxy, or an ordinary HTTP client.

```html
<!-- build-pipeline note (kira, 2026-03-19):
the rebuild script is wired at /api/internal/build
-- keep it off-network at deploy.
flag will land in the body of the response. -->
```

![Production build-pipeline comment embedded in the Colophon HTML source.](05-caido-build-pipeline-comment.png)

*Figure 5: Production source disclosure. The comment names `/api/internal/build`, associates it with a rebuild script, states the intended off-network boundary, and defines the response body as the objective oracle.*

| Disclosed fact | Security meaning |
| --- | --- |
| `/api/internal/build` | Route to test; no further discovery was required. |
| `rebuild script` | The route was associated with an internal build or catalogue pipeline. |
| `keep it off-network` | The intended deployment boundary was explicit and testable. |
| `flag ... in the body` | The comment says that the response body contains the flag. |

The comment was a lead, not a confirmed vulnerability. The next step was one anonymous `GET` to the disclosed endpoint.

> **METHODOLOGY BOUNDARY**
>
> Turn the source comment into one testable route, remove the session before checking anonymous access, do not infer server-side effects from `GET` alone, and repeat the response with a second client.

### 3.5 Anonymous Caido Replay Validation

The captured Colophon request was sent to Replay and only the path was changed. `Cookie` was removed, and no `Authorization` header, token, query parameter, or request body was supplied.

**R-03: Anonymous internal-endpoint request.**

```http
GET /api/internal/build HTTP/1.1
Host: <LAB_HOST>
Accept: */*

# No Cookie
# No Authorization
# No request body
```

**Expected result:** HTTP 200 with `text/plain`, a build ID, status `ok`, and a flag shown publicly as `WEBVERSE{REDACTED}`.

![Anonymous Caido Replay request to the disclosed internal build endpoint.](06-caido-anonymous-internal-build-request.png)

*Figure 6: The disclosed route is requested without credentials or a payload.*

![Caido response from the internal build endpoint with the complete flag raster-redacted.](07-caido-internal-build-response-redacted.png)

*Figure 7: Caido shows HTTP 200, `text/plain`, a build ID, status `ok`, and the redacted flag.*

This confirms anonymous external read access and sensitive data disclosure. It does not show whether `GET` also started a build or changed server state.

### 3.6 Repeating the Request with `curl`

A second client requested the same endpoint without session material, ruling out a Caido display or Replay-state artifact. The private local output-capture filename is intentionally omitted.

**C-01: Executed `curl` request.**

```bash
curl --silent --show-error --include \
  'https://<LAB_HOST>/api/internal/build'
```

**Expected result:** a matching anonymous response during the same session.

```text
HTTP/2 200
content-type: text/plain; charset=utf-8
content-length: 87

build-id: 2026.05.03-a91c4
status: ok
flag: WEBVERSE{REDACTED}
```

![Raw curl reproduction with the temporary host and lab flag redacted.](08-curl-internal-build-prefix-only.png)

*Figure 8: `curl` returns the same status, content type, build metadata, and redacted flag without cookies or authorization.*

> **Protocol note:** Caido Replay used HTTP/1.1 while `curl` negotiated HTTP/2. Both clients still reached the same endpoint and received matching status, content type, build metadata, and flag.

### 3.7 WebVerse Result and Stop Point

I submitted the full value from the raw response to WebVerse. The platform reported **Challenge Solved** and **Flag accepted**.

```text
LAB FLAG
WEBVERSE{REDACTED}
```

![WebVerse challenge solved state for Front Matter.](09-webverse-front-matter-solved-state.png)

*Figure 9: WebVerse accepts the value returned by the anonymous Front Matter request.*

| Tool | What it proved |
| --- | --- |
| Caido History | The legitimate storefront-to-Colophon flow and exact production HTML disclosure. |
| Caido Replay | The internal endpoint remained reachable after session credentials were removed. |
| `curl` | A second client reproduced the matching anonymous response during the same session. |
| WebVerse UI | The recovered flag was accepted and the challenge marked solved. |

| Final evidence field | Verified result |
| --- | --- |
| Endpoint | `/api/internal/build` |
| Method | `GET` |
| Authentication | None |
| Status | HTTP 200 |
| Content-Type | `text/plain; charset=utf-8` |
| Build ID | `2026.05.03-a91c4` |
| Build status | `ok` |
| Flag | `WEBVERSE{REDACTED}` |
| Platform result | Challenge Solved, Flag accepted |

> **WHERE TESTING STOPPED**
>
> Reproduction stopped after the `curl` check and WebVerse acceptance. I did not send non-`GET` methods, fuzz methods, crawl the site, brute-force routes, or test unrelated endpoints.

## 4. Vulnerability Classification

| Attribute | Verified value |
| --- | --- |
| Primary class | Unauthorized sensitive-data exposure from an internal endpoint |
| Secondary class | Sensitive route disclosure in production HTML comments |
| Affected endpoint | `/api/internal/build` |
| HTTP method | `GET` |
| Input / parameter | None |
| Authentication | No application session or credential required |
| Response type | `text/plain; charset=utf-8` |
| Security effect | Build metadata and the challenge secret disclosed to an anonymous external client |

### Best-Fit Standards Mapping

| Reference | Evidence-based relevance |
| --- | --- |
| `CWE-201` | Primary runtime weakness: the response sent build metadata and the challenge secret to an anonymous actor outside the intended trust boundary. |
| `CWE-615` | Discovery enabler: a production source-code comment disclosed the internal route, its operational purpose, and the intended off-network boundary. |
| `CWE-862` | Supporting access-control weakness: the external request was not rejected even though the route was described as off-network. Backend authorization design was not inspected. |
| `OWASP A01:2025` | Primary OWASP category: an intended non-public resource was accessible to an anonymous external client. |
| `OWASP A02:2025` | Contributing category: an internal route and deployment note remained exposed in the production application. |

> **Classification limit:** Runtime evidence proves anonymous external read access and sensitive disclosure. It does not prove the server framework, backend authorization design, internal network topology, or whether `GET` initiated build activity or another server-side state change.

## 5. Root Cause

The confirmed issue resulted from three connected failures rather than from a single isolated mistake.

### Production Comment Disclosure

A development note containing an internal route, its operational purpose, its intended deployment boundary, and the location of a sensitive result remained embedded in public production HTML. HTML comments are hidden from normal rendering, not from clients.

### Deployment Boundary Failure

The comment said the build route should stay off-network. In practice, an anonymous external request received HTTP `200`.

### Sensitive Data in an Unauthenticated Response

The endpoint returned a build identifier, operational status, and the challenge secret to an anonymous external client without an application session, credential, or observable access-control challenge. Even if the route had not been disclosed in the HTML, publicly routing an internal build endpoint with sensitive output would remain a security defect.

## 6. False-Positive Controls

| Potential false conclusion | Control applied |
| --- | --- |
| A route in a comment proves exposure | The route was requested and returned HTTP `200`; the comment alone was not treated as final proof. |
| HTTP `200` proves sensitive disclosure | The response body was inspected and shown to contain build metadata and the challenge secret. |
| A browser session enabled access | `Cookie` and `Authorization` headers were absent from the Replay request, and `curl` reproduced the result anonymously. |
| The result was a proxy or UI artifact | A second client returned the same status, content type, body, and full flag. |
| The flag was stale or from another instance | It was obtained from the active hostname and accepted by WebVerse during the same session. |

## 7. Impact

Within the lab, the issue resulted in complete compromise of the challenge objective: any unauthenticated user who inspected the relevant source could retrieve the flag directly from the internal endpoint.

In production, impact would depend on the endpoint's real data and capabilities. It might expose build IDs, deployment metadata, environment details, status information, tokens, or other secrets. This lab confirmed only the values shown in the evidence.

> **Severity note:** No CVSS score is assigned because this educational instance does not provide the asset value, trust boundaries, confidentiality requirements, or production business context required for a defensible score.

## 8. Remediation

| Priority | Control | Required action |
| --- | --- | --- |
| `P0` | Remove sensitive response data | Never return flags, tokens, credentials, environment secrets, or deployment secrets from diagnostic or build endpoints. |
| `P0` | Remove public routing | Exclude the internal build handler from the production application or restrict it at the reverse proxy and network layers. |
| `P1` | Enforce authentication and authorization | If operational access is required, apply strong identity checks and explicit role-based authorization in addition to network controls. |
| `P1` | Strip development comments | Remove HTML comments, TODO notes, internal routes, debug instructions, and operational annotations during the production build. |
| `P1` | Add deployment security tests | Fail CI/CD when public builds contain sensitive values, unintended internal route references, debug endpoints, sensitive or unintended source maps, or unauthenticated administrative functions. |
| `P2` | Apply least exposure | Publish only routes and metadata required by end users; keep operational functions in separate, monitored management planes. |

## 9. Validation After the Fix

1. Confirm that the production Colophon HTML no longer contains internal build notes or route names.
2. Verify that external requests to `/api/internal/build` receive `404` or an equivalent non-routable result.
3. From an authorized management context, confirm that any retained build endpoint requires authentication and explicit authorization.
4. Search the complete production artifact for secrets, unintended internal endpoints, TODO comments, debug routes, and sensitive or unintended source maps before deployment.

## Conclusion

Front Matter shows why reading public source is still valuable. There was no need for broad automation: follow the clue, inspect the relevant page, take the disclosed route, and test it with one anonymous request.

A production HTML comment disclosed an internal build route and said it should remain off-network. The route was still reachable without authentication and returned build data plus the lab flag. Caido captured the application flow, `curl` returned the same response, and WebVerse accepted the flag.

```text
FINAL VERDICT
CONFIRMED - A production HTML comment disclosed an internal route that was externally reachable by an anonymous client and returned sensitive build information together with the challenge secret.
```

### Evidence Artifacts

| Artifact | Purpose |
| --- | --- |
| Caido storefront request/response | Current-host baseline and public `/colophon` route. |
| Caido Colophon request/response | Production HTML comment and exact internal route disclosure. |
| Caido Replay request/response | Anonymous access to `/api/internal/build` and sensitive response. |
| Private raw HTTP response | Full flag verification; the public article shows it as `WEBVERSE{REDACTED}`. |
| `Front_Matter.png` | WebVerse solved-state confirmation. |
