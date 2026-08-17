---
title: "WebVerse Flap Copy: Public AASA Metadata Reveals an Internal Staff Route"
date: 2026-08-13T00:00:00+02:00
lastmod: 2026-08-13T00:00:00+02:00
draft: false
author: "Mdk22"
description: "PWA and Apple App Site Association files expose matching route patterns and reveal a live internal staff page."
summary: "Flap Copy's landing page disclosed its PWA manifest. Comparing it with the public AASA file revealed an unadvertised staff route, and one request returned internal handoff details plus the redacted flag."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Flap Copy"
  - "Reconnaissance"
  - "AASA"
  - "Universal Links"
  - "PWA"
  - "Public Metadata"
  - "Internal Endpoint Exposure"
  - "Sensitive Information Disclosure"
  - "Caido"
  - "CWE-538"
platform: "WebVerse"
lab: "Flap Copy"
difficulty: "Medium"
showToc: true
TocOpen: false
case_id: "CASE-012"
case_featured: false
case_summary_short: "Public PWA/AASA metadata disclosed a live internal staff route and handoff metadata."
case_status: "VERIFIED / PREVIOUSLY SOLVED"
case_classification: "Public Metadata Disclosure / Internal Route Exposure"
case_family: "access-exposure"
case_evidence:
  - "Caido"
  - "Chromium"
case_verified: true
case_caido: true
case_independent_curl: false
primary_cwe: "CWE-538"
cwes:
  - "CWE-538"
patterns:
  - "Public Metadata Route Disclosure"
  - "Internal Endpoint Exposure"
  - "Sensitive Information Disclosure"
methods:
  - "Source Inspection"
  - "Cross-Artifact Route Correlation"
  - "Disclosed Route Follow-Up"
  - "Authoritative Status Check"
---

> **Publication note:** This article documents a fresh reproduction in an authorised WebVerse educational lab. The live hostname, reusable session material, and literal objective are excluded. Public evidence uses `<LAB_HOST>`, `<LAB_ORIGIN>`, and `WEBVERSE{REDACTED}`. The solved-state interface retains the account's earlier solve date and is not presented as the timestamp of this reproduction.

## Executive Summary

I started with the metadata already linked by Flap Copy instead of scanning for routes. The landing page referenced a PWA manifest, while the standard Apple App Site Association (AASA) file listed the app's Universal Links. Both files used the same route structure, and one unadvertised path stood out: `/staff-only/dispatch*`.

One request to `/staff-only/dispatch` returned a staff page, environment and build details, and the redacted flag. The public metadata therefore revealed a live internal route. I did not test authentication bypass, privilege escalation, administrative access, or real-user data.

> **CONFIRMED FINDING**
>
> A public AASA file contained a staff-only route pattern and marked it for internal use. One `GET` request confirmed that the route was live and returned internal handoff information.

## 1. Report Profile

| Field | Verified value |
| --- | --- |
| Platform | WebVerse |
| Lab | Flap Copy |
| Difficulty | Medium |
| Reproduction date | 13 August 2026 |
| Evidence | Caido request/response evidence and Chromium full-body views |
| Primary weakness | [CWE-538](/cwes/cwe-538/): Insertion of Sensitive Information into Externally-Accessible File or Directory |
| Final evidence route | `GET /staff-only/dispatch` |
| Authentication boundary | Existing browser session preserved; no anonymous/authenticated differential performed |
| curl reproduction | Not performed |
| Platform state | Previously solved; UI retains 7 August 2026 |

### Verified Attack Chain

```text
Fresh challenge landing page
  > HTML links /manifest.webmanifest
Public PWA manifest
  > /today, /upcoming, /console/quick-actions
Public AASA file
  > matching public route families
  > /staff-only/dispatch* marked internal and "do not advertise"
Cross-artifact consistency control
  > matching route patterns justify one candidate
GET /staff-only/dispatch
  > internal handoff content + build/environment metadata
  > WEBVERSE{REDACTED}
Stop
```

## 2. Scope, Authorisation, and Evidence Boundary

This manuscript covers a previously solved, authorised WebVerse educational challenge reproduced against a fresh challenge instance. Only the known static chain was re-run. No wordlist fuzzing, suffix guessing, authentication manipulation, scanner, destructive action, or post-objective target request was introduced.

- Fresh requests and responses are used for every runtime claim.
- The existing browser cookie was preserved; no claim of anonymous access or authentication bypass is made.
- No terminal or `curl` reproduction was performed.
- AASA disclosure identifies a candidate; it is not proof that the candidate is live.
- HTTP 200 alone is not enough; the staff content and flag are what confirm the finding.
- The historical solved-state UI is separate from the fresh target evidence.

## 3. Step-by-Step Reproduction

### 3.1 Fresh-instance baseline and application-provided discovery

The landing page linked the next reconnaissance step directly from its own HTML. No route was guessed.

```http
GET / HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** a normal landing response containing a concrete application metadata reference.

![Caido request for the fresh Flap Copy landing page](FlapCopy_Figure_01_Landing_Request.png)

**Figure 1: Fresh-instance baseline.** Caido records the public `GET /` request while the live origin is replaced with a stable publication placeholder.

![Landing HTML response declaring the PWA manifest path](FlapCopy_Figure_02_Landing_Manifest_Reference.png)

**Figure 2: Application-provided manifest discovery.** The landing HTML explicitly declares `/manifest.webmanifest`, proving that the next path came from the application rather than enumeration.

### 3.2 PWA manifest route mapping

The manifest listed the application's shortcut routes. Those routes are normal navigation metadata, not vulnerabilities by themselves. They provided patterns to compare with AASA.

```http
GET /manifest.webmanifest HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** parseable PWA metadata with application-owned shortcut URLs.

![Caido request for the HTML-declared PWA manifest](FlapCopy_Figure_03_Manifest_Request.png)

**Figure 3: Manifest request.** Caido preserves the exact request for `/manifest.webmanifest`; the origin and referrer are publication-sanitised.

![Caido response showing the manifest content type and JSON body](FlapCopy_Figure_04_Manifest_Response.png)

**Figure 4: Manifest response.** The server returns `application/manifest+json` with the shortcut data used in the comparison.

![Complete Chromium view of the PWA manifest shortcuts](FlapCopy_Figure_05_Manifest_Full_View.png)

**Figure 5: PWA route set.** The complete manifest view exposes `/today?compose=1`, `/today`, `/upcoming`, and `/console/quick-actions`.

### 3.3 AASA route-pattern mapping

The canonical Universal Links artefact was then retrieved from its well-known path. AASA files are externally retrievable association metadata; the issue is not their existence, but the sensitive internal routing detail placed inside this one.

```http
GET /.well-known/apple-app-site-association HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** parseable Universal Links metadata whose path patterns can be compared with the PWA manifest.

![Caido request for the canonical AASA file](FlapCopy_Figure_06_AASA_Request.png)

**Figure 6: AASA request.** Caido records the canonical well-known request. The live origin and multi-line reusable cookie are redacted without hiding the requested path.

![AASA response containing public and staff-only route patterns](FlapCopy_Figure_07_AASA_Response.png)

**Figure 7: Sensitive route metadata.** The AASA response lists `/staff-only/dispatch*` and labels it `Internal dispatch handoff (do not advertise)` alongside ordinary Universal Links patterns.

![Complete Chromium view of the AASA components array](FlapCopy_Figure_08_AASA_Full_View.png)

**Figure 8: Full AASA context.** The complete body preserves the relationship between public route families, the staff-only candidate, and the operational annotation.

### 3.4 Cross-artifact consistency control

Before requesting the candidate, I compared the two route lists offline. `/today` matched `/today*`, and `/upcoming` matched `/upcoming*`. The same pattern made `/staff-only/dispatch*` a reasonable route to test, but did not prove it was live.

| Source | Observed route patterns |
| --- | --- |
| Landing page | Links the manifest but does not advertise `/staff-only/dispatch` |
| PWA manifest | `/today?compose=1`, `/today`, `/upcoming`, `/console/quick-actions` |
| AASA | `/today*`, `/upcoming*`, `/inbox*`, `/projects/*`, `/areas/*`, `/share/*`, `/staff-only/dispatch*` |
| Correlation anchors | `/today` ↔ `/today*`; `/upcoming` ↔ `/upcoming*` |
| Highest-signal candidate | `/staff-only/dispatch*`, listed only in AASA and explicitly marked internal |

> **CORRELATION CONTROL**
>
> The AASA entry remained an inference until one runtime request returned the staff-dispatch page and its build details. No suffixes or adjacent internal-looking paths were tested.

### 3.5 Request to the Disclosed Route

The wildcard pattern was reduced to its bare prefix and requested once in Caido Replay. No parameter, identity, role, or cookie value was changed.

```http
GET /staff-only/dispatch HTTP/1.1
Host: <LAB_HOST>
```

**Expected result:** a live internal route must return the expected staff-handoff content; a status code alone is insufficient.

![Caido Replay request for the metadata-disclosed staff route](FlapCopy_Figure_09_Staff_Route_Request.png)

**Figure 9: Request to the staff route.** Caido sends the one request supported by the metadata. The live host and reusable cookie are redacted, while the path and other request details stay visible.

![Caido response headers for the staff-dispatch route](FlapCopy_Figure_10_Staff_Route_Response.png)

**Figure 10: Live route response.** The candidate returns an HTML document in the current session. That confirms the route exists, but not why it matters.

![Staff-dispatch response body showing internal metadata and a redacted objective](FlapCopy_Figure_11_Staff_Route_Body.png)

**Figure 11: Staff page content.** The body identifies an iOS/staff-PWA handoff, shows `environment: production` and build details, and contains `WEBVERSE{REDACTED}`. This content turns the disclosed path into a security finding.

### 3.6 WebVerse State and Stop Point

The challenge UI was inspected separately after the target evidence was complete. It confirms account-level completion but retains the earlier solve date, so it is not used to date this reproduction.

![WebVerse Flap Copy challenge page showing the historical solved state](FlapCopy_Figure_12_Solved_State.png)

**Figure 12: Historical solved state.** WebVerse marks Flap Copy as solved and retains 7 August 2026. The fresh objective itself was recovered in Figure 11.

> **WHERE TESTING STOPPED**
>
> No additional challenge-target action was introduced after the objective-bearing response. The platform-state check is recorded separately from target interaction.

## 4. Controls and False-Positive Boundaries

| Control or boundary | Why it matters |
| --- | --- |
| Application-provided discovery | The landing source supplied `/manifest.webmanifest`; no wordlist or guessed manifest path was used. |
| Cross-artifact anchors | Known `/today` and `/upcoming` families align across the manifest and AASA. |
| AASA pattern ≠ live route | The staff entry remained a candidate until a runtime request returned the expected staff content. |
| HTTP 200 is not enough | The conclusion depends on the staff page content and redacted flag. |
| Wildcard ≠ brute-force licence | Only the exact bare prefix was requested; no suffix guessing occurred. |
| Hidden ≠ authentication bypass | Authentication state, identity, role, and cookie presence were not varied. |
| Solved UI ≠ fresh timestamp | The interface preserves the account's earlier solve date. |

## 5. Root Cause and Classification

The root cause is insertion of sensitive routing information into an externally accessible association file. The AASA file must be retrievable for Universal Links, yet this instance advertises `/staff-only/dispatch*` and labels it as an internal handoff that should not be advertised. This maps directly to [CWE-538](/cwes/cwe-538/), a Base-level CWE that MITRE permits for vulnerability mapping.

The route returned internal staff information in the observed browser session. Because the request kept an existing cookie and did not compare authenticated and unauthenticated behavior, this is not classified as an access-control or authentication-bypass issue.

## 6. Impact

In this lab, public mobile and PWA metadata reduced the search space. It revealed a staff-only route missing from normal navigation, and one request returned internal handoff, environment, and build information.

The broader lesson is simple: public association and application files can expose internal route names and hidden application areas. It becomes a security issue when those routes return information or functions that should not be available in the current context. This reproduction does not claim user-data exposure, extra privileges, or state changes.

## 7. Remediation

- Review AASA, PWA manifests, Android App Links metadata, and similar public routing artefacts before deployment.
- Remove `/staff-only/dispatch*` and its operational comment from public association metadata unless the route is genuinely required for a public deep-link flow.
- If the route must remain addressable, enforce the intended server-side authentication and authorization independently of route secrecy.
- Do not place environment, build, diagnostic, secret, or challenge-equivalent data in an internal handoff page merely because it is unlinked.
- Add deployment checks that flag newly introduced `internal`, `staff`, `admin`, `debug`, `dispatch`, or operational route patterns in externally accessible metadata.

## 8. Validation Guidance

1. Fetch the deployed PWA and AASA metadata and confirm that internal-only route patterns and operational comments are absent unless intentionally required.
2. Verify that legitimate public deep links such as `/today` and `/upcoming` still resolve after metadata cleanup.
3. Request the former internal route from the intended low-privilege context and confirm that sensitive handoff content is no longer returned.
4. If the route remains required, validate its intended authentication and authorization boundary with explicit identity/role controls rather than relying on obscurity.
5. Repeat cross-artifact route correlation to ensure no alternate public metadata artefact reintroduces the same disclosure.

## 9. Conclusion

Flap Copy shows why mobile and PWA integration files belong in web reconnaissance. The landing page linked the manifest, the manifest and AASA used matching route patterns, and that comparison revealed one internal candidate. A single request to the prefix route returned the staff page and flag.

The evidence supports a narrow, defensible conclusion: externally accessible application metadata exposed a non-advertised internal route that returned internal information in the observed session. It intentionally stops short of claiming untested authentication or privilege impact.
