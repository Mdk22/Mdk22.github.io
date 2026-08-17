---
title: "WebVerse Routing Slip: Public OpenAPI Contract to Unauthenticated Internal Operation"
date: 2026-08-13T00:00:00+02:00
lastmod: 2026-08-13T00:00:00+02:00
draft: false
author: "Mdk22"
description: "A public OpenAPI contract exposed a local authentication override on an internal liveness operation, which returned runtime metadata without credentials."
summary: "Routing Slip's developer portal linked the live OpenAPI file. Bearer authentication was required globally, but one internal read-only operation declared `security: []`. A single browser request then returned runtime data without authentication."
categories:
  - "Web Security Write-Ups"
tags:
  - "WebVerse"
  - "Routing Slip"
  - "OpenAPI"
  - "API Security"
  - "Missing Authentication"
  - "Internal Endpoint Exposure"
  - "Sensitive Information Disclosure"
  - "CWE-306"
  - "CWE-200"
platform: "WebVerse"
lab: "Routing Slip"
difficulty: "Unspecified"
showToc: true
TocOpen: false
case_id: "CASE-011"
case_featured: false
case_summary_short: "A public OpenAPI auth override exposed an unauthenticated internal liveness operation and sensitive runtime metadata."
case_status: "VERIFIED / PREVIOUSLY SOLVED"
case_classification: "Missing Authentication / Sensitive Information Disclosure"
case_family: "access-exposure"
case_evidence:
  - "Browser"
  - "OpenAPI contract"
case_verified: true
case_caido: false
case_independent_curl: false
primary_cwe: "CWE-306"
cwes:
  - "CWE-306"
  - "CWE-200"
patterns:
  - "Missing Authentication"
  - "Internal Endpoint Exposure"
  - "Sensitive Information Disclosure"
methods:
  - "Disclosed Route Follow-Up"
  - "Browser Runtime Validation"
---

> **Publication note:** This article documents a fresh reproduction in an authorised WebVerse educational lab. The instance hostname, dynamic runtime values, and objective value are excluded. The documented lab route `/_ops/echo` is retained because it is required to preserve the public evidence chain. The public objective representation is `WEBVERSE{REDACTED}`.

## Executive Summary

Routing Slip exposed public developer documentation with a link to its OpenAPI file. The file required Bearer authentication by default, but one internal liveness operation used `security: []`. In OpenAPI, that operation-level setting overrides the global requirement.

One unauthenticated, read-only browser request to the documented operation returned JSON runtime metadata and the current WebVerse objective. No route guessing, fuzzing, credentials, scanner, payload mutation, or write action was required.

> **CONFIRMED FINDING**
>
> A public OpenAPI contract disclosed an internal operational GET function with an explicit authentication override. The deployed operation was reachable without credentials and returned sensitive runtime metadata.

## 1. Report Profile

| Field | Verified value |
| --- | --- |
| Platform | WebVerse |
| Lab | Routing Slip |
| Status | Fresh runtime reproduction verified; challenge had previously been solved |
| Evidence | Fresh browser evidence and the linked OpenAPI contract |
| Primary weakness | [CWE-306](/cwes/cwe-306/): Missing Authentication for Critical Function |
| Supporting weakness | [CWE-200](/cwes/cwe-200/): Exposure of Sensitive Information to an Unauthorized Actor |
| curl reproduction | Not performed |
| Write actions / state mutation | None |
| Requests after objective hit | 0 target requests |

### Verified Attack Chain

```text
Normal dashboard visit
  > Visible Developers and API-reference entry points
Public developer documentation
  > Linked current OpenAPI contract
OpenAPI contract
  > Global BearerAuth baseline
Documented internal GET operation
  > Local security: [] override and runtime-metadata response contract
One unauthenticated browser GET
  > JSON runtime metadata plus WEBVERSE{REDACTED}
Stop
  > No further target requests
```

## 2. Scope and Evidence Boundary

The reproduction was intentionally limited to the known, documentation-led solution path on a fresh authorised lab instance.

- I followed the dashboard, developer documentation, OpenAPI file, and live endpoint in that order.
- The internal operation was requested once, without an `Authorization` header, Cookie, body, query parameter, credential, or payload mutation.
- No route fuzzing, scanner, credential guessing, customer-data probing, webhook registration, or other write endpoint was used.
- The first response containing the objective ended target interaction.
- The available solved-state image is historical platform state. It is not used to claim a fresh submission or fresh platform acceptance.

The evidence covers one documented operation that responds without authentication. I did not test customer shipments, cross-tenant data, writes, account takeover, SSRF, SQL injection, RCE, or the rest of the API.

## 3. Step-by-Step Reproduction

### 3.1 Legitimate Baseline and Developer Entry Point

The fresh instance loaded without authentication and displayed a **Developers** link plus an API reference in the footer. The documentation route came directly from the application and did not need to be guessed.

![Fresh unauthenticated Routing Slip dashboard with visible Developers and API reference navigation](RoutingSlip_Figure_01_Baseline.png)

**Figure 1: Legitimate baseline.** The visible application UI exposes the developer and API-reference entry points. This is discovery context, not vulnerability evidence; the hostname and region are redacted.

### 3.2 Public Developer Documentation

The **Developers** link opened public documentation. It described Bearer authentication for customer-data endpoints and linked `openapi.json`. The page itself is not a vulnerability; it simply explains where the API description came from. I did not run its example curl command.

![Public Routing Slip developer portal with Bearer-authentication guidance and the visible openapi.json contract link](RoutingSlip_Figure_02_Developer_Portal.png)

**Figure 2: Public developer portal.** The application itself provides the documentation route, shows the intended Bearer-authentication model, and directly links the live `openapi.json` contract. The live browser origin and region are excluded; the documentation's static `.example` API reference and token variable are retained because they explain the public contract without disclosing a credential.

**R-01: developer documentation URL model.**

```text
<LAB_ORIGIN>/api/docs
```

Expected result: public developer documentation containing a direct link to the current API contract.

### 3.3 Global Bearer Authentication Baseline

The linked OpenAPI 3.0.3 contract defined `BearerAuth` globally. The scheme is HTTP Bearer with JWT-format tokens, so this is the default authentication policy inherited by operations unless an operation defines its own security requirement.

**R-02: public contract URL model.**

```text
<LAB_ORIGIN>/api/docs/openapi.json
```

```json
"security": [
  { "BearerAuth": [] }
],
"securitySchemes": {
  "BearerAuth": {
    "type": "http",
    "scheme": "bearer",
    "bearerFormat": "JWT"
  }
}
```

![Focused OpenAPI contract excerpt showing the global BearerAuth requirement and HTTP bearer scheme](RoutingSlip_Figure_02_Global_BearerAuth.png)

**Figure 3: Global authentication.** The OpenAPI file requires Bearer authentication by default. The next operation is important because it overrides this setting.

### 3.4 Local Authentication Override on an Internal Operation

The same contract documented an internal liveness GET operation with `security: []` and a `200` response described as runtime metadata. In OpenAPI, this empty operation-level requirement is the key difference: it overrides the global Bearer baseline for that operation. The **Internal** label alone would not prove a security issue; the authentication exception and later runtime result do.

```json
"/_ops/echo": {
  "get": {
    "summary": "Operational liveness probe. Echoes runtime metadata. Internal use only.",
    "tags": ["Internal"],
    "security": [],
    "responses": {
      "200": { "description": "Runtime metadata." }
    }
  }
}
```

![Focused OpenAPI excerpt showing the internal operation, empty security array, and runtime metadata response](RoutingSlip_Figure_03_Local_Override.png)

**Figure 4: Operation-level override.** The empty `security` array removes authentication from `/_ops/echo`. The path remains visible for the next request, while the temporary origin is withheld.

### 3.5 One Unauthenticated Request

The exact documented operation was then opened once in the browser without credentials or input mutation. This is a normalised public representation of the browser request: the documented route is retained, while the live origin is withheld.

**R-03: normalised browser request.**

```http
GET /_ops/echo HTTP/1.1
Host: <LAB_HOST>
```

Expected result: JSON runtime metadata without Bearer authentication. No payload is required.

```json
{
  "service": "routing-slip",
  "version": "2.7.1",
  "node": "<REDACTED>",
  "uptime_s": "<REDACTED>",
  "flag": "WEBVERSE{REDACTED}"
}
```

![Sanitized browser response showing runtime metadata and the redacted WebVerse objective](RoutingSlip_Figure_04_Runtime_Proof.png)

**Figure 5: Runtime proof.** The documented `/_ops/echo` operation returned operational metadata and the current objective without credentials. The hostname, node value, uptime, and literal objective are redacted.

## 4. Runtime Check and False-Positive Controls

| Claim | Evidence | Not enough on its own |
| --- | --- | --- |
| Developer route was legitimate | Visible application navigation and public developer portal | A guessed documentation path |
| OpenAPI was the public contract | The portal directly linked the JSON contract | Assuming a conventional `/openapi.json` route |
| Bearer authentication was global | Fresh contract `security` and `BearerAuth` scheme | Documentation prose alone |
| The internal operation had an auth exception | Operation-level `security: []` | The **Internal** tag alone |
| The operation was unauthenticated at runtime | One fresh browser GET returned JSON without credentials | Source-only inference or an HTTP status alone |
| Sensitive effect was present | Runtime metadata and `WEBVERSE{REDACTED}` | A generic health banner |

The public OpenAPI document is a discovery amplifier, not the vulnerability by itself. The finding requires both a documented authentication exception and the current unauthenticated runtime effect.

## 5. Final Result and Historical Completion State

Fresh-instance evidence verifies a public contract, a global Bearer baseline, a local empty-security override on an internal GET operation, and an unauthenticated runtime response containing sensitive metadata. The first objective-containing response ended the reproduction.

The WebVerse challenge had already been marked solved before this fresh evidence session. The available platform image is therefore retained as historical context only, not as proof of fresh objective submission.

![Historical WebVerse solved state for Routing Slip](RoutingSlip_Figure_05_Historical_Solved.png)

**Figure 6: Historical solved state only.** This confirms previous platform completion but makes no fresh-submission claim.

## 6. Root Cause and Classification

The root cause is public exposure of an internal operational function without authentication, combined with a response contract that returns more information than a minimal public health check needs. Publishing the operation and its `security: []` exception in the public contract makes the exposure directly discoverable.

| Classification | Assessment | Evidence basis |
| --- | --- | --- |
| Primary | [CWE-306](/cwes/cwe-306/): Missing Authentication for Critical Function | An internal operation is reachable without authentication. |
| Secondary | [CWE-200](/cwes/cwe-200/): Exposure of Sensitive Information to an Unauthorized Actor | The unauthenticated response includes runtime metadata and objective material. |
| Severity | Not assigned | The supplied evidence proves the weakness and disclosure, but provides no external severity rubric. |

## 7. Impact and Evidence Limits

Confirmed impact is unauthenticated disclosure from an internal operational endpoint. In a real deployment, analogous metadata can reveal build versions, deployment identifiers, topology hints, dependency state, or debug material; severity depends on the actual response and trust boundary.

No evidence supports claims of customer shipment exposure, cross-tenant access, privileged writes, account takeover, remote code execution, SQL injection, SSRF, or a broader break in the API's authentication model.

## 8. Remediation and Validation Guidance

- Remove internal operational functions from the public origin. Use a private management plane, restricted network boundary, mTLS/service identity, or an authenticated administrative interface.
- If a public health endpoint is necessary, return only an allowlisted minimal response such as `{"status":"ok"}`; exclude runtime, build, configuration, and debug values.
- Publish a customer/partner OpenAPI contract containing only intended public operations. Keep internal management operations in a separate protected contract.
- Treat public-contract `security: []` declarations as policy exceptions requiring explicit review and approval in CI.
- Add deployment regression tests that compare public routing to an approved allowlist and ensure internal operations return `401`/`403` or remain network-inaccessible.

A remediation is effective when internal operations are absent from public API documentation, unauthenticated public requests cannot reach them, intentional public health responses match a minimal allowlisted schema, and release review explicitly approves every authentication exception.

## Conclusion

Routing Slip shows a simple documentation-led API issue. Public docs linked the OpenAPI file, the file showed an authentication exception on an internal operation, and one unauthenticated `GET` returned sensitive runtime data. The finding is limited to that read-only path; no wider API capability was tested.
