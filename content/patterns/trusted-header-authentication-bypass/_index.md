---
title: "Trusted Header Authentication Bypass"
weight: 63
definition: "A backend trusts a client-reachable identity header that should only be set by an authenticated gateway or reverse proxy."
discovery_signals:
  - "The normal request is denied because no gateway identity is present."
  - "Source or configuration names the trusted identity header and accepted principal."
  - "Adding only that header changes the same request from denied to authorized."
safe_validation: "Keep the method, route, and request state fixed, add one source-derived identity header, and stop after the protected read-only response is confirmed."
---
