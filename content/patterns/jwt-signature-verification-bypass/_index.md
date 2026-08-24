---
title: "JWT Signature Verification Bypass"
weight: 95
definition: "A server accepts JWT claims without requiring a valid signature, allowing a client to alter trusted identity or authorization data."
discovery_signals:
  - "A signed lower-privilege JWT is rejected by a protected route, while an unsigned token with changed claims reaches it."
  - "A token using alg none and an empty signature is accepted as an authenticated session."
safe_validation: "Keep the original session as a control, change only the minimum authorization claim, test one protected read-only route, and redact both token values from public evidence."
---
