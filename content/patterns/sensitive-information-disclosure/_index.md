---
title: "Sensitive Information Disclosure"
weight: 140
definition: "A public response reveals operational information beyond what the intended audience should receive."
discovery_signals:
  - "Anonymous responses include internal metadata, identifiers, or restricted status data."
  - "The disclosed information is tied to the active application instance."
safe_validation: "Use a single anonymous read-only request, record only necessary fields, and redact flags, tokens, and reusable secrets."
---
