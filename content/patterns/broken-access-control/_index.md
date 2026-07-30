---
title: "Broken Access Control"
weight: 20
definition: "A server-side authorization boundary does not prevent an unauthorized client from reaching protected data or functionality."
discovery_signals:
  - "Restricted routes respond successfully without the expected authorization context."
  - "Publicly disclosed resources lead to functions intended for a narrower audience."
safe_validation: "Use a minimal anonymous or lower-privilege request and compare it with the documented access expectation without modifying protected state."
---
