---
title: "Stored XSS"
weight: 42
definition: "User-controlled content is stored and later runs as script when another browser renders it."
discovery_signals:
  - "A public submission is later shown in an authenticated review page."
  - "A callback reports the protected page path and title after the stored item is viewed."
safe_validation: "Start with a small callback that reports only the page context. Do not take cookies or reusable credentials."
---
