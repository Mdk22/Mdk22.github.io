---
title: "Sensitive Configuration Disclosure"
weight: 130
definition: "A publicly reachable artifact reveals configuration values or operational secrets that should remain outside the public boundary."
discovery_signals:
  - "Backup configuration files are served as source text."
  - "The exposed values map to live application components or consumers."
safe_validation: "Capture only the minimum evidence, redact secret values, and verify relevance without publishing reusable credentials."
---
