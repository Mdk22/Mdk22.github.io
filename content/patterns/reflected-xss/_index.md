---
title: "Reflected XSS"
weight: 110
definition: "Request-controlled input is reflected into a generated page in a form that enables browser-side script execution."
discovery_signals:
  - "A query value appears in one or more HTML response contexts."
  - "Delimiter and canary tests show control of executable DOM structure."
safe_validation: "Progress from inert reflection markers to a minimal local execution proof with no data access or external callback."
---
