---
title: "Template-to-Command Execution"
weight: 180
definition: "A server-side template injection reaches a callable operating-system primitive and returns dynamic command output."
discovery_signals:
  - "A template-callable function invokes a deterministic, non-destructive operating-system command."
  - "The response contains command-generated output that was absent from the stored template source."
safe_validation: "Use a harmless deterministic command, avoid shells or persistence, constrain any follow-up file access, and stop when the authorized impact is proven."
---
