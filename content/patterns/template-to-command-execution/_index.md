---
title: "Template-to-Command Execution"
weight: 180
definition: "A server-side template injection reaches a callable operating-system primitive and returns dynamic command output."
discovery_signals:
  - "A template-callable function runs a harmless operating-system command with a predictable result."
  - "The response contains command-generated output that was absent from the stored template source."
safe_validation: "Use a harmless command with a predictable result, avoid shells or persistence, limit any file check to the authorized objective, and stop once the impact is confirmed."
---
