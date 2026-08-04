---
title: "Server-Side Template Injection"
weight: 170
definition: "Attacker-controlled content is compiled or evaluated as server-side template source instead of being passed to a fixed template strictly as data."
discovery_signals:
  - "Template syntax is stored raw but its evaluated result appears in the rendered response."
  - "A unique arithmetic marker changes from source syntax to a deterministic server-side value."
safe_validation: "Begin with a harmless arithmetic expression, prove evaluation rather than reflection, preserve application state, and restore any temporary content immediately."
---
