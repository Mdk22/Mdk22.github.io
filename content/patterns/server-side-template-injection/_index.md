---
title: "Server-Side Template Injection"
weight: 170
definition: "Attacker-controlled content is compiled or evaluated as server-side template source instead of being passed to a fixed template strictly as data."
discovery_signals:
  - "Template syntax is stored raw but its evaluated result appears in the rendered response."
  - "A unique arithmetic expression returns the calculated server-side value instead of its original source text."
safe_validation: "Begin with a harmless arithmetic expression, prove evaluation rather than reflection, preserve application state, and restore any temporary content immediately."
---
