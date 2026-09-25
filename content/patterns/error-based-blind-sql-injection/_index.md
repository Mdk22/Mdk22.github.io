---
title: "Error-Based Blind SQL Injection"
weight: 160
definition: "An injected SQL predicate is converted into an observable error-versus-success response even though query output is not directly returned."
discovery_signals:
  - "Logically true and false predicates consistently map to different HTTP outcomes."
  - "A chosen database error can be triggered only when the tested condition is true, without exposing raw SQL errors."
safe_validation: "Confirm the oracle repeatedly with harmless predicates, extract only the value needed for proof, and stop as soon as that proof is complete."
---
