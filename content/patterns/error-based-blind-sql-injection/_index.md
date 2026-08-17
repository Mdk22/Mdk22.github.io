---
title: "Error-Based Blind SQL Injection"
weight: 160
definition: "An injected SQL predicate is converted into an observable error-versus-success response even though query output is not directly returned."
discovery_signals:
  - "Logically true and false predicates consistently map to different HTTP outcomes."
  - "A deliberate database error can be conditionally triggered without exposing raw SQL errors."
safe_validation: "Confirm the oracle repeatedly with harmless predicates, extract only the value needed for proof, and stop as soon as that proof is complete."
---
