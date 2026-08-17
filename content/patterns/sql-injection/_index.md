---
title: "SQL Injection"
weight: 150
definition: "Untrusted input reaches a database query as executable SQL structure instead of remaining a bound data value."
discovery_signals:
  - "A quote changes the response while benign unknown input follows the normal application path."
  - "SQL structural probes produce repeatable, database-consistent response differences."
safe_validation: "Change one value at a time, confirm query influence with harmless input, avoid destructive statements, and publish only redacted values from authorized targets."
---
