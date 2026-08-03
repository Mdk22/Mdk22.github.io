---
title: "SQL Injection"
weight: 150
definition: "Untrusted input reaches a database query as executable SQL structure instead of remaining a bound data value."
discovery_signals:
  - "A quote changes the response while benign unknown input follows the normal application path."
  - "SQL structural probes produce repeatable, database-consistent response differences."
safe_validation: "Use the smallest controlled differential that proves query influence, avoid destructive statements, and disclose only redacted values from authorized targets."
---
