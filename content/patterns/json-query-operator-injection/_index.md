---
title: "JSON Query Operator Injection"
weight: 175
definition: "A JSON API accepts query operators or object-shaped filter values where the public client is expected to send simple data values."
discovery_signals:
  - "Replacing a string with a structured operator object changes which records are returned."
  - "Normal values, impossible values, and operator objects produce repeatable differences on the same endpoint."
safe_validation: "Start with normal and empty-result controls, change one field at a time, combine fields only when earlier results justify it, and stop after the authorised objective is confirmed."
---
