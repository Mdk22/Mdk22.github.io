---
title: "Context-Specific Output Encoding Failure"
weight: 40
definition: "Attacker-controlled data is emitted without the encoding required by its exact HTML output context."
discovery_signals:
  - "The same input is encoded differently across text and attribute sinks."
  - "A context delimiter survives reflection and changes document structure."
safe_validation: "Map each sink separately and begin with harmless delimiter and canary payloads before any controlled runtime proof."
---
