---
title: "PHP Object Injection"
weight: 58
definition: "Untrusted PHP serialized data rebuilds application objects whose properties or magic methods can perform an unintended action."
discovery_signals:
  - "A portable application file decodes to PHP object serialization syntax."
  - "Changing a nested object property changes a server-side file, query, or other sensitive operation during unserialization or object destruction."
safe_validation: "Start from the application's own export, change only the needed object properties, record a negative control, and stop after the first confirmed result."
---
