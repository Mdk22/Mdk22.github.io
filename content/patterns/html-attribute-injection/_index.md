---
title: "HTML Attribute Injection"
weight: 60
definition: "Untrusted input escapes an existing HTML attribute value and creates attacker-controlled attributes on the rendered element."
discovery_signals:
  - "A quotation mark terminates a reflected quoted attribute value."
  - "A harmless data attribute appears in the parsed DOM."
safe_validation: "Use a non-executing data-* canary to confirm the DOM structure before a small browser-side test."
---
