---
title: "Production Comment Disclosure"
weight: 90
definition: "Production markup retains an operational comment that discloses sensitive implementation or routing information."
discovery_signals:
  - "HTML comments mention deployment notes, internal routes, or environment assumptions."
  - "The disclosed detail maps to a resource on the same active instance."
safe_validation: "Inspect public source and follow only directly disclosed, in-scope references using read-only requests."
---
