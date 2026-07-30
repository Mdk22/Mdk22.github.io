---
title: "Security Misconfiguration"
weight: 120
definition: "A deployment or server configuration exposes resources or behavior that the documented security boundary did not intend."
discovery_signals:
  - "Directory listing or default server behavior reveals deployment residue."
  - "Production resources conflict with removal or access expectations in deployment notes."
safe_validation: "Confirm the specific exposed behavior with minimal read-only requests and avoid inferring unrelated configuration weaknesses."
---
