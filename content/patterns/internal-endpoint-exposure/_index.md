---
title: "Internal Endpoint Exposure"
weight: 70
definition: "An endpoint described or intended as internal is reachable from the public application boundary."
discovery_signals:
  - "Public source or documentation names an internal route."
  - "An anonymous request receives the endpoint's genuine response rather than an access denial."
safe_validation: "Follow only the disclosed route with a read-only anonymous request and confirm identity from minimal response markers."
---
