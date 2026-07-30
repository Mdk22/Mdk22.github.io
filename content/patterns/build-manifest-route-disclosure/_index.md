---
title: "Build Manifest Route Disclosure"
weight: 30
definition: "A public client build manifest exposes routes or chunks that reveal otherwise undisclosed application structure."
discovery_signals:
  - "Framework manifests enumerate routes not present in visible navigation."
  - "Dedicated client chunks contain route names or access-control metadata."
safe_validation: "Inspect already-public build assets, then validate only specifically disclosed routes with read-only requests."
---
