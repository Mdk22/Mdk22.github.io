---
title: "Public Metadata Route Disclosure"
weight: 65
definition: "Public application metadata exposes an internal or otherwise unadvertised route together with enough context to prioritise bounded validation."
discovery_signals:
  - "A PWA manifest, AASA file, application-link declaration, or similar public artefact names non-navigation routes."
  - "An operational comment or route family distinguishes an internal candidate from ordinary public links."
safe_validation: "Correlate the disclosed route with known public route families, then issue only the smallest read-only request needed to determine whether the exact candidate is live."
---
