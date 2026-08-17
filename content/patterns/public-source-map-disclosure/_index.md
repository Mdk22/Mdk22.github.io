---
title: "Public Source Map Disclosure"
weight: 75
definition: "A production JavaScript source map is publicly retrievable and exposes embedded original source or security-relevant implementation contracts."
discovery_signals:
  - "A first-party bundle publishes a sourceMappingURL directive."
  - "The referenced map contains sources and sourcesContent rather than an HTML fallback."
safe_validation: "Follow the map path provided by the application, check that it is a real source map, and treat recovered routes as leads until a direct request confirms them."
---
