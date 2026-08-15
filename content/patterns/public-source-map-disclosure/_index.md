---
title: "Public Source Map Disclosure"
weight: 75
definition: "A production JavaScript source map is publicly retrievable and exposes embedded original source or security-relevant implementation contracts."
discovery_signals:
  - "A first-party bundle publishes a sourceMappingURL directive."
  - "The referenced map contains sources and sourcesContent rather than an HTML fallback."
safe_validation: "Follow only the application-provided map locator, validate the source-map structure, and treat any recovered route as discovery evidence until one bounded runtime request confirms it."
---
