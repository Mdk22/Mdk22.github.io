---
title: "Dangerous File Upload"
weight: 44
definition: "An upload accepts a filename or file type that the web server can later execute or interpret unsafely."
discovery_signals:
  - "The upload directory is public and executable extensions are not handled consistently."
  - "A static multi-extension control and an executable-extension test produce different responses."
safe_validation: "Use a small fixed proof reader, compare storage with execution, and stop after the first confirmed result."
---
