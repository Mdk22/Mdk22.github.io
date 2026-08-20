---
title: "Path Traversal"
weight: 47
definition: "User-controlled path elements let a file operation reach outside the directory intended by the application."
discovery_signals:
  - "A public file feature accepts a filename or path from the request."
  - "Dot-relative input still returns a known file."
  - "A parent-directory value returns known content from outside the normal file area."
safe_validation: "Map the normal file flow first, record a missing-file control, then compare one harmless known file through its normal route and through the file handler."
---
