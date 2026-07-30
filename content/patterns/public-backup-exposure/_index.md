---
title: "Public Backup Exposure"
weight: 100
definition: "Backup or migration artifacts remain retrievable from a publicly reachable web path."
discovery_signals:
  - "Directory indexes expose backup-style extensions or migration folders."
  - "Deployment notes describe residual files that were meant to be removed."
safe_validation: "Review only confirmed public artifacts needed to establish sensitivity and avoid broad collection or publication of secrets."
---
