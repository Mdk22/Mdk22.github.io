---
title: "Hard-Coded Credential Exposure"
weight: 50
definition: "A deployed artifact exposes a fixed credential or secret that is still accepted by its intended consumer."
discovery_signals:
  - "Configuration backups contain credential-like constants or keys."
  - "Application code identifies the endpoint or field that consumes the value."
safe_validation: "Keep the value private and use a single invalid-versus-valid comparison against the mapped consumer without expanding access."
---
