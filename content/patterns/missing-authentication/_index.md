---
title: "Missing Authentication"
weight: 80
definition: "A critical function is available without first establishing an authenticated user identity."
discovery_signals:
  - "Client route metadata marks a privileged path with no guard."
  - "The function returns privileged content when authentication headers are suppressed."
safe_validation: "Send a read-only request with Cookie and Authorization explicitly absent and stop after confirming the protected function."
---
