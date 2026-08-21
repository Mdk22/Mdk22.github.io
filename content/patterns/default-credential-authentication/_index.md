---
title: "Default Credential Authentication"
weight: 145
definition: "A login surface accepts a documented or predictable default credential and grants access that should require a deployment-specific secret."
discovery_signals:
  - "The interface or briefing says the administrator password was never changed."
  - "An invalid control is rejected while a known default value reaches an authenticated route."
safe_validation: "Record the normal login contract, send one invalid control, change only the credential value, and stop after the first verified authenticated result."
---
