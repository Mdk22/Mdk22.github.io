---
title: "Server-Side Request Forgery"
weight: 46
definition: "User-controlled input changes where the application server sends an outbound request."
discovery_signals:
  - "The application fetches a URL supplied by the user."
  - "Equivalent host forms receive different allow or block decisions."
  - "The response exposes remote content or connection details."
safe_validation: "Start with the application's normal fetch flow, compare one blocked destination with an equivalent representation, and stop when the requested objective is proved."
---
