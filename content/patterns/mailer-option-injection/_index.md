---
title: "Mailer Option Injection"
weight: 140
definition: "A mail form passes user-controlled address text into mailer arguments, letting it change options rather than remain an address."
discovery_signals:
  - "The form accepts an address with whitespace and option-shaped text."
  - "A new mailer artefact appears only after a request carrying that text."
  - "The artefact shows the mailer's own output, not just reflected form data."
safe_validation: "Use a unique file name and check it is absent first. Confirm each change with a readback and stop after the needed effect is proven."
---
