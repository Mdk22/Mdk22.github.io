---
title: "Attribute Canary"
weight: 20
purpose: "Use an inert custom attribute to test whether reflected input can alter parsed HTML element structure."
evidence_boundary: "The canary demonstrates DOM attribute control at the tested sink only."
proves: "That input escaped the original attribute value and created a new attacker-controlled attribute."
does_not_prove: "It does not by itself demonstrate JavaScript execution or impact beyond that element."
---
