---
title: "JSON Shape Differential"
weight: 108
purpose: "Compare a normal JSON value with an object or array in the same field to see whether the server enforces the client's expected input shape."
evidence_boundary: "Keep the endpoint and other request conditions unchanged, and compare the returned record set rather than relying only on HTTP status."
proves: "That changing the JSON value type affects server-side processing when the response difference is repeatable."
does_not_prove: "It does not identify the database, framework, query builder, or source implementation by itself."
---
