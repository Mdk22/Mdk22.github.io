---
title: "ORDER BY Projection Differential"
weight: 170
purpose: "Compare adjacent ORDER BY positions to infer the number of columns in the injectable query projection."
evidence_boundary: "The inference applies to the tested query branch and response differential."
proves: "That one tested column position is valid while the next produces a repeatable database-dependent failure."
does_not_prove: "It does not alone identify table names, column types, privileges, or retrievable data."
---
