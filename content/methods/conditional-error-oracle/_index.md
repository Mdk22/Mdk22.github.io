---
title: "Conditional Error Oracle"
weight: 180
purpose: "Convert a Boolean SQL predicate into a repeatable application success-or-error signal."
evidence_boundary: "Only the tested predicates and stable response mapping are established."
proves: "That attacker-controlled SQL logic can influence whether the backend query completes or raises an error."
does_not_prove: "It does not by itself prove the contents of a table or the correctness of an extracted value."
---
