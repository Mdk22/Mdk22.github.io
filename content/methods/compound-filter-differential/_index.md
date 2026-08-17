---
title: "Compound Filter Differential"
weight: 109
purpose: "Combine a small number of already-tested policy fields when their individual results show that the target record may require more than one state change."
evidence_boundary: "Use only fields supported by earlier single-field results, make one planned combined request, and avoid broad operator or field combinations."
proves: "That the selected fields jointly change the returned record set under the tested conditions."
does_not_prove: "It does not reveal the backend merge order, close unrelated field combinations, or justify a combinatorial search."
---
