---
title: "Serialized Object Inspection"
weight: 214
purpose: "Decode an application-generated object file locally and identify its classes, properties, values, and serialized string lengths before changing it."
evidence_boundary: "The result describes the captured object format. Runtime behavior still needs its own before-and-after proof."
proves: "Which object classes and properties are present in the exported data and whether a controlled mutation preserves valid serialization."
does_not_prove: "It does not by itself prove that the server accepts the object or runs a magic method."
---
