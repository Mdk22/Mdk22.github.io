---
title: "CWE-347"
weight: 347
cwe_id: "CWE-347"
cwe_name: "Improper Verification of Cryptographic Signature"
classification_family: "Authentication and Integrity Verification"
source_authority: "MITRE Common Weakness Enumeration"
mitre_url: "https://cwe.mitre.org/data/definitions/347.html"
---

Within this archive, CWE-347 is used when a signed value is accepted without a valid cryptographic signature. Changing JWT claims is not enough by itself. The changed token must pass the server boundary that rejected the original lower-privilege session.
