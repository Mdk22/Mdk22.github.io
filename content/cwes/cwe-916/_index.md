---
title: "CWE-916"
weight: 916
cwe_id: "CWE-916"
cwe_name: "Use of Password Hash With Insufficient Computational Effort"
classification_family: "Credentials and Password Storage"
source_authority: "MITRE Common Weakness Enumeration"
mitre_url: "https://cwe.mitre.org/data/definitions/916.html"
---

Within this archive, CWE-916 is used where password verification relies on a fast general-purpose digest or another scheme that does not impose an adequate cost on offline guesses. Digest shape alone does not establish the algorithm; a controlled candidate match or equivalent evidence is required.
