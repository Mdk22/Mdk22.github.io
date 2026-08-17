---
title: "Independent curl Verification"
weight: 100
purpose: "Reproduce an HTTP claim with curl using an explicit minimal request outside the primary interception client."
evidence_boundary: "The curl request must preserve the endpoint, method, relevant body, and intentional authentication state."
proves: "That a separate HTTP client receives the same meaningful status and response body."
does_not_prove: "It does not independently establish business impact or conditions that were not included in the request."
---
