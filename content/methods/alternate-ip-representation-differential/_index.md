---
title: "Alternate IP Representation Differential"
weight: 118
purpose: "Keep the destination fixed while changing only how the IP address is written."
evidence_boundary: "The scheme, port, path, request body, and account state stay the same. Only the host representation changes."
proves: "A different response shows that validation and destination resolution handle equivalent address forms differently."
does_not_prove: "It does not show access to other hosts, address ranges, ports, or protocols that were not tested."
---
