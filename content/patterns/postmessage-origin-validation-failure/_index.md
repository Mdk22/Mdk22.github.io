---
title: "postMessage Origin Validation Failure"
weight: 49
definition: "A message receiver accepts data from an untrusted browser origin or window because it does not validate event.origin and event.source."
discovery_signals:
  - "Client code registers a message event listener."
  - "The handler uses event.data without an exact origin and source check."
  - "Received data reaches an HTML or script-capable DOM sink."
safe_validation: "Use a controlled sender page, a harmless marker, and a small browser-side effect. Stop when the receiver and sink are confirmed."
---
