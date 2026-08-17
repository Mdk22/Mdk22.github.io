---
title: "Weak Password Storage"
weight: 190
definition: "Stored password verification data uses a fast or insufficiently costly scheme that makes offline guessing inexpensive after disclosure."
discovery_signals:
  - "A general-purpose digest is used directly as a password representation."
  - "An offline candidate test recovers a weak password with minimal effort."
safe_validation: "Test only lawfully obtained authorized-lab material offline, never publish the recovered secret, and verify authentication separately before claiming account access."
---
