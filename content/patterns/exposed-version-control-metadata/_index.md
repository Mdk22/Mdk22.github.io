---
title: "Exposed Version-Control Metadata"
weight: 62
definition: "A deployed web root exposes repository metadata or object files that allow public recovery of source code or deployment history."
discovery_signals:
  - "A request to /.git/HEAD returns a branch reference."
  - "The referenced branch and loose Git objects are publicly readable."
  - "Recovered commit, tree, or blob objects contain server-side source or deployment details."
safe_validation: "Follow only the object IDs derived from the exposed repository data, verify each object locally, and stop after the source needed for the tested claim is recovered."
---
