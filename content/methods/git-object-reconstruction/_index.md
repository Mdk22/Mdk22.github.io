---
title: "Git Object Reconstruction"
weight: 82
purpose: "Follow exposed Git references through commit, tree, and blob objects while verifying each downloaded object locally."
evidence_boundary: "Only object IDs returned by the exposed repository chain are requested. Local decompression and SHA-1 checks bind each decoded result to the downloaded object."
proves: "That the public service exposed the recorded Git objects and that the decoded commit, tree, or source blob matches its object ID."
does_not_prove: "It does not prove that every repository object is public, that the recovered source matches another deployment, or that source-level behavior is reachable at runtime."
---
