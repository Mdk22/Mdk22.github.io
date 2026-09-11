# Mdk22 Security Write-Ups

This repository contains write-ups from authorised web security labs and training environments.

Each case follows the same publication system for metadata, redaction, navigation, and local QA. The technical story is written from the evidence available for that specific lab, so the structure can change when the investigation calls for it.

## Local checks

Run the publication audit before the Hugo build:

```powershell
pwsh -File ./scripts/Test-WriteupPublication.ps1
hugo --gc --minify
pwsh -File ./scripts/Test-RenderedSite.ps1 -SiteRoot ./public
```

Use `-CheckStaged` before a commit to catch source documents or internal working files that must not enter the public repository:

```powershell
pwsh -File ./scripts/Test-WriteupPublication.ps1 -CheckStaged
```

The public site is built by GitHub Actions after an approved commit reaches `main`. Passing the automated checks does not replace the local browser review or the final LIVE verification.
