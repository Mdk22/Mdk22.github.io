# Mdk22 write-up process

## 1. Intake

Use the complete candidate folder as the source:

- detailed Obsidian document;
- chronological chat transcript;
- Caido/Burp screenshots;
- Terminal/CLI screenshots;
- browser, Interact, DevTools, or solved-state screenshots;
- scripts and other artifacts created during the run.

A Word document can help with orientation, but it is not treated as proof by itself.

## 2. Evidence map

Create a private case manifest from `docs/templates/CASE_EVIDENCE_MANIFEST.template.yaml`. Keep it in the candidate folder, not in the public article bundle.

Map each useful screenshot to the request, command, payload, result, claim, and redaction decision it supports. Mark duplicate images and gaps before writing.

## 3. Technical review

Check every claim against the supplied request, response, command output, browser result, or solved state. Keep negative results narrow and do not infer frameworks, database behavior, privileges, or impact that the evidence does not confirm.

## 4. Story pass

Write a five-line story spine before drafting:

1. Starting point.
2. First useful signal.
3. Important comparison or failed attempt.
4. Proof that completed the chain.
5. The detail that makes this case different.

Use the structure in `docs/WRITEUP_BASELINE.md`, but change the pacing and optional headings when the evidence calls for it.

## 5. Reproduction pass

Keep the real chronological order. Pair every published step with the material needed to understand it:

- the check being performed;
- raw HTTP request or body when Caido/Burp was used;
- matching screenshot;
- observed response and meaning;
- matching curl command when Terminal/CLI was used;
- terminal output screenshot when one exists.

Use a request/response composite when it is easier to read than two disconnected images. Keep useful flags in screenshots after pixel-precise redaction instead of deleting the evidence.

## 6. Editorial pass

Use `docs/AUTHOR_VOICE.md`. Remove repeated explanations, stock phrases, and report-style filler. Keep the author's wording and technical reasoning.

## 7. Publication gate

Run:

```powershell
pwsh -File ./scripts/Test-WriteupPublication.ps1
hugo --gc --minify --environment production --baseURL "https://mdk22.github.io/"
pwsh -File ./scripts/Test-RenderedSite.ps1 -SiteRoot ./public
git diff --check
```

Open localhost and inspect the page, code-copy buttons, long commands, lightbox, captions, mobile width, homepage card, archive count, and intelligence links.

## 8. Approval and publication

Do not commit or push until the user explicitly approves the visual result. Before committing, run the audit again with `-CheckStaged`. After the push, wait for GitHub Pages and verify the LIVE article, featured card, links, images, copy buttons, and redactions.
