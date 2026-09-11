[CmdletBinding()]
param(
    [switch]$Ci,
    [switch]$CheckStaged,
    [switch]$Quick
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$errors = [System.Collections.Generic.List[string]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()

function Add-AuditError {
    param([string]$Message)
    $script:errors.Add($Message)
}

function Add-AuditWarning {
    param([string]$Message)
    $script:warnings.Add($Message)
}

function Get-FrontMatter {
    param([string]$Text)
    $match = [regex]::Match($Text, '\A---\s*\r?\n(?<front>.*?)\r?\n---\s*(?:\r?\n|$)', 'Singleline')
    if (-not $match.Success) {
        return $null
    }
    return $match.Groups['front'].Value
}

function Get-YamlScalar {
    param(
        [string]$FrontMatter,
        [string]$Key
    )
    $escaped = [regex]::Escape($Key)
    $match = [regex]::Match($FrontMatter, "(?m)^$escaped\s*:\s*(?<value>[^\r\n#]+)")
    if (-not $match.Success) {
        return $null
    }
    return $match.Groups['value'].Value.Trim().Trim('"').Trim("'")
}

function Get-YamlList {
    param(
        [string]$FrontMatter,
        [string]$Key
    )
    $escaped = [regex]::Escape($Key)
    $inline = [regex]::Match($FrontMatter, "(?m)^$escaped\s*:\s*\[(?<value>[^\]]*)\]")
    if ($inline.Success) {
        if ([string]::IsNullOrWhiteSpace($inline.Groups['value'].Value)) {
            return @()
        }
        return @($inline.Groups['value'].Value.Split(',') | ForEach-Object { $_.Trim().Trim('"').Trim("'") } | Where-Object { $_ })
    }

    $block = [regex]::Match($FrontMatter, "(?ms)^$escaped\s*:\s*\r?\n(?<value>(?:[ \t]+-[^\r\n]*(?:\r?\n|$))*)")
    if (-not $block.Success) {
        return @()
    }

    return @($block.Groups['value'].Value -split '\r?\n' | ForEach-Object {
        if ($_ -match '^\s+-\s*(?<value>.+?)\s*$') {
            $matches['value'].Trim().Trim('"').Trim("'")
        }
    } | Where-Object { $_ })
}

function Get-TaxonomyTitles {
    param([string]$Taxonomy)
    $titles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $root = Join-Path $repoRoot "content/$Taxonomy"
    if (-not (Test-Path -LiteralPath $root)) {
        return $titles
    }

    Get-ChildItem -LiteralPath $root -Recurse -Filter '_index.md' -File | ForEach-Object {
        [void]$titles.Add((Split-Path $_.DirectoryName -Leaf))
        $text = Get-Content -LiteralPath $_.FullName -Raw
        $frontMatter = Get-FrontMatter -Text $text
        if ($frontMatter) {
            $title = Get-YamlScalar -FrontMatter $frontMatter -Key 'title'
            if ($title) {
                [void]$titles.Add($title)
            }
        }
    }
    return $titles
}

function ConvertTo-TaxonomySlug {
    param([string]$Value)
    if (-not $Value) {
        return ''
    }
    return ([regex]::Replace($Value.ToLowerInvariant(), '[^a-z0-9]+', '-')).Trim('-')
}

Push-Location $repoRoot
try {
    $writeupRoot = Join-Path $repoRoot 'content/writeups/webverse'
    $writeupFiles = @(Get-ChildItem -LiteralPath $writeupRoot -Recurse -Filter 'index.md' -File | Sort-Object FullName)
    if ($writeupFiles.Count -eq 0) {
        Add-AuditError 'No WebVerse write-up index.md files were found.'
    }

    $requiredFields = @(
        'title', 'date', 'draft', 'author', 'description', 'summary',
        'platform', 'lab', 'difficulty', 'case_id', 'case_featured',
        'case_summary_short', 'case_status', 'case_classification',
        'case_family', 'case_evidence', 'case_verified', 'case_caido',
        'case_independent_curl', 'primary_cwe', 'cwes', 'patterns', 'methods'
    )

    $taxonomyTitles = @{
        cwes = Get-TaxonomyTitles -Taxonomy 'cwes'
        patterns = Get-TaxonomyTitles -Taxonomy 'patterns'
        methods = Get-TaxonomyTitles -Taxonomy 'methods'
    }

    $records = @()
    $allProseLines = @()

    foreach ($file in $writeupFiles) {
        $caseName = Split-Path $file.DirectoryName -Leaf
        $text = Get-Content -LiteralPath $file.FullName -Raw
        $frontMatter = Get-FrontMatter -Text $text

        if (-not $frontMatter) {
            Add-AuditError "${caseName}: missing or invalid YAML front matter."
            continue
        }

        $draft = Get-YamlScalar -FrontMatter $frontMatter -Key 'draft'
        $isPublished = $draft -eq 'false'

        if ($isPublished) {
            foreach ($field in $requiredFields) {
                if ($frontMatter -notmatch "(?m)^$([regex]::Escape($field))\s*:") {
                    Add-AuditError "${caseName}: required front matter field '$field' is missing."
                }
            }
        }

        $caseId = Get-YamlScalar -FrontMatter $frontMatter -Key 'case_id'
        $featured = Get-YamlScalar -FrontMatter $frontMatter -Key 'case_featured'
        $primaryCwe = Get-YamlScalar -FrontMatter $frontMatter -Key 'primary_cwe'
        $cwes = @(Get-YamlList -FrontMatter $frontMatter -Key 'cwes')
        $patterns = @(Get-YamlList -FrontMatter $frontMatter -Key 'patterns')
        $methods = @(Get-YamlList -FrontMatter $frontMatter -Key 'methods')

        if ($isPublished) {
            if ($caseId -notmatch '^CASE-(?<number>\d{3})$') {
                Add-AuditError "${caseName}: case_id '$caseId' must use CASE-###."
            }

            if ($featured -notin @('true', 'false')) {
                Add-AuditError "${caseName}: case_featured must be explicitly true or false."
            }

            if ($primaryCwe -and $primaryCwe -notin $cwes) {
                Add-AuditError "${caseName}: primary_cwe '$primaryCwe' is not present in cwes."
            }

            foreach ($entry in $cwes) {
                if (-not $taxonomyTitles.cwes.Contains($entry) -and -not $taxonomyTitles.cwes.Contains((ConvertTo-TaxonomySlug $entry))) {
                    Add-AuditError "${caseName}: CWE page is missing for '$entry'."
                }
            }
            foreach ($entry in $patterns) {
                if (-not $taxonomyTitles.patterns.Contains($entry) -and -not $taxonomyTitles.patterns.Contains((ConvertTo-TaxonomySlug $entry))) {
                    Add-AuditError "${caseName}: pattern page is missing for '$entry'."
                }
            }
            foreach ($entry in $methods) {
                if (-not $taxonomyTitles.methods.Contains($entry) -and -not $taxonomyTitles.methods.Contains((ConvertTo-TaxonomySlug $entry))) {
                    Add-AuditError "${caseName}: method page is missing for '$entry'."
                }
            }
        }

        $records += [pscustomobject]@{
            Case = $caseName
            CaseId = $caseId
            Featured = $featured
            Published = $isPublished
        }

        $referencedImages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $imageMatches = [regex]::Matches($text, '!\[(?<alt>[^\]]*)\]\((?<path><[^>]+>|[^\)]+)\)')
        foreach ($imageMatch in $imageMatches) {
            $alt = $imageMatch.Groups['alt'].Value.Trim()
            $relativePath = $imageMatch.Groups['path'].Value.Trim().Trim('<', '>')
            if ($relativePath -match '\s+["'']') {
                $relativePath = ($relativePath -split '\s+["'']', 2)[0]
            }
            if ($relativePath -match '^(https?:|data:)') {
                continue
            }

            $decodedPath = [uri]::UnescapeDataString($relativePath)
            $fullPath = Join-Path $file.DirectoryName $decodedPath
            [void]$referencedImages.Add([IO.Path]::GetFileName($decodedPath))
            if (-not (Test-Path -LiteralPath $fullPath)) {
                Add-AuditError "${caseName}: referenced image does not exist: $relativePath"
            }
            if (-not $alt) {
                Add-AuditWarning "${caseName}: image '$relativePath' has empty alt text."
            }
        }

        $bundleImages = @(Get-ChildItem -LiteralPath $file.DirectoryName -File | Where-Object { $_.Extension -match '^\.(png|jpe?g|webp|gif)$' })
        foreach ($image in $bundleImages) {
            if (-not $referencedImages.Contains($image.Name)) {
                Add-AuditWarning "${caseName}: bundle image is not referenced: $($image.Name)"
            }
        }

        if (-not $Quick -and $bundleImages.Count -gt 1) {
            $duplicateGroups = $bundleImages | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
            } | Group-Object Hash | Where-Object Count -gt 1
            foreach ($group in $duplicateGroups) {
                Add-AuditWarning "${caseName}: exact duplicate images: $($group.Group.Name -join ', ')"
            }
        }

        $toneChecks = [ordered]@{
            'em dash punctuation' = '—'
            'bounded' = '(?i)\bbounded\b'
            'evidence-backed' = '(?i)evidence[- ]backed'
            'deliberately' = '(?i)\bdeliberat(?:e|ely)\b'
            'establishes' = '(?i)\bestablish(?:es|ed)?\b'
            'demonstrates' = '(?i)\bdemonstrat(?:e|es|ed)\b'
            'robust' = '(?i)\brobust\b'
            'comprehensive' = '(?i)\bcomprehensive\b'
            'seamless' = '(?i)\bseamless\b'
        }
        foreach ($label in $toneChecks.Keys) {
            $count = [regex]::Matches($text, $toneChecks[$label]).Count
            if ($count -gt 0) {
                Add-AuditWarning "${caseName}: review $count occurrence(s) of $label."
            }
        }

        if (-not $Quick) {
            $inFence = $false
            $frontDelimiters = 0
            foreach ($line in ($text -split '\r?\n')) {
                if ($line -eq '---' -and $frontDelimiters -lt 2) {
                    $frontDelimiters++
                    continue
                }
                if ($frontDelimiters -lt 2) {
                    continue
                }
                if ($line -match '^```') {
                    $inFence = -not $inFence
                    continue
                }
                $trimmed = $line.Trim()
                if (-not $inFence -and $trimmed.Length -ge 65 -and $trimmed -notmatch '^(#|!\[|\||[-*+]\s|\d+\.\s|<|{{)') {
                    $allProseLines += [pscustomobject]@{ Text = $trimmed; Case = $caseName }
                }
            }
        }
    }

    $publishedRecords = @($records | Where-Object Published)
    $duplicateIds = @($publishedRecords | Group-Object CaseId | Where-Object Count -gt 1)
    foreach ($duplicate in $duplicateIds) {
        Add-AuditError "Duplicate case_id '$($duplicate.Name)' appears in: $($duplicate.Group.Case -join ', ')"
    }

    $caseNumbers = @($publishedRecords | Where-Object { $_.CaseId -match '^CASE-(\d{3})$' } | ForEach-Object { [int]($_.CaseId.Substring(5)) } | Sort-Object)
    if ($caseNumbers.Count -gt 0) {
        $expected = @(1..$caseNumbers.Count)
        if (($caseNumbers -join ',') -ne ($expected -join ',')) {
            Add-AuditError "Published CASE numbers are not sequential: $($caseNumbers -join ', ')"
        }
    }

    $featuredCases = @($publishedRecords | Where-Object Featured -eq 'true')
    if ($featuredCases.Count -ne 1) {
        Add-AuditError "Exactly one published case must be featured. Found $($featuredCases.Count)."
    }

    if (-not $Quick) {
        $repeatedLines = @($allProseLines | Group-Object Text | Where-Object { ($_.Group.Case | Sort-Object -Unique).Count -ge 3 })
        foreach ($group in $repeatedLines) {
            $cases = @($group.Group.Case | Sort-Object -Unique)
            Add-AuditWarning "The same long prose line appears in $($cases.Count) cases: '$($group.Name)'"
        }
    }

    $publicTextFiles = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'content') -Recurse -Filter '*.md' -File)
    foreach ($file in $publicTextFiles) {
        $text = Get-Content -LiteralPath $file.FullName -Raw
        $literalFlags = [regex]::Matches($text, 'WEBVERSE\{(?!(?:REDACTED|\.\.\.|\*|%))[A-Za-z0-9_-]{12,}\}', 'IgnoreCase')
        if ($literalFlags.Count -gt 0) {
            $relative = [IO.Path]::GetRelativePath($repoRoot, $file.FullName)
            Add-AuditError "${relative}: possible literal WebVerse flag found."
        }

        $bearerTokens = [regex]::Matches($text, '(?i)Authorization:\s*Bearer\s+(?!<|\$|REDACTED)[A-Za-z0-9._-]{20,}')
        if ($bearerTokens.Count -gt 0) {
            $relative = [IO.Path]::GetRelativePath($repoRoot, $file.FullName)
            Add-AuditError "${relative}: possible reusable bearer token found."
        }
    }

    $trackedFiles = @(& git ls-files 2>$null)
    foreach ($path in $trackedFiles) {
        $isPrivateManifest = $path -match 'CASE_EVIDENCE_MANIFEST' -and $path -ne 'docs/templates/CASE_EVIDENCE_MANIFEST.template.yaml'
        if ($path -eq 'AGENTS.md' -or $path -match '\.docx$' -or $path -match '^(public|resources)/' -or $path -match '(?i)(TRANSCRIPT|OBSIDIAN)' -or $isPrivateManifest) {
            Add-AuditError "Forbidden publication file is tracked: $path"
        }
    }

    if ($CheckStaged) {
        $staged = @(& git diff --cached --name-only --diff-filter=ACMR 2>$null)
        foreach ($path in $staged) {
            $isPrivateManifest = $path -match 'CASE_EVIDENCE_MANIFEST' -and $path -ne 'docs/templates/CASE_EVIDENCE_MANIFEST.template.yaml'
            if ($path -match '(^|/)(AGENTS\.md|.*\.docx|.*(?:TRANSCRIPT|OBSIDIAN).*)$' -or $path -match '^(public|resources)/' -or $isPrivateManifest) {
                Add-AuditError "Forbidden staged file: $path"
            }
        }
        & git diff --cached --check
        if ($LASTEXITCODE -ne 0) {
            Add-AuditError 'git diff --cached --check failed.'
        }
    }

    Write-Host "Publication audit: $($publishedRecords.Count) published cases checked."
    if ($featuredCases.Count -eq 1) {
        Write-Host "Featured case: $($featuredCases[0].CaseId) ($($featuredCases[0].Case))"
    }

    if ($warnings.Count -gt 0) {
        Write-Host "`nWarnings ($($warnings.Count)):" -ForegroundColor Yellow
        $warnings | ForEach-Object { Write-Host "  WARN  $_" -ForegroundColor Yellow }
    }

    if ($errors.Count -gt 0) {
        Write-Host "`nErrors ($($errors.Count)):" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "  ERROR $_" -ForegroundColor Red }
        exit 1
    }

    Write-Host "`nPublication audit passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
