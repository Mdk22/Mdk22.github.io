[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SiteRoot,

    [string]$BaseUrl = 'https://mdk22.github.io/'
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $SiteRoot).Path
$baseUri = [uri]$BaseUrl
$broken = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$checked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Resolve-RenderedTarget {
    param(
        [string]$Reference,
        [string]$SourceDirectory
    )

    $decoded = [Net.WebUtility]::HtmlDecode($Reference)
    if ($decoded -match '^(mailto:|tel:|data:|javascript:|#|//)') {
        return $null
    }

    $withoutFragment = ($decoded -split '[?#]', 2)[0]
    if (-not $withoutFragment) {
        return $null
    }

    if ($withoutFragment -match '^https?://') {
        $uri = [uri]$withoutFragment
        if ($uri.Host -ne $baseUri.Host) {
            return $null
        }
        $withoutFragment = $uri.AbsolutePath
    }

    if ($withoutFragment.StartsWith('/')) {
        $candidate = Join-Path $resolvedRoot $withoutFragment.TrimStart('/')
    }
    else {
        $candidate = Join-Path $SourceDirectory $withoutFragment
    }

    if ($withoutFragment.EndsWith('/')) {
        $candidate = Join-Path $candidate 'index.html'
    }
    elseif (-not [IO.Path]::GetExtension($candidate)) {
        $candidate = Join-Path $candidate 'index.html'
    }

    return [IO.Path]::GetFullPath($candidate)
}

$htmlFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Filter '*.html' -File)
foreach ($file in $htmlFiles) {
    $html = Get-Content -LiteralPath $file.FullName -Raw
    $matches = [regex]::Matches(
        $html,
        '(?is)<(?:a|link|script|img|source)\b[^>]*?\s(?:href|src)=(?<quote>["'']?)(?<url>[^"''\s>]+)\k<quote>'
    )

    foreach ($match in $matches) {
        $reference = $match.Groups['url'].Value
        $target = Resolve-RenderedTarget -Reference $reference -SourceDirectory $file.DirectoryName
        if (-not $target) {
            continue
        }

        $key = "$($file.FullName)|$target"
        if (-not $checked.Add($key)) {
            continue
        }

        if (-not (Test-Path -LiteralPath $target)) {
            $sourceRelative = [IO.Path]::GetRelativePath($resolvedRoot, $file.FullName)
            $targetRelative = [IO.Path]::GetRelativePath($resolvedRoot, $target)
            [void]$broken.Add("$sourceRelative -> $reference [$targetRelative]")
        }
    }
}

Write-Host "Rendered link audit: $($htmlFiles.Count) HTML files checked."
if ($broken.Count -gt 0) {
    Write-Host "`nBroken internal references ($($broken.Count)):" -ForegroundColor Red
    $broken | Sort-Object | ForEach-Object { Write-Host "  ERROR $_" -ForegroundColor Red }
    exit 1
}

Write-Host 'Rendered link audit passed.' -ForegroundColor Green
