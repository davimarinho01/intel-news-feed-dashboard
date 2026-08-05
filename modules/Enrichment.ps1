# ==============================================================================
# Module: Enrichment.ps1
# Description: Keyword filtering plus per-article enrichment (severity scoring,
#              CVE extraction, best-effort IOC extraction).
# ==============================================================================

# Keywords that force at least "High" severity even without an explicit CVSS
# score in the text (e.g. "0day", "actively exploited").
$Global:HighSeverityFallbackKeywords = @(
    "0day", "0-day", "zeroday", "zero-day",
    "active attack", "actively exploited", "exploited in the wild"
)

# --- ENRICHMENT: CVE ID EXTRACTION ---
function Get-ArticleCves {
    param ([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    $CveMatches = [regex]::Matches($Text, '(?i)CVE-\d{4}-\d{4,7}')
    if ($CveMatches.Count -eq 0) { return @() }

    # Leading comma prevents PowerShell from unrolling a single-CVE array into a
    # bare string on return (same idiom used by Get-LocalDatabase/Get-RssFeed).
    return ,@($CveMatches | ForEach-Object { $_.Value.ToUpper() } | Select-Object -Unique)
}

# --- ENRICHMENT: CVSS SCORE EXTRACTION (E.G. "CVSS 4.0 score: 9.4", "CVSS score: 8.2") ---
function Get-ArticleCvssScore {
    param ([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $ScoreMatch = [regex]::Match($Text, '(?i)cvss.*?score:?\s*([\d]+(?:\.\d+)?)')
    if ($ScoreMatch.Success) {
        return [double]$ScoreMatch.Groups[1].Value
    }
    return $null
}

# --- ENRICHMENT: BEST-EFFORT IOC EXTRACTION (IPs AND FILE HASHES) ---
# Article intros are journalistic summaries, not technical bulletins, so IOCs
# will often come back empty — that's expected, not a bug.
function Get-ArticleIOCs {
    param ([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return [PSCustomObject]@{ IPs = @(); Hashes = @() }
    }

    $IpPattern = '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
    $Ips = @([regex]::Matches($Text, $IpPattern) | ForEach-Object { $_.Value } | Select-Object -Unique)

    # MD5 (32 hex), SHA1 (40 hex) and SHA256 (64 hex) — matched by exact length to avoid false positives.
    $HashPattern = '\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
    $Hashes = @([regex]::Matches($Text, $HashPattern) | ForEach-Object { $_.Value.ToLower() } | Select-Object -Unique)

    return [PSCustomObject]@{ IPs = $Ips; Hashes = $Hashes }
}

# --- ENRICHMENT: SEVERITY SCORING ---
# Uses the extracted CVSS score when available (Critical >=9, High >=7,
# Medium >=4, Low otherwise). Falls back to keyword heuristics when no CVSS
# score is present in the text.
function Get-ArticleSeverity {
    param (
        [Parameter(Mandatory=$true)][string]$Text,
        $CvssScore
    )

    if ($null -ne $CvssScore) {
        if ($CvssScore -ge 9.0) { return "Critical" }
        if ($CvssScore -ge 7.0) { return "High" }
        if ($CvssScore -ge 4.0) { return "Medium" }
        return "Low"
    }

    $LowerText = $Text.ToLower()

    foreach ($Keyword in $Global:HighSeverityFallbackKeywords) {
        if ($LowerText.Contains($Keyword)) { return "High" }
    }
    foreach ($Keyword in $Global:TargetKeywords) {
        if ($LowerText.Contains($Keyword.ToLower())) { return "Medium" }
    }
    return "Low"
}

# --- ENRICHMENT: SINGLE ENTRY POINT COMBINING ALL OF THE ABOVE ---
function Get-ArticleEnrichment {
    param (
        [Parameter(Mandatory=$true)][string]$Title,
        [string]$Introduction
    )

    $CombinedText = "$Title $Introduction"
    $Cvss = Get-ArticleCvssScore -Text $CombinedText

    return [PSCustomObject]@{
        Severity = Get-ArticleSeverity -Text $CombinedText -CvssScore $Cvss
        Cvss     = $Cvss
        Cves     = Get-ArticleCves -Text $CombinedText
        Iocs     = Get-ArticleIOCs -Text $CombinedText
    }
}

# --- HELPER: KEYWORD-BASED FILTERING WITH BLACKLIST FILTER ---
function Filter-NewsByKeywords {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$NewsList,

        [Parameter(Mandatory=$true)]
        [string[]]$Keywords,

        [string[]]$Blacklist = $Global:BlacklistKeywords
    )

    if ($NewsList.Count -eq 0) { return @() }

    # Escape and build regex for target keywords (inclusion filter)
    $EscapedKeywords = $Keywords | ForEach-Object { [regex]::Escape($_) }
    $Pattern = $EscapedKeywords -join '|'

    # Filter entries matching target keywords
    $FilteredList = $NewsList | Where-Object { $_.Title -match $Pattern }

    # Exclude entries matching blacklist words
    if ($null -ne $Blacklist -and $Blacklist.Count -gt 0) {
        $EscapedBlacklist = $Blacklist | ForEach-Object { [regex]::Escape($_) }
        $BlacklistPattern = $EscapedBlacklist -join '|'

        # Strip out matching blacklist items from the dataset
        $FilteredList = $FilteredList | Where-Object { $_.Title -notmatch $BlacklistPattern }
    }

    return $FilteredList
}
