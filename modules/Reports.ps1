# ==============================================================================
# Module: Reports.ps1
# Description: Markdown report generation.
# ==============================================================================

# --- HELPER: MARKDOWN REPORT GENERATOR ---
function Generate-MarkdownReport {
    param (
        [Parameter(Mandatory=$true)]$Data,
        [Parameter(Mandatory=$true)][string]$FileName,
        [Parameter(Mandatory=$true)][string]$Header
    )

    $ReportsFolder = $Global:ReportsPath
    $MarkdownPath  = Join-Path -Path $ReportsFolder -ChildPath $FileName

    if (-not (Test-Path -Path $ReportsFolder)) {
        New-Item -Path $ReportsFolder -ItemType Directory | Out-Null
    }

    $TotalCount = @($Data).Count
    $SourceCounts = $Data | Group-Object Source | Sort-Object Count -Descending

    $SeverityOrder = @("Critical", "High", "Medium", "Low")
    $SeverityCounts = $Data | Where-Object { $_.Severity } | Group-Object Severity

    $TermHits = [System.Collections.Generic.List[string]]::new()
    foreach ($News in $Data) {
        foreach ($Keyword in $Global:TargetKeywords) {
            if ($News.Title.ToLower().Contains($Keyword.ToLower())) {
                $TermHits.Add($Keyword)
            }
        }
    }

    $HotTerms = "None"
    if ($TermHits.Count -gt 0) {
        $Top3Groups = $TermHits | Group-Object | Sort-Object Count -Descending | Select-Object -First 3
        $HotTerms = ($Top3Groups.Name) -join ", "
    }

    $Content = New-Object System.Collections.Generic.List[string]

    $Content.Add("# $Header")
    $Content.Add("")
    $Content.Add("This cyber intelligence report aggregates critical, filtered news from a curated list of trusted security websites and publications.")
    $Content.Add("")

    # Executive Summary Section
    $Content.Add("## Executive Summary")
    $Content.Add("This section provides a high-level overview of high-priority cybersecurity news matching our target monitoring criteria.")
    $Content.Add("")
    $Content.Add("| Metric | Value |")
    $Content.Add("| :--- | :--- |")
    $Content.Add("| **Total News** | $TotalCount |")
    foreach ($SourceGroup in $SourceCounts) {
        $Content.Add("| **$($SourceGroup.Name)** | $($SourceGroup.Count) |")
    }
    foreach ($Level in $SeverityOrder) {
        $LevelGroup = $SeverityCounts | Where-Object { $_.Name -eq $Level }
        if ($LevelGroup) {
            $Content.Add("| **Severity: $Level** | $($LevelGroup.Count) |")
        }
    }
    $Content.Add("| **Top Mentioned Indicators** | $HotTerms |")
    $Content.Add("")

    # Security News Findings Section
    $Content.Add("## Security News Findings")
    $Content.Add("The following selection covers the security news matching our monitoring criteria.")
    $Content.Add("")

    foreach ($Item in $Data) {
        $Content.Add("---")
        $Content.Add("### $($Item.Title)")
        $Content.Add("")
        $SeverityLabel = if ($Item.Severity) { " | *Severity:* **$($Item.Severity)**" } else { "" }
        $Content.Add("*Source:* **$($Item.Source)** | *Published (UTC):* $($Item.PublishedAt.ToString('yyyy-MM-dd HH:mm:ssZ'))$SeverityLabel")
        $Content.Add("")
        $Content.Add("**Introduction:** $($Item.Introduction)")
        $Content.Add("")
        if ($Item.Cves -and @($Item.Cves).Count -gt 0) {
            $Content.Add("**CVEs:** $((@($Item.Cves)) -join ', ')")
            $Content.Add("")
        }
        $Content.Add("**Url:** [$($Item.Url)]($($Item.Url))")
        $Content.Add("")
    }

    $Content | Out-File -FilePath $MarkdownPath -Encoding utf8 -Force
    Write-Host "SUCCESS: Report generated at $MarkdownPath" -ForegroundColor Green
}
