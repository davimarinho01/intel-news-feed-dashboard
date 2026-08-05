# ==============================================================================
# Module: Dashboard.ps1
# Description: Aggregates the full historical database into a small
#              data/summary.json consumed by the static dashboard. Doing the
#              aggregation here (server-side, once a day) keeps the dashboard's
#              client-side JS a dumb renderer with no build step.
# ==============================================================================

function Export-DashboardData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][array]$Articles,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [int]$RecentCriticalCount = 20,
        [int]$TopCveCount = 10,
        [int]$TopKeywordCount = 10
    )

    if (@($Articles).Count -eq 0) {
        Write-Host "INFO: No articles in database yet; skipping dashboard export." -ForegroundColor Yellow
        return
    }

    # --- Source breakdown ---
    $SourceBreakdown = @($Articles | Group-Object Source | Sort-Object Count -Descending | ForEach-Object {
        [PSCustomObject]@{ Source = $_.Name; Count = $_.Count }
    })

    # --- Severity breakdown (fixed order, always includes all 4 levels even at 0) ---
    $SeverityOrder = @("Critical", "High", "Medium", "Low")
    $SeverityGroups = $Articles | Where-Object { $_.Severity } | Group-Object Severity
    $SeverityBreakdown = @(foreach ($Level in $SeverityOrder) {
        $Group = $SeverityGroups | Where-Object { $_.Name -eq $Level }
        [PSCustomObject]@{ Severity = $Level; Count = if ($Group) { $Group.Count } else { 0 } }
    })

    # --- Daily trend, pivoted per source so the dashboard can feed it straight into Chart.js ---
    $DailyBySource = $Articles | ForEach-Object {
        [PSCustomObject]@{ Date = $_.PublishedAt.ToString("yyyy-MM-dd"); Source = $_.Source }
    }
    $Labels = @($DailyBySource | Select-Object -ExpandProperty Date -Unique | Sort-Object)
    $SourceNames = @($SourceBreakdown | Select-Object -ExpandProperty Source)

    $Datasets = @(foreach ($SourceName in $SourceNames) {
        $CountsByDate = $DailyBySource | Where-Object { $_.Source -eq $SourceName } | Group-Object Date
        $Data = @(foreach ($Label in $Labels) {
            $Match = $CountsByDate | Where-Object { $_.Name -eq $Label }
            if ($Match) { $Match.Count } else { 0 }
        })
        [PSCustomObject]@{ Source = $SourceName; Data = $Data }
    })

    # --- Top CVEs mentioned across the whole history ---
    $CveHits = [System.Collections.Generic.List[object]]::new()
    foreach ($Article in $Articles) {
        foreach ($Cve in @($Article.Cves)) {
            if ($Cve) {
                $CveHits.Add([PSCustomObject]@{ Cve = $Cve; Severity = $Article.Severity; Url = $Article.Url })
            }
        }
    }
    $TopCves = @($CveHits | Group-Object Cve | Sort-Object Count -Descending | Select-Object -First $TopCveCount | ForEach-Object {
        $Example = $_.Group | Select-Object -First 1
        [PSCustomObject]@{ Cve = $_.Name; Count = $_.Count; Severity = $Example.Severity; Url = $Example.Url }
    })

    # --- Top keywords (same matching rule as the markdown report, applied to the full history) ---
    $KeywordHits = [System.Collections.Generic.List[string]]::new()
    foreach ($Article in $Articles) {
        $LowerTitle = $Article.Title.ToLower()
        foreach ($Keyword in $Global:TargetKeywords) {
            if ($LowerTitle.Contains($Keyword.ToLower())) {
                $KeywordHits.Add($Keyword)
            }
        }
    }
    $TopKeywords = @($KeywordHits | Group-Object | Sort-Object Count -Descending | Select-Object -First $TopKeywordCount | ForEach-Object {
        [PSCustomObject]@{ Keyword = $_.Name; Count = $_.Count }
    })

    # --- Most recent Critical/High findings, for a "needs attention" table ---
    $RecentCritical = @($Articles |
        Where-Object { $_.Severity -in @("Critical", "High") } |
        Sort-Object PublishedAt -Descending |
        Select-Object -First $RecentCriticalCount |
        ForEach-Object {
            [PSCustomObject]@{
                Title       = $_.Title
                Source      = $_.Source
                PublishedAt = $_.PublishedAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
                Url         = $_.Url
                Severity    = $_.Severity
                Cvss        = $_.Cvss
                Cves        = @($_.Cves)
            }
        })

    $Summary = [PSCustomObject]@{
        GeneratedAt       = ([DateTime]::UtcNow).ToString("yyyy-MM-ddTHH:mm:ssZ")
        TotalArticles     = @($Articles).Count
        SourceBreakdown   = $SourceBreakdown
        SeverityBreakdown = $SeverityBreakdown
        DailyTrend        = [PSCustomObject]@{ Labels = $Labels; Datasets = $Datasets }
        TopCves           = $TopCves
        TopKeywords       = $TopKeywords
        RecentCritical    = $RecentCritical
    }

    $OutputFolder = Split-Path -Path $OutputPath -Parent
    if ($OutputFolder -and -not (Test-Path -Path $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory | Out-Null
    }

    $Summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Host "SUCCESS: Dashboard summary exported to $OutputPath" -ForegroundColor Green
}
