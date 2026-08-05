# ==============================================================================
# Script: IntelNewsFeed.ps1
# Author: Bruno Ricci
# Description: Automated multi-source cyber threat intelligence aggregator
#              supporting Local DB Caching, Target-Date Web Fetching, and reports.
# ==============================================================================

# --- GLOBAL TARGET KEYWORDS CONFIGURATION ---
$Global:TargetKeywords = @(
    "malware", "0day", "0-day", "zeroday", "zero-day",
    "critical", "security flaw", "code execution",
    "cvss", "leak", "vulnerability", "takeover", "abused", "phishing",
    "ransomware", "exploit", "active attack"
)

# --- GLOBAL BLACKLIST KEYWORDS CONFIGURATION (TERMS TO EXCLUDE) ---
$Global:BlacklistKeywords = @(
    "webinar", "webminar", "weekly recap"
)

# --- FILE PATH CONFIGURATION ---
$Global:DbPath = Join-Path -Path $PSScriptRoot -ChildPath "data/feed_database.json"
$Global:ReportsPath = Join-Path -Path $PSScriptRoot -ChildPath "reports"
$Global:SummaryPath = Join-Path -Path $PSScriptRoot -ChildPath "data/summary.json"

# --- MODULE IMPORTS ---
$Global:ModulesPath = Join-Path -Path $PSScriptRoot -ChildPath "modules"
. (Join-Path -Path $Global:ModulesPath -ChildPath "Sources.ps1")
. (Join-Path -Path $Global:ModulesPath -ChildPath "Enrichment.ps1")
. (Join-Path -Path $Global:ModulesPath -ChildPath "Reports.ps1")
. (Join-Path -Path $Global:ModulesPath -ChildPath "Dashboard.ps1")
. (Join-Path -Path $Global:ModulesPath -ChildPath "Notify.ps1")

# --- HELPER: LOAD / SAVE LOCAL DATABASE ---
function Get-LocalDatabase {
    $List = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -Path $Global:DbPath) {
        try {
            $Content = Get-Content -Path $Global:DbPath -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($Content)) {
                $Data = ConvertFrom-Json $Content
                if ($Data) {
                    foreach ($Item in $Data) {
                        $Item.PublishedAt = [DateTime]$Item.PublishedAt
                        $List.Add($Item)
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to read local database. Starting a new database. Error: $($_)"
        }
    }
    return ,$List
}

function Save-LocalDatabase {
    param (
        [Parameter(Mandatory=$true)]
        $Database
    )
    try {
        $DataFolder = Split-Path -Path $Global:DbPath -Parent
        if (-not (Test-Path -Path $DataFolder)) {
            New-Item -Path $DataFolder -ItemType Directory | Out-Null
        }
        $Json = ConvertTo-Json -InputObject $Database -Depth 5
        $Json | Out-File -FilePath $Global:DbPath -Encoding utf8 -Force
    }
    catch {
        Write-Error "Failed to save local database. Error: $($_)"
    }
}

# --- SINK: FEED SYNCHRONIZATION WITH TARGETED TIME RANGE ---
function Sync-FeedsToDatabase {
    param (
        [Parameter(Mandatory=$true)][DateTime]$StartDate,
        [Parameter(Mandatory=$true)][DateTime]$EndDate
    )

    $CurrentDb = Get-LocalDatabase
    if ($null -eq $CurrentDb) {
        $CurrentDb = [System.Collections.Generic.List[object]]::new()
    }

    # Calculate date range span to scale API pagination depth dynamically
    $DaysDifference = ($EndDate - $StartDate).TotalDays
    $PagesNeeded = 3
    if ($DaysDifference -gt 10) {
        $PagesNeeded = 20 # Extend page depth limit to successfully fetch full monthly history
    }

    Write-Host "INFO: Requesting data from web for range: $($StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndDate.ToString('yyyy-MM-dd HH:mm:ss')) (Depth Pages: $PagesNeeded)..." -ForegroundColor Cyan

    $AllFetched = [System.Collections.Generic.List[object]]::new()

    # Force query execution on the Blogger API with calculated pagination limits
    $ThnData = Get-HackerNewsFeed -StartDate $StartDate -EndDate $EndDate -MaxPagesToFetch $PagesNeeded
    if ($null -ne $ThnData) { $AllFetched.AddRange($ThnData) }

    # Plain RSS sources only publish recent entries; fetched and filtered locally against the date range
    foreach ($RssSource in $Global:RssSources) {
        $SourceData = Get-RssFeed -FeedUrl $RssSource.Url -SourceName $RssSource.Name
        if ($null -ne $SourceData) { $AllFetched.AddRange($SourceData) }
    }

    $NewArticles = 0
    foreach ($Article in $AllFetched) {
        $Exists = $CurrentDb | Where-Object { $_.Url -eq $Article.Url }
        if (-not $Exists) {
            $Enrichment = Get-ArticleEnrichment -Title $Article.Title -Introduction $Article.Introduction
            $Article | Add-Member -NotePropertyName Severity -NotePropertyValue $Enrichment.Severity
            $Article | Add-Member -NotePropertyName Cvss -NotePropertyValue $Enrichment.Cvss
            $Article | Add-Member -NotePropertyName Cves -NotePropertyValue $Enrichment.Cves
            $Article | Add-Member -NotePropertyName Iocs -NotePropertyValue $Enrichment.Iocs

            $CurrentDb.Add($Article)
            $NewArticles++
        }
    }

    if ($NewArticles -gt 0) {
        $SortedDb = $CurrentDb | Sort-Object PublishedAt -Descending
        $ArrayToSave = @($SortedDb)
        Save-LocalDatabase -Database $ArrayToSave
        Write-Host "INFO: Added $NewArticles new articles to local database." -ForegroundColor Green
    } else {
        Write-Host "INFO: No new articles to add to database for this range." -ForegroundColor Yellow
    }
}

# ==============================================================================
# --- MAIN FILTRATION & REPORT GENERATION FUNCTIONS (USER INTERFACE) ---
# ==============================================================================

# --- FILTER 1: SINGLE DATE REPORT ---
function Get-NewsByDate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$TargetDate,

        [string[]]$Keywords = $Global:TargetKeywords
    )

    # If no date is specified, default to yesterday
    if ([string]::IsNullOrWhiteSpace($TargetDate)) {
        $TargetDate = ([DateTime]::UtcNow.Date).AddDays(-1).ToString("yyyy-MM-dd")
        Write-Host "INFO: No specific date provided. Defaulting to yesterday: $TargetDate" -ForegroundColor Gray
    }

    try {
        $TargetDateParsed = [DateTime]$TargetDate
        $NextDayParsed    = $TargetDateParsed.AddDays(1)
    }
    catch {
        Write-Error "Invalid date format ($TargetDate). Please use YYYY-MM-DD pattern."
        return
    }

    # Fetch and sync fresh feed data for the 24-hour target date range
    Sync-FeedsToDatabase -StartDate $TargetDateParsed -EndDate $NextDayParsed

    $LocalDb = Get-LocalDatabase
    Write-Host "INFO: Filtering local database for: $($TargetDateParsed.ToString('yyyy-MM-dd')) (UTC)" -ForegroundColor Cyan

    $DateFiltered = $LocalDb | Where-Object {
        $_.PublishedAt -ge $TargetDateParsed -and $_.PublishedAt -lt $NextDayParsed
    }

    if ($DateFiltered.Count -eq 0) {
        Write-Host "INFO: No cached articles found for this date." -ForegroundColor Yellow
        return
    }

    $PriorityNews = Filter-NewsByKeywords -NewsList $DateFiltered -Keywords $Keywords

    if ($PriorityNews.Count -eq 0) {
        Write-Host "INFO: $($DateFiltered.Count) articles found, but zero matches for security keywords." -ForegroundColor Yellow
        return
    }

    $OutputFileName = "$($TargetDateParsed.ToString('yyyy-MM-dd')).md"
    $HeaderTitle    = "Daily Security News Report: $($TargetDateParsed.ToString('yyyy-MM-dd'))"

    Generate-MarkdownReport -Data $PriorityNews -FileName $OutputFileName -Header $HeaderTitle
    Send-SeverityAlertEmail -Articles $PriorityNews
}

# --- FILTER 2: MONTHLY REPORT (DEFAULTS TO PREVIOUS MONTH IF OMITTED) ---
function Get-NewsByMonth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$TargetMonth,

        [string[]]$Keywords = $Global:TargetKeywords
    )

    # Automatically calculate previous month in YYYY-MM if no month parameter is provided
    if ([string]::IsNullOrWhiteSpace($TargetMonth)) {
        $TargetMonth = ([DateTime]::UtcNow).AddMonths(-1).ToString("yyyy-MM")
        Write-Host "INFO: No target month specified. Automatically targeting previous month: $TargetMonth" -ForegroundColor Gray
    }

    try {
        $StartOfMonth = [DateTime]"$TargetMonth-01"
        $EndOfMonth   = $StartOfMonth.AddMonths(1)
    }
    catch {
        Write-Error "Invalid month format ($TargetMonth). Please use YYYY-MM pattern."
        return
    }

    # Retrieve and sync data for the full month period with expanded deep-pagination checks
    Sync-FeedsToDatabase -StartDate $StartOfMonth -EndDate $EndOfMonth

    $LocalDb = Get-LocalDatabase
    $MonthLabel = $StartOfMonth.ToString("yyyy-MM")
    Write-Host "INFO: Filtering local database for month: $MonthLabel (UTC)" -ForegroundColor Cyan

    $MonthFiltered = $LocalDb | Where-Object {
        $_.PublishedAt -ge $StartOfMonth -and $_.PublishedAt -lt $EndOfMonth
    }

    if ($MonthFiltered.Count -eq 0) {
        Write-Host "INFO: No cached articles found for month $MonthLabel." -ForegroundColor Yellow
        return
    }

    $PriorityNews = Filter-NewsByKeywords -NewsList $MonthFiltered -Keywords $Keywords

    if ($PriorityNews.Count -eq 0) {
        Write-Host "INFO: $($MonthFiltered.Count) articles found, but zero matches for security keywords." -ForegroundColor Yellow
        return
    }

    $OutputFileName = "Monthly-Report-$MonthLabel.md"
    $HeaderTitle    = "Monthly Security News Summary: $MonthLabel"

    Generate-MarkdownReport -Data $PriorityNews -FileName $OutputFileName -Header $HeaderTitle
}

# --- FILTER 3: CUSTOM DATE RANGE REPORT ---
function Get-NewsByRange {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$StartDate,

        [Parameter(Mandatory=$true)]
        [string]$EndDate,

        [string[]]$Keywords = $Global:TargetKeywords
    )

    try {
        $Start = [DateTime]$StartDate
        $End   = ([DateTime]$EndDate).Date.AddDays(1)
    }
    catch {
        Write-Error "Invalid date input. Please use the YYYY-MM-DD pattern for both dates."
        return
    }

    if ($Start -gt $End) {
        Write-Error "The start date ($StartDate) cannot be later than the end date ($EndDate)."
        return
    }

    # Pull latest data within custom constraints
    Sync-FeedsToDatabase -StartDate $Start -EndDate $End

    $LocalDb = Get-LocalDatabase
    $RangeLabel = "$($Start.ToString('yyyyMMdd'))-to-$((($End).AddDays(-1)).ToString('yyyyMMdd'))"
    Write-Host "INFO: Filtering local database from $($Start.ToString('yyyy-MM-dd')) to $((($End).AddDays(-1)).ToString('yyyy-MM-dd')) (UTC)" -ForegroundColor Cyan

    $RangeFiltered = $LocalDb | Where-Object {
        $_.PublishedAt -ge $Start -and $_.PublishedAt -lt $End
    }

    if ($RangeFiltered.Count -eq 0) {
        Write-Host "INFO: No cached articles found for the specified date range." -ForegroundColor Yellow
        return
    }

    $PriorityNews = Filter-NewsByKeywords -NewsList $RangeFiltered -Keywords $Keywords

    if ($PriorityNews.Count -eq 0) {
        Write-Host "INFO: $($RangeFiltered.Count) articles found, but zero matches for security keywords." -ForegroundColor Yellow
        return
    }

    $OutputFileName = "Range-Report-$($Start.ToString('yyyy-MM-dd'))-to-$((($End).AddDays(-1)).ToString('yyyy-MM-dd')).md"
    $HeaderTitle    = "Custom Range Security News Report ($($Start.ToString('yyyy-MM-dd')) to $((($End).AddDays(-1)).ToString('yyyy-MM-dd')))"

    Generate-MarkdownReport -Data $PriorityNews -FileName $OutputFileName -Header $HeaderTitle
}

# --- DEFAULT SCRIPT EXECUTION ---
# Runs daily checks for yesterday's data on script execution if no parameters are supplied
Get-NewsByDate
Get-NewsByMonth
#Get-NewsByDate -TargetDate "2026-05-13"
#Get-NewsByRange -StartDate "2026-05-01" -EndDate "2026-05-15"

# Refresh the dashboard summary from the full accumulated history (not just today/this month)
Export-DashboardData -Articles (Get-LocalDatabase) -OutputPath $Global:SummaryPath
