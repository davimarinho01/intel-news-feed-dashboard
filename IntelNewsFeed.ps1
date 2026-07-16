# ==============================================================================
# Script: Intel-News-Feed.ps1
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
$Global:DbPath = Join-Path -Path $PSScriptRoot -ChildPath "feed_database.json"

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
        $ReportsFolder = Split-Path -Path $Global:DbPath -Parent
        if (-not (Test-Path -Path $ReportsFolder)) {
            New-Item -Path $ReportsFolder -ItemType Directory | Out-Null
        }
        $Json = ConvertTo-Json -InputObject $Database -Depth 5
        $Json | Out-File -FilePath $Global:DbPath -Encoding utf8 -Force
    }
    catch {
        Write-Error "Failed to save local database. Error: $($_)"
    }
}

# --- HELPER: THE HACKER NEWS INGESTION (DATE-FILTERED & PAGINATED) ---
function Get-HackerNewsFeed {
    [CmdletBinding()]
    param (
        [string]$BaseFeedUrl = "https://thehackernews.com/feeds/posts/default",
        [DateTime]$StartDate,
        [DateTime]$EndDate,
        [int]$MaxPagesToFetch = 15
    )

    $ParsedNews = [System.Collections.Generic.List[object]]::new()
    $MaxResults = 150
    $StartIndex = 1

    # Format dates to RFC 3339 standard required by the Blogger API
    $PublishedMin = $StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $PublishedMax = $EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    for ($Page = 1; $Page -le $MaxPagesToFetch; $Page++) {
        # Build API request URL using pagination and published date parameters
        $FeedUrl = "$BaseFeedUrl`?alt=json&max-results=$MaxResults&start-index=$StartIndex&published-min=$PublishedMin&published-max=$PublishedMax"
        
        Write-Host "INFO: Fetching The Hacker News [Page $Page] (Range: $PublishedMin to $PublishedMax)..." -ForegroundColor Gray

        try {
            $Response = Invoke-RestMethod -Uri $FeedUrl -Method Get -Headers @{ "User-Agent" = "Mozilla/5.0" } -TimeoutSec 30
            $Entries = $Response.feed.entry
            
            # Stop paginating if no entries are returned
            if ($null -eq $Entries -or $Entries.Count -eq 0) {
                Write-Host "INFO: No more entries returned from API on page $Page." -ForegroundColor Gray
                break
            }

            foreach ($Entry in $Entries) {
                $RawDate = $Entry.published.'$t'
                $ArticleLink = ($Entry.link | Where-Object { $_.rel -eq "alternate" }).href

                $CleanIntro = ($Entry.summary.'$t' -replace '\s+', ' ').Trim()
                if ($CleanIntro) {
                    $CleanIntro = $CleanIntro.TrimEnd(" .…") + "..."
                }

                $NewsObj = [PSCustomObject]@{
                    Source       = "The Hacker News"
                    Title        = $Entry.title.'$t'
                    Introduction = $CleanIntro
                    PublishedAt  = ([DateTime]$RawDate).ToUniversalTime()
                    Url          = $ArticleLink
                }
                $ParsedNews.Add($NewsObj)
            }

            $StartIndex += $MaxResults
            Start-Sleep -Milliseconds 500
        }
        catch {
            Write-Warning "Failed to fetch The Hacker News feed on page $Page. Error: $($_)"
            break
        }
    }

    return ,$ParsedNews
}

# --- HELPER: BLEEPINGCOMPUTER INGESTION (STANDARD RSS) ---
function Get-BleepingComputerFeed {
    [CmdletBinding()]
    param (
        [string]$FeedUrl = "https://www.bleepingcomputer.com/feed/"
    )

    try {
        $Response = Invoke-RestMethod -Uri $FeedUrl -Method Get -TimeoutSec 30
        if (-not $Response) { return @() }

        $ParsedNews = [System.Collections.Generic.List[object]]::new()
        foreach ($Item in $Response) {
            $RawDate = $Item.pubDate
            
            $RawDescription = ""
            if ($Item.description -is [System.Xml.XmlElement]) {
                $RawDescription = $Item.description.InnerText
            } else {
                $RawDescription = $Item.description.ToString()
            }

            $CleanIntro = $RawDescription -replace '<[^>]+>', ''
            $CleanIntro = ($CleanIntro -replace '\s+', ' ').Trim()
            
            if ($CleanIntro) {
                $CleanIntro = $CleanIntro.TrimEnd(" .…") + "..."
            }

            $NewsObj = [PSCustomObject]@{
                Source       = "BleepingComputer"
                Title        = $Item.title
                Introduction = $CleanIntro
                PublishedAt  = ([DateTime]$RawDate).ToUniversalTime()
                Url          = $Item.link
            }
            $ParsedNews.Add($NewsObj)
        }
        return ,$ParsedNews
    }
    catch {
        Write-Warning "Failed to fetch BleepingComputer RSS feed. Error: $($_)"
        return @()
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
    
    # Force query execution on the Blogger API with calculated pagination limits
    $ThnData = Get-HackerNewsFeed -StartDate $StartDate -EndDate $EndDate -MaxPagesToFetch $PagesNeeded
    # Bleeping Computer only publishes recent entries via RSS; fetched and filtered locally
    $BcData = Get-BleepingComputerFeed

    $AllFetched = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $ThnData) { $AllFetched.AddRange($ThnData) }
    if ($null -ne $BcData) { $AllFetched.AddRange($BcData) }

    $NewArticles = 0
    foreach ($Article in $AllFetched) {
        $Exists = $CurrentDb | Where-Object { $_.Url -eq $Article.Url }
        if (-not $Exists) {
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

# --- HELPER: KEYWORD-BASED FILTERING WITH BLACKLIST FILTER ---
function Filter-NewsByKeywords {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
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

# --- HELPER: MARKDOWN REPORT GENERATOR ---
function Generate-MarkdownReport {
    param (
        [Parameter(Mandatory=$true)]$Data,
        [Parameter(Mandatory=$true)][string]$FileName,
        [Parameter(Mandatory=$true)][string]$Header
    )

    $ReportsFolder = Join-Path -Path $PSScriptRoot -ChildPath "reports"
    $MarkdownPath  = Join-Path -Path $ReportsFolder -ChildPath $FileName

    if (-not (Test-Path -Path $ReportsFolder)) {
        New-Item -Path $ReportsFolder -ItemType Directory | Out-Null
    }

    $TotalCount = @($Data).Count
    $ThnCount   = @($Data | Where-Object { $_.Source -eq "The Hacker News" }).Count
    $BcCount    = @($Data | Where-Object { $_.Source -eq "BleepingComputer" }).Count

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
    $Content.Add("| **The Hacker News** | $ThnCount |")
    $Content.Add("| **BleepingComputer** | $BcCount |")
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
        $Content.Add("*Source:* **$($Item.Source)** | *Published (UTC):* $($Item.PublishedAt.ToString('yyyy-MM-dd HH:mm:ssZ'))")
        $Content.Add("")
        $Content.Add("**Introduction:** $($Item.Introduction)")
        $Content.Add("")
        $Content.Add("**Url:** [$($Item.Url)]($($Item.Url))")
        $Content.Add("")
    }

    $Content | Out-File -FilePath $MarkdownPath -Encoding utf8 -Force
    Write-Host "SUCCESS: Report generated at $MarkdownPath" -ForegroundColor Green
}

# ==============================================================================
# --- MAIN FILTRATION & REPORT GENERATION FUNCTIONS (USER INTERFACE) ---
# ==============================================================================

# --- FILTER 1: SPECIFIC DATE REPORT ---
function Get-SpecificDateNews {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$TargetDate = ([DateTime]::UtcNow.Date).AddDays(-1).ToString("yyyy-MM-dd"),

        [string[]]$Keywords = $Global:TargetKeywords
    )

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
}

# --- FILTER 2: MONTHLY REPORT (DEFAULTS TO PREVIOUS MONTH IF OMITTED) ---
function Get-SpecificMonthNews {
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

    $OutputFileName = "CustomRange-Report-$RangeLabel.md"
    $HeaderTitle    = "Custom Range Security News Report ($($Start.ToString('yyyy-MM-dd')) to $((($End).AddDays(-1)).ToString('yyyy-MM-dd')))"

    Generate-MarkdownReport -Data $PriorityNews -FileName $OutputFileName -Header $HeaderTitle
}

# --- DAILY EXECUTION HELPER WRAPPER ---
function Get-DailyCyberNews {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$TargetDate
    )

    if ([string]::IsNullOrWhiteSpace($TargetDate)) {
        $TargetDate = ([DateTime]::UtcNow.Date).AddDays(-1).ToString("yyyy-MM-dd")
        Write-Host "INFO: No specific date provided. Fetching yesterday's entries: $TargetDate" -ForegroundColor Gray
    }

    Get-SpecificDateNews -TargetDate $TargetDate
}

# --- DEFAULT SCRIPT EXECUTION ---
# Runs daily checks for yesterday's data on script execution if no parameters are supplied
Get-DailyCyberNews
Get-SpecificMonthNews 
#Get-NewsByRange -StartDate "2026-05-01" -EndDate "2026-05-15"
