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
        $FeedUrl = "$BaseFeedUrl`?alt=json&max-results=$MaxResults&start-index=$StartIndex&published-min=$PublishedMin&published-max=$PublishedMax"
        
        Write-Host "INFO: Fetching The Hacker News [Page $Page] (Range: $PublishedMin to $PublishedMax)..." -ForegroundColor Gray

        try {
            $Response = Invoke-RestMethod -Uri $FeedUrl -Method Get -Headers @{ "User-Agent" = "Mozilla/5.0" } -TimeoutSec 30
            $Entries = $Response.feed.entry
            
            if ($null -eq $Entries -or $Entries.Count -eq 0) {
                Write-Host "INFO: No more entries returned from API on page $Page." -ForegroundColor Gray
                break
            }

            foreach ($Entry in $Entries) {
                $RawDate = $Entry.published.'$t'
                $ArticleLink = ($Entry.link | Where-Object { $_.rel -eq "alternate" }).href
                $CleanIntro = ($Entry.summary.'$t' -replace '\s+', ' ').Trim()
                if ($CleanIntro) { $CleanIntro = $CleanIntro.TrimEnd(" .…") + "..." }

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
    param ([string]$FeedUrl = "https://www.bleepingcomputer.com/feed/")

    try {
        $Response = Invoke-RestMethod -Uri $FeedUrl -Method Get -TimeoutSec 30
        if (-not $Response) { return @() }

        $ParsedNews = [System.Collections.Generic.List[object]]::new()
        foreach ($Item in $Response) {
            $RawDate = $Item.pubDate
            $RawDescription = if ($Item.description -is [System.Xml.XmlElement]) { $Item.description.InnerText } else { $Item.description.ToString() }
            $CleanIntro = ($RawDescription -replace '<[^>]+>', '' -replace '\s+', ' ').Trim()
            if ($CleanIntro) { $CleanIntro = $CleanIntro.TrimEnd(" .…") + "..." }

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

# --- SINK: FEED SYNCHRONIZATION ---
function Sync-FeedsToDatabase {
    param ([Parameter(Mandatory=$true)][DateTime]$StartDate, [Parameter(Mandatory=$true)][DateTime]$EndDate)

    $CurrentDb = Get-LocalDatabase
    if ($null -eq $CurrentDb) { $CurrentDb = [System.Collections.Generic.List[object]]::new() }

    $DaysDifference = ($EndDate - $StartDate).TotalDays
    $PagesNeeded = if ($DaysDifference -gt 10) { 20 } else { 3 }

    Write-Host "INFO: Syncing data range: $($StartDate.ToString('yyyy-MM-dd')) to $($EndDate.ToString('yyyy-MM-dd')) (Pages: $PagesNeeded)..." -ForegroundColor Cyan
    
    $ThnData = Get-HackerNewsFeed -StartDate $StartDate -EndDate $EndDate -MaxPagesToFetch $PagesNeeded
    $BcData = Get-BleepingComputerFeed

    $AllFetched = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $ThnData) { $AllFetched.AddRange($ThnData) }
    if ($null -ne $BcData) { $AllFetched.AddRange($BcData) }

    $NewArticles = 0
    foreach ($Article in $AllFetched) {
        if (-not ($CurrentDb | Where-Object { $_.Url -eq $Article.Url })) {
            $CurrentDb.Add($Article)
            $NewArticles++
        }
    }

    if ($NewArticles -gt 0) {
        Save-LocalDatabase -Database ($CurrentDb | Sort-Object PublishedAt -Descending)
        Write-Host "INFO: Added $NewArticles new articles." -ForegroundColor Green
    }
}

# --- HELPER: FILTERING (WITH BLACKLIST) ---
function Filter-NewsByKeywords {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][array]$NewsList, [Parameter(Mandatory=$true)][string[]]$Keywords, [string[]]$Blacklist = $Global:BlacklistKeywords)

    if ($NewsList.Count -eq 0) { return @() }
    $Pattern = ($Keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $FilteredList = $NewsList | Where-Object { $_.Title -match $Pattern }

    if ($null -ne $Blacklist -and $Blacklist.Count -gt 0) {
        $BlacklistPattern = ($Blacklist | ForEach-Object { [regex]::Escape($_) }) -join '|'
        $FilteredList = $FilteredList | Where-Object { $_.Title -notmatch $BlacklistPattern }
    }
    return $FilteredList
}

# --- HELPER: MARKDOWN GENERATOR ---
function Generate-MarkdownReport {
    param ([Parameter(Mandatory=$true)]$Data, [Parameter(Mandatory=$true)][string]$FileName, [Parameter(Mandatory=$true)][string]$Header)

    $ReportsFolder = Join-Path -Path $PSScriptRoot -ChildPath "reports"
    if (-not (Test-Path -Path $ReportsFolder)) { New-Item -Path $ReportsFolder -ItemType Directory | Out-Null }
    
    $Content = New-Object System.Collections.Generic.List[string]
    $Content.Add("# $Header`n`nThis cyber intelligence report aggregates critical, filtered news.")
    $Content.Add("## Security News Findings`n")
    
    foreach ($Item in $Data) {
        $Content.Add("---`n### $($Item.Title)`n*Source:* **$($Item.Source)** | *Published (UTC):* $($Item.PublishedAt.ToString('yyyy-MM-dd HH:mm:ssZ'))`n`n**Introduction:** $($Item.Introduction)`n`n**Url:** [$($Item.Url)]($($Item.Url))`n")
    }

    $Content | Out-File -FilePath (Join-Path $ReportsFolder $FileName) -Encoding utf8 -Force
    Write-Host "SUCCESS: Report generated at $(Join-Path $ReportsFolder $FileName)" -ForegroundColor Green
}

# --- FILTERS ---
function Get-SpecificDateNews {
    [CmdletBinding()]
    param ([string]$TargetDate = ([DateTime]::UtcNow.Date).AddDays(-1).ToString("yyyy-MM-dd"), [string[]]$Keywords = $Global:TargetKeywords)
    $Start = [DateTime]$TargetDate; $End = $Start.AddDays(1)
    Sync-FeedsToDatabase -StartDate $Start -EndDate $End
    $PriorityNews = Filter-NewsByKeywords -NewsList (Get-LocalDatabase | Where-Object { $_.PublishedAt -ge $Start -and $_.PublishedAt -lt $End }) -Keywords $Keywords
    if ($PriorityNews) { Generate-MarkdownReport -Data $PriorityNews -FileName "$TargetDate.md" -Header "Daily Security News: $TargetDate" }
}

function Get-SpecificMonthNews {
    [CmdletBinding()]
    param ([string]$TargetMonth, [string[]]$Keywords = $Global:TargetKeywords)
    if (-not $TargetMonth) { $TargetMonth = ([DateTime]::UtcNow).AddMonths(-1).ToString("yyyy-MM") }
    $Start = [DateTime]"$TargetMonth-01"; $End = $Start.AddMonths(1)
    Sync-FeedsToDatabase -StartDate $Start -EndDate $End
    $PriorityNews = Filter-NewsByKeywords -NewsList (Get-LocalDatabase | Where-Object { $_.PublishedAt -ge $Start -and $_.PublishedAt -lt $End }) -Keywords $Keywords
    if ($PriorityNews) { Generate-MarkdownReport -Data $PriorityNews -FileName "Monthly-Report-$TargetMonth.md" -Header "Monthly Security News: $TargetMonth" }
}

function Get-NewsByRange {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true)][string]$StartDate, [Parameter(Mandatory=$true)][string]$EndDate, [string[]]$Keywords = $Global:TargetKeywords)
    $Start = [DateTime]$StartDate; $End = ([DateTime]$EndDate).Date.AddDays(1)
    Sync-FeedsToDatabase -StartDate $Start -EndDate $End
    $PriorityNews = Filter-NewsByKeywords -NewsList (Get-LocalDatabase | Where-Object { $_.PublishedAt -ge $Start -and $_.PublishedAt -lt $End }) -Keywords $Keywords
    if ($PriorityNews) { 
        $FileName = "Range-Report-$($StartDate)-to-$($EndDate).md"
        Generate-MarkdownReport -Data $PriorityNews -FileName $FileName -Header "Custom Range Report ($StartDate to $EndDate)" 
    }
}

# Execution
Get-SpecificDateNews
Get-SpecificMonthNews
