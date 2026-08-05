# ==============================================================================
# Module: Sources.ps1
# Description: Feed ingestion functions and the registry of RSS sources.
#              Add a new plain-RSS source by appending to $Global:RssSources —
#              Get-RssFeed handles the rest.
# ==============================================================================

$Global:RssSources = @(
    @{ Name = "BleepingComputer"; Url = "https://www.bleepingcomputer.com/feed/" },
    @{ Name = "Krebs on Security"; Url = "https://krebsonsecurity.com/feed/" },
    @{ Name = "Dark Reading"; Url = "https://www.darkreading.com/rss.xml" },
    @{ Name = "CISA Advisories"; Url = "https://www.cisa.gov/cybersecurity-advisories/all.xml" }
)

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

# --- HELPER: SAFELY UNWRAP RSS TEXT NODES (SOME SOURCES WRAP VALUES IN CDATA,
#     WHICH INVOKE-RESTMETHOD SURFACES AS AN XmlElement INSTEAD OF A STRING) ---
function Get-RssNodeText {
    param ($Node)
    if ($null -eq $Node) { return "" }
    if ($Node -is [System.Xml.XmlElement]) { return $Node.InnerText }
    return $Node.ToString()
}

# --- HELPER: GENERIC RSS INGESTION (ANY STANDARD RSS 2.0 SOURCE) ---
function Get-RssFeed {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FeedUrl,

        [Parameter(Mandatory=$true)]
        [string]$SourceName
    )

    try {
        $Response = Invoke-RestMethod -Uri $FeedUrl -Method Get -TimeoutSec 30
        if (-not $Response) { return @() }

        $ParsedNews = [System.Collections.Generic.List[object]]::new()
        foreach ($Item in $Response) {
            $RawDate = Get-RssNodeText $Item.pubDate
            $RawDescription = Get-RssNodeText $Item.description

            $CleanIntro = $RawDescription -replace '<[^>]+>', ''
            $CleanIntro = ($CleanIntro -replace '\s+', ' ').Trim()

            if ($CleanIntro) {
                $CleanIntro = $CleanIntro.TrimEnd(" .…") + "..."
            }

            $NewsObj = [PSCustomObject]@{
                Source       = $SourceName
                Title        = Get-RssNodeText $Item.title
                Introduction = $CleanIntro
                PublishedAt  = ([DateTime]$RawDate).ToUniversalTime()
                Url          = Get-RssNodeText $Item.link
            }
            $ParsedNews.Add($NewsObj)
        }
        return ,$ParsedNews
    }
    catch {
        Write-Warning "Failed to fetch RSS feed '$SourceName' ($FeedUrl). Error: $($_)"
        return @()
    }
}
