# ==============================================================================
# Script: Intel-News-Feed.ps1
# Author: Bruno Ricci
# Description: Automated multi-source cyber threat intelligence aggregator
#              supporting Local DB Caching, Target-Date Web Fetching, and reports.
# ==============================================================================

# --- CONFIGURAÇÃO GLOBAL DE PALAVRAS-CHAVE ---
$Global:TargetKeywords = @(
    "malware", "0day", "0-day", "zeroday", "zero-day", 
    "critical", "security flaw", "code execution", 
    "cvss", "leak", "vulnerability", "takeover", "abused", "phishing",
    "ransomware", "exploit", "active attack"
)

# --- CONFIGURAÇÃO GLOBAL DA BLACKLIST ---
$Global:BlacklistKeywords = @(
    "webinar", "webminar", "weekly recap"
)

# --- CAMINHOS DE ARQUIVOS ---
$Global:DbPath = Join-Path -Path $PSScriptRoot -ChildPath "feed_database.json"

# --- AUXILIAR: CARREGAR / SALVAR BANCO DE DADOS LOCAL ---
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
            Write-Warning "Falha ao ler banco de dados local. Iniciando novo banco de dados. Erro: $($_)"
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
        Write-Error "Falha ao salvar banco de dados local. Erro: $($_)"
    }
}

# --- AUXILIAR: THE HACKER NEWS INGESTION (FILTRADO POR DATA E PAGINADO) ---
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
            Write-Warning "Falha ao obter feed do The Hacker News na página $Page. Erro: $($_)"
            break
        }
    }

    return ,$ParsedNews
}

# --- AUXILIAR: BLEEPINGCOMPUTER INGESTION (RSS PADRÃO) ---
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
        Write-Warning "Falha ao obter feed oficial do BleepingComputer. Erro: $($_)"
        return @()
    }
}

# --- SINK: SINCRONIZAÇÃO DE FEEDS ---
function Sync-FeedsToDatabase {
    param (
        [Parameter(Mandatory=$true)][DateTime]$StartDate,
        [Parameter(Mandatory=$true)][DateTime]$EndDate
    )

    $CurrentDb = Get-LocalDatabase
    if ($null -eq $CurrentDb) {
        $CurrentDb = [System.Collections.Generic.List[object]]::new()
    }

    $DaysDifference = ($EndDate - $StartDate).TotalDays
    $PagesNeeded = 3
    if ($DaysDifference -gt 10) {
        $PagesNeeded = 20 
    }

    Write-Host "INFO: Requesting data from web for range: $($StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndDate.ToString('yyyy-MM-dd HH:mm:ss')) (Depth Pages: $PagesNeeded)..." -ForegroundColor Cyan
    
    $ThnData = Get-HackerNewsFeed -StartDate $StartDate -EndDate $EndDate -MaxPagesToFetch $PagesNeeded
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

# --- AUXILIAR: FILTRAGEM POR PALAVRAS-CHAVE E BLACKLIST ---
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

    $EscapedKeywords = $Keywords | ForEach-Object { [regex]::Escape($_) }
    $Pattern = $EscapedKeywords -join '|'

    # Aplica filtro positivo
    $FilteredList = $NewsList | Where-Object { $_.Title -match $Pattern }

    # Aplica filtro negativo (Blacklist)
    if ($null -ne $Blacklist -and $Blacklist.Count -gt 0) {
        $EscapedBlacklist = $Blacklist | ForEach-Object { [regex]::Escape($_) }
        $BlacklistPattern = $EscapedBlacklist -join '|'
        $FilteredList = $FilteredList | Where-Object { $_.Title -notmatch $BlacklistPattern }
    }

    return $FilteredList
}

# --- AUXILIAR: GERADOR DE RELATÓRIO MARKDOWN ---
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

    # Sumário Executivo
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

    # Detalhamento dos Registros
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
# --- FUNÇÕES DE FILTRAGEM E GERAÇÃO DE RELATÓRIO (INTERFACE DO USUÁRIO) ---
# ==============================================================================

# --- FILTRO 1: DATA ESPECÍFICA ---
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
        Write-Error "Formato de data inválido ($TargetDate). Use o padrão YYYY-MM-DD."
        return
    }

    Sync-FeedsToDatabase -StartDate $TargetDateParsed -EndDate $NextDayParsed

    $LocalDb = Get-LocalDatabase
    
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

# --- FILTRO 2: RELATÓRIO MENSAL ---
function Get-SpecificMonthNews {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetMonth,

        [string[]]$Keywords = $Global:TargetKeywords
    )

    try {
        $StartOfMonth = [DateTime]"$TargetMonth-01"
        $EndOfMonth   = $StartOfMonth.AddMonths(1)
    }
    catch {
        Write-Error "Formato de mês inválido ($TargetMonth). Use o padrão YYYY-MM."
        return
    }

    Sync-FeedsToDatabase -StartDate $StartOfMonth -EndDate $EndOfMonth

    $LocalDb = Get-LocalDatabase
    $MonthLabel = $StartOfMonth.ToString("yyyy-MM")

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

# --- FILTRO 3: INTERVALO CUSTOMIZADO ---
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
        Write-Error "Formato de datas inválido. Use o padrão YYYY-MM-DD para ambas as datas."
        return
    }

    if ($Start -gt $End) {
        Write-Error "A data inicial ($StartDate) não pode ser posterior à data final ($EndDate)."
        return
    }

    Sync-FeedsToDatabase -StartDate $Start -EndDate $End

    $LocalDb = Get-LocalDatabase
    $RangeLabel = "$($Start.ToString('yyyyMMdd'))-to-$((($End).AddDays(-1)).ToString('yyyyMMdd'))"

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

# --- HELPER DE EXECUÇÃO DIÁRIA ---
function Get-DailyCyberNews {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$TargetDate
    )

    if ([string]::IsNullOrWhiteSpace($TargetDate)) {
        $TargetDate = ([DateTime]::UtcNow.Date).AddDays(-1).ToString("yyyy-MM-dd")
        Write-Host "INFO: Nenhuma data especificada. Buscando notícias de ontem: $TargetDate" -ForegroundColor Gray
    }

    Get-SpecificDateNews -TargetDate $TargetDate
}

# --- EXECUÇÃO PADRÃO ---
Get-DailyCyberNews
Get-SpecificMonthNews
Get-NewsByRange -StartDate "2026-05-01" -EndDate "2026-05-15"
