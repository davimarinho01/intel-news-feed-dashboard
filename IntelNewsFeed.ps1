# ==============================================================================
# Script: Intel-News-Feed.ps1
# Author: Bruno Ricci
# Description: Automated multi-source cyber threat intelligence aggregator
#              supporting The Hacker News and BleepingComputer.
# ==============================================================================

# --- CONFIGURAÇÃO GLOBAL DE PALAVRAS-CHAVE ---
$Global:TargetKeywords = @(
    "malware", "0day", "0-day", "zeroday", "zero-day", 
    "critical", "security flaw", "code execution", 
    "cvss", "leak", "vulnerability", "takeover", "abused", "phishing",
    "ransomware", "exploit", "active attack"
)

# --- AUXILIAR: THE HACKER NEWS INGESTION ---
function Get-HackerNewsFeed {
    [CmdletBinding()]
    param (
        [string]$FeedUrl = "https://thehackernews.com/feeds/posts/default?alt=json"
    )

    try {
        $Response = Invoke-RestMethod -Uri $FeedUrl -Method Get -Headers @{ "User-Agent" = "Mozilla/5.0" } -TimeoutSec 30
        $Entries = $Response.feed.entry
        if (-not $Entries) { return @() }

        $ParsedNews = [System.Collections.Generic.List[object]]::new()
        foreach ($Entry in $Entries) {
            $RawDate = $Entry.published.'$t'
            $ArticleLink = ($Entry.link | Where-Object { $_.rel -eq "alternate" }).href

            # Limpa o texto e garante que termine com reticências limpas
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
        return $ParsedNews
    }
    catch {
        Write-Warning "Falha ao obter feed do The Hacker News: $_"
        return @()
    }
}

# --- AUXILIAR: BLEEPINGCOMPUTER INGESTION ---
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
            
            # Garante extração de string limpa caso o motor retorne XmlElement
            $RawDescription = ""
            if ($Item.description -is [System.Xml.XmlElement]) {
                $RawDescription = $Item.description.InnerText
            } else {
                $RawDescription = $Item.description.ToString()
            }

            $CleanIntro = $RawDescription -replace '<[^>]+>', ''
            $CleanIntro = ($CleanIntro -replace '\s+', ' ').Trim()
            
            # Limpa pontuações órfãs no final e adiciona reticências padronizadas
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
        return $ParsedNews
    }
    catch {
        Write-Warning "Falha ao obter feed oficial do BleepingComputer: $_"
        return @()
    }
}

# --- AUXILIAR: FILTRAGEM POR PALAVRAS-CHAVE ---
function Filter-NewsByKeywords {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$NewsList,

        [Parameter(Mandatory=$true)]
        [string[]]$Keywords
    )

    if ($NewsList.Count -eq 0) { return @() }

    $EscapedKeywords = $Keywords | ForEach-Object { [regex]::Escape($_) }
    $Pattern = $EscapedKeywords -join '|'

    $FilteredList = $NewsList | Where-Object { $_.Title -match $Pattern }
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

    # Mapeamento de termos mais incidentes nos títulos recolhidos
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

    # Estruturação do Relatório Markdown
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
        # Hierarquia: Título principal (H3)
        $Content.Add("### $($Item.Title)")
        $Content.Add("")
        # Source e Date unificados de forma discreta
        $Content.Add("*Source:* **$($Item.Source)** | *Published (UTC):* $($Item.PublishedAt.ToString('yyyy-MM-dd HH:mm:ssZ'))")
        $Content.Add("")
        $Content.Add("**Introduction:** $($Item.Introduction)")
        $Content.Add("")
        $Content.Add("**Url:** [$($Item.Url)]($($($Item.Url)))")
        $Content.Add("")
    }

    $Content | Out-File -FilePath $MarkdownPath -Encoding utf8 -Force
    Write-Host "SUCCESS: Report generated at $MarkdownPath" -ForegroundColor Green
}

# --- FUNÇÃO 1: RELATÓRIO DIÁRIO (ONTEM UTC) ---
function Get-DailyCyberNews {
    [CmdletBinding()]
    param (
        [string[]]$Keywords = $Global:TargetKeywords
    )

    $OntemStr = ([DateTime]::UtcNow.Date).AddDays(-1).ToString("yyyy-MM-dd")
    Get-SpecificDateCyberNews -TargetDate $OntemStr -Keywords $Keywords
}

# --- FUNÇÃO 2: RELATÓRIO DE DATA ESPECÍFICA ---
function Get-SpecificDateCyberNews {
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

    Write-Host "INFO: Aggregating feeds..." -ForegroundColor Cyan
    
    $AllFeeds = [System.Collections.Generic.List[object]]::new()
    
    $ThnData = Get-HackerNewsFeed
    if ($null -ne $ThnData -and $ThnData.Count -gt 0) {
        $AllFeeds.AddRange($ThnData)
    }

    $BcData = Get-BleepingComputerFeed
    if ($null -ne $BcData -and $BcData.Count -gt 0) {
        $AllFeeds.AddRange($BcData)
    }

    if ($AllFeeds.Count -eq 0) {
        Write-Warning "Nenhum dado pôde ser coletado das fontes externas."
        return
    }

    Write-Host "INFO: Filtering articles published on: $($TargetDateParsed.ToString('yyyy-MM-dd')) (UTC)" -ForegroundColor Cyan
    $DateFiltered = $AllFeeds | Where-Object { 
        $_.PublishedAt -ge $TargetDateParsed -and $_.PublishedAt -lt $NextDayParsed 
    }

    if ($DateFiltered.Count -eq 0) {
        Write-Host "INFO: No articles published on this date in UTC." -ForegroundColor Yellow
        return
    }

    $PriorityNews = Filter-NewsByKeywords -NewsList $DateFiltered -Keywords $Keywords

    if ($PriorityNews.Count -eq 0) {
        Write-Host "INFO: $($DateFiltered.Count) articles found, but zero matches for security keywords." -ForegroundColor Yellow
        return
    }

    # O arquivo gerado assume exatamente o nome da data em formato YYYY-MM-DD
    $OutputFileName = "$($TargetDateParsed.ToString('yyyy-MM-dd')).md"
    $HeaderTitle    = "Daily Security News Report: $($TargetDateParsed.ToString('yyyy-MM-dd'))"

    Generate-MarkdownReport -Data $PriorityNews -FileName $OutputFileName -Header $HeaderTitle
}

# --- EXECUÇÃO ---
Get-DailyCyberNews
