BeforeAll {
    . (Join-Path $PSScriptRoot "..\modules\Enrichment.ps1")

    # Mirrors the production config in IntelNewsFeed.ps1. Kept local to the test
    # file so this suite never dot-sources the orchestrator itself (which would
    # fire real network requests and file writes as a side effect).
    $Global:TargetKeywords = @(
        "malware", "0day", "0-day", "zeroday", "zero-day",
        "critical", "security flaw", "code execution",
        "cvss", "leak", "vulnerability", "takeover", "abused", "phishing",
        "ransomware", "exploit", "active attack"
    )
    $Global:BlacklistKeywords = @("webinar", "webminar", "weekly recap")
}

Describe "Get-ArticleCves" {
    It "extracts a single CVE as a proper array, not a collapsed scalar" {
        # Regression test: Get-ArticleCves used to `return @(...)` without the
        # leading comma, which PowerShell unrolls into a bare string when the
        # pipeline yields exactly one item. Locks that fix in place.
        $result = Get-ArticleCves -Text "Tracked as CVE-2026-58048 in the advisory."
        , $result | Should -BeOfType [array]
        $result.Count | Should -Be 1
        $result[0] | Should -Be "CVE-2026-58048"
    }

    It "extracts multiple unique CVEs, deduplicated" {
        $result = Get-ArticleCves -Text "See CVE-2026-1111 and CVE-2026-2222, also CVE-2026-1111 again."
        $result.Count | Should -Be 2
        $result | Should -Contain "CVE-2026-1111"
        $result | Should -Contain "CVE-2026-2222"
    }

    It "returns an empty array when there are no CVEs" {
        $result = Get-ArticleCves -Text "No identifiers in this sentence."
        @($result).Count | Should -Be 0
    }

    It "normalizes case to uppercase" {
        $result = Get-ArticleCves -Text "cve-2026-9999 mentioned in lowercase"
        $result[0] | Should -Be "CVE-2026-9999"
    }
}

Describe "Get-ArticleCvssScore" {
    It "parses the CVSS score format that includes a version number" {
        Get-ArticleCvssScore -Text "tracked as CVE-2026-58048 (CVSS 4.0 score: 9.4) and affects..." | Should -Be 9.4
    }

    It "parses the CVSS score format without a version number" {
        Get-ArticleCvssScore -Text "the vulnerability (CVSS score: 8.2) is a case of..." | Should -Be 8.2
    }

    It "returns null when no CVSS mention exists" {
        Get-ArticleCvssScore -Text "No score mentioned anywhere here." | Should -BeNullOrEmpty
    }
}

Describe "Get-ArticleSeverity" {
    It "returns Critical for a CVSS score of 9.0 or above" {
        Get-ArticleSeverity -Text "x" -CvssScore 9.4 | Should -Be "Critical"
    }

    It "returns High for a CVSS score between 7.0 and 8.9" {
        Get-ArticleSeverity -Text "x" -CvssScore 8.2 | Should -Be "High"
    }

    It "returns Medium for a CVSS score between 4.0 and 6.9" {
        Get-ArticleSeverity -Text "x" -CvssScore 5.0 | Should -Be "Medium"
    }

    It "returns Low for a CVSS score below 4.0" {
        Get-ArticleSeverity -Text "x" -CvssScore 2.0 | Should -Be "Low"
    }

    It "falls back to High for 0day-style keywords with no explicit CVSS" {
        Get-ArticleSeverity -Text "Attackers exploit new 0day in popular VPN appliance" | Should -Be "High"
    }

    It "falls back to Medium when only a general target keyword matches" {
        Get-ArticleSeverity -Text "Phishing service spoofs RingCentral to steal accounts" | Should -Be "Medium"
    }

    It "falls back to Low when nothing matches" {
        Get-ArticleSeverity -Text "Weekly recap of productivity tips for remote teams" | Should -Be "Low"
    }
}

Describe "Get-ArticleIOCs" {
    It "extracts an IPv4 address" {
        (Get-ArticleIOCs -Text "C2 server at 185.220.101.45 was observed").IPs | Should -Contain "185.220.101.45"
    }

    It "extracts an MD5 hash by exact length" {
        (Get-ArticleIOCs -Text "Sample hash 44d88612fea8a8f36de82e1278abb02f found").Hashes | Should -Contain "44d88612fea8a8f36de82e1278abb02f"
    }

    It "returns empty arrays, not null, when nothing technical is present" {
        $iocs = Get-ArticleIOCs -Text "Nothing technical in this journalistic summary."
        @($iocs.IPs).Count | Should -Be 0
        @($iocs.Hashes).Count | Should -Be 0
    }
}

Describe "Get-ArticleEnrichment" {
    It "matches the real cPanel example end to end" {
        $title = "New cPanel Critical Flaw Could Let Hosting Customers Run SQL as Database Root"
        $intro = "...tracked as CVE-2026-58048 (CVSS 4.0 score: 9.4) and affects..."
        $result = Get-ArticleEnrichment -Title $title -Introduction $intro

        $result.Severity | Should -Be "Critical"
        $result.Cvss | Should -Be 9.4
        $result.Cves.Count | Should -Be 1
        $result.Cves[0] | Should -Be "CVE-2026-58048"
    }
}

Describe "Filter-NewsByKeywords" {
    BeforeAll {
        $SampleNews = @(
            [PSCustomObject]@{ Title = "Critical RCE flaw disclosed in popular CMS" },
            [PSCustomObject]@{ Title = "Weekly recap: critical vulnerabilities of the week" },
            [PSCustomObject]@{ Title = "New coffee shop opens downtown" }
        )
    }

    It "keeps only articles matching a target keyword" {
        $result = Filter-NewsByKeywords -NewsList $SampleNews -Keywords $Global:TargetKeywords -Blacklist @()
        $result.Count | Should -Be 2
    }

    It "excludes blacklisted terms even when a target keyword also matches" {
        $result = Filter-NewsByKeywords -NewsList $SampleNews -Keywords $Global:TargetKeywords -Blacklist $Global:BlacklistKeywords
        $result.Count | Should -Be 1
        $result[0].Title | Should -Be "Critical RCE flaw disclosed in popular CMS"
    }

    It "returns an empty array for an empty input list" {
        $result = Filter-NewsByKeywords -NewsList @() -Keywords $Global:TargetKeywords
        @($result).Count | Should -Be 0
    }
}
