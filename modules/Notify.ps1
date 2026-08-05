# ==============================================================================
# Module: Notify.ps1
# Description: Email alerting for Critical/High severity findings. Reads SMTP
#              config from environment variables so it works unchanged both
#              locally and in GitHub Actions (secrets injected as env vars).
#              Silently no-ops when SMTP isn't configured, so it never breaks
#              a run for someone who hasn't set up alerting.
# ==============================================================================

# --- NOTIFY: EMAIL ALERT FOR TODAY'S CRITICAL/HIGH FINDINGS ---
function Send-SeverityAlertEmail {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Articles
    )

    $AlertArticles = @($Articles | Where-Object { $_.Severity -in @("Critical", "High") })
    if ($AlertArticles.Count -eq 0) {
        Write-Host "INFO: No Critical/High findings in this report; no alert email needed." -ForegroundColor Gray
        return
    }

    $SmtpServer   = $env:SMTP_SERVER
    $SmtpPort     = if ($env:SMTP_PORT) { [int]$env:SMTP_PORT } else { 587 }
    $SmtpUser     = $env:SMTP_USER
    $SmtpPassword = $env:SMTP_PASS
    $ToAddress    = $env:ALERT_EMAIL_TO

    if (-not ($SmtpServer -and $SmtpUser -and $SmtpPassword -and $ToAddress)) {
        Write-Host "INFO: $($AlertArticles.Count) Critical/High finding(s), but SMTP_SERVER/SMTP_USER/SMTP_PASS/ALERT_EMAIL_TO aren't fully configured — skipping alert email." -ForegroundColor Yellow
        return
    }

    $SortedAlerts = $AlertArticles | Sort-Object PublishedAt -Descending
    $Subject = "[Intel News Feed] $($AlertArticles.Count) achado(s) Critical/High - $(([DateTime]::UtcNow).ToString('yyyy-MM-dd'))"

    $BodyLines = [System.Collections.Generic.List[string]]::new()
    $BodyLines.Add("Foram encontrados $($AlertArticles.Count) artigo(s) de severidade Critical ou High:")
    $BodyLines.Add("")
    foreach ($Article in $SortedAlerts) {
        $CveSuffix = if ($Article.Cves -and @($Article.Cves).Count -gt 0) {
            " | CVEs: $((@($Article.Cves)) -join ', ')"
        } else { "" }
        $BodyLines.Add("[$($Article.Severity)] $($Article.Title)")
        $BodyLines.Add("  Fonte: $($Article.Source) | Publicado (UTC): $($Article.PublishedAt.ToString('yyyy-MM-dd HH:mm:ssZ'))$CveSuffix")
        $BodyLines.Add("  $($Article.Url)")
        $BodyLines.Add("")
    }
    $Body = $BodyLines -join "`n"

    if ($PSCmdlet.ShouldProcess($ToAddress, "Send Critical/High security alert email ($Subject)")) {
        $SecurePassword = ConvertTo-SecureString -String $SmtpPassword -AsPlainText -Force
        $Credential = [System.Management.Automation.PSCredential]::new($SmtpUser, $SecurePassword)

        try {
            Send-MailMessage -SmtpServer $SmtpServer -Port $SmtpPort -UseSsl `
                -From $SmtpUser -To $ToAddress -Subject $Subject -Body $Body `
                -Credential $Credential -ErrorAction Stop
            Write-Host "SUCCESS: Alert email sent to $ToAddress ($($AlertArticles.Count) finding(s))." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to send alert email. Error: $($_)"
        }
    }
}
