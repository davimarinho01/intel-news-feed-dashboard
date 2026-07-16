# Intel News Feed 📰

Automated Threat Intelligence tool that aggregates, filters, and reports on the latest cybersecurity news from trusted industry sources.

## 🚀 Overview

This project provides an automated pipeline to monitor and track the cybersecurity landscape. The script performs the following tasks:

1. **Ingests** data from multiple security news sources (The Hacker News, BleepingComputer).
2. **Filters** news based on a curated list of high-priority security keywords (e.g., "0day", "ransomware", "critical").
3. **Excludes** noise using a pre-defined blacklist.
4. **Generates** clean Markdown reports in the `reports/` directory with an executive summary and technical highlights.

## 🛠️ Technology Stack

- **Language:** PowerShell (Core)
- **Automation:** GitHub Actions (CI/CD)
- **Intelligence Sources:** The Hacker News & BleepingComputer
- **Output:** Markdown (.md) reports

## 📖 Usage & Functions

The script supports the following reporting modes:

### Daily Report
Checks for news published on a specific date (defaults to yesterday if no date is provided).

```
Get-NewsByDate -TargetDate "2026-07-15"
```
### Monthly Summary
Aggregates all relevant security news published during a specific month.
```
Get-NewsByMonth -TargetMonth "2026-06"
```
### Custom Range
Generates a report for a specific window of time.
```
Get-NewsByRange -StartDate "2026-07-01" -EndDate "2026-07-15"
```

## 📋 Report Structure
Each generated report includes an Executive Summary and detailed findings per article:

- Metric Table: Total count of news and source breakdown.
- Top Mentions: Analysis of most frequent threat indicators identified.
- Article Details:
  - Title of the News.
  - Source and precise UTC publication timestamp.
  - Brief introduction/summary.
  - Direct URL for deeper investigation.

## 🤖 Automation Schedule

The feed is configured to run automatically via GitHub Actions:

- **Schedule:** Daily at `03:00 AM UTC`.  
 
 ## 📂 Project Structure
```
├── reports/                # History of generated daily/monthly/range reports
├── feed_database.json      # Local cache of ingested security articles
├── Intel-News-Feed.ps1     # Main PowerShell logic
└── README.md               # Project documentation
```

## 👤 Author
**Bruno Ricci, CISSP, OSCP, PMP**  
*Cybersecurity Specialist | Technical Author*  
- **Website:** [techexpert.tips](https://techexpert.tips)
- **LinkedIn:** [linkedin.com/in/brunoricci/](https://www.linkedin.com/in/brunoricci/)
- **Books:** [Network](https://www.amazon.com.br/Network-Project-HP-Switch-Ricci/dp/153529387X) | [Linux](https://www.amazon.com.br/Slackware-Linux-Pratico-Bruno-Ricci/dp/8573933739) | [Proxy](https://www.amazon.com.br/Squid-Solucao-Definitiva-Nelson-Mendonca/dp/8573935235) | [VPN](https://www.amazon.com.br/Rede-Segura-Linux-Bruno-Ricci/dp/8573935839/) 

