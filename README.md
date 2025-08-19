# CyberTrace

Python Threat Intelligence Log Analyzer — Enrich Indicators of Compromise (IOCs) with:

DNS lookups

WHOIS data

URLhaus malware feed

AlienVault OTX threat intel

Store results in SQLite

Generate structured reports

CyberTrace helps analysts quickly process raw log files, correlate with external threat feeds, and produce actionable intelligence

# Features

Parse .log and .txt files containing suspicious domains, IPs, or URLs

Enrich IOCs with DNS resolution and WHOIS registration data

Query external threat intelligence feeds (URLhaus, OTX)

Store results in SQLite for easy querying

Export human-readable reports and structured data

Lightweight, easy to deploy (Python-based, no heavy dependencies)

# Configuration

Create a settings.yaml in the root folder:

otx_api_key: "YOUR-OTX-API-KEY"

report_format: "html"

db_path: "cybertrace.sqlite3"

# Example Workflow

Drop .log or .txt files into sample_logs/

Run cybertrace.py to process IOCs

Enriched IOCs are stored in SQLite

Export reports (HTML/CSV) for analysts


# Contributing

Contributions are welcome! Please fork the repo and open a pull request with improvements.







