# CTI Pipeline - OSINT Collection Script

## Overview
This Python script collects Cyber Threat Intelligence (CTI) data from open-source intelligence (OSINT) feeds and stores them in Notion databases.

## Data Sources

### 1. CISA KEV (Known Exploited Vulnerabilities)
- **Source**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **Description**: CISA's catalog of vulnerabilities known to be exploited in the wild
- **Fields Collected**:
  - CVE ID
  - Vendor/Project
  - Product
  - Vulnerability Name
  - Date Added
  - Short Description
  - Required Action
  - Due Date
  - Known Ransomware Campaign Usage
  - Notes

### 2. EPSS (Exploit Prediction Scoring System)
- **Source**: https://api.first.org/data/v1/epss
- **Description**: FIRST.org's probability scores for CVE exploitation
- **Fields Collected**:
  - CVE ID
  - EPSS Score (0-1 range)
  - Percentile Ranking
  - Date of Score

## Environment Variables

### Required
- `NOTION_TOKEN`: Notion API integration token

### Optional
- `DB_RUNLOG` or `NOTION_DB_RUN_LOG`: Database ID for run logs
- `DB_KEV`: Database ID for KEV entries
- `DB_EPSS`: Database ID for EPSS scores
- `HTTP_TIMEOUT`: Timeout for HTTP requests (default: 180 seconds)
- `MAX_KEV`: Maximum number of KEV entries to process (0 = all, default: 0)
- `MAX_EPSS`: Maximum number of EPSS scores to fetch (0 = all, default: 0)
- `VERBOSE`: Enable detailed logging (set to "1" to enable)

## Usage

### Basic Usage
```bash
python scripts/ingest_cti.py
```

### With Limits (for testing)
```bash
MAX_KEV=5 MAX_EPSS=50 VERBOSE=1 python scripts/ingest_cti.py
```

### GitHub Actions
The script runs automatically via GitHub Actions on a daily schedule:
- Schedule: 12:00 UTC daily
- Can also be triggered manually via workflow_dispatch

## Features

### Data Collection
- **Automatic Deduplication**: Checks for existing CVEs before creating new entries
- **Batch Processing**: EPSS queries are batched (100 CVEs per request) for efficiency
- **Cross-linking**: EPSS scores are automatically linked to their corresponding KEV entries
- **Error Handling**: Gracefully handles network errors and continues processing

### Notion Integration
- Creates new database entries for KEV and EPSS data
- Updates existing entries when data changes
- Links EPSS scores to KEV entries via relations
- Handles field truncation (2000 character limit)

### Logging & Monitoring
- Logs all operations to stdout
- Creates timestamped log files in `logs/` directory
- Writes run metadata to Notion (counts, duration, health status)
- Tracks SLA status: Healthy (≤15min), Warning (≤30min), Failed (>30min)

## Database Schema

### KEV Database
Properties expected:
- `CVE ID` (title)
- `Vendor/Project` (rich_text)
- `Product` (rich_text)
- `Vulnerability Name` (rich_text)
- `Date Added` (date)
- `Short Description` (rich_text)
- `Required Action` (rich_text)
- `Due Date` (date)
- `Known Ransomware` (checkbox)
- `Notes` (rich_text)

### EPSS Database
Properties expected:
- `CVE ID` (title)
- `EPSS Score` (number)
- `Percentile` (number)
- `Date` (date)
- `KEV Reference` (relation to KEV database)

### Run Log Database
Properties expected:
- `Run Title` (title)
- `Timestamp` (date)
- `Source` (select)
- `KEV Created` (number)
- `KEV Updated` (number)
- `EPSS Created` (number)
- `EPSS Updated` (number)
- `Linked` (number)
- `Duration (m)` (number)
- `Build SHA` (rich_text)
- `Logs URL` (url)
- `Health Status` (select)
- `Details` (rich_text)
- `Errors` (rich_text)

## Error Handling

The script includes comprehensive error handling:
- Network errors during data fetching are logged and raised
- Failed EPSS batches are logged but processing continues
- Notion API errors are caught and logged
- Failed runs write error logs to Notion and exit with code 1

## Dependencies

- Python 3.11+
- `requests>=2.31.0` (for HTTP requests)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Testing

The script has been tested with:
- Unit tests for data structure validation
- Notion property structure verification
- CVE mapping logic validation
- Field truncation logic

## Security

- ✅ CodeQL analysis: 0 vulnerabilities
- ✅ Dependency scanning: 0 known CVEs
- ✅ Secrets managed via environment variables
- ✅ HTTPS connections for all external API calls

## Troubleshooting

### No Data Collected
- Check `NOTION_TOKEN` is set correctly
- Verify `DB_KEV` and `DB_EPSS` database IDs are correct
- Check network connectivity to external APIs

### API Rate Limiting
- Use `MAX_KEV` and `MAX_EPSS` to limit processing
- EPSS API has no documented rate limits but batches are limited to 100 CVEs

### Notion API Errors
- Ensure database schemas match expected properties
- Check Notion integration has access to the databases
- Verify date fields don't contain empty strings

## License

This project is part of the CTI pipeline for OSINT collection.
