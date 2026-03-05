# PRISM Dashboard

Simple web-based security dashboard for visualizing vulnerability trends.

## Features

- 📊 **Real-time Metrics**: Total scans, average vulnerabilities, risk scores
- 📈 **Trend Charts**: Track vulnerabilities and risk over time
- 🎯 **Severity Distribution**: Visual breakdown by severity level
- ⚡ **CVSS Tracking**: Monitor maximum CVSS scores across scans

## Setup

### 1. Generate Dashboard Data

Run scans to populate dashboard data:

```bash
python -m agent.main samples/sample_sbom.json --output scan-output
```

The scan will automatically log results to `dashboard_data/scan_history.json`.

### 2. View Dashboard

Simply open the dashboard in a browser:

```bash
# Option 1: Direct file access
start dashboard/index.html

# Option 2: Simple HTTP server (recommended)
python -m http.server 8000
# Then visit: http://localhost:8000/dashboard/
```

## Dashboard Components

### Summary Metrics
- **Total Scans**: Number of security scans performed
- **Avg Vulnerabilities**: Average vulnerabilities per scan
- **Avg Risk Score**: Average risk score (0-10 scale)
- **Highest Risk**: Maximum risk score detected

### Charts
1. **Vulnerability Trend**: Line chart showing vulnerability counts over time
2. **Severity Distribution**: Pie chart of vulnerability severities
3. **Risk Score Trend**: Line chart of risk scores over time
4. **CVSS Score Trend**: Bar chart of maximum CVSS scores

## Data Storage

Dashboard data is stored in JSON format:
- `dashboard_data/scan_history.json` - Historical scan results
- `dashboard_data/dashboard_data.json` - Aggregated dashboard data

## Auto-Refresh

The dashboard automatically refreshes every 60 seconds to show the latest data.

## Customization

Edit `dashboard/index.html` to:
- Change color schemes
- Adjust chart types
- Modify refresh interval
- Add custom metrics

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript
- **Charts**: Chart.js v4.4.0
- **Data**: JSON files
- **Backend**: Python (data aggregation)
