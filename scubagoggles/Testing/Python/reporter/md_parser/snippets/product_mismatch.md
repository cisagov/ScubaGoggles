# CISA Google Workspace Secure Configuration Baseline for Google Calendar

# Baseline Policies

## 1. External Sharing Options

This section determines what information is shared from calendars with external entities.

### Policies

<!-- 
    md_parser.py expects the file name to match the product name,
    hence why we test if the parser raises an error when 
    "product_mismatch" != "CALENDAR"
-->
#### GWS.CALENDAR.1.1v0.6
External Sharing Options for Primary Calendars SHALL be configured to "Only free/busy information (hide event details)."