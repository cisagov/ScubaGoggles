# CISA Google Workspace Secure Configuration Baseline for Google Calendar

# Baseline Policies

## 1. External Sharing Options

This section determines what information is shared from calendars with external entities.

### Policies

<!-- 
    md_parser.py expects the file name to match the product name.

    For the group mismatch test, notice how the policy ID below, 2.1, 
    does not match under section "1. External Sharing Options".
    The parser must raise an error if this occurs.
-->
#### GWS.group_mismatch.2.1v0.6
External Sharing Options for Primary Calendars SHALL be configured to "Only free/busy information (hide event details)."