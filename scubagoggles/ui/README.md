# ScubaGoggles Configuration UI

This directory contains a professional Streamlit-based configuration interface for ScubaGoggles, inspired by ScubaGear's ScubaConfigApp but built with Python and web technologies.

## Overview

The ScubaGoggles Configuration UI provides a comprehensive web interface for creating ScubaGoggles configuration files to manage policy exclusions, annotations, and baseline control settings. The interface features:

- **Organization Information Management**: Configure organization details and descriptions
- **Product/Baseline Selection**: Visual selection of Google Workspace products to assess (11 products available)
- **Policy Omission**: Exclude specific policies with documented rationale and expiration dates
- **Policy Annotation**: Add comments, mark incorrect results, and set remediation dates
- **Break Glass Account Configuration**: Define emergency access accounts for special handling
- **Configuration Preview & Export**: View and download YAML configuration files
- **Dark Mode Support**: Toggle between light and dark themes for the interface

## Features

The application consolidates all configuration capabilities into a single, professional interface with the following features:

- **Organization Configuration**: Configure organization name (required), unit name, and assessment description
- **Product Selection**: Choose from 11 Google Workspace baselines (Common Controls, Assured Controls, Gmail, Drive, Calendar, Meet, Groups, Chat, Sites, Classroom, Gemini) with icons, policy counts, and Select All/Clear All functionality
- **Policy Omission Management**: Exclude specific policies from assessment with documented rationale, optional expiration dates, and summary views
- **Policy Annotation**: Add comments and documentation to policies, mark incorrect results, set remediation dates with visual status indicators
- **Break Glass Account Configuration**: Define and manage super admin emergency access accounts with email validation
- **Authentication Settings**: Configure Service Account credentials (Customer ID, Subject Email, JSON file path), OAuth 2.0, or Application Default Credentials
- **Output & Execution Options**: Set output directory, report formats, quiet mode, and dark mode preferences
- **Configuration Management**: Import existing YAML files, preview generated configuration with validation, and download formatted YAML files
- **Visual Feedback**: Real-time status indicators (green dots for configured items, orange for editing), selection summaries, and comprehensive validation

## Files

- `scubaconfigapp.py` - Complete professional configuration application with all features
- `launch.py` - Launcher script for starting the UI
- `validation.py` - Configuration validation utilities
- `__init__.py` - Package initialization

## Installation

### Prerequisites

1. **ScubaGoggles** must be installed and available
2. **Python 3.10+** is required
3. **Streamlit** and UI dependencies

### Install Dependencies

```bash
# Install all requirements including UI dependencies (from the ScubaGoggles directory)
pip install -r requirements.txt
```

## Usage

### Method 1: Direct Launch (Recommended)

```bash
# From the ScubaGoggles root directory
python -m scubagoggles.ui.launch
```

This will automatically detect and launch the configuration application.

### Method 2: Streamlit Command

```bash
# From the ScubaGoggles root directory
streamlit run scubagoggles/ui/scubaconfigapp.py
```

## Interface Overview

### Navigation Tabs

1. **🏢 Main** - Configure organization information and select products to assess
2. **🚫 Omit Policies** - Exclude specific policies with documented rationale
3. **📝 Annotate Policies** - Add comments, mark incorrect results, and set remediation dates
4. **🚨 Break Glass** - Configure emergency access accounts
5. **👁️ Preview** - Review and download the generated YAML configuration

### Sidebar Features

- **Import Configuration**: Upload existing YAML configuration files
- **Help Button**: Access comprehensive help and documentation
- **Dark Mode Toggle**: Available in the header (🌙 icon)

### Key Interface Elements

- **Status Indicators**: Green dots (🟢) indicate configured items, orange dots (🟠) show items being edited
- **Context Help**: Expandable help sections in each tab with guidelines and best practices
- **Validation**: Real-time validation ensures required fields are completed before export
- **Professional Styling**: CISA-inspired design with support for light and dark modes

## Configuration Workflow

1. **Start the UI**: Launch using one of the methods above
2. **Organization Information**: Enter organization name (required) and unit name in the Main tab
3. **Select Products**: Choose which Google Workspace products to assess (at least one required)
4. **Omit Policies** (Optional): Exclude specific policies with documented rationale
5. **Annotate Policies** (Optional): Add comments and documentation to policy results
6. **Break Glass Accounts** (Optional): Configure emergency access accounts
7. **Preview & Export**: Review the generated configuration and download the YAML file

### Typical Use Cases

- **Creating a New Configuration**: Start with Main tab → Select products → Preview & Export
- **Managing Policy Exceptions**: Select products → Go to Omit Policies tab → Configure exclusions with rationale
- **Documentation & Remediation**: Select products → Go to Annotate Policies tab → Add comments and set remediation dates
- **Importing Existing Configuration**: Use sidebar Import feature → Review/modify settings → Export updated configuration

## Development

### Adding New Features

1. **UI Components**: Add to respective tab rendering methods
2. **Validation**: Extend `validation.py` with new validators


## Troubleshooting

### Common Issues

1. **ScubaGoggles Not Found**
   - Ensure ScubaGoggles is installed: `pip install scubagoggles`
   - Check Python path includes ScubaGoggles installation directory
   - Run from the ScubaGoggles root directory

2. **Streamlit Not Available**
   - Install requirements: `pip install -r requirements.txt`
   - Or install directly: `pip install streamlit`
   - Verify installation: `streamlit --version`

3. **Port Already in Use**
   - Streamlit default port (8501) may be in use
   - Specify different port: `streamlit run scubagoggles/ui/scubaconfigapp.py --server.port 8502`

4. **Module Import Errors**
   - Ensure you're running from the ScubaGoggles root directory
   - Check that `scubagoggles` package is in your Python path
   - Verify ScubaGoggles baseline files exist in `scubagoggles/baselines/`

5. **File Upload/Configuration Import Issues**
   - Check file permissions for uploaded files
   - Ensure YAML files are properly formatted
   - Verify configuration file schema matches ScubaGoggles requirements

### Getting Help

- [ScubaGoggles Documentation](https://github.com/cisagov/ScubaGoggles)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [Report Issues](https://github.com/cisagov/ScubaGoggles/issues)

## License

This code is part of ScubaGoggles and follows the same license terms.

## Contributing

Contributions are welcome! Please see the main ScubaGoggles repository for contribution guidelines.
