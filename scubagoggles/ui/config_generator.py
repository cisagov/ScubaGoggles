"""
Configuration file generation utilities for ScubaGoggles UI.
"""

import json
from datetime import datetime
from typing import Any, Dict

import yaml


class ConfigGenerator:
    """Handles generation of ScubaGoggles configuration files."""

    @staticmethod
    def clean_config_dict(config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Remove empty, None, or default values from configuration."""
        cleaned: Dict[str, Any] = {}

        for key, value in config_dict.items():
            # Skip empty strings, None values, and empty lists
            if value is None or value == "" or value == []:
                continue

            # Skip default values that do not need to be in config
            if key == "outputpath" and value in ["./", "."]:
                continue

            # Handle special cases
            if key == "darkmode" and value == "false":
                continue

            cleaned[key] = value

        return cleaned

    @staticmethod
    def generate_yaml_config(
        config_dict: Dict[str, Any],
        include_comments: bool = True,
    ) -> str:
        """Generate YAML configuration with optional comments."""
        cleaned_config = ConfigGenerator.clean_config_dict(config_dict)

        if include_comments:
            return ConfigGenerator._generate_commented_yaml(cleaned_config)

        return yaml.dump(cleaned_config, default_flow_style=False, sort_keys=False)

    @staticmethod
    def _generate_commented_yaml(config_dict: Dict[str, Any]) -> str:
        """Generate YAML with helpful comments."""
        lines: list[str] = []

        # Header comment
        lines.append("# ScubaGoggles Configuration File")
        lines.append(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("# https://github.com/cisagov/ScubaGoggles")
        lines.append("")

        # Authentication section
        if "credentials" in config_dict:
            lines.append("# Authentication: Service Account Credentials")
            lines.append(f"credentials: {config_dict['credentials']}")
            lines.append("")
        elif "accesstoken" in config_dict:
            lines.append("# Authentication: Access Token")
            lines.append(f"accesstoken: {config_dict['accesstoken']}")
            lines.append("")

        # Baselines section
        if "baselines" in config_dict:
            lines.append("# Baselines to assess")
            lines.append("baselines:")
            for baseline in config_dict["baselines"]:
                lines.append(f"  - {baseline}")
            lines.append("")

        # Output configuration
        if "outputpath" in config_dict:
            lines.append("# Output directory for reports")
            lines.append(f"outputpath: {config_dict['outputpath']}")
            lines.append("")

        # Report options
        if "darkmode" in config_dict:
            lines.append("# Report display options")
            lines.append(f"darkmode: {config_dict['darkmode']}")
            lines.append("")

        # Advanced options
        advanced_keys = ["breakglassaccounts", "tenant", "opapath"]
        advanced_config = {k: v for k, v in config_dict.items() if k in advanced_keys}

        if advanced_config:
            lines.append("# Advanced Options")

            if "breakglassaccounts" in advanced_config:
                lines.append(
                    "# Emergency access accounts to exclude from certain checks",
                )
                lines.append("breakglassaccounts:")
                for account in advanced_config["breakglassaccounts"]:
                    lines.append(f"  - {account}")
                lines.append("")

            if "tenant" in advanced_config:
                lines.append("# Tenant domain")
                lines.append(f"tenant: {advanced_config['tenant']}")
                lines.append("")

            if "opapath" in advanced_config:
                lines.append("# Custom OPA executable path")
                lines.append(f"opapath: {advanced_config['opapath']}")
                lines.append("")

        return "\n".join(lines)

    @staticmethod
    def generate_json_config(config_dict: Dict[str, Any]) -> str:
        """Generate JSON configuration."""
        cleaned_config = ConfigGenerator.clean_config_dict(config_dict)
        return json.dumps(cleaned_config, indent=2, sort_keys=False)

    @staticmethod
    def create_sample_configs() -> Dict[str, str]:
        """Create sample configuration files for different use cases."""
        samples: Dict[str, str] = {}

        # Basic GWS configuration
        basic_gws = {
            "credentials": "/path/to/service-account.json",
            "baselines": ["gmail", "drive", "calendar"],
            "outputpath": "./reports",
        }
        samples["basic_gws"] = ConfigGenerator.generate_yaml_config(basic_gws)

        # Advanced configuration with break glass accounts
        advanced_config = {
            "credentials": "/path/to/service-account.json",
            "baselines": ["gmail", "drive", "calendar", "meet", "groups"],
            "outputpath": "./compliance-reports",
            "darkmode": "true",
            "breakglassaccounts": [
                "12345678-1234-1234-1234-123456789012",
                "87654321-4321-4321-4321-210987654321",
            ],
            "tenant": "example.com",
        }
        samples["advanced"] = ConfigGenerator.generate_yaml_config(advanced_config)

        # Access token configuration
        token_config = {
            "accesstoken": "your-access-token-here",
            "baselines": ["gmail", "drive"],
            "outputpath": "./reports",
        }
        samples["access_token"] = ConfigGenerator.generate_yaml_config(token_config)

        return samples