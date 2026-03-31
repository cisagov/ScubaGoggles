"""
Configuration validation utilities for ScubaGoggles UI.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ConfigValidator:
    """Handles validation of ScubaGoggles configuration parameters"""

    @staticmethod
    def validate_credentials_file(file_path: str) -> Tuple[bool, Optional[str]]:
        """Validate Google service account credentials file"""
        error: Optional[str] = None

        if not file_path:
            error = "Credentials file path is required"

        path = Path(file_path) if not error else None
        if path and not path.exists():
            error = f"Credentials file does not exist: {file_path}"

        if path and path.suffix.lower() != ".json":
            error = "Credentials file must be a JSON file"

        try:
            if not error and path is not None:
                with open(path, "r", encoding="utf-8") as file:
                    creds_data = json.load(file)
            else:
                creds_data = None
        except json.JSONDecodeError as exc:
            error = f"Invalid JSON in credentials file: {exc}"
            creds_data = None
        except OSError as exc:
            error = f"Error reading credentials file: {exc}"
            creds_data = None

        if not error and creds_data is not None:
            required_fields = ["type", "client_id", "client_email", "private_key"]
            missing_fields = [
                field for field in required_fields if field not in creds_data
            ]

            if missing_fields:
                error = (
                    "Credentials file missing required fields: "
                    f"{', '.join(missing_fields)}"
                )
            elif creds_data.get("type") != "service_account":
                error = "Credentials file must be for a service account"

        return error is None, error

    @staticmethod
    def validate_access_token(token: str) -> Tuple[bool, Optional[str]]:
        """Validate access token format"""
        if not token:
            return False, "Access token is required"

        # Basic token format validation.
        # Google tokens are typically long alphanumeric strings.
        if len(token) < 50:
            return False, "Access token appears to be too short"

        # Check for common token patterns
        if not re.match(r"^[A-Za-z0-9._-]+$", token):
            return False, "Access token contains invalid characters"

        return True, None

    @staticmethod
    def validate_output_path(output_path: str) -> Tuple[bool, Optional[str]]:
        """Validate output directory path"""
        if not output_path:
            return False, "Output path is required"

        path = Path(output_path)

        # Check if parent directory exists
        if not path.parent.exists():
            return False, f"Parent directory does not exist: {path.parent}"

        # Check if path is writable
        try:
            # Try to create the directory if it doesn't exist
            path.mkdir(parents=True, exist_ok=True)

            # Test write permissions
            test_file = path / "test_write.tmp"
            test_file.touch()
            test_file.unlink()

            return True, None
        except PermissionError:
            return False, f"No write permission for output path: {output_path}"
        except Exception as exc:
            return False, f"Error with output path: {exc}"

    @staticmethod
    def validate_baselines(
        baselines: List[str],
        available_baselines: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """Validate selected baselines"""
        if not baselines:
            return False, "At least one baseline must be selected"

        invalid_baselines = [baseline for baseline in baselines
                             if baseline not in available_baselines]
        if invalid_baselines:
            return False, (
                "Invalid baselines selected: "
                f"{', '.join(invalid_baselines)}"
            )

        return True, None

    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    @staticmethod
    def validate_break_glass_accounts(
        accounts: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """Validate break glass account email addresses"""
        if not accounts:
            return True, None  # Optional field

        invalid_emails: List[str] = []
        for account in accounts:
            if not ConfigValidator.EMAIL_PATTERN.match(account.strip()):
                invalid_emails.append(account)

        if invalid_emails:
            return False, (
                "Invalid email format for break glass accounts: "
                f"{', '.join(invalid_emails)}"
            )

        return True, None

    @staticmethod
    def validate_email(email: str) -> bool:
        """Return True if email has a valid format."""
        return bool(ConfigValidator.EMAIL_PATTERN.match(email.strip()))

    @staticmethod
    def validate_imap_exceptions(
        exceptions: List[Dict[str, Any]],
    ) -> Tuple[bool, Optional[str]]:
        """Validate IMAP exception entries."""
        if not exceptions:
            return True, None

        errors: List[str] = []
        for i, entry in enumerate(exceptions):
            if not isinstance(entry, dict):
                errors.append(f"Entry {i + 1}: must be a mapping")
                continue
            ou = entry.get('ou', '').strip() if entry.get('ou') else ''
            group = entry.get('group', '').strip() if entry.get('group') else ''
            if not ou and not group:
                errors.append(
                    f"Entry {i + 1}: at least an OU or group is required"
                )
            if group and not ConfigValidator.EMAIL_PATTERN.match(group):
                errors.append(
                    f"Entry {i + 1}: invalid group email format: {group}"
                )

        if errors:
            return False, "; ".join(errors)
        return True, None

    @staticmethod
    def validate_tenant_domain(domain: str) -> Tuple[bool, Optional[str]]:
        """Validate tenant domain format"""
        if not domain:
            return True, None  # Optional field

        # Basic domain validation
        domain_pattern = re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
        )

        if not domain_pattern.match(domain):
            return False, "Invalid domain format"

        return True, None

    @staticmethod
    def validate_complete_config(
        config_dict: Dict[str, Any],
        available_baselines: List[str],
    ) -> Tuple[bool, List[str]]:
        """Validate complete configuration and return all errors"""
        errors: List[str] = []

        # Authentication validation
        has_creds = config_dict.get("credentials")
        has_token = config_dict.get("accesstoken")

        if not has_creds and not has_token:
            errors.append("Either credentials file or access token is required")
        elif has_creds:
            is_valid, error = ConfigValidator.validate_credentials_file(has_creds)
            if not is_valid:
                errors.append(f"Credentials validation: {error}")
        elif has_token:
            is_valid, error = ConfigValidator.validate_access_token(has_token)
            if not is_valid:
                errors.append(f"Access token validation: {error}")

        # Baseline validation
        baselines = config_dict.get("baselines", [])
        is_valid, error = ConfigValidator.validate_baselines(
            baselines,
            available_baselines,
        )
        if not is_valid:
            errors.append(f"Baseline validation: {error}")

        # Output path validation
        output_path = config_dict.get("outputpath")
        if output_path:
            is_valid, error = ConfigValidator.validate_output_path(output_path)
            if not is_valid:
                errors.append(f"Output path validation: {error}")

        # Break glass accounts validation
        break_glass = config_dict.get("breakglassaccounts", [])
        if break_glass:
            is_valid, error = ConfigValidator.validate_break_glass_accounts(
                break_glass,
            )
            if not is_valid:
                errors.append(f"Break glass accounts validation: {error}")

        # IMAP exceptions validation
        imap_exceptions = config_dict.get("imapexceptions", [])
        if imap_exceptions:
            is_valid, error = ConfigValidator.validate_imap_exceptions(
                imap_exceptions,
            )
            if not is_valid:
                errors.append(f"IMAP exceptions validation: {error}")

        # Tenant domain validation
        tenant_domain = config_dict.get("tenant")
        if tenant_domain:
            is_valid, error = ConfigValidator.validate_tenant_domain(tenant_domain)
            if not is_valid:
                errors.append(f"Tenant domain validation: {error}")

        return len(errors) == 0, errors
