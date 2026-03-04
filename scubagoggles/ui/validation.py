"""
Configuration validation utilities for ScubaGoggles UI
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st


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

    @staticmethod
    def validate_break_glass_accounts(
        accounts: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """Validate break glass account UUIDs"""
        if not accounts:
            return True, None  # Optional field

        # UUID pattern (basic validation)
        uuid_pattern = re.compile(
            (
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
            re.IGNORECASE,
        )

        invalid_uuids: List[str] = []
        for account in accounts:
            if not uuid_pattern.match(account.strip()):
                invalid_uuids.append(account)

        if invalid_uuids:
            return False, (
                "Invalid UUID format for break glass accounts: "
                f"{', '.join(invalid_uuids)}"
            )

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

        # Tenant domain validation
        tenant_domain = config_dict.get("tenant")
        if tenant_domain:
            is_valid, error = ConfigValidator.validate_tenant_domain(tenant_domain)
            if not is_valid:
                errors.append(f"Tenant domain validation: {error}")

        return len(errors) == 0, errors


class UIValidator:
    """UI-specific validation and feedback"""

    @staticmethod
    def show_validation_results(is_valid: bool, errors: List[str]):
        """Display validation results in Streamlit UI"""
        if is_valid:
            st.success("Configuration is valid!")
            return

        st.error("Configuration has errors:")
        for error in errors:
            st.error(f"  • {error}")

    @staticmethod
    def show_field_validation(
        field_name: str,
        value: Any,
        validator_func,
        *args,
    ) -> bool:
        """Show real-time validation for individual fields"""
        if value:  # Only validate if value is provided
            is_valid, error = validator_func(value, *args)
            if not is_valid:
                st.error(f"❌ {field_name}: {error}")
                return False

            st.success(f"✅ {field_name}: Valid")
            return True

        return True

    @staticmethod
    def create_validation_summary(
        config_dict: Dict[str, Any],
        available_baselines: List[str],
    ) -> None:
        """Create a validation summary section"""
        st.subheader("Configuration Validation")

        is_valid, errors = ConfigValidator.validate_complete_config(
            config_dict,
            available_baselines,
        )

        if is_valid:
            st.success("All validations passed! Configuration is ready to use.")
        else:
            st.error("Configuration validation failed:")
            for idx, error in enumerate(errors, 1):
                st.error(f"{idx}. {error}")

        # Validation details in expander
        with st.expander("Validation Details"):
            auth_status = (
                "Valid"
                if (
                    config_dict.get("credentials")
                    or config_dict.get("accesstoken")
                )
                else "❌ Missing"
            )

            baselines_status = (
                f"{len(config_dict.get('baselines', []))} selected"
                if config_dict.get("baselines")
                else "❌ None selected"
            )

            output_status = (
                "Valid" if config_dict.get("outputpath") else "❌ Not specified"
            )

            advanced_options_count = len(
                [
                    key
                    for key in ["breakglassaccounts", "tenant", "opapath"]
                    if config_dict.get(key)
                ],
            )

            advanced_options_status = (
                f"{advanced_options_count} configured"
                if advanced_options_count
                else "ℹ️ None configured"
            )

            validation_details = {
                "Authentication": auth_status,
                "Baselines": baselines_status,
                "Output Path": output_status,
                "Advanced Options": advanced_options_status,
            }

            for check, status in validation_details.items():
                st.write(f"**{check}:** {status}")
