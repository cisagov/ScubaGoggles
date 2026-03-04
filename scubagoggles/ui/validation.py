"""
Configuration validation utilities for ScubaGoggles UI
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import streamlit as st


class ConfigValidator:
    """Handles validation of ScubaGoggles configuration parameters"""
    
    @staticmethod
    def validate_credentials_file(file_path: str) -> Tuple[bool, Optional[str]]:
        """Validate Google service account credentials file"""
        if not file_path:
            return False, "Credentials file path is required"
        
        path = Path(file_path)
        if not path.exists():
            return False, f"Credentials file does not exist: {file_path}"
        
        if not path.suffix.lower() == '.json':
            return False, "Credentials file must be a JSON file"
        
        try:
            with open(path, 'r') as f:
                creds_data = json.load(f)
            
            # Check for required fields in service account JSON
            required_fields = ['type', 'client_id', 'client_email', 'private_key']
            missing_fields = [field for field in required_fields if field not in creds_data]
            
            if missing_fields:
                return False, f"Credentials file missing required fields: {', '.join(missing_fields)}"
            
            if creds_data.get('type') != 'service_account':
                return False, "Credentials file must be for a service account"
            
            return True, None
            
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in credentials file: {e}"
        except Exception as e:
            return False, f"Error reading credentials file: {e}"
    
    @staticmethod
    def validate_access_token(token: str) -> Tuple[bool, Optional[str]]:
        """Validate access token format"""
        if not token:
            return False, "Access token is required"
        
        # Basic token format validation (Google tokens are typically long alphanumeric strings)
        if len(token) < 50:
            return False, "Access token appears to be too short"
        
        # Check for common token patterns
        if not re.match(r'^[A-Za-z0-9._-]+$', token):
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
        except Exception as e:
            return False, f"Error with output path: {e}"
    
    @staticmethod
    def validate_baselines(baselines: List[str], available_baselines: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate selected baselines"""
        if not baselines:
            return False, "At least one baseline must be selected"
        
        invalid_baselines = [b for b in baselines if b not in available_baselines]
        if invalid_baselines:
            return False, f"Invalid baselines selected: {', '.join(invalid_baselines)}"
        
        return True, None
    
    @staticmethod
    def validate_break_glass_accounts(accounts: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate break glass account UUIDs"""
        if not accounts:
            return True, None  # Optional field
        
        # UUID pattern (basic validation)
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.IGNORECASE)
        
        invalid_uuids = []
        for account in accounts:
            if not uuid_pattern.match(account.strip()):
                invalid_uuids.append(account)
        
        if invalid_uuids:
            return False, f"Invalid UUID format for break glass accounts: {', '.join(invalid_uuids)}"
        
        return True, None
    
    @staticmethod
    def validate_tenant_domain(domain: str) -> Tuple[bool, Optional[str]]:
        """Validate tenant domain format"""
        if not domain:
            return True, None  # Optional field
        
        # Basic domain validation
        domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        
        if not domain_pattern.match(domain):
            return False, "Invalid domain format"
        
        return True, None
    
    @staticmethod
    def validate_complete_config(config_dict: Dict[str, Any], available_baselines: List[str]) -> Tuple[bool, List[str]]:
        """Validate complete configuration and return all errors"""
        errors = []
        
        # Authentication validation
        has_creds = config_dict.get('credentials')
        has_token = config_dict.get('accesstoken')
        
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
        baselines = config_dict.get('baselines', [])
        is_valid, error = ConfigValidator.validate_baselines(baselines, available_baselines)
        if not is_valid:
            errors.append(f"Baseline validation: {error}")
        
        # Output path validation
        output_path = config_dict.get('outputpath')
        if output_path:
            is_valid, error = ConfigValidator.validate_output_path(output_path)
            if not is_valid:
                errors.append(f"Output path validation: {error}")
        
        # Break glass accounts validation
        break_glass = config_dict.get('breakglassaccounts', [])
        if break_glass:
            is_valid, error = ConfigValidator.validate_break_glass_accounts(break_glass)
            if not is_valid:
                errors.append(f"Break glass accounts validation: {error}")
        
        # Tenant domain validation
        tenant_domain = config_dict.get('tenant')
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
        else:
            st.error("Configuration has errors:")
            for error in errors:
                st.error(f"  • {error}")
    
    @staticmethod
    def show_field_validation(field_name: str, value: Any, validator_func, *args) -> bool:
        """Show real-time validation for individual fields"""
        if value:  # Only validate if value is provided
            is_valid, error = validator_func(value, *args)
            if not is_valid:
                st.error(f"❌ {field_name}: {error}")
                return False
            else:
                st.success(f"✅ {field_name}: Valid")
                return True
        return True
    
    @staticmethod
    def create_validation_summary(config_dict: Dict[str, Any], available_baselines: List[str]) -> None:
        """Create a validation summary section"""
        st.subheader("Configuration Validation")
        
        is_valid, errors = ConfigValidator.validate_complete_config(config_dict, available_baselines)
        
        if is_valid:
            st.success("All validations passed! Configuration is ready to use.")
        else:
            st.error("Configuration validation failed:")
            for i, error in enumerate(errors, 1):
                st.error(f"{i}. {error}")
        
        # Validation details in expander
        with st.expander("Validation Details"):
            validation_details = {
                "Authentication": "Valid" if (config_dict.get('credentials') or config_dict.get('accesstoken')) else "❌ Missing",
                "Baselines": f"{len(config_dict.get('baselines', []))} selected" if config_dict.get('baselines') else "❌ None selected",
                "Output Path": "Valid" if config_dict.get('outputpath') else "❌ Not specified",
                "Advanced Options": f"{len([k for k in ['breakglassaccounts', 'tenant', 'opapath'] if config_dict.get(k)])} configured" if any(config_dict.get(k) for k in ['breakglassaccounts', 'tenant', 'opapath']) else "ℹ️ None configured"
            }
            
            for check, status in validation_details.items():
                st.write(f"**{check}:** {status}")
        
        return is_valid