"""
Configuration file generation utilities for ScubaGoggles UI
"""

import yaml
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import streamlit as st


class ConfigGenerator:
    """Handles generation of ScubaGoggles configuration files"""
    
    @staticmethod
    def clean_config_dict(config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Remove empty, None, or default values from configuration"""
        cleaned = {}
        
        for key, value in config_dict.items():
            # Skip empty strings, None values, and empty lists
            if value is None or value == "" or value == []:
                continue
            
            # Skip default values that don't need to be in config
            if key == 'outputpath' and value in ['./', '.']:
                continue
            
            # Handle special cases
            if key == 'darkmode' and value == 'false':
                continue
                
            cleaned[key] = value
        
        return cleaned
    
    @staticmethod
    def generate_yaml_config(config_dict: Dict[str, Any], include_comments: bool = True) -> str:
        """Generate YAML configuration with optional comments"""
        cleaned_config = ConfigGenerator.clean_config_dict(config_dict)
        
        if include_comments:
            return ConfigGenerator._generate_commented_yaml(cleaned_config)
        else:
            return yaml.dump(cleaned_config, default_flow_style=False, sort_keys=False)
    
    @staticmethod
    def _generate_commented_yaml(config_dict: Dict[str, Any]) -> str:
        """Generate YAML with helpful comments"""
        lines = []
        
        # Header comment
        lines.append("# ScubaGoggles Configuration File")
        lines.append(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("# https://github.com/cisagov/ScubaGoggles")
        lines.append("")
        
        # Authentication section
        if 'credentials' in config_dict:
            lines.append("# Authentication: Service Account Credentials")
            lines.append(f"credentials: {config_dict['credentials']}")
            lines.append("")
        elif 'accesstoken' in config_dict:
            lines.append("# Authentication: Access Token")
            lines.append(f"accesstoken: {config_dict['accesstoken']}")
            lines.append("")
        
        # Baselines section
        if 'baselines' in config_dict:
            lines.append("# Baselines to assess")
            lines.append("baselines:")
            for baseline in config_dict['baselines']:
                lines.append(f"  - {baseline}")
            lines.append("")
        
        # Output configuration
        if 'outputpath' in config_dict:
            lines.append("# Output directory for reports")
            lines.append(f"outputpath: {config_dict['outputpath']}")
            lines.append("")
        
        # Report options
        if 'darkmode' in config_dict:
            lines.append("# Report display options")
            lines.append(f"darkmode: {config_dict['darkmode']}")
            lines.append("")
        
        # Advanced options
        advanced_keys = ['breakglassaccounts', 'tenant', 'opapath']
        advanced_config = {k: v for k, v in config_dict.items() if k in advanced_keys}
        
        if advanced_config:
            lines.append("# Advanced Options")
            
            if 'breakglassaccounts' in advanced_config:
                lines.append("# Emergency access accounts to exclude from certain checks")
                lines.append("breakglassaccounts:")
                for account in advanced_config['breakglassaccounts']:
                    lines.append(f"  - {account}")
                lines.append("")
            
            if 'tenant' in advanced_config:
                lines.append("# Tenant domain")
                lines.append(f"tenant: {advanced_config['tenant']}")
                lines.append("")
            
            if 'opapath' in advanced_config:
                lines.append("# Custom OPA executable path")
                lines.append(f"opapath: {advanced_config['opapath']}")
                lines.append("")
        
        return '\n'.join(lines)
    
    @staticmethod
    def generate_json_config(config_dict: Dict[str, Any]) -> str:
        """Generate JSON configuration"""
        cleaned_config = ConfigGenerator.clean_config_dict(config_dict)
        return json.dumps(cleaned_config, indent=2, sort_keys=False)
    
    @staticmethod
    def save_config_file(config_content: str, file_path: str, file_format: str = 'yaml') -> bool:
        """Save configuration to file"""
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(config_content)
            
            return True
        except Exception as e:
            st.error(f"Error saving configuration file: {e}")
            return False
    
    @staticmethod
    def create_sample_configs() -> Dict[str, str]:
        """Create sample configuration files for different use cases"""
        samples = {}
        
        # Basic GWS configuration
        basic_gws = {
            'credentials': '/path/to/service-account.json',
            'baselines': ['gmail', 'drive', 'calendar'],
            'outputpath': './reports'
        }
        samples['basic_gws'] = ConfigGenerator.generate_yaml_config(basic_gws)
        
        # Advanced configuration with break glass accounts
        advanced_config = {
            'credentials': '/path/to/service-account.json',
            'baselines': ['gmail', 'drive', 'calendar', 'meet', 'groups'],
            'outputpath': './compliance-reports',
            'darkmode': 'true',
            'breakglassaccounts': [
                '12345678-1234-1234-1234-123456789012',
                '87654321-4321-4321-4321-210987654321'
            ],
            'tenant': 'example.com'
        }
        samples['advanced'] = ConfigGenerator.generate_yaml_config(advanced_config)
        
        # Access token configuration
        token_config = {
            'accesstoken': 'your-access-token-here',
            'baselines': ['gmail', 'drive'],
            'outputpath': './reports'
        }
        samples['access_token'] = ConfigGenerator.generate_yaml_config(token_config)
        
        return samples


class ConfigLoader:
    """Handles loading of existing configuration files"""
    
    @staticmethod
    def load_config_file(file_path: str) -> Optional[Dict[str, Any]]:
        """Load configuration from YAML or JSON file"""
        try:
            path = Path(file_path)
            if not path.exists():
                return None
            
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try YAML first, then JSON
            try:
                return yaml.safe_load(content)
            except yaml.YAMLError:
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    st.error("File is neither valid YAML nor JSON")
                    return None
                    
        except Exception as e:
            st.error(f"Error loading configuration file: {e}")
            return None
    
    @staticmethod
    def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two configuration dictionaries, with override taking precedence"""
        merged = base_config.copy()
        
        for key, value in override_config.items():
            if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
                merged[key] = ConfigLoader.merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged


def render_config_generator_section(config_dict: Dict[str, Any]):
    """Render the configuration generator UI section"""
    st.subheader("📄 Configuration File Generation")
    
    col1, col2 = st.columns(2)
    
    with col1:
        include_comments = st.checkbox("Include helpful comments", value=True)
        file_format = st.selectbox("File format", ["YAML", "JSON"])
    
    with col2:
        filename = st.text_input(
            "Filename", 
            value=f"scubagoggles_config.{file_format.lower()}"
        )
    
    # Generate configuration
    if file_format == "YAML":
        config_content = ConfigGenerator.generate_yaml_config(config_dict, include_comments)
        language = 'yaml'
    else:
        config_content = ConfigGenerator.generate_json_config(config_dict)
        language = 'json'
    
    # Display generated configuration
    st.code(config_content, language=language)
    
    # Download button
    st.download_button(
        label=f"💾 Download {file_format} Configuration",
        data=config_content,
        file_name=filename,
        mime=f"text/{language}"
    )
    
    return config_content


def render_sample_configs_section():
    """Render sample configurations section"""
    with st.expander("📋 Sample Configurations"):
        st.subheader("Sample Configuration Files")
        
        samples = ConfigGenerator.create_sample_configs()
        
        sample_type = st.selectbox(
            "Choose sample configuration",
            ["basic_gws", "advanced", "access_token"],
            format_func=lambda x: {
                "basic_gws": "Basic Google Workspace",
                "advanced": "Advanced with Break Glass Accounts",
                "access_token": "Using Access Token"
            }[x]
        )
        
        if sample_type in samples:
            st.code(samples[sample_type], language='yaml')
            
            st.download_button(
                label=f"💾 Download {sample_type.replace('_', ' ').title()} Sample",
                data=samples[sample_type],
                file_name=f"sample_{sample_type}.yaml",
                mime="text/yaml"
            )