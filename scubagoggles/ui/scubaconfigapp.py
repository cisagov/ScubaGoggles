"""
ScubaGoggles Configuration Interface

Streamlit-based configuration editor for ScubaGoggles Google Workspace
security assessments.  Provides tabbed UI for organization info, baseline
selection, policy omissions/annotations, break-glass accounts, and
YAML config export/import.
"""

# pylint: disable=line-too-long,too-many-lines

import base64
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict

import re
import streamlit as st
import yaml

from scubagoggles.reporter.md_parser import MarkdownParser, MarkdownParserError
from scubagoggles.ui.validation import ConfigValidator

_CSS_LIGHT_BASE = """<style>
@import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@300;400;500;600;700&display=swap');

:root {
    --primary-color: #28a745;
    --primary-color-dark: #1e7e34;
    --sg-bg: #f6fbfe;
    --sg-secondary-bg: #ffffff;
    --sg-text: #262730;
    --sg-section-bg: white;
    --sg-border: #e8f4fd;
    --sg-muted: #6b7280;
    --sg-context-help-bg: rgba(74, 144, 226, 0.1);
    --sg-status-success-bg: #d4edda;
    --sg-status-success-text: #155724;
    --sg-status-success-border: #c3e6cb;
    --sg-status-warning-bg: #fff3cd;
    --sg-status-warning-text: #856404;
    --sg-status-warning-border: #ffeeba;
    --sg-status-error-bg: #f8d7da;
    --sg-status-error-text: #721c24;
    --sg-status-error-border: #f5c6cb;
}
"""

_CSS_COMMON = """
.stApp {
    background-color: var(--sg-bg);
    font-family: 'Segoe UI', sans-serif;
    color: var(--sg-text);
}

.header-bar {
    background: var(--sg-secondary-bg);
    border-bottom: 1px solid var(--sg-border);
    padding: 0.6rem 1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    border-radius: 8px 8px 0 0;
    margin-bottom: 0.25rem;
}

.header-logo {
    font-size: 2rem;
    line-height: 1;
    flex-shrink: 0;
}

.header-text {
    flex: 1;
    min-width: 0;
}

.header-title {
    font-size: 1.2rem;
    font-weight: 700;
    margin: 0;
    color: var(--sg-text);
    white-space: nowrap;
}

.header-subtitle {
    font-size: 0.78rem;
    color: var(--sg-muted);
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    background-color: var(--sg-secondary-bg);
    border-radius: 8px 8px 0 0;
    padding: 0.5rem;
}

.stTabs [data-baseweb="tab"] {
    background-color: transparent;
    border: none;
    padding: 0.75rem 1.5rem;
    font-weight: 500;
    color: var(--sg-text);
}

.stTabs [aria-selected="true"] {
    background-color: var(--sg-section-bg);
    border-radius: 6px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.section-container {
    background: transparent;
    padding: 0;
    border-radius: 0;
    box-shadow: none;
    margin-bottom: 0;
}

.section-title {
    font-size: 1.4rem;
    font-weight: 600;
    color: var(--sg-text);
    margin-bottom: 1.5rem;
    border-bottom: 2px solid var(--sg-border);
    padding-bottom: 0.5rem;
}

.stTextInput > div > div > input {
    border: 1px solid #d0d5e0;
    border-radius: 6px;
    padding: 0.75rem;
    font-size: 0.95rem;
}

.stTextInput > div > div > input:focus {
    border-color: #4a90e2;
    box-shadow: 0 0 0 2px rgba(74, 144, 226, 0.2);
}

.stSelectbox > div > div > div {
    border: 1px solid #d0d5e0;
    border-radius: 6px;
}

.product-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.product-card {
    background: #f8f9fa;
    border: 2px solid #e9ecef;
    border-radius: 8px;
    padding: 1.25rem;
    transition: all 0.2s ease;
}

.product-card:hover {
    border-color: #4a90e2;
    box-shadow: 0 4px 12px rgba(74, 144, 226, 0.1);
}

.product-card.selected {
    border-color: #4a90e2;
    background: #f0f8ff;
}

.product-icon {
    font-size: 2rem;
    margin-bottom: 0.5rem;
}

.product-title {
    font-weight: 600;
    color: #2c3e50;
    margin-bottom: 0.5rem;
}

.product-description {
    font-size: 0.9rem;
    color: #6c757d;
    line-height: 1.4;
}

.stButton > button {
    border-radius: 6px;
    font-weight: 500;
    padding: 0.5rem 1rem;
    transition: all 0.2s ease;
    font-size: 0.85rem;
}

.stCheckbox {
    margin-top: 0 !important;
}

.status-indicator {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
}

.status-success {
    background: var(--sg-status-success-bg);
    color: var(--sg-status-success-text);
    border: 1px solid var(--sg-status-success-border);
}

.status-warning {
    background: var(--sg-status-warning-bg);
    color: var(--sg-status-warning-text);
    border: 1px solid var(--sg-status-warning-border);
}

.status-error {
    background: var(--sg-status-error-bg);
    color: var(--sg-status-error-text);
    border: 1px solid var(--sg-status-error-border);
}

.status-indicator,
.status-indicator * {
    color: inherit !important;
}

.help-modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.7);
    z-index: 9999;
    display: flex;
    justify-content: center;
    align-items: center;
}

.help-content {
    background: var(--sg-section-bg);
    border-radius: 12px;
    padding: 2rem;
    max-width: 800px;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    color: var(--sg-text);
}

.help-close {
    float: right;
    font-size: 1.5rem;
    cursor: pointer;
    color: var(--sg-text);
    margin: -1rem -1rem 1rem 1rem;
}

.help-section {
    margin-bottom: 1.5rem;
}

.help-title {
    color: #4a90e2;
    font-size: 1.2rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
}

.context-help {
    background: var(--sg-context-help-bg);
    border-left: 4px solid #4a90e2;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 4px;
}

.help-icon {
    color: #4a90e2;
    font-size: 1.2rem;
    cursor: pointer;
    margin-left: 0.5rem;
}

.help-icon:hover {
    color: #3d5b96;
}

#MainMenu {display: none !important;}
footer {display: none !important;}
.stDeployButton {display: none !important;}
button[kind="header"] {display: none !important;}
[data-testid="stToolbar"] {display: none !important;}
.stActionButton {display: none !important;}
header {display: none !important;}
[data-testid="stSidebar"],
[data-testid="collapsedControl"] {display: none !important;}

.stAppViewBlockContainer,
[data-testid="stAppViewBlockContainer"] {
    padding-top: 0 !important;
}
.block-container {
    padding-top: 0 !important;
}
[data-testid="stApp"] > div:first-child {
    padding-top: 0 !important;
}
.stMain {
    padding-top: 0 !important;
}
.main .block-container {
    padding-top: 0.25rem !important;
    margin-top: 0 !important;
}
</style>
"""


class ScubaConfigApp:
    """Streamlit-based configuration editor for ScubaGoggles."""

    @staticmethod
    def _load_scubagoggles_backend():
        """Load backend classes when available, otherwise return safe fallbacks."""
        current_dir = Path(__file__).parent.parent.parent
        if str(current_dir) not in sys.path:
            sys.path.insert(0, str(current_dir))

        try:
            from scubagoggles.config import UserConfig  # pylint: disable=import-outside-toplevel
            from scubagoggles.version import Version  # pylint: disable=import-outside-toplevel
            return True, UserConfig, Version
        except ImportError:
            class MockUserConfig:  # pylint: disable=too-few-public-methods
                """Fallback when ScubaGoggles backend is not installed."""
                def __init__(self):
                    self.output_dir = "./"
                    self.credentials_file = None

            class MockVersion:  # pylint: disable=too-few-public-methods
                """Fallback when ScubaGoggles backend is not installed."""
                number = "1.0.0"

                @classmethod
                def initialize(cls):
                    """No-op; satisfies the Version.initialize() interface."""

            return False, MockUserConfig, MockVersion

    def __init__(self):
        (
            self.scubagoggles_available,
            user_config_class,
            version_class,
        ) = self._load_scubagoggles_backend()
        self.version_class = version_class
        self.user_config = user_config_class()
        self.version_class.initialize()
        self.available_policies = self.parse_baseline_policies()

        if 'config_data' not in st.session_state:
            st.session_state.config_data = {
                'orgname': '',
                'orgunitname': '',
                'subjectemail': '',
                'customerid': '',
                'description': '',
                'baselines': [],
                'credentials': '',
                'outputpath': './',
                'darkmode': False,
                'quiet': False,
                'omitpolicy': {},
                'annotatepolicy': {},
                'breakglassaccounts': [],
                'imapexceptions': [],
                'preferreddnsresolvers': [],
                'skipdoh': False,
                'outjsonfilename': '',
                'regopath': '',
                'documentpath': '',
                'outputproviderfilename': '',
                'outputactionplanfilename': '',
                'outputregofilename': '',
                'outputreportfilename': '',
                'numberofuuidcharacterstotruncate': 18,
                'accesstoken': '',
            }

        if 'ui_show_help' not in st.session_state:
            st.session_state.ui_show_help = False

        for key in ('orgname', 'orgunitname', 'description'):
            if key not in st.session_state:
                st.session_state[key] = st.session_state.config_data.get(key, '')

    @staticmethod
    def parse_baseline_policies() -> Dict[str, Dict[str, str]]:
        """Parse policies from baseline markdown files using MarkdownParser.

        Returns a dict keyed by uppercase product name, where each value is
        a dict mapping policy ID to its description text.
        """

        baseline_dir = Path('scubagoggles/baselines')
        if not baseline_dir.exists():
            return {}

        products = [
            f.stem for f in baseline_dir.glob('*.md')
            if f.name != 'README.md'
        ]
        if not products:
            return {}

        try:
            parser = MarkdownParser(baseline_dir)
            parsed = parser.parse_baselines(products)
        except (MarkdownParserError, OSError):
            return {}

        policies: Dict[str, Dict[str, str]] = {}
        for product, groups in parsed.items():
            flat: Dict[str, str] = {}
            for group in groups:
                for control in group['Controls']:
                    flat[control['Id']] = control['Value']
            policies[product.upper()] = flat

        return policies

    def setup_page_config(self):
        """Configure the Streamlit page with professional styling"""
        st.set_page_config(
            page_title="ScubaGoggles Configuration Editor",
            page_icon="🤿",
            layout="wide",
            initial_sidebar_state="collapsed"
        )
        st.markdown(self._generate_css(), unsafe_allow_html=True)

    _DARK_MODE_CSS = """
    :root {
        --sg-bg: #0e1117;
        --sg-secondary-bg: #262730;
        --sg-text: #fafafa;
        --sg-section-bg: #262730;
        --sg-border: #4b5563;
        --sg-muted: #9ca3af;
        --sg-context-help-bg: rgba(74, 144, 226, 0.2);
        --sg-status-success-bg: #163a2d;
        --sg-status-success-text: #d1fae5;
        --sg-status-success-border: #1f6f4a;
        --sg-status-warning-bg: #3f3110;
        --sg-status-warning-text: #fde68a;
        --sg-status-warning-border: #6b4f1d;
        --sg-status-error-bg: #3f1d20;
        --sg-status-error-text: #fecaca;
        --sg-status-error-border: #7f1d1d;
    }

    .stMarkdown, .stMarkdown p, .stMarkdown div, .stMarkdown span,
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6,
    .stText, p, div, span, label {
        color: #fafafa !important;
    }

    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div,
    .stNumberInput > div > div > input {
        background-color: #374151 !important;
        color: #fafafa !important;
        border-color: #6b7280 !important;
    }

    .stButton > button {
        background-color: #374151 !important;
        color: #fafafa !important;
        border-color: #6b7280 !important;
    }

    .stTextInput label, .stTextArea label, .stSelectbox label,
    .stNumberInput label, .stCheckbox label {
        color: #fafafa !important;
    }

    .stTabs [data-baseweb="tab"] {
        color: #fafafa !important;
    }

    [data-testid="stMarkdownContainer"] p,
    [data-testid="stMarkdownContainer"] div,
    [data-testid="stMarkdownContainer"] span,
    [data-testid="stText"] {
        color: #fafafa !important;
    }

    .stAlert, [data-testid="stNotification"],
    [data-testid="stAlert"], .stWarning, .stError, .stSuccess, .stInfo {
        background-color: #374151 !important;
        color: #fafafa !important;
        border-color: #6b7280 !important;
    }

    .stAlert > div, .stAlert p, .stAlert span,
    [data-testid="stNotification"] > div,
    [data-testid="stNotification"] p,
    [data-testid="stNotification"] span {
        color: #fafafa !important;
    }

    .streamlit-expander {
        background-color: #374151 !important;
        border-color: #6b7280 !important;
    }

    .streamlit-expander .streamlit-expander-header {
        background-color: #374151 !important;
        color: #fafafa !important;
    }

    .streamlit-expander .streamlit-expander-content {
        background-color: #262730 !important;
    }

    .stContainer, [data-testid="stVerticalBlock"] > div,
    [data-testid="stHorizontalBlock"] > div {
        background-color: transparent !important;
    }

    .metric-container, [data-testid="stMetric"] {
        background-color: #374151 !important;
        color: #fafafa !important;
    }

    .stDataFrame, [data-testid="stDataFrame"] {
        background-color: #374151 !important;
        color: #fafafa !important;
    }
    """

    def _generate_css(self):
        """Generate CSS with automatic browser dark mode via media query.

        When SCUBAGOGGLES_UI_DARK is set, dark mode is forced regardless
        of browser preference.  Otherwise the browser's
        ``prefers-color-scheme`` media query controls it automatically.
        """
        force_dark = os.environ.get(
            "SCUBAGOGGLES_UI_DARK", "",
        ).strip().lower() in ("1", "true", "yes", "on")

        if force_dark:
            dark_section = self._DARK_MODE_CSS
        else:
            dark_section = (
                "@media (prefers-color-scheme: dark) {"
                + self._DARK_MODE_CSS
                + "\n}\n"
            )

        return (
            _CSS_LIGHT_BASE
            + dark_section
            + _CSS_COMMON
        )

    def import_configuration(self, uploaded_file):
        """Import configuration from uploaded YAML file."""
        try:
            yaml_content = uploaded_file.read().decode('utf-8')
            config = yaml.safe_load(yaml_content)

            if not config:
                st.error("Invalid or empty YAML file")
                return

            # ScubaGoggles expects lowercase parameter names; normalize keys so
            # imports remain compatible with historical mixed-case files.
            config = self._normalize_config_keys(config)

            self._import_org_fields(config)
            self._import_auth_fields(config)
            self._import_baselines(config)
            self._import_output_settings(config)
            self._import_advanced_settings(config)
            self._import_policy_and_account_sections(config)
            self._show_import_summary()
            st.rerun()

        except yaml.YAMLError as e:
            st.error(f"❌ YAML parsing error: {str(e)}")
        except Exception as e:
            st.error(f"❌ Import error: {str(e)}")

    _SHORTHAND_ALIASES = {
        'b': 'baselines',
        'o': 'outputpath',
        'c': 'credentials',
    }

    @classmethod
    def _normalize_config_keys(cls, config: dict) -> dict:
        """Return a copy of *config* with top-level keys normalized.

        Normalization includes lowercasing and expanding shorthand
        aliases (e.g. ``b`` -> ``baselines``) so that config files
        using the CLI shorthand options are handled correctly.
        """
        normalized = {}
        for key, value in config.items():
            canon = str(key).lower()
            canon = cls._SHORTHAND_ALIASES.get(canon, canon)
            normalized[canon] = value
        return normalized

    @staticmethod
    def _import_org_fields(config: dict):
        """Import organization-level fields from *config* into session state."""
        for key in ('orgname', 'orgunitname', 'description'):
            if key in config:
                st.session_state.config_data[key] = config[key]
                st.session_state[key] = config[key]

    @staticmethod
    def _import_auth_fields(config: dict):
        """Import authentication fields from *config* into session state."""
        for key in ('customerid', 'subjectemail', 'credentials'):
            if key in config:
                st.session_state.config_data[key] = config[key]

    def _import_baselines(self, config: dict):
        """Import baselines from *config*, validating against known baselines."""
        if 'baselines' not in config:
            return

        baselines = config['baselines']
        if isinstance(baselines, str):
            baselines = [baselines]
        elif not isinstance(baselines, list):
            baselines = []

        baseline_info = self.get_baseline_info()
        valid = [b for b in baselines if b in baseline_info]
        invalid = [b for b in baselines if b not in baseline_info]

        st.session_state.config_data['baselines'] = valid
        self._sync_baseline_checkboxes(valid)

        if invalid:
            st.warning(f"⚠️ **Skipped unknown baselines:** {', '.join(invalid)}")

    @staticmethod
    def _import_output_settings(config: dict):
        """Import output-related settings from *config*."""
        if 'outputpath' in config:
            st.session_state.config_data['outputpath'] = config['outputpath']
        if 'darkmode' in config:
            darkmode = config['darkmode']
            if isinstance(darkmode, str):
                st.session_state.config_data['darkmode'] = darkmode.lower() == 'true'
            else:
                st.session_state.config_data['darkmode'] = bool(darkmode)
        if 'quiet' in config:
            st.session_state.config_data['quiet'] = bool(config['quiet'])

    @staticmethod
    def _import_advanced_settings(config: dict):
        """Import advanced / rarely-changed settings from *config*."""
        data = st.session_state.config_data
        for key in (
            'outjsonfilename', 'regopath', 'documentpath',
            'outputproviderfilename', 'outputactionplanfilename',
            'outputregofilename', 'outputreportfilename',
            'accesstoken',
        ):
            if key in config:
                data[key] = str(config[key])
        if 'numberofuuidcharacterstotruncate' in config:
            try:
                data['numberofuuidcharacterstotruncate'] = int(
                    config['numberofuuidcharacterstotruncate'],
                )
            except (ValueError, TypeError):
                pass

    @staticmethod
    def _normalize_to_list(value, coerce=None):
        """Normalize a config value to a list.

        *coerce*, when provided, is applied to wrap a bare scalar
        (e.g. ``str`` for DNS resolver IPs).
        """
        if isinstance(value, list):
            return value
        if value:
            return [coerce(value) if coerce else value]
        return []

    @staticmethod
    def _import_policy_and_account_sections(config: dict):
        """Import omit-policy, annotate-policy, break-glass accounts, and DNS settings."""
        data = st.session_state.config_data
        normalize = ScubaConfigApp._normalize_to_list

        for key in ('omitpolicy', 'annotatepolicy'):
            if key in config and isinstance(config[key], dict):
                data[key] = config[key]

        for key, coerce in (
            ('breakglassaccounts', None),
            ('imapexceptions', None),
            ('preferreddnsresolvers', str),
        ):
            if key in config:
                data[key] = normalize(config[key], coerce=coerce)

        if 'skipdoh' in config:
            data['skipdoh'] = bool(config['skipdoh'])
            st.session_state['skipdoh_checkbox'] = bool(config['skipdoh'])

    @staticmethod
    def _show_import_summary():
        """Store import summary in session state to display after rerun.

        Toasts called immediately before ``st.rerun()`` are lost because
        the rerun halts execution before they reach the browser.  Instead
        we stash the message and display it on the next render cycle via
        ``_flush_import_toast``.
        """
        summary_keys = {
            'orgname': lambda v: f"Organization: {v}",
            'baselines': lambda v: f"Baselines: {len(v)} selected",
            'annotatepolicy': lambda v: f"Annotated Policies: {len(v)}",
            'omitpolicy': lambda v: f"Omitted Policies: {len(v)}",
            'breakglassaccounts': lambda v: f"Break Glass Accounts: {len(v)}",
            'preferreddnsresolvers': lambda v: f"DNS Resolvers: {len(v)} configured",
        }
        imported_items = [
            fmt(val)
            for key, fmt in summary_keys.items()
            if (val := st.session_state.config_data.get(key))
        ]

        msg = "Configuration imported successfully!"
        if imported_items:
            msg += "\n\nImported: " + " · ".join(imported_items)
        st.session_state._import_toast = msg

    @staticmethod
    def _flush_import_toast():
        """Show a pending import-success toast if one was stashed."""
        msg = st.session_state.pop("_import_toast", None)
        if msg:
            st.toast(msg, icon="✅")

    @st.dialog("Import Configuration")
    def _show_import_dialog(self):
        """Show a file upload dialog for importing YAML configuration."""
        uploader_gen = st.session_state.get("_uploader_gen", 0)
        uploaded = st.file_uploader(
            "Upload a YAML configuration file",
            type=["yaml", "yml"],
            key=f"config_file_uploader_{uploader_gen}",
        )
        if uploaded is not None:
            st.session_state._uploader_gen = uploader_gen + 1
            st.success(f"✅ **{uploaded.name}** loaded successfully — importing...")
            self.import_configuration(uploaded)

    @st.dialog("Confirm Reset")
    def _show_reset_dialog(self):
        """Show a confirmation dialog before resetting all fields."""
        st.warning(
            "Are you sure you want to reset all fields to their defaults?\n\n"
            "All unsaved changes will be lost."
        )
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Yes, Reset", type="primary", key="confirm_reset_yes"):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
        with col2:
            if st.button("Cancel", key="confirm_reset_cancel"):
                st.rerun()

    def _validate_before_save(self) -> list:
        """Validate the configuration and return a list of error messages."""
        data = st.session_state.config_data
        errors = []

        if not data.get('orgname'):
            errors.append("Organization Name is required.")
        if not data.get('baselines'):
            errors.append("At least 1 product must be selected for the configuration to be valid.")

        creds_path = data.get('credentials', '')
        if creds_path:
            valid, err = ConfigValidator.validate_credentials_file(creds_path)
            if not valid:
                errors.append(err)

        output_path = data.get('outputpath', '')
        if output_path and output_path != './':
            valid, err = ConfigValidator.validate_output_path(output_path)
            if not valid:
                errors.append(err)

        break_glass = data.get('breakglassaccounts', [])
        if break_glass:
            valid, err = ConfigValidator.validate_break_glass_accounts(break_glass)
            if not valid:
                errors.append(err)

        subject_email = data.get('subjectemail', '')
        if subject_email and not ConfigValidator.validate_email(subject_email):
            errors.append("Subject email has an invalid format.")

        return errors

    @staticmethod
    def _show_validation_errors(errors: list):
        """Display validation errors inline."""
        for err in errors:
            st.error(f"❌ {err}")

    # ------------------------------------------------------------------
    # Shared helpers to reduce duplication across tabs
    # ------------------------------------------------------------------

    def _get_selected_baseline_policies(self) -> Dict[str, Dict[str, str]]:
        """Map selected baselines to their available policies."""
        selected_baselines = st.session_state.config_data.get('baselines', [])
        result: Dict[str, Dict[str, str]] = {}
        if selected_baselines and self.available_policies:
            for baseline in selected_baselines:
                upper = baseline.upper()
                if upper in self.available_policies:
                    result[baseline.title()] = self.available_policies[upper]
        return result

    @staticmethod
    def _normalize_session_date(key: str):
        """Coerce a session-state date value from string to date object."""
        if key in st.session_state and isinstance(st.session_state[key], str):
            try:
                st.session_state[key] = datetime.strptime(
                    st.session_state[key], '%Y-%m-%d',
                ).date()
            except (ValueError, TypeError):
                del st.session_state[key]

    @staticmethod
    def _load_existing_date(existing_data: dict, config_key: str, session_key: str):
        """Load a date string from config into session state as a date object."""
        if config_key in existing_data:
            try:
                st.session_state[session_key] = datetime.strptime(
                    existing_data[config_key], '%Y-%m-%d',
                ).date()
            except (ValueError, TypeError):
                st.session_state.pop(session_key, None)
        else:
            st.session_state.pop(session_key, None)

    @staticmethod
    def _parse_config_date(existing_data: dict, config_key: str):
        """Parse a YYYY-MM-DD string from config, returning None on failure."""
        raw = existing_data.get(config_key)
        if raw:
            try:
                return datetime.strptime(raw, '%Y-%m-%d').date()
            except (ValueError, TypeError):
                pass
        return None

    def _sync_baseline_checkboxes(self, selected: list):
        """Synchronise per-baseline checkbox session keys with *selected*."""
        for baseline in self.get_baseline_info():
            st.session_state[f"baseline_{baseline}"] = baseline in selected

    @staticmethod
    def _yaml_array_to_flow(yaml_str: str, key: str) -> str:
        """Convert a YAML block-style list to flow-style for *key*."""
        return re.sub(
            rf'{re.escape(key)}:\n(?:- (.+)\n)+',
            lambda m: (
                f'{key}: ['
                + ', '.join(re.findall(r'- (.+)', m.group(0)))
                + ']\n'
            ),
            yaml_str,
        )

    # ------------------------------------------------------------------
    # Generic policy-configuration tab (omit / annotate)
    # ------------------------------------------------------------------

    def _render_policy_config_tab(
        self,
        *,
        config_key: str,
        prefix: str,
        title: str,
        help_content: str,
        description: str,
        configured_label: str,
        add_button_label: str,
        config_noun: str,
        field_map: Dict[str, str],
        date_fields: set,
        render_form,
        render_summary,
        pre_render=None,
    ):
        """Render a policy-configuration tab (shared by omit and annotate).

        Parameters
        ----------
        config_key : session-state key holding the policies dict
        prefix : short string used in widget keys ('omit' / 'annotate')
        title : tab heading text
        help_content : HTML for the help expander
        description : markdown intro paragraph
        configured_label : status label shown for configured policies
        add_button_label : text on the "add" button (e.g. '➕ Omit')
        config_noun : noun for form headers (e.g. 'Omission' / 'Annotation')
        field_map : maps session-key suffix -> config dict key
        date_fields : set of session-key suffixes that are date fields
        render_form : callable(policy_id, policies, is_editing) that renders the form
        render_summary : callable(policies) that renders the summary section
        pre_render : optional callable() run before the policy list
        """
        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown(f'<h2 class="section-title">{title}</h2>', unsafe_allow_html=True)

        with st.expander(f"ℹ️ Help: {title} Guidelines", expanded=False):
            st.markdown(help_content, unsafe_allow_html=True)

        st.markdown(description)

        policies = st.session_state.config_data.get(config_key, {})

        if pre_render:
            pre_render()

        selected_baseline_policies = self._get_selected_baseline_policies()
        selected_baselines = st.session_state.config_data.get('baselines', [])

        if not selected_baselines:
            st.container(border=True).warning(
                "**No products selected.** "
                "Please select at least one product from the "
                "**Main** tab to view and configure policies."
            )
        elif not self.available_policies:
            st.warning(
                "⚠️ Baseline policy data is unavailable. "
                "Ensure the ScubaGoggles baselines directory exists."
            )
        elif not selected_baseline_policies:
            st.info("ℹ️ No policies available for selected products")
        else:
            st.markdown("**Available Policies from Selected Products:**")
            baseline_tabs = st.tabs(list(selected_baseline_policies.keys()))
            for i, (baseline_name, baseline_policies) in enumerate(
                selected_baseline_policies.items(),
            ):
                with baseline_tabs[i]:
                    self._render_baseline_policy_list(
                        baseline_name, baseline_policies, policies,
                        config_key=config_key, prefix=prefix,
                        configured_label=configured_label,
                        add_button_label=add_button_label,
                        config_noun=config_noun,
                        field_map=field_map, date_fields=date_fields,
                        render_form=render_form,
                    )
            st.divider()

        render_summary(policies)
        st.markdown('</div>', unsafe_allow_html=True)

    def _render_baseline_policy_list(
        self, baseline_name, baseline_policies, policies, *,
        config_key, prefix, configured_label, add_button_label,
        config_noun, field_map, date_fields, render_form,
    ):
        """Render the policy rows for a single baseline inside its tab."""
        if not baseline_policies:
            st.info(f"No policies found for {baseline_name} product")
            return
        for policy_id, policy_desc in baseline_policies.items():
            self._render_policy_row(
                policy_id, policy_desc, policies,
                config_key=config_key, prefix=prefix,
                configured_label=configured_label,
                add_button_label=add_button_label,
                config_noun=config_noun,
                field_map=field_map, date_fields=date_fields,
                render_form=render_form,
            )

    def _render_policy_row(
        self, policy_id, policy_desc, policies, *,
        config_key, prefix, configured_label, add_button_label,
        config_noun, field_map, date_fields, render_form,
    ):
        """Render a single policy's status label, action buttons, and inline form."""
        is_configured = policy_id in policies
        expand_key = f"expand_{prefix}_{policy_id}"
        editing_key = f"editing_{prefix}_{policy_id}"

        col1, col2 = st.columns([4, 1])
        with col1:
            if is_configured:
                st.markdown(f"🟢 **{policy_id}** ({configured_label})")
            elif st.session_state.get(expand_key, False):
                st.markdown(f"🟠 **{policy_id}** (Configuring...)")
            else:
                st.markdown(f"**{policy_id}**")
            st.caption(policy_desc)

        with col2:
            if is_configured:
                col_edit, col_remove = st.columns(2)
                with col_edit:
                    if st.button("✏️ Edit", key=f"edit_{prefix}_{policy_id}"):
                        self._populate_edit_fields(policies[policy_id], field_map, date_fields, policy_id)
                        st.session_state[expand_key] = True
                        st.session_state[editing_key] = True
                        st.rerun()
                with col_remove:
                    if st.button("🗑️ Remove", key=f"remove_{prefix}_{policy_id}"):
                        del policies[policy_id]
                        st.session_state.config_data[config_key] = policies
                        st.success(f"✅ Removed {prefix}ed policy: {policy_id}")
                        st.rerun()
            else:
                if expand_key not in st.session_state:
                    st.session_state[expand_key] = False
                if st.button(add_button_label, key=f"toggle_{prefix}_{policy_id}"):
                    for sk in field_map:
                        st.session_state.pop(f"{sk}_{policy_id}", None)
                    st.session_state[expand_key] = not st.session_state[expand_key]
                    st.session_state[editing_key] = False
                    st.rerun()

        if st.session_state.get(expand_key, False):
            is_editing = st.session_state.get(editing_key, False)
            with st.container():
                st.markdown("---")
                action = "Edit" if is_editing else "Configure"
                st.markdown(f"**{action} {config_noun} for {policy_id}**")
                render_form(policy_id, policies, is_editing)

    def _populate_edit_fields(self, existing, field_map, date_fields, policy_id):
        """Load existing policy values into session state for editing."""
        for sk, cfg_key in field_map.items():
            full_key = f"{sk}_{policy_id}"
            if sk in date_fields:
                self._load_existing_date(existing, cfg_key, full_key)
            elif isinstance(existing.get(cfg_key, ''), bool):
                st.session_state[full_key] = existing.get(cfg_key, False)
            else:
                st.session_state[full_key] = existing.get(cfg_key, '')

    # --- Omit-specific form and summary ---

    def _render_omit_form(self, policy_id: str, policies: dict, is_editing: bool):
        """Render the omit-policy inline form."""
        existing = policies.get(policy_id, {})
        existing_rationale = existing.get('rationale', '')
        existing_expiration = self._parse_config_date(existing, 'expiration')

        rationale = st.text_input(
            "Rationale (Required)",
            value=existing_rationale,
            placeholder="Reason for omitting this policy",
            key=f"rationale_{policy_id}",
        )

        self._normalize_session_date(f"expiration_{policy_id}")
        exp_value = existing_expiration if existing_expiration and existing_expiration >= date.today() else None
        expiration = st.date_input(
            "Expiration Date (Optional)",
            value=exp_value,
            min_value=date.today(),
            help="Date after which the policy should no longer be omitted",
            key=f"expiration_{policy_id}",
        )

        col_save, col_cancel = st.columns(2)
        with col_save:
            label = "💾 Update Omission" if is_editing else "✅ Save Omission"
            if st.button(label, key=f"save_omit_{policy_id}", type="primary"):
                if rationale:
                    cfg: Dict[str, Any] = {'rationale': rationale}
                    if expiration:
                        cfg['expiration'] = expiration.strftime('%Y-%m-%d')
                    policies[policy_id] = cfg
                    st.session_state.config_data['omitpolicy'] = policies
                    st.session_state[f"expand_omit_{policy_id}"] = False
                    st.session_state[f"editing_omit_{policy_id}"] = False
                    st.success(f"✅ {'Updated' if is_editing else 'Added'} omitted policy: {policy_id}")
                    st.rerun()
                else:
                    st.error("❌ Rationale is required")
        with col_cancel:
            if st.button("❌ Cancel", key=f"cancel_omit_{policy_id}"):
                st.session_state[f"expand_omit_{policy_id}"] = False
                st.session_state[f"editing_omit_{policy_id}"] = False
                st.rerun()

    @staticmethod
    def _render_omit_summary(policies: dict):
        """Render the omit-policy summary block."""
        if policies:
            st.markdown("---")
            st.subheader("📋 Summary of Omitted Policies")
            for pid, data in policies.items():
                st.markdown(f"🚫 **{pid}**: {data.get('rationale', 'No rationale provided')}")
                if 'expiration' in data:
                    st.caption(f"Expires: {data['expiration']}")
        else:
            st.markdown("---")
            st.info("ℹ️ No policies are currently omitted")

    # --- Annotate-specific form and summary ---

    def _render_annotate_form(self, policy_id: str, policies: dict, is_editing: bool):
        """Render the annotate-policy inline form."""
        existing = policies.get(policy_id, {})
        existing_comment = existing.get('comment', '')
        existing_incorrect = existing.get('incorrectresult', False)
        existing_remediation = self._parse_config_date(existing, 'remediationdate')

        comment = st.text_area(
            "Comment/Annotation",
            value=existing_comment,
            placeholder="Implementation in progress...",
            help="Comment to add to the report for this policy",
            key=f"comment_{policy_id}",
            height=100,
        )

        col1, col2 = st.columns(2)
        with col1:
            incorrect_result = st.checkbox(
                "Mark as Incorrect Result",
                value=existing_incorrect,
                help="Check if the result for this policy is incorrect",
                key=f"incorrect_{policy_id}",
            )
        with col2:
            self._normalize_session_date(f"remediation_{policy_id}")
            rem_value = existing_remediation if existing_remediation and existing_remediation >= date.today() else None
            remediation_date = st.date_input(
                "Remediation Date (Optional)",
                value=rem_value,
                min_value=date.today(),
                help="Date when a failing control is expected to be implemented",
                key=f"remediation_{policy_id}",
            )

        col_save, col_cancel = st.columns(2)
        with col_save:
            label = "💾 Update Annotation" if is_editing else "✅ Save Annotation"
            if st.button(label, key=f"save_annotate_{policy_id}", type="primary"):
                cfg: Dict[str, Any] = {}
                if comment:
                    cfg['comment'] = comment
                if incorrect_result:
                    cfg['incorrectresult'] = True
                if remediation_date:
                    cfg['remediationdate'] = remediation_date.strftime('%Y-%m-%d')
                if cfg:
                    policies[policy_id] = cfg
                    st.session_state.config_data['annotatepolicy'] = policies
                    st.session_state[f"expand_annotate_{policy_id}"] = False
                    st.session_state[f"editing_annotate_{policy_id}"] = False
                    st.success(f"✅ {'Updated' if is_editing else 'Added'} annotation for policy: {policy_id}")
                    st.rerun()
                else:
                    st.error("❌ At least one annotation field is required")
        with col_cancel:
            if st.button("❌ Cancel", key=f"cancel_annotate_{policy_id}"):
                st.session_state[f"expand_annotate_{policy_id}"] = False
                st.session_state[f"editing_annotate_{policy_id}"] = False
                st.rerun()

    @staticmethod
    def _render_annotate_summary(policies: dict):
        """Render the annotate-policy summary block."""
        if policies:
            st.markdown("---")
            st.subheader("📋 Summary of Annotated Policies")
            for pid, data in policies.items():
                st.markdown(f"📝 **{pid}**")
                if 'comment' in data:
                    st.caption(f"Comment: {data['comment']}")
                if data.get('incorrectresult', False):
                    st.caption("🔴 Marked as Incorrect Result")
                if 'remediationdate' in data:
                    st.caption(f"Remediation Date: {data['remediationdate']}")
        else:
            st.markdown("---")
            st.info("ℹ️ No policies are currently annotated")

    def render_header(self):
        """Render a header toolbar matching SCuBAGear style"""
        self._flush_import_toast()
        st.markdown("""
        <div class="header-bar">
            <span class="header-logo">🤿</span>
            <div class="header-text">
                <div class="header-title">ScubaGoggles Configuration Editor</div>
                <div class="header-subtitle">Create a configuration file for ScubaGoggles exclusions, annotations, and omissions baseline controls</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        btn_open, btn_reset, btn_help, _spacer = st.columns([1, 1, 1, 4])
        with btn_open:
            if st.button("📂 Open", use_container_width=True, help="Import a YAML configuration file"):
                self._show_import_dialog()
        with btn_reset:
            if st.button("🔄 Reset", use_container_width=True, help="Reset all fields to defaults"):
                self._show_reset_dialog()
        with btn_help:
            if st.button("❓ Help", use_container_width=True, help="Show help & documentation"):
                st.session_state.ui_show_help = True

        self.render_help_modal()

    def render_help_modal(self):
        """Render help modal overlay"""
        if st.session_state.ui_show_help:
            self._show_help_dialog()

    @st.dialog("🤿 ScubaGoggles Help & Documentation")
    def _show_help_dialog(self):
        """Show help content in a proper modal dialog"""

        # Help content
        st.markdown("### This professional interface helps you create configuration files for ScubaGoggles security assessments.")

        st.markdown("## 🚀 Quick Start Guide")
        st.markdown("""
        1. **Main Tab:** Select products and baselines to assess
        2. **Annotate Policies:** Add custom notes and documentation
        3. **Omit Policies:** Exclude specific policies from assessment
        4. **Break Glass:** Configure emergency access accounts
        5. **Preview:** Review your configuration before saving
        """)

        st.markdown("## 📋 Tab Documentation")
        st.markdown("""
        - **Main:** Product selection with baseline coverage
        - **Annotate Policies:** Add rationale and documentation for policy decisions
        - **Omit Policies:** Use green dots to indicate configured policies, orange during editing
        - **Break Glass:** Emergency accounts that bypass normal security controls
        """)

        st.markdown("## 💡 Tips & Best Practices")
        st.markdown("""
        - Use the import feature to load existing configurations
        - Green checkboxes indicate selected products in main tab
        - Status indicators show configuration progress
        - Dark mode: set environment variable SCUBAGOGGLES_UI_DARK=1 or run the launcher with --dark
        - All fields are validated before configuration generation
        - Preview tab shows the exact YAML that will be generated
        """)

        st.markdown("## 🔗 Resources")
        st.markdown("""
        - [ScubaGoggles GitHub](https://github.com/cisagov/ScubaGoggles)
        - [SCuBA Project](https://cisa.gov/scuba)
        - [Documentation](https://github.com/cisagov/ScubaGoggles/blob/main/docs)
        """)

        # Close button
        if st.button("✅ Got it!", key="close_help_dialog", type="primary"):
            st.session_state.ui_show_help = False
            st.rerun()

    _BASELINE_INFO = {
        'commoncontrols': {
            'icon': '🔐',
            'title': 'Common Controls',
            'description': 'Enterprise-level security controls across the entire GWS admin console including authentication, access control, and session management',
        },
        'assuredcontrols': {
            'icon': '🛡️',
            'title': 'Assured Controls',
            'description': 'Advanced security controls for organizations with Assured Controls or Assured Controls Plus licenses including data access approvals and data regions',
        },
        'gmail': {
            'icon': '📧',
            'title': 'Gmail',
            'description': 'Email security controls and policies for Gmail configuration',
        },
        'drive': {
            'icon': '📁',
            'title': 'Google Drive',
            'description': 'File sharing and access controls for Google Drive',
        },
        'calendar': {
            'icon': '📅',
            'title': 'Calendar',
            'description': 'Calendar sharing and privacy settings for Google Calendar',
        },
        'meet': {
            'icon': '📹',
            'title': 'Google Meet',
            'description': 'Video conferencing security and access controls',
        },
        'groups': {
            'icon': '👥',
            'title': 'Groups',
            'description': 'Google Groups configuration and permissions',
        },
        'chat': {
            'icon': '💬',
            'title': 'Google Chat',
            'description': 'Chat and messaging security controls',
        },
        'sites': {
            'icon': '🌐',
            'title': 'Google Sites',
            'description': 'Website creation and sharing controls',
        },
        'classroom': {
            'icon': '🎓',
            'title': 'Classroom',
            'description': 'Educational platform security and privacy controls',
        },
        'gemini': {
            'icon': '🤖',
            'title': 'Gemini',
            'description': 'AI-powered features and data processing controls',
        },
    }

    def get_baseline_info(self):
        """Get information about available baselines."""
        return self._BASELINE_INFO

    def render_main_tab(self):
        """Render the main configuration tab"""
        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown('<h2 class="section-title">Organization Information</h2>', unsafe_allow_html=True)

        # Context help for main tab
        with st.expander("ℹ️ Help: Organization & Product Selection", expanded=False):
            st.markdown("""
            <div class="context-help">
            <strong>Organization Information:</strong><br>
            • <strong>Organization Name:</strong> Official name of your organization (required)<br>
            • <strong>Organization Unit:</strong> Specific department or division being assessed<br><br>

            <strong>Product Selection:</strong><br>
            • Choose which Google Workspace products to assess<br>
            • Green checkboxes indicate selected products<br>
            • Each product has specific security baselines<br>
            • You can select multiple products for coverage<br><br>

            <strong>Best Practices:</strong><br>
            • Start with core products (commoncontrols, gmail, calendar)<br>
            • Add additional products based on your organization's usage<br>
            • Organization name is required for report generation
            </div>
            """, unsafe_allow_html=True)

        # Organization Name
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**ℹ️ Organization Name***")
        with col2:
            orgname = st.text_input(
                "Organization Name",
                placeholder="Department of Homeland Security",
                help="Name of your organization",
                key="orgname",
                label_visibility="collapsed"
            )
            st.session_state.config_data['orgname'] = orgname

        # Organization Unit Name
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**ℹ️ Organization Unit Name**")
        with col2:
            orgunitname = st.text_input(
                "Organization Unit Name",
                placeholder="Cybersecurity and Infrastructure Security Agency (optional)",
                help="Name of your organizational unit (optional)",
                key="orgunitname",
                label_visibility="collapsed"
            )
            st.session_state.config_data['orgunitname'] = orgunitname

        # Description
        st.markdown("**Description**")
        description = st.text_area(
            "Description",
            placeholder="Enter a description for this configuration (optional)",
            height=100,
            key="description",
            label_visibility="collapsed"
        )
        st.session_state.config_data['description'] = description

        # Product Selection Section
        st.markdown('<h3 style="margin-top: 2rem;">Select at least one product:*</h3>', unsafe_allow_html=True)

        baseline_info = self.get_baseline_info()
        available_baselines = list(baseline_info.keys())
        current_selection = st.session_state.config_data.get('baselines', [])

        # Ensure checkbox keys exist in session state
        for baseline in available_baselines:
            bkey = f"baseline_{baseline}"
            if bkey not in st.session_state:
                st.session_state[bkey] = baseline in current_selection

        # Select All / None buttons
        col1, col2, _col3 = st.columns([1, 1, 4])
        with col1:
            if st.button("✅ Select All", key="select_all_main"):
                st.session_state.config_data['baselines'] = available_baselines.copy()
                self._sync_baseline_checkboxes(available_baselines)
                st.rerun()

        with col2:
            if st.button("❌ Clear All", key="clear_all_main"):
                st.session_state.config_data['baselines'] = []
                self._sync_baseline_checkboxes([])
                st.rerun()

        # Create product grid with icons and policy counts
        cols = st.columns(2)
        for i, baseline in enumerate(available_baselines):
            info = baseline_info[baseline]
            baseline_policies = self.available_policies.get(baseline.upper(), {}) if self.available_policies else {}
            policy_count = len(baseline_policies)

            with cols[i % 2]:
                # Create a checkbox with custom styling including policy count
                selected = st.checkbox(
                    f"{info['icon']} **{info['title']}** ({policy_count} policies)",
                    key=f"baseline_{baseline}"
                )

                if selected and baseline not in current_selection:
                    current_selection.append(baseline)
                elif not selected and baseline in current_selection:
                    current_selection.remove(baseline)

                st.caption(info['description'])
                st.markdown("---")

        st.session_state.config_data['baselines'] = current_selection

        # Products supporting exclusions note
        if current_selection:
            total_policies = sum(
                len(self.available_policies.get(b.upper(), {})) for b in current_selection
            )
            # Filter out baselines that don't exist in baseline_info to prevent KeyError
            valid_baselines = [b for b in current_selection if b in baseline_info]
            invalid_baselines = [b for b in current_selection if b not in baseline_info]

            if valid_baselines:
                titles = [baseline_info[b]['title'] for b in valid_baselines]
                st.info("📝 **Products selected:** " + ", ".join(titles))

            if invalid_baselines:
                st.warning(
                    "⚠️ **Unknown baselines imported:** "
                    + ", ".join(invalid_baselines),
                )

            st.success(
                f"✅ Selected {len(current_selection)} products with "
                f"{total_policies} policies total",
            )

        st.markdown('</div>', unsafe_allow_html=True)

    def render_dns_config_tab(self):
        """Render the DNS Configuration tab."""
        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown('<h2 class="section-title">DNS Configuration</h2>', unsafe_allow_html=True)

        with st.expander("ℹ️ Help: DNS Configuration", expanded=False):
            st.markdown("""
            <div class="context-help">
            <strong>DNS Configuration:</strong><br>
            • These settings control how ScubaGoggles resolves DNS records (SPF, DKIM, DMARC) required by Gmail security policies<br>
            • <strong>Preferred DNS Resolvers:</strong> Custom DNS resolver IP addresses to use instead of system defaults<br>
            • <strong>Skip DoH:</strong> Disable DNS over HTTPS fallback when traditional DNS requests fail<br><br>

            <strong>Common DNS Resolvers:</strong><br>
            • Google: 8.8.8.8, 8.8.4.4<br>
            • Cloudflare: 1.1.1.1, 1.0.0.1<br>
            • If not specified, the system default DNS resolver will be used
            </div>
            """, unsafe_allow_html=True)

        dns_resolvers = st.session_state.config_data.get('preferreddnsresolvers', [])

        st.markdown("**Preferred DNS Resolvers**")
        st.caption(
            "Specify custom DNS resolver IP addresses for SPF, DKIM, and DMARC lookups. "
            "If not provided, the system default will be used."
        )

        with st.form("dns_resolver_form", clear_on_submit=True):
            col1, col2 = st.columns([3, 1])
            with col1:
                dns_ip_input = st.text_input(
                    "DNS Resolver IP Address",
                    placeholder="8.8.8.8",
                    help="IP address of a DNS resolver (e.g., 8.8.8.8)",
                    key="new_dns_resolver",
                    label_visibility="collapsed"
                )
            with col2:
                dns_submitted = st.form_submit_button(
                    "➕ Add Resolver", type="primary"
                )

        if dns_submitted:
            ip = dns_ip_input.strip()
            if not ip:
                st.session_state.dns_add_status = ("empty", "")
            elif not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                st.session_state.dns_add_status = ("invalid", ip)
            elif ip in dns_resolvers:
                st.session_state.dns_add_status = ("duplicate", ip)
            else:
                dns_resolvers.append(ip)
                st.session_state.config_data['preferreddnsresolvers'] = dns_resolvers
                st.session_state.dns_add_status = ("success", ip)
            st.rerun()

        self._show_add_status("dns_add_status", {
            "success": (st.success, lambda ip: f"✅ Added DNS resolver: {ip}"),
            "invalid": (st.error, lambda ip: f"❌ Invalid IP address format: {ip}"),
            "duplicate": (st.error, "❌ Resolver already exists in list"),
        }, fallback_msg="❌ IP address is required")

        if dns_resolvers:
            for i, resolver in enumerate(dns_resolvers):
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"🌐 **{resolver}**")
                with col2:
                    if st.button("🗑️ Remove", key=f"remove_dns_{i}"):
                        dns_resolvers.remove(resolver)
                        st.session_state.config_data['preferreddnsresolvers'] = dns_resolvers
                        st.rerun()

        st.divider()

        skipdoh = st.checkbox(
            "Skip DNS over HTTPS (DoH) Fallback",
            value=st.session_state.config_data.get('skipdoh', False),
            help="If enabled, ScubaGoggles will not fall back to DNS over HTTPS "
                 "when traditional DNS requests fail for SPF, DKIM, and DMARC lookups",
            key="skipdoh_checkbox"
        )
        st.session_state.config_data['skipdoh'] = skipdoh

        st.markdown('</div>', unsafe_allow_html=True)

    @staticmethod
    def _show_add_status(session_key: str, messages: dict, fallback_msg: str = "❌ Input is required"):
        """Display feedback from the most recent add attempt.

        *session_key* is popped from session state.  *messages* maps a
        status kind to ``(streamlit_func, message_text)`` pairs.
        """
        status = st.session_state.pop(session_key, None)
        if not status:
            return
        kind, detail = status
        fn, msg = messages.get(kind, (st.error, fallback_msg))
        if callable(msg):
            msg = msg(detail)
        fn(msg)

    def render_omit_policies_tab(self):
        """Render omit policies configuration tab"""
        self._render_policy_config_tab(
            config_key='omitpolicy',
            prefix='omit',
            title='Omit Policies',
            help_content="""
            <div class="context-help">
            <strong>What is Policy Omission?</strong><br>
            Excluding specific security policies from ScubaGoggles evaluation when they don't apply to your organization or are handled by external controls.<br><br>

            <strong>Valid Reasons to Omit:</strong><br>
            • Policy implemented by third-party service that ScubaGoggles cannot audit<br>
            • Policy not applicable to your organization's operational model<br>
            • Compensating controls provide equivalent security<br>
            • Accepting documented risk for specific controls<br><br>

            <strong>Status Indicators:</strong><br>
            • 🟢 Green dot: Policy configured for omission<br>
            • 🟠 Orange dot: Policy being edited<br>
            • No dot: Policy not omitted<br><br>

            <strong>Important:</strong> All omissions should be documented and approved by your security team.
            </div>
            """,
            description="""
        **Use this section to exclude specific policies from ScubaGoggles evaluation.**

        ⚠️ **Important:** Any omitted policies should be carefully considered and documented as part of your organization's cybersecurity risk management program.

        Common reasons for omitting policies:
        - Policy is implemented by a third-party service that ScubaGoggles cannot audit
        - Policy is not applicable to your organization
        - Accepting risk for specific controls with proper documentation
        """,
            configured_label='Omitted',
            add_button_label='➕ Omit',
            config_noun='Omission',
            field_map={'rationale': 'rationale', 'expiration': 'expiration'},
            date_fields={'expiration'},
            render_form=self._render_omit_form,
            render_summary=self._render_omit_summary,
        )

    @staticmethod
    def _annotate_pre_render():
        """Handle tab-switch signal and pre-selected policy for annotate tab."""
        if st.session_state.get('switch_to_annotate_tab', False):
            st.session_state.switch_to_annotate_tab = False

        preselected_policy = st.session_state.get('selected_policy_for_annotation')
        if preselected_policy:
            st.success(f"📝 Ready to annotate: **{preselected_policy[0]}**")
            st.info(f"Description: {preselected_policy[1]}")
            if st.button("✅ Acknowledged"):
                del st.session_state.selected_policy_for_annotation
                st.rerun()

    def render_annotate_policies_tab(self):
        """Render annotate policies configuration tab"""
        self._render_policy_config_tab(
            config_key='annotatepolicy',
            prefix='annotate',
            title='Annotate Policies',
            help_content="""
            <div class="context-help">
            <strong>What are Policy Annotations?</strong><br>
            Adding contextual information and documentation to specific policy results for audit trails and remediation planning.<br><br>

            <strong>Annotation Types:</strong><br>
            • <strong>Action Plan:</strong> Document remediation steps for failing controls<br>
            • <strong>Incorrect Result:</strong> Mark false positives (use with caution)<br>
            • <strong>Context:</strong> Provide additional background information<br>
            • <strong>Remediation Date:</strong> Set target dates for addressing issues<br><br>

            <strong>Best Practices:</strong><br>
            • Always document reasons for marking results as incorrect<br>
            • Include specific remediation steps and responsible parties<br>
            • Set realistic remediation dates<br>
            • Review annotations regularly during security assessments<br><br>

            <strong>Warning:</strong> Use "Incorrect Result" sparingly to avoid security blind spots.
            </div>
            """,
            description="""
        **Use this section to add annotations to specific policy results.**

        Annotations allow you to:
        - Document action plans for failing controls
        - Mark incorrect results
        - Provide additional context for results
        - Set remediation dates for failing controls

        ⚠️ **Caution:** Exercise care when marking results as incorrect to avoid introducing blind spots.
        """,
            configured_label='Annotated',
            add_button_label='📝 Annotate',
            config_noun='Annotation',
            field_map={
                'comment': 'comment',
                'incorrect': 'incorrectresult',
                'remediation': 'remediationdate',
            },
            date_fields={'remediation'},
            render_form=self._render_annotate_form,
            render_summary=self._render_annotate_summary,
            pre_render=self._annotate_pre_render,
        )

    def render_exclusions_tab(self):
        """Render exclusions configuration tab (break glass + IMAP exceptions)"""
        self._render_break_glass_section()
        st.markdown("---")
        self._render_imap_exceptions_section()

    def _render_break_glass_section(self):  # pylint: disable=too-many-branches
        """Render break glass accounts section within the Exclusions tab."""
        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown('<h2 class="section-title">Break Glass Accounts</h2>', unsafe_allow_html=True)

        st.markdown("""
        **Configure super admin accounts that should be considered "break glass accounts".**

        Break glass accounts are emergency access accounts used only in critical situations and should be excluded
        from the overall super admin count in ScubaGoggles assessments.

        ⚠️ **Important:** These accounts should:
        - Be used only for emergency access
        - Have strong authentication controls
        - Be regularly audited
        - Have minimal day-to-day access
        """)

        break_glass_accounts = st.session_state.config_data.get('breakglassaccounts', [])

        st.subheader("➕ Add Break Glass Account")

        with st.form("break_glass_form", clear_on_submit=True):
            col1, col2 = st.columns([3, 1])
            with col1:
                bg_email_input = st.text_input(
                    "Break Glass Account Email",
                    placeholder="emergency-admin@example.org",
                    help="Email address of break glass account",
                    key="new_break_glass",
                    label_visibility="collapsed"
                )
            with col2:
                bg_submitted = st.form_submit_button(
                    "➕ Add Account", type="primary"
                )

        if bg_submitted:
            email = bg_email_input.strip()
            if not email:
                st.session_state.bg_add_status = ("empty", "")
            elif not ConfigValidator.validate_email(email):
                st.session_state.bg_add_status = ("invalid", email)
            elif email in break_glass_accounts:
                st.session_state.bg_add_status = ("duplicate", email)
            else:
                break_glass_accounts.append(email)
                st.session_state.config_data['breakglassaccounts'] = break_glass_accounts
                st.session_state.bg_add_status = ("success", email)
            st.rerun()

        self._show_add_status("bg_add_status", {
            "success": (st.success, lambda e: f"✅ Added break glass account: {e}"),
            "invalid": (st.error, lambda e: f"❌ Invalid email format: {e}"),
            "duplicate": (st.error, "❌ Account already exists in list"),
        }, fallback_msg="❌ Email address is required")

        if break_glass_accounts:
            st.subheader("📋 Current Break Glass Accounts")
            for i, account in enumerate(break_glass_accounts):
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"🚨 **{account}**")
                    st.caption("Emergency access account")
                with col2:
                    if st.button("🗑️ Remove", key=f"remove_bg_{i}"):
                        break_glass_accounts.remove(account)
                        st.session_state.config_data['breakglassaccounts'] = break_glass_accounts
                        st.success(f"✅ Removed break glass account: {account}")
                        st.rerun()
        else:
            st.info("ℹ️ No break glass accounts configured")

        st.markdown('</div>', unsafe_allow_html=True)

    def _render_imap_exceptions_section(self):
        """Render IMAP exceptions section within the Exclusions tab."""
        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown('<h2 class="section-title">IMAP Exceptions</h2>', unsafe_allow_html=True)

        st.markdown("""
        **Configure OUs and groups where IMAP access is allowed per GWS.GMAIL.9.1.**

        IMAP MAY be enabled on a per-OU or per-group basis when there is a specific need.
        Each exception requires at least an OU or a group (or both). If both are provided,
        the exception only applies to users in both the OU and the group.

        ⚠️ **Important:**
        - The OU must be a path relative to the top-level OU (cannot be the top-level OU itself)
        - Groups should be entered as email addresses (e.g., `examplegroup@example.com`)
        """)

        imap_exceptions = st.session_state.config_data.get('imapexceptions', [])

        st.subheader("➕ Add IMAP Exception")

        def _add_imap_exception():
            """Callback: validate and add an IMAP exception."""
            ou = st.session_state.get("new_imap_ou", "").strip()
            group = st.session_state.get("new_imap_group", "").strip()
            justification = st.session_state.get("new_imap_justification", "").strip()

            if not ou and not group:
                st.session_state.imap_add_status = ("missing_target", "")
            elif group and not ConfigValidator.validate_email(group):
                st.session_state.imap_add_status = ("invalid_group", group)
            else:
                exceptions = st.session_state.config_data.get('imapexceptions', [])
                entry: dict = {}
                if ou:
                    entry['ou'] = ou
                if group:
                    entry['group'] = group
                if justification:
                    entry['justification'] = justification
                exceptions.append(entry)
                st.session_state.config_data['imapexceptions'] = exceptions
                st.session_state.imap_add_status = ("success", "")

            st.session_state.new_imap_ou = ""
            st.session_state.new_imap_group = ""
            st.session_state.new_imap_justification = ""

        col1, col2 = st.columns(2)
        with col1:
            st.text_input(
                "Org Unit (OU)",
                placeholder="My OU/My sub OU",
                help="Org unit path relative to the top-level OU where IMAP should be allowed",
                key="new_imap_ou"
            )
        with col2:
            st.text_input(
                "Group Email",
                placeholder="examplegroup@example.com",
                help="Group email address where IMAP should be allowed",
                key="new_imap_group"
            )

        st.text_input(
            "Justification",
            placeholder="Brief explanation of why IMAP is needed",
            help="Optional justification for the IMAP exception",
            key="new_imap_justification"
        )

        st.button("➕ Add Exception", type="primary", on_click=_add_imap_exception,
                   key="add_imap_exception_btn")

        self._show_add_status("imap_add_status", {
            "success": (st.success, "✅ Added IMAP exception"),
            "invalid_group": (st.error, lambda d: f"❌ Invalid group email format: {d}"),
            "missing_target": (st.error, "❌ At least an OU or group email is required"),
        })

        if imap_exceptions:
            st.subheader("📋 Current IMAP Exceptions")
            for i, exc in enumerate(imap_exceptions):
                col1, col2 = st.columns([4, 1])
                with col1:
                    parts = []
                    if exc.get('ou'):
                        parts.append(f"**OU:** {exc['ou']}")
                    if exc.get('group'):
                        parts.append(f"**Group:** {exc['group']}")
                    st.markdown(" · ".join(parts))
                    if exc.get('justification'):
                        st.caption(exc['justification'])
                with col2:
                    if st.button("🗑️ Remove", key=f"remove_imap_{i}"):
                        imap_exceptions.pop(i)
                        st.session_state.config_data['imapexceptions'] = imap_exceptions
                        st.success("✅ Removed IMAP exception")
                        st.rerun()
        else:
            st.info("ℹ️ No IMAP exceptions configured")

        st.markdown('</div>', unsafe_allow_html=True)

    @staticmethod
    def _on_advanced_field_change():
        """Callback for advanced text inputs — sets a flag to show save feedback."""
        st.session_state.adv_field_saved = True

    def render_advanced_tab(self):
        """Render advanced configuration options that most users will never need."""
        if st.session_state.pop('adv_field_saved', False):
            st.toast("Setting saved", icon="✅")

        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown(
            '<h2 class="section-title">Advanced Configuration</h2>',
            unsafe_allow_html=True,
        )

        with st.expander("ℹ️ Help: Advanced Configuration", expanded=False):
            st.markdown("""
            <div class="context-help">
            <strong>Advanced Configuration:</strong><br>
            These settings override internal defaults used by ScubaGoggles.
            Most users will never need to change them.<br><br>

            <strong>Output File Names:</strong> Change the default base names
            for the various output artifacts (JSON, HTML, CSV, etc.).<br><br>

            <strong>Paths:</strong> Override the directories where Rego rules
            and baseline documents are loaded from.<br><br>

            <strong>Access Token:</strong> Provide a raw OAuth token instead
            of a credentials file.  Using a credentials file is the
            recommended approach; only use this when integrating with
            external tooling such as ScubaConnect.<br><br>

            <strong>UUID Truncation:</strong> Controls how many characters of
            the report UUID are appended to the output JSON filename.
            </div>
            """, unsafe_allow_html=True)

        st.warning(
            "⚠️ **These settings are for advanced users only.** "
            "Leaving fields blank will use the ScubaGoggles defaults."
        )

        data = st.session_state.config_data
        _on_change = self._on_advanced_field_change

        # --- Output file names ---
        st.markdown("### Output File Names")

        col1, col2 = st.columns(2)
        with col1:
            data['outjsonfilename'] = st.text_input(
                "Output JSON Filename",
                value=data.get('outjsonfilename', ''),
                placeholder="ScubaResults",
                help="Base name for the consolidated assessment JSON output",
                key="adv_outjsonfilename",
                on_change=_on_change,
            )
            data['outputproviderfilename'] = st.text_input(
                "Provider Output Filename",
                value=data.get('outputproviderfilename', ''),
                placeholder="ProviderSettingsExport",
                help="Base name for the provider settings export JSON",
                key="adv_outputproviderfilename",
                on_change=_on_change,
            )
            data['outputregofilename'] = st.text_input(
                "Rego Output Filename",
                value=data.get('outputregofilename', ''),
                placeholder="TestResults",
                help="Base name for the Rego/test results JSON",
                key="adv_outputregofilename",
                on_change=_on_change,
            )
        with col2:
            data['outputreportfilename'] = st.text_input(
                "Report Output Filename",
                value=data.get('outputreportfilename', ''),
                placeholder="BaselineReports",
                help="Base name for the main HTML report",
                key="adv_outputreportfilename",
                on_change=_on_change,
            )
            data['outputactionplanfilename'] = st.text_input(
                "Action Plan Output Filename",
                value=data.get('outputactionplanfilename', ''),
                placeholder="ActionPlan",
                help="Base name for the action plan CSV output",
                key="adv_outputactionplanfilename",
                on_change=_on_change,
            )

        st.divider()

        # --- Paths ---
        st.markdown("### Custom Paths")

        col1, col2 = st.columns(2)
        with col1:
            data['regopath'] = st.text_input(
                "Rego Path",
                value=data.get('regopath', ''),
                placeholder="(default: package rego/ directory)",
                help="Directory containing Rego policy files",
                key="adv_regopath",
                on_change=_on_change,
            )
        with col2:
            data['documentpath'] = st.text_input(
                "Document Path",
                value=data.get('documentpath', ''),
                placeholder="(default: package baselines/ directory)",
                help="Directory containing SCuBA baseline markdown documents",
                key="adv_documentpath",
                on_change=_on_change,
            )

        st.divider()

        # --- UUID truncation ---
        st.markdown("### Report Settings")

        uuid_choices = [0, 13, 18, 36]
        current_uuid = data.get('numberofuuidcharacterstotruncate', 18)
        if current_uuid not in uuid_choices:
            current_uuid = 18
        data['numberofuuidcharacterstotruncate'] = st.selectbox(
            "UUID Characters to Truncate",
            options=uuid_choices,
            index=uuid_choices.index(current_uuid),
            help=(
                "Controls how many characters are truncated from the "
                "report UUID when appended to outjsonfilename. "
                "Default is 18."
            ),
            key="adv_uuid_truncate",
            on_change=_on_change,
        )

        st.divider()

        # --- Access token ---
        st.markdown("### Authentication")

        data['accesstoken'] = st.text_input(
            "Access Token",
            value=data.get('accesstoken', ''),
            placeholder="(optional — credentials file is recommended)",
            help=(
                "OAuth access token to use instead of a credentials file. "
                "If provided, takes precedence over the credentials file. "
                "Using a credentials file is the recommended authentication method."
            ),
            type="password",
            key="adv_accesstoken",
            on_change=_on_change,
        )

        st.markdown('</div>', unsafe_allow_html=True)

    def render_preview_tab(self):
        """Render configuration preview"""
        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown('<h2 class="section-title">Configuration Preview</h2>', unsafe_allow_html=True)

        # Generate clean config
        clean_config = self.generate_clean_config()

        if clean_config:
            yaml_config = yaml.dump(clean_config, default_flow_style=False, sort_keys=False)

            for key in ('baselines', 'breakglassaccounts', 'preferreddnsresolvers'):
                yaml_config = self._yaml_array_to_flow(yaml_config, key)

            st.code(yaml_config, language='yaml')

            st.markdown("---")
            st.subheader("Save Configuration")

            errors = self._validate_before_save()
            if errors:
                self._show_validation_errors(errors)
            else:
                self._render_save_button(yaml_config)
        else:
            st.warning("Please fill in required fields in the Main tab")

        st.markdown('</div>', unsafe_allow_html=True)

    @staticmethod
    def _render_save_button(yaml_config: str):
        """Render a save button that opens a native Save-As dialog.

        Uses the File System Access API (``showSaveFilePicker``) supported
        by Chromium-based browsers (Chrome, Edge) to let the user choose
        where to save.  Falls back to a standard download for other browsers.
        """
        b64 = base64.b64encode(yaml_config.encode("utf-8")).decode("ascii")

        # The JS tries showSaveFilePicker first (Chrome/Edge).  If the
        # browser doesn't support it, it falls back to a classic download.
        save_js = f"""
        <script>
        async function saveConfig() {{
            const data = atob("{b64}");
            try {{
                if (window.showSaveFilePicker) {{
                    const handle = await window.showSaveFilePicker({{
                        suggestedName: "scubagoggles_config.yaml",
                        types: [{{
                            description: "YAML files",
                            accept: {{"text/yaml": [".yaml", ".yml"]}},
                        }}],
                    }});
                    const writable = await handle.createWritable();
                    await writable.write(data);
                    await writable.close();
                    return;
                }}
            }} catch (e) {{
                if (e.name === "AbortError") return;
            }}
            // Fallback: standard download
            const blob = new Blob([data], {{type: "text/yaml"}});
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "scubagoggles_config.yaml";
            a.click();
            URL.revokeObjectURL(url);
        }}
        </script>
        <button onclick="saveConfig()" style="
            background-color: #4a90e2;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 0.5rem 1rem;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
        ">💾 Save Configuration</button>
        """
        st.components.v1.html(save_js, height=50)

    def generate_clean_config(self) -> Dict[str, Any]:
        """Generate clean configuration dictionary"""
        config = {}
        data = st.session_state.config_data

        _pass_through = (
            'customerid', 'subjectemail', 'orgname', 'baselines',
            'credentials', 'orgunitname', 'description', 'quiet',
            'annotatepolicy', 'omitpolicy', 'breakglassaccounts',
            'imapexceptions', 'preferreddnsresolvers',
        )
        for key in _pass_through:
            if data.get(key):
                config[key] = data[key]

        # Output settings with special handling
        if data.get('outputpath') and data['outputpath'] != './':
            config['outputpath'] = data['outputpath']
        if data.get('darkmode'):
            config['darkmode'] = True
        if data.get('skipdoh'):
            config['skipdoh'] = True

        # Advanced settings (only emit when non-default)
        for key in (
            'outjsonfilename', 'regopath', 'documentpath',
            'outputproviderfilename', 'outputactionplanfilename',
            'outputregofilename', 'outputreportfilename',
            'accesstoken',
        ):
            if data.get(key):
                config[key] = data[key]

        uuid_val = data.get('numberofuuidcharacterstotruncate', 18)
        if uuid_val != 18:
            config['numberofuuidcharacterstotruncate'] = uuid_val

        return config

    def run(self):
        """Main application entry point"""
        self.setup_page_config()

        self.render_header()

        if not self.scubagoggles_available:
            st.warning(
                "ScubaGoggles backend is not installed. "
                "Running with limited functionality — version info and "
                "default configuration values may be inaccurate."
            )

        tabs = st.tabs([
            "🏢 Main",
            "📝 Annotate Policies",
            "🚫 Omit Policies",
            "🔒 Exclusions",
            "🌐 DNS Configuration",
            "⚙️ Advanced",
            "👁️ Preview"
        ])

        with tabs[0]:
            self.render_main_tab()

        with tabs[1]:
            self.render_annotate_policies_tab()

        with tabs[2]:
            self.render_omit_policies_tab()

        with tabs[3]:
            self.render_exclusions_tab()

        with tabs[4]:
            self.render_dns_config_tab()

        with tabs[5]:
            self.render_advanced_tab()

        with tabs[6]:
            self.render_preview_tab()

        # Status bar
        st.markdown("---")
        col1, col2, col3 = st.columns([2, 1, 1])

        with col1:
            if self.scubagoggles_available:
                st.markdown(
                    '<span class="status-indicator status-success">'
                    '✅ ScubaGoggles</span>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<span class="status-indicator status-warning">'
                    '⚠️ ScubaGoggles (backend not installed)</span>',
                    unsafe_allow_html=True,
                )

        with col2:
            st.markdown(f"**Version:** {self.version_class.number}")

        with col3:
            st.markdown("**[GitHub Repository](https://github.com/cisagov/ScubaGoggles)**")


def main():
    """Main function to run the professional UI"""
    app = ScubaConfigApp()
    app.run()


if __name__ == "__main__":
    main()
