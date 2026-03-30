"""
ScubaGoggles Configuration Interface

Streamlit-based configuration editor for ScubaGoggles Google Workspace
security assessments.  Provides tabbed UI for organization info, baseline
selection, policy omissions/annotations, break-glass accounts, and
YAML config export/import.
"""

# pylint: disable=line-too-long,too-many-lines

import base64
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict

import re
import streamlit as st
import yaml

from scubagoggles.reporter.md_parser import MarkdownParser, MarkdownParserError
from scubagoggles.ui.validation import ConfigValidator

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
                'preferreddnsresolvers': [],
                'skipdoh': False,
                'ui_dark_mode': False,
            }

        if 'ui_show_help' not in st.session_state:
            st.session_state.ui_show_help = False

        _defaults = {
            'orgname': '', 'orgunitname': '', 'description': '',
        }
        for widget_key, source in _defaults.items():
            if widget_key not in st.session_state:
                if isinstance(source, tuple):
                    st.session_state[widget_key] = (
                        st.session_state.config_data.get(source[0], source[1])
                    )
                else:
                    st.session_state[widget_key] = (
                        st.session_state.config_data.get(widget_key, source)
                    )

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

        # Set custom theme with green primary color for checkboxes
        st.markdown("""
        <script>
        const theme = {
            primaryColor: "#28a745",
            backgroundColor: "#f6fbfe",
            secondaryBackgroundColor: "#ffffff",
            textColor: "#262730"
        };
        window.streamlitTheme = theme;
        </script>
        """, unsafe_allow_html=True)

        # Custom CSS to match ScubaGear's professional look with dark mode support
        dark_mode = st.session_state.config_data.get('ui_dark_mode', False)

        # Always regenerate CSS to ensure it matches current state
        css_content = self._generate_css(dark_mode)
        st.markdown(css_content, unsafe_allow_html=True)

    def _generate_css(self, dark_mode):
        """Generate CSS based on dark mode setting"""

        if dark_mode:
            bg_color = "#0e1117"
            secondary_bg = "#262730"
            text_color = "#fafafa"
            section_bg = "#262730"
            border_color = "#4b5563"
        else:
            bg_color = "#f6fbfe"
            secondary_bg = "#ffffff"
            text_color = "#262730"
            section_bg = "white"
            border_color = "#e8f4fd"

        return f"""
        <style>
        /* Import Google Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@300;400;500;600;700&display=swap');

        /* Set Streamlit theme variables for green checkboxes */
        :root {{
            --primary-color: #28a745;
            --primary-color-dark: #1e7e34;
        }}

        /* Main app styling */
        .stApp {{
            background-color: {bg_color};
            font-family: 'Segoe UI', sans-serif;
            color: {text_color};
        }}

        /* Header toolbar bar */
        .header-bar {{
            background: {secondary_bg};
            border-bottom: 1px solid {border_color};
            padding: 0.6rem 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            border-radius: 8px 8px 0 0;
            margin-bottom: 0.25rem;
        }}

        .header-logo {{
            font-size: 2rem;
            line-height: 1;
            flex-shrink: 0;
        }}

        .header-text {{
            flex: 1;
            min-width: 0;
        }}

        .header-title {{
            font-size: 1.2rem;
            font-weight: 700;
            margin: 0;
            color: {text_color};
            white-space: nowrap;
        }}

        .header-subtitle {{
            font-size: 0.78rem;
            color: {'#9ca3af' if dark_mode else '#6b7280'};
            margin: 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        /* Tab styling */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 0;
            background-color: {secondary_bg};
            border-radius: 8px 8px 0 0;
            padding: 0.5rem;
        }}

        .stTabs [data-baseweb="tab"] {{
            background-color: transparent;
            border: none;
            padding: 0.75rem 1.5rem;
            font-weight: 500;
            color: {text_color};
        }}

        .stTabs [aria-selected="true"] {{
            background-color: {section_bg};
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        /* Section styling */
        .section-container {{
            background: transparent;
            padding: 0;
            border-radius: 0;
            box-shadow: none;
            margin-bottom: 0;
        }}

        .section-title {{
            font-size: 1.4rem;
            font-weight: 600;
            color: {text_color};
            margin-bottom: 1.5rem;
            border-bottom: 2px solid {border_color};
            padding-bottom: 0.5rem;
        }}

        /* Dark mode specific overrides */
        {'' if not dark_mode else '''
        /* Text colors for dark mode */
        .stMarkdown, .stMarkdown p, .stMarkdown div, .stMarkdown span,
        .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6,
        .stText, p, div, span, label {
            color: #fafafa !important;
        }

        /* Form elements */
        .stTextInput > div > div > input,
        .stTextArea > div > div > textarea,
        .stSelectbox > div > div > div,
        .stNumberInput > div > div > input {
            background-color: #374151 !important;
            color: #fafafa !important;
            border-color: #6b7280 !important;
        }

        /* Buttons */
        .stButton > button {
            background-color: #374151 !important;
            color: #fafafa !important;
            border-color: #6b7280 !important;
        }

        /* Labels and help text */
        .stTextInput label, .stTextArea label, .stSelectbox label,
        .stNumberInput label, .stCheckbox label {
            color: #fafafa !important;
        }

        /* Tab labels */
        .stTabs [data-baseweb="tab"] {
            color: #fafafa !important;
        }

        /* General text elements */
        [data-testid="stMarkdownContainer"] p,
        [data-testid="stMarkdownContainer"] div,
        [data-testid="stMarkdownContainer"] span,
        [data-testid="stText"] {
            color: #fafafa !important;
        }

        /* Alert boxes and notifications */
        .stAlert, [data-testid="stNotification"],
        [data-testid="stAlert"], .stWarning, .stError, .stSuccess, .stInfo {
            background-color: #374151 !important;
            color: #fafafa !important;
            border-color: #6b7280 !important;
        }

        /* Warning/Error/Success box content */
        .stAlert > div, .stAlert p, .stAlert span,
        [data-testid="stNotification"] > div,
        [data-testid="stNotification"] p,
        [data-testid="stNotification"] span {
            color: #fafafa !important;
        }

        /* Expander components */
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


        /* Container backgrounds */
        .stContainer, [data-testid="stVerticalBlock"] > div,
        [data-testid="stHorizontalBlock"] > div {
            background-color: transparent !important;
        }

        /* Metric components */
        .metric-container, [data-testid="stMetric"] {
            background-color: #374151 !important;
            color: #fafafa !important;
        }

        /* Dataframe/table styling */
        .stDataFrame, [data-testid="stDataFrame"] {
            background-color: #374151 !important;
            color: #fafafa !important;
        }

        '''}

        /* Form styling */
        .stTextInput > div > div > input {{
            border: 1px solid #d0d5e0;
            border-radius: 6px;
            padding: 0.75rem;
            font-size: 0.95rem;
        }}

        .stTextInput > div > div > input:focus {{
            border-color: #4a90e2;
            box-shadow: 0 0 0 2px rgba(74, 144, 226, 0.2);
        }}

        .stSelectbox > div > div > div {{
            border: 1px solid #d0d5e0;
            border-radius: 6px;
        }}

        /* Product selection grid */
        .product-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}

        .product-card {{
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 1.25rem;
            transition: all 0.2s ease;
        }}

        .product-card:hover {{
            border-color: #4a90e2;
            box-shadow: 0 4px 12px rgba(74, 144, 226, 0.1);
        }}

        .product-card.selected {{
            border-color: #4a90e2;
            background: #f0f8ff;
        }}

        .product-icon {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}

        .product-title {{
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 0.5rem;
        }}

        .product-description {{
            font-size: 0.9rem;
            color: #6c757d;
            line-height: 1.4;
        }}

        /* Button styling */
        .stButton > button {{
            border-radius: 6px;
            font-weight: 500;
            padding: 0.5rem 1rem;
            transition: all 0.2s ease;
            font-size: 0.85rem;
        }}

        .stCheckbox {{
            margin-top: 0 !important;
        }}

        /* Status indicators */
        .status-indicator {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 500;
        }}

        .status-success {{
            background: #d4edda;
            color: #155724;
        }}

        .status-warning {{
            background: #fff3cd;
            color: #856404;
        }}

        .status-error {{
            background: #f8d7da;
            color: #721c24;
        }}

        /* Help modal styling */
        .help-modal {{
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
        }}

        .help-content {{
            background: {section_bg};
            border-radius: 12px;
            padding: 2rem;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            color: {text_color};
        }}

        .help-close {{
            float: right;
            font-size: 1.5rem;
            cursor: pointer;
            color: {text_color};
            margin: -1rem -1rem 1rem 1rem;
        }}

        .help-section {{
            margin-bottom: 1.5rem;
        }}

        .help-title {{
            color: #4a90e2;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}

        /* Context help styling */
        .context-help {{
            background: {('rgba(74, 144, 226, 0.1)' if not dark_mode else 'rgba(74, 144, 226, 0.2)')};
            border-left: 4px solid #4a90e2;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 4px;
        }}

        .help-icon {{
            color: #4a90e2;
            font-size: 1.2rem;
            cursor: pointer;
            margin-left: 0.5rem;
        }}

        .help-icon:hover {{
            color: #3d5b96;
        }}

        /* Hide Streamlit default elements */
        #MainMenu {{display: none !important;}}
        footer {{display: none !important;}}
        .stDeployButton {{display: none !important;}}
        button[kind="header"] {{display: none !important;}}
        [data-testid="stToolbar"] {{display: none !important;}}
        .stActionButton {{display: none !important;}}
        header {{display: none !important;}}
        [data-testid="stSidebar"],
        [data-testid="collapsedControl"] {{display: none !important;}}

        /* Remove the top padding/margin Streamlit reserves for its hidden header */
        .stAppViewBlockContainer,
        [data-testid="stAppViewBlockContainer"] {{
            padding-top: 0 !important;
        }}
        .block-container {{
            padding-top: 0 !important;
        }}
        [data-testid="stApp"] > div:first-child {{
            padding-top: 0 !important;
        }}
        .stMain {{
            padding-top: 0 !important;
        }}
        .main .block-container {{
            padding-top: 0.25rem !important;
            margin-top: 0 !important;
        }}
        </style>
        """

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
            self._import_policy_and_account_sections(config)
            self._show_import_summary()
            st.rerun()

        except yaml.YAMLError as e:
            st.error(f"❌ YAML parsing error: {str(e)}")
        except Exception as e:
            st.error(f"❌ Import error: {str(e)}")

    @staticmethod
    def _normalize_config_keys(config: dict) -> dict:
        """Return a copy of *config* with top-level keys normalized to lowercase."""
        normalized = {}
        for key, value in config.items():
            normalized[str(key).lower()] = value
        return normalized

    @staticmethod
    def _import_org_fields(config: dict):
        """Import organization-level fields from *config* into session state."""
        for yaml_key, state_key in (
            ('orgname', 'orgname'),
            ('orgunitname', 'orgunitname'),
            ('description', 'description'),
        ):
            if yaml_key in config:
                st.session_state.config_data[state_key] = config[yaml_key]
                st.session_state[state_key] = config[yaml_key]

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
    def _import_policy_and_account_sections(config: dict):
        """Import omit-policy, annotate-policy, break-glass accounts, and DNS settings."""
        if 'omitpolicy' in config and isinstance(config['omitpolicy'], dict):
            st.session_state.config_data['omitpolicy'] = config['omitpolicy']

        if 'annotatepolicy' in config and isinstance(config['annotatepolicy'], dict):
            st.session_state.config_data['annotatepolicy'] = config['annotatepolicy']

        if 'breakglassaccounts' in config:
            breakglass = config['breakglassaccounts']
            if isinstance(breakglass, list):
                st.session_state.config_data['breakglassaccounts'] = breakglass
            elif breakglass:
                st.session_state.config_data['breakglassaccounts'] = [breakglass]
            else:
                st.session_state.config_data['breakglassaccounts'] = []

        if 'preferreddnsresolvers' in config:
            resolvers = config['preferreddnsresolvers']
            if isinstance(resolvers, list):
                st.session_state.config_data['preferreddnsresolvers'] = resolvers
            elif resolvers:
                st.session_state.config_data['preferreddnsresolvers'] = [str(resolvers)]
            else:
                st.session_state.config_data['preferreddnsresolvers'] = []

        if 'skipdoh' in config:
            st.session_state.config_data['skipdoh'] = bool(config['skipdoh'])
            st.session_state['skipdoh_checkbox'] = bool(config['skipdoh'])

    @staticmethod
    def _show_import_summary():
        """Display a success toast summarising what was imported."""
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

        st.success("✅ Configuration imported successfully!")
        if imported_items:
            st.info("📋 **Imported:** " + " • ".join(imported_items))

    def open_configuration_from_disk(self):
        """Open a native file dialog and load the selected YAML config."""
        try:
            file_path = self._run_tk_dialog(
                "from tkinter import filedialog; "
                "print(filedialog.askopenfilename("
                "defaultextension='.yaml', "
                "filetypes=[('YAML files','*.yaml'),('YAML files','*.yml'),('All files','*.*')], "
                "title='Open ScubaGoggles Configuration')); "
                "root.destroy()"
            )

            if not file_path:
                st.info("Open cancelled.")
                return

            path = Path(file_path)
            if not path.is_file():
                st.error(f"File not found: {file_path}")
                return

            yaml_content = path.read_text(encoding="utf-8")
            config = yaml.safe_load(yaml_content)

            if not config or not isinstance(config, dict):
                st.error("Invalid or empty YAML file.")
                return

            class _Wrapper:  # pylint: disable=too-few-public-methods
                """Mimic an uploaded file so import_configuration can be reused."""
                def __init__(self, data: bytes):
                    self._data = data
                def read(self):
                    """Return the stored bytes."""
                    return self._data

            self.import_configuration(_Wrapper(yaml_content.encode("utf-8")))

        except subprocess.TimeoutExpired:
            st.info("Open dialog timed out.")
        except Exception as e:
            st.error(f"Failed to open configuration: {e}")

    @staticmethod
    def _run_tk_dialog(script: str, timeout: int = 120) -> str:
        """Run a tkinter dialog in a subprocess and return stdout.

        The script is prefixed with the standard tkinter root-window
        boilerplate (hidden, topmost) so callers only need to supply
        the dialog-specific logic.
        """
        preamble = (
            "import tkinter as tk; "
            "root = tk.Tk(); root.withdraw(); "
            "root.attributes('-topmost', True); root.update(); "
        )
        result = subprocess.run(
            [sys.executable, "-c", preamble + script],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip()

    def _confirm_and_reset(self):
        """Show a native Yes/No confirmation before resetting."""
        try:
            answer = self._run_tk_dialog(
                "from tkinter import messagebox; "
                "answer = messagebox.askyesno("
                "'Confirm Reset', "
                "'Are you sure you want to reset all fields to their defaults?\\n\\n"
                "All unsaved changes will be lost.'); "
                "print('yes' if answer else 'no'); "
                "root.destroy()",
                timeout=60,
            )
            if answer == "yes":
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
        except Exception:
            pass

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

    def _show_validation_errors(self, errors: list):
        """Show validation errors in a native warning dialog."""
        bullet_list = "\n".join(f"  - {e}" for e in errors)
        message = f"The following validation errors occurred:\n{bullet_list}"
        encoded = base64.b64encode(message.encode("utf-8")).decode("ascii")
        try:
            self._run_tk_dialog(
                "from tkinter import messagebox; "
                "import base64; "
                f"msg = base64.b64decode('{encoded}').decode('utf-8'); "
                "messagebox.showwarning('Validation Errors', msg); "
                "root.destroy()",
                timeout=60,
            )
        except Exception:
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

        if not (selected_baselines and self.available_policies):
            st.warning("⚠️ Please select products in the Main tab first to see available policies")
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
            if st.button("📂 Open", use_container_width=True, help="Open an existing configuration file"):
                self.open_configuration_from_disk()
        with btn_reset:
            if st.button("🔄 Reset", use_container_width=True, help="Reset all fields to defaults"):
                self._confirm_and_reset()
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
        - Dark mode is available via the header toggle
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

    def get_baseline_info(self):
        """Get information about available baselines"""
        return {
            'commoncontrols': {
                'icon': '🔐',
                'title': 'Common Controls',
                'description': 'Enterprise-level security controls across the entire GWS admin console including authentication, access control, and session management'
            },
            'assuredcontrols': {
                'icon': '🛡️',
                'title': 'Assured Controls',
                'description': 'Advanced security controls for organizations with Assured Controls or Assured Controls Plus licenses including data access approvals and data regions'
            },
            'gmail': {
                'icon': '📧',
                'title': 'Gmail',
                'description': 'Email security controls and policies for Gmail configuration'
            },
            'drive': {
                'icon': '📁',
                'title': 'Google Drive',
                'description': 'File sharing and access controls for Google Drive'
            },
            'calendar': {
                'icon': '📅',
                'title': 'Calendar',
                'description': 'Calendar sharing and privacy settings for Google Calendar'
            },
            'meet': {
                'icon': '📹',
                'title': 'Google Meet',
                'description': 'Video conferencing security and access controls'
            },
            'groups': {
                'icon': '👥',
                'title': 'Groups',
                'description': 'Google Groups configuration and permissions'
            },
            'chat': {
                'icon': '💬',
                'title': 'Google Chat',
                'description': 'Chat and messaging security controls'
            },
            'sites': {
                'icon': '🌐',
                'title': 'Google Sites',
                'description': 'Website creation and sharing controls'
            },
            'classroom': {
                'icon': '🎓',
                'title': 'Classroom',
                'description': 'Educational platform security and privacy controls'
            },
            'gemini': {
                'icon': '🤖',
                'title': 'Gemini',
                'description': 'AI-powered features and data processing controls'
            }
        }

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

        self._render_dns_config()

        st.markdown('</div>', unsafe_allow_html=True)

    def _render_dns_config(self):
        """Render the DNS configuration section inside the Main tab."""
        st.markdown('<h3 style="margin-top: 2rem;">DNS Configuration</h3>', unsafe_allow_html=True)

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

        def _add_dns_resolver():
            """Callback: validate and add a DNS resolver IP, then clear the input."""
            ip = st.session_state.get("new_dns_resolver", "").strip()
            resolvers = st.session_state.config_data.get('preferreddnsresolvers', [])
            if not ip:
                st.session_state.dns_add_status = ("empty", "")
            elif not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                st.session_state.dns_add_status = ("invalid", ip)
            elif ip in resolvers:
                st.session_state.dns_add_status = ("duplicate", ip)
            else:
                resolvers.append(ip)
                st.session_state.config_data['preferreddnsresolvers'] = resolvers
                st.session_state.dns_add_status = ("success", ip)
            st.session_state.new_dns_resolver = ""

        col1, col2 = st.columns([3, 1])
        with col1:
            st.text_input(
                "DNS Resolver IP Address",
                placeholder="8.8.8.8",
                help="IP address of a DNS resolver (e.g., 8.8.8.8)",
                key="new_dns_resolver",
                label_visibility="collapsed"
            )
        with col2:
            st.button("➕ Add Resolver", type="primary",
                       on_click=_add_dns_resolver, key="add_dns_btn")

        self._show_dns_add_status()

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

    @staticmethod
    def _show_dns_add_status():
        """Display feedback from the most recent DNS resolver add attempt."""
        status = st.session_state.pop("dns_add_status", None)
        if not status:
            return
        kind, ip = status
        _messages = {
            "success": (st.success, f"✅ Added DNS resolver: {ip}"),
            "invalid": (st.error, f"❌ Invalid IP address format: {ip}"),
            "duplicate": (st.error, "❌ Resolver already exists in list"),
        }
        fn, msg = _messages.get(kind, (st.error, "❌ IP address is required"))
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

    def render_break_glass_tab(self):
        """Render break glass accounts configuration tab"""
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

        # Current break glass accounts
        break_glass_accounts = st.session_state.config_data.get('breakglassaccounts', [])

        # Add new break glass account
        st.subheader("➕ Add Break Glass Account")

        def _add_break_glass_account():
            """Callback: runs before the next render so we can clear the widget."""
            email = st.session_state.get("new_break_glass", "").strip()
            accounts = st.session_state.config_data.get('breakglassaccounts', [])
            if not email:
                st.session_state.bg_add_status = ("empty", "")
            elif not ConfigValidator.validate_email(email):
                st.session_state.bg_add_status = ("invalid", email)
            elif email in accounts:
                st.session_state.bg_add_status = ("duplicate", email)
            else:
                accounts.append(email)
                st.session_state.config_data['breakglassaccounts'] = accounts
                st.session_state.bg_add_status = ("success", email)
            st.session_state.new_break_glass = ""

        col1, col2 = st.columns([3, 1])
        with col1:
            st.text_input(
                "Break Glass Account Email",
                placeholder="emergency-admin@example.org",
                help="Email address of break glass account",
                key="new_break_glass"
            )

        with col2:
            st.button("➕ Add Account", type="primary", on_click=_add_break_glass_account)

        status = st.session_state.pop("bg_add_status", None)
        if status:
            kind, email = status
            if kind == "success":
                st.success(f"✅ Added break glass account: {email}")
            elif kind == "invalid":
                st.error(f"❌ Invalid email format: {email}")
            elif kind == "duplicate":
                st.error("❌ Account already exists in list")
            else:
                st.error("❌ Email address is required")

        # Display current break glass accounts
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

    def render_preview_tab(self):
        """Render configuration preview"""
        st.markdown('<div class="section-container">', unsafe_allow_html=True)
        st.markdown('<h2 class="section-title">Configuration Preview</h2>', unsafe_allow_html=True)

        # Generate clean config
        clean_config = self.generate_clean_config()

        if clean_config:
            # Show YAML preview with flow style for arrays to match ScubaGoggles conventions
            yaml_config = yaml.dump(clean_config, default_flow_style=False, sort_keys=False)

            for key in ('baselines', 'breakglassaccounts', 'preferreddnsresolvers'):
                yaml_config = self._yaml_array_to_flow(yaml_config, key)

            st.code(yaml_config, language='yaml')

            st.markdown("---")
            st.subheader("Save Configuration")

            if st.button("💾 Save Configuration"):
                errors = self._validate_before_save()
                if errors:
                    self._show_validation_errors(errors)
                else:
                    try:
                        file_path = self._run_tk_dialog(
                            "from tkinter import filedialog; "
                            "print(filedialog.asksaveasfilename("
                            "defaultextension='.yaml', "
                            "filetypes=[('YAML files','*.yaml'),"
                            "('YAML files','*.yml'),"
                            "('All files','*.*')], "
                            "initialfile='scubagoggles_config.yaml', "
                            "title='Save ScubaGoggles Configuration')); "
                            "root.destroy()"
                        )

                        if file_path:
                            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                            Path(file_path).write_text(yaml_config, encoding="utf-8")
                            st.success(f"Configuration saved to **{Path(file_path).resolve()}**")
                        else:
                            st.info("Save cancelled.")
                    except subprocess.TimeoutExpired:
                        st.info("Save dialog timed out.")
                    except Exception as e:
                        st.error(f"Failed to save: {e}")
        else:
            st.warning("Please fill in required fields in the Main tab")

        st.markdown('</div>', unsafe_allow_html=True)

    def generate_clean_config(self) -> Dict[str, Any]:
        """Generate clean configuration dictionary"""
        config = {}
        data = st.session_state.config_data

        # data-key → config-key for simple pass-through fields
        _direct = (
            ('customerid', 'customerid'),
            ('subjectemail', 'subjectemail'),
            ('orgname', 'orgname'),
            ('baselines', 'baselines'),
            ('credentials', 'credentials'),
            ('orgunitname', 'orgunitname'),
            ('description', 'description'),
            ('quiet', 'quiet'),
            ('annotatepolicy', 'annotatepolicy'),
            ('omitpolicy', 'omitpolicy'),
            ('breakglassaccounts', 'breakglassaccounts'),
            ('preferreddnsresolvers', 'preferreddnsresolvers'),
        )
        for src, dest in _direct:
            if data.get(src):
                config[dest] = data[src]

        # Output settings with special handling
        if data.get('outputpath') and data['outputpath'] != './':
            config['outputpath'] = data['outputpath']
        if data.get('darkmode'):
            config['darkmode'] = True
        if data.get('skipdoh'):
            config['skipdoh'] = True

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
            "🚨 Break Glass",
            "👁️ Preview"
        ])

        with tabs[0]:
            self.render_main_tab()

        with tabs[1]:
            self.render_annotate_policies_tab()

        with tabs[2]:
            self.render_omit_policies_tab()

        with tabs[3]:
            self.render_break_glass_tab()

        with tabs[4]:
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
