"""
ScubaGoggles UI Package
Configuration interface for ScubaGoggles using Streamlit
"""

__version__ = "1.0.0"
__author__ = "CISA SCuBA Team"

from .config_generator import ConfigGenerator
from .runner import ReportManager, ScubaRunner
from .scubaconfigapp import ScubaConfigApp
from .validation import ConfigValidator, UIValidator

__all__ = [
    "ScubaConfigApp",
    "ConfigValidator",
    "UIValidator",
    "ConfigGenerator",
    "ScubaRunner",
    "ReportManager",
]


def launch_ui() -> None:
    """Launch the ScubaGoggles configuration UI."""
    from .launch import main

    main()


def get_ui_info() -> dict:
    """Get information about the UI package."""
    return {
        'version': __version__,
        'author': __author__,
        'description': 'Streamlit-based configuration interface for ScubaGoggles',
        'dependencies': ['streamlit', 'pyyaml'],
        'launch_command': 'python -m scubagoggles.ui.launch'
    }