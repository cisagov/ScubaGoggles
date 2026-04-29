"""
ScubaGoggles UI Package
Configuration interface for ScubaGoggles using Streamlit
"""

__version__ = "1.0.0"
__author__ = "CISA SCuBA Team"

from .scubaconfigapp import ScubaConfigApp
from .validation import ConfigValidator

__all__ = [
    "ScubaConfigApp",
    "ConfigValidator",
]
