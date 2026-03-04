"""
ScubaGoggles UI Package
Configuration interface for ScubaGoggles using Streamlit
"""

__version__ = "1.0.0"
__author__ = "CISA SCuBA Team"

# Make main components available at package level
try:
    from .scubaconfigapp import ScubaConfigApp
    from .validation import ConfigValidator, UIValidator
    from .config_generator import ConfigGenerator
    from .runner import ScubaRunner, ReportManager
    
    __all__ = [
        'ScubaConfigApp',
        'ConfigValidator',
        'UIValidator',
        'ConfigGenerator',
        'ScubaRunner',
        'ReportManager'
    ]
    
except ImportError:
    # Graceful degradation if dependencies are missing
    __all__ = []


def launch_ui():
    """Launch the ScubaGoggles configuration UI"""
    try:
        from .launch import main
        main()
    except ImportError as e:
        print(f"❌ Cannot launch UI: {e}")
        print("📦 Please install UI requirements: pip install streamlit")


def get_ui_info():
    """Get information about the UI package"""
    return {
        'version': __version__,
        'author': __author__,
        'description': 'Streamlit-based configuration interface for ScubaGoggles',
        'dependencies': ['streamlit', 'pyyaml'],
        'launch_command': 'python -m scubagoggles.ui.launch'
    }