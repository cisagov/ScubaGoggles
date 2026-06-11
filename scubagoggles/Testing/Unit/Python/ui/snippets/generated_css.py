"""Expected CSS output for ScubaConfigApp._generate_css tests."""

FORCED_DARK_CSS = """<style>
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

AUTO_DARK_CSS = """<style>
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
@media (prefers-color-scheme: dark) {
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
    
}

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

EXPECTED_CSS = {
    True: FORCED_DARK_CSS,
    False: AUTO_DARK_CSS,
}
