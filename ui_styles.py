"""
This module defines the visual appearance (the 'theme') of the entire application.
It uses 'Qt Style Sheets' (similar to CSS for websites) to set colors, fonts, 
and layouts for buttons, tables, and other user interface elements.
"""

def get_dark_theme():
    """
    Provides a comprehensive 'Dark Mode' theme for the application.
    
    This theme uses dark grays and blacks for backgrounds, with blue and 
    green accents for buttons and interactive elements.
    
    Returns:
        str: A large string containing all the style rules.
    """
    return """
    QMainWindow {
        background-color: #121212;
        color: #e0e0e0;
    }
    QWidget {
        background-color: #121212;
        color: #e0e0e0;
        font-family: 'Segoe UI', sans-serif;
    }
    QPushButton {
        background-color: #333333;
        border: 1px solid #555555;
        border-radius: 4px;
        padding: 8px 16px;
        min-width: 80px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #444444;
        border-color: #007acc;
    }
    QPushButton:pressed {
        background-color: #007acc;
    }
    
    /* Styles for the section headers (Breadcrumbs) */
    QLabel#Breadcrumb {
        font-size: 14px;
        font-weight: bold;
        padding: 10px;
        color: #555555;
        border-bottom: 2px solid #333333;
    }
    QLabel#Breadcrumb[active="true"] {
        color: #0078d4;
        border-bottom: 2px solid #0078d4;
    }
    
    /* Styles for smaller, less important text labels */
    QLabel#Subtitle {
        font-size: 11px;
        color: #888888;
        margin-bottom: 10px;
    }

    /* Styles for the big 'Action' buttons (like 'Execute') */
    QPushButton#ActionButton {
        background-color: #0078d4;
        font-size: 14px;
        min-height: 40px;
        border-radius: 6px;
        color: white;
    }
    QPushButton#ActionButton:disabled {
        background-color: #222222;
        color: #555555;
    }
    QPushButton#ActionButton[state="dry"] {
        background-color: #d48800; /* Orange color for 'preview' mode */
    }
    QPushButton#ActionButton[state="success"] {
        background-color: #28a745; /* Green color for 'ready' or 'done' state */
    }

    QPushButton#ActionButton[state="muted"] {
        background-color: #444444;
        font-size: 12px;
        height: 35px;
    }
    
    /* Special styling for the Protocol selection buttons (TCP/UDP) */
    QPushButton#ProtocolBtn {
        background-color: #333333;
        border: 1px solid #555555;
        border-radius: 0px;
        min-width: 80px;
        padding: 6px;
    }
    QPushButton#ProtocolBtn[active="true"] {
        background-color: #0078d4;
        border-color: #0078d4;
        color: white;
    }
    QPushButton#ProtoLeft {
        border-top-left-radius: 4px;
        border-bottom-left-radius: 4px;
    }
    QPushButton#ProtoRight {
        border-top-right-radius: 4px;
        border-bottom-right-radius: 4px;
        border-left: none;
    }
    
    /* Styling for the data tables */
    QTableWidget::item:selected {
        background-color: #0078d4;
        color: white;
    }
    QLineEdit, QTextEdit, QTableWidget {
        background-color: #1e1e1e;
        border: 1px solid #333333;
        border-radius: 4px;
        padding: 4px;
        color: #e0e0e0;
    }
    QHeaderView::section {
        background-color: #252525;
        color: #e0e0e0;
        padding: 4px;
        border: 1px solid #333333;
    }
    
    /* Styling for the progress bars */
    QProgressBar {
        border: 1px solid #333333;
        border-radius: 4px;
        text-align: center;
        height: 12px;
    }
    QProgressBar::chunk {
        background-color: #007acc;
    }
    
    /* Styling for the labeled boxes (Group Boxes) */
    QGroupBox {
        border: 1px solid #333333;
        border-radius: 6px;
        margin-top: 15px;
        font-weight: bold;
    }
    
    /* Miscellaneous IDs used for specific containers */
    QWidget#MainContent {
        background-color: #121212;
    }
    QWidget#AppHeader, QWidget#AppFooter {
        background-color: #101010;
        border: 1px solid #222222;
    }
    QScrollArea#BodyScroller {
        background-color: #181818;
        border: none;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 3px 0 3px;
    }
    
    /* Styling for checkboxes used as toggles */
    QCheckBox#ProtocolToggle {
        spacing: 5px;
    }
    QCheckBox#ProtocolToggle::indicator {
        width: 50px;
        height: 24px;
    }
    """

def get_console_style():
    """
    Provides styling for the log console/terminal at the bottom of the app.
    
    This uses a 'Monospaced' font (like Consolas) so that text and columns 
    align perfectly, just like in a code editor.
    
    Returns:
        str: The console-specific style sheet.
    """
    return """
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.4;
    background-color: #0a0a0a;
    border: none;
    """

def format_log(level, msg):
    """
    Turns a plain log message into a colorful HTML string for the console.
    
    Inputs:
        level (str): The log level (e.g., 'INFO', 'ERROR', 'SUCCESS').
        msg (str): The message text.
        
    Returns:
        str: An HTML snippet with the level highlighted in color.
    """
    # Define a color for each level
    colors = {
        "INFO": "#00d4ff",   # Cyan
        "SYNC": "#00ff7f",   # Spring Green
        "WARN": "#ffcc00",   # Yellow/Amber
        "ERROR": "#ff3333",  # Red
        "STAGE": "#bb86fc"   # Purple
    }
    color = colors.get(level, "#ffffff") # Default to white if level is unknown
    return f'<span style="color: {color};">[{level}]</span> {msg}'
