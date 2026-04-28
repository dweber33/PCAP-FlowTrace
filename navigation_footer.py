"""
This module defines the 'Footer' or bottom bar of the application.
The footer is used to display the current system status (like 'Ready' or 'Syncing...')
and provides a quick way for the user to reset their entire workspace.
"""

from PyQt6.QtWidgets import QWidget, QHBoxLayout, QPushButton, QLabel, QProgressBar, QVBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal

class NavigationFooter(QWidget):
    """
    A persistent bottom bar that shows status and common actions.
    
    It stays at the bottom of the main window no matter which tab is selected.
    """
    # This signal is sent when the user clicks 'Reset Workspace'.
    reset_clicked = pyqtSignal()

    def __init__(self, parent=None):
        """
        Initializes the footer and builds its layout.
        
        Inputs:
            parent (QWidget, optional): The main window containing this footer.
        """
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        """
        Creates and arranges the status labels and reset button within the footer.
        """
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 6, 16, 6)
        layout.setSpacing(12)
        
        # --- LEFT SIDE: THE RESET BUTTON ---
        self.btn_reset = QPushButton("Reset Workspace")
        self.btn_reset.setMinimumWidth(120)
        self.btn_reset.setMinimumHeight(40)
        # When clicked, we tell the rest of the app via our 'reset_clicked' signal.
        self.btn_reset.clicked.connect(self.reset_clicked.emit)
        layout.addWidget(self.btn_reset)
        
        # Add space to push the status area to the center
        layout.addStretch()
        
        # --- CENTER AREA: SYSTEM STATUS ---
        status_container = QWidget()
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(2)
        
        # The text label (e.g., 'System Ready' or 'Processing...')
        self.status_label = QLabel("System Ready")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #888888; font-size: 11px; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        
        # A small progress bar that appears when a long task is running
        self.status_progress = QProgressBar()
        # An 'indeterminate' progress bar (bouncing back and forth)
        self.status_progress.setRange(0, 0)
        self.status_progress.setVisible(False) # Hidden by default
        self.status_progress.setFixedHeight(12)
        self.status_progress.setMaximumWidth(250)
        status_layout.addWidget(self.status_progress, 0, Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(status_container)
        
        # Add space to keep the status centered
        layout.addStretch()
        
        # --- RIGHT SIDE: SPACER ---
        # This keeps the layout balanced since there's a button on the left
        right_spacer = QWidget()
        right_spacer.setMinimumWidth(120)
        layout.addWidget(right_spacer)

    def set_status(self, text, show_progress=False, color="#888888"):
        """
        Updates the text and appearance of the status bar.
        
        Inputs:
            text (str): The message to display to the user.
            show_progress (bool): Whether to show the bouncing progress bar.
            color (str): The color of the text (in hex format, e.g., '#ff0000').
        """
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold;")
        self.status_progress.setVisible(show_progress)
