"""
main.py - The Main Entry Point
------------------------------
This is the starting file for the entire application. When you run this program,
this is where the computer begins reading the code.

Think of this file as the 'Grand Architect' of the app. It:
1. Opens the 'Job Setup' window first to see who is using the app.
2. If that looks good, it builds the 'Main Window'.
3. It sets up the 'Tabs' (like different rooms in a house) for the user to work in.
4. It hooks up the 'Communication Lines' (called Signals) so that when something 
   happens in one part of the app, the other parts know about it.
"""

import sys
import os

# These are the building blocks from PyQt6 that let us create windows, buttons, and text boxes.
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QScrollArea, QPushButton, QLabel,
                             QSizePolicy, QMessageBox, QTabWidget, QTextEdit, QFrame)
from PyQt6.QtCore import Qt

# These are other files in this project that we are 'importing' so we can use them here.
import ui_styles
from dashboard_view import UnifiedDashboard
from utilities_view import UtilitiesView
from navigation_footer import NavigationFooter
from job_modal import JobSetupModal
from logger import get_logger

class PCAPFlowTraceApp(QMainWindow):
    """
    This class represents the Main Window of the application.
    It acts as a container for everything else the user sees.
    """
    def __init__(self, job_info):
        """
        The 'Setup' function that runs as soon as we create the window.
        Input: 'job_info' is a dictionary containing the Analyst's name and the Incident ID.
        """
        super().__init__()
        self.job_info = job_info # Save the job details so we can use them later
        
        # Set the text that appears at the very top bar of the window
        self.setWindowTitle(f"PCAP FlowTrace Enterprise - [{job_info['incident_id']}]")
        
        # Set the starting size of the window (Width: 1300, Height: 900)
        self.setMinimumSize(1300, 900)
        
        # 'get_logger()' gives us access to our custom logging system so we can record events
        self.logger = get_logger()
        
        # Build all the visual parts of the window
        self.setup_ui()
        
        # Apply the 'Dark Mode' colors and fonts
        self.apply_styles()
        
        # This is a 'Signal Connection'. 
        # Every time the logger records a message, it sends a 'log_signal'.
        # We 'connect' that signal to our 'update_console' function so the message pops up in the UI.
        self.logger.log_signal.connect(self.update_console)
        
        # Record a successful startup message
        self.logger.log("INFO", f"Enterprise Workspace initialized for {job_info['user']}.")

    def apply_styles(self):
        """
        This is where we tell the app how to look. 
        It reads the 'CSS' styles from our ui_styles.py file.
        """
        self.setStyleSheet(ui_styles.get_dark_theme())

    def setup_ui(self):
        """
        This function is like the blueprint for the window. 
        It defines the Header, the Tabs, the Console, and the Footer.
        """
        # The 'Central Widget' is the main area of the window.
        central = QWidget()
        central.setObjectName("MainContent")
        self.setCentralWidget(central)
        
        # A 'VBoxLayout' stacks things vertically (one on top of the other).
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0) # Remove empty space around the edges
        main_layout.setSpacing(0) # Remove space between components

        # --- PART 1: THE HEADER ---
        # This is the bar at the very top showing the Job ID and Analyst name.
        header_widget = QWidget()
        header_widget.setObjectName("AppHeader")
        header_widget.setMinimumHeight(60)
        
        # An 'HBoxLayout' stacks things horizontally (side-by-side).
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 0, 20, 0)
        
        title_label = QLabel(f"PCAP FLOWTRACE: {self.job_info['incident_id']}")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #0078d4;")
        header_layout.addWidget(title_label)
        
        # 'addStretch()' acts like a spring, pushing the items apart.
        header_layout.addStretch()
        
        user_label = QLabel(f"Analyst: {self.job_info['user']}")
        user_label.setStyleSheet("color: #888888; font-weight: bold;")
        header_layout.addWidget(user_label)
        
        # Add the completed header to the main vertical layout
        main_layout.addWidget(header_widget)

        # --- PART 2: THE MAIN TABS ---
        # This creates the 'Diagnostic Workspace' and 'Utility Suite' tabs.
        self.tabs = QTabWidget()
        self.tabs.setObjectName("MainTabs")
        
        # TAB A: Diagnostic Workspace (where the primary syncing happens)
        # We put it inside a 'ScrollArea' so if the content is too big, the user can scroll down.
        self.dashboard_scroll = QScrollArea()
        self.dashboard_scroll.setWidgetResizable(True)
        self.dashboard_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.dashboard = UnifiedDashboard(self.job_info)
        self.dashboard_scroll.setWidget(self.dashboard)
        self.tabs.addTab(self.dashboard_scroll, "Diagnostic Workspace")
        
        # TAB B: PCAP Utility Suite (extra tools like merging and extracting)
        self.utilities_scroll = QScrollArea()
        self.utilities_scroll.setWidgetResizable(True)
        self.utilities_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.utilities = UtilitiesView(self.job_info)
        self.utilities_scroll.setWidget(self.utilities)
        self.tabs.addTab(self.utilities_scroll, "PCAP Utility Suite")
        
        # Add the tabs to the main layout. 
        # The '1' at the end tells the layout to let the tabs take up as much space as possible.
        main_layout.addWidget(self.tabs, 1)

        # --- PART 3: THE LOG CONSOLE ---
        # This is the area at the bottom that shows tech details while the app works.
        console_container = QWidget()
        console_container.setObjectName("LogContainer")
        console_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.setSpacing(0) 

        # A small bar with a 'Hide/Show' button for the logs
        logs_header = QHBoxLayout()
        logs_header.setContentsMargins(16, 2, 16, 2) 
        logs_header.addWidget(QLabel("<b>Diagnostic Logs</b>"))
        logs_header.addStretch()
        self.btn_toggle_logs = QPushButton("Hide Logs")
        self.btn_toggle_logs.setMaximumWidth(90)
        self.btn_toggle_logs.setMinimumHeight(24) 
        self.btn_toggle_logs.clicked.connect(self.toggle_logs)
        logs_header.addWidget(self.btn_toggle_logs)
        console_layout.addLayout(logs_header)

        # The actual text box where logs are displayed
        self.console = QTextEdit()
        self.console.setReadOnly(True) # User shouldn't be able to type here
        self.console.setFixedHeight(120)
        self.console.setStyleSheet(ui_styles.get_console_style())
        console_layout.addWidget(self.console)
        
        main_layout.addWidget(console_container)

        # --- PART 4: THE FOOTER ---
        # This is the very bottom bar with the 'Reset Workspace' button.
        self.footer = NavigationFooter()
        self.footer.setObjectName("AppFooter")
        # When 'Reset Workspace' is clicked in the footer, run our 'reset_workspace' function.
        self.footer.reset_clicked.connect(self.reset_workspace)
        main_layout.addWidget(self.footer)

        # --- COMMUNICATION CONNECTIONS ---
        # Here we connect the sub-pages (Dashboard and Utilities) to the Footer.
        # This way, when they are working, they can send a message to the Footer to update the status.
        self.dashboard.status_update.connect(self.footer.set_status)
        self.utilities.status_update.connect(self.footer.set_status)

    def update_console(self, level, message):
        """
        Updates the text box at the bottom with a new log message.
        'level' is the type of message (INFO, ERROR, etc.)
        'message' is the actual text.
        """
        # Format the log with colors using our ui_styles helper
        self.console.append(ui_styles.format_log(level, message))
        # Move the scroll bar to the very bottom so the newest message is always visible
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def toggle_logs(self):
        """
        Hides or shows the log console text box when the button is clicked.
        """
        visible = self.console.isVisible()
        self.console.setVisible(not visible)
        self.btn_toggle_logs.setText("Show Logs" if visible else "Hide Logs")

    def reset_workspace(self):
        """
        This function clears out all the files and data from the app.
        It shows a 'Pop-up' first to make sure the user really wants to do this.
        """
        confirm = QMessageBox.question(
            self, "Reset Session", "Clear all session data and files?", 
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Tell each part of the app to clear its data
            self.dashboard.clear_pool()
            self.dashboard.filter_preview.clear()
            self.dashboard.flow_table.setRowCount(0)
            self.dashboard_scroll.verticalScrollBar().setValue(0)
            self.logger.log("INFO", "Enterprise Workspace Reset.")

# --- THE POWER SWITCH ---
# This block of code only runs if you start this file directly.
# It's like the main power switch for the whole program.
if __name__ == "__main__":
    # Create the 'Application' object (the engine of the GUI)
    app = QApplication(sys.argv)
    
    # 1. First, show the 'Job Setup' modal window
    modal = JobSetupModal()
    
    # '.exec()' pauses the code here until the user closes the modal window
    if modal.exec() == JobSetupModal.DialogCode.Accepted:
        # 2. If they clicked 'Launch Workspace', get the info they typed in
        job_info = modal.get_info()
        
        # 3. Create and show the main window using that info
        window = PCAPFlowTraceApp(job_info)
        window.show()
        
        # 4. Keep the app running until the user closes it
        sys.exit(app.exec())
    else:
        # If they clicked 'Cancel' on the setup, just exit the program
        sys.exit(0)
