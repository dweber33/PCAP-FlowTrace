"""
This module provides a setup dialog (a 'modal' window) that appears when the app starts.
It collects basic information about the investigation, such as the Incident ID, 
the name of the analyst, and where to save the processed files.
"""

import os
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QFileDialog, QFormLayout)
from PyQt6.QtCore import Qt

class JobSetupModal(QDialog):
    """
    A pop-up window to configure the initial settings for a PCAP analysis job.
    
    This window ensures that every investigation starts with a clear Incident ID 
    and a designated output folder.
    """
    
    def __init__(self, parent=None):
        """
        Sets up the window's basic properties and starts building the user interface.
        
        Inputs:
            parent (QWidget, optional): The main window that 'owns' this dialog.
        """
        super().__init__(parent)
        self.setWindowTitle("PCAP FlowTrace - Enterprise Job Setup")
        self.setMinimumWidth(450)
        self.setup_ui()
        self.job_info = {}

    def setup_ui(self):
        """
        Creates and arranges all the buttons, labels, and text boxes in the window.
        """
        layout = QVBoxLayout(self)
        
        # Add a welcoming header
        header = QLabel("<h2>Enterprise Diagnostics - Job Setup</h2>")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Create a form-style layout for the inputs
        form = QFormLayout()
        
        # 1. Incident ID Input
        self.edit_incident = QLineEdit("INC-0001")
        
        # 2. Analyst Name Input (defaults to the current Windows username)
        self.edit_user = QLineEdit(os.getlogin() if hasattr(os, 'getlogin') else "Analyst")
        
        # 3. Output Directory Input (with a 'Browse' button)
        self.edit_out_dir = QLineEdit(os.path.abspath("output"))
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self.browse_output)
        
        # Bundle the text box and the browse button together horizontally
        out_layout = QHBoxLayout()
        out_layout.addWidget(self.edit_out_dir)
        out_layout.addWidget(btn_browse)
        
        # Add the rows to the form
        form.addRow("Incident ID:", self.edit_incident)
        form.addRow("Analyst Name:", self.edit_user)
        form.addRow("Output Directory:", out_layout)
        
        layout.addLayout(form)
        
        # The main button to launch the application
        btn_start = QPushButton("Launch Workspace")
        btn_start.setObjectName("ActionButton")
        btn_start.setFixedHeight(40)
        btn_start.clicked.connect(self.accept_job)
        layout.addWidget(btn_start)

    def browse_output(self):
        """
        Opens a standard Windows folder selector so the user can choose 
        where to save their work.
        """
        d = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if d:
            self.edit_out_dir.setText(d)

    def accept_job(self):
        """
        Collects all the information from the text boxes and closes the window.
        
        This is called when the user clicks 'Launch Workspace'.
        """
        self.job_info = {
            "incident_id": self.edit_incident.text(),
            "user": self.edit_user.text(),
            "output_dir": self.edit_out_dir.text()
        }
        # 'accept' tells the main app that the user finished successfully
        self.accept()

    def get_info(self):
        """
        Provides the collected job information to whichever part of the app needs it.
        
        Returns:
            dict: A dictionary containing incident_id, user, and output_dir.
        """
        return self.job_info
