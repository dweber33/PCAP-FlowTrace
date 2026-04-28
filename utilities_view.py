"""
utilities_view.py - The PCAP Utility Suite
-----------------------------------------
This file creates the 'PCAP Utility Suite' tab. 
It contains standalone tools that don't necessarily need the main 
diagnostic workflow.

Tools included:
1. Multi-Merge: Combine many PCAPs into one with custom labels.
2. Data Extraction: Convert PCAPs to CSV, JSON, or Parquet for analysis.
3. Query Engine: Search through PCAPs or Parquet files using filters.
4. AI Token Counter: See how many 'AI tokens' are in a file.
"""

import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QFileDialog, QMenu, QMessageBox,
                             QFrame, QSizePolicy, QGroupBox, QLineEdit, 
                             QComboBox, QRadioButton, QButtonGroup, QCheckBox,
                             QTextEdit, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSignal
from engine_logic import MergePcapsThread, ExtractDataThread, QueryParquetThread, QueryPcapThread, TokenCounterThread
from logger import get_logger

# Helper for logging information
logger = get_logger()

class UtilitiesView(QWidget):
    """
    The UI class for the Utility Suite tab.
    It organizes different forensic tools into groups for easy access.
    """
    status_update = pyqtSignal(str, bool, str)

    def __init__(self, job_info, parent=None):
        super().__init__(parent)
        self.job_info = job_info
        self.utility_pool = [] # List of files for the Merge tool
        self.query_results_df = None # Stores results from the Query Engine
        self.setup_ui()

    def setup_ui(self):
        """Builds the UI components for all the different utility tools."""
        layout = QVBoxLayout(self)
        layout.setSpacing(25)
        layout.setContentsMargins(16, 16, 16, 16)

        # --- SECTION 1: MULTI-MERGE UTILITY ---
        # Combines multiple files into one. 
        # Great for seeing 'The Big Picture' in Wireshark.
        merge_box = QGroupBox("Multi-Merge Utility (File Pool Based)")
        merge_layout = QVBoxLayout(merge_box)
        merge_layout.setSpacing(15)
        
        merge_layout.addWidget(QLabel("<b>1. Manage Merge Pool:</b> Add files and assign an 'Alias' to label packets."))
        self.table_pool = QTableWidget(0, 3)
        self.table_pool.setMinimumHeight(200)
        self.table_pool.setHorizontalHeaderLabels(["Filename", "Packet Alias (Origin)", "Full Path"])
        header = self.table_pool.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        merge_layout.addWidget(self.table_pool)
        
        pool_btn_row = QHBoxLayout()
        btn_add = QPushButton("Add PCAPs to Pool"); btn_add.setMinimumHeight(32); btn_add.clicked.connect(self.add_to_pool)
        btn_clear = QPushButton("Clear Pool"); btn_clear.setMinimumHeight(32); btn_clear.clicked.connect(self.clear_pool)
        pool_btn_row.addWidget(btn_add); pool_btn_row.addWidget(btn_clear); pool_btn_row.addStretch()
        merge_layout.addLayout(pool_btn_row)

        self.check_add_origin = QCheckBox("Apply 'Alias' as Packet Origin Labels")
        self.check_add_origin.setChecked(True)
        self.check_add_origin.setStyleSheet("color: #00ff7f; font-weight: bold;")
        merge_layout.addWidget(self.check_add_origin)

        dest_row = QHBoxLayout()
        dest_row.addWidget(QLabel("Output File:"))
        self.edit_merge_out = QLineEdit()
        dest_row.addWidget(self.edit_merge_out)
        btn_browse = QPushButton("Browse"); btn_browse.setMaximumWidth(80)
        btn_browse.clicked.connect(self.browse_merge_out)
        dest_row.addWidget(btn_browse)
        merge_layout.addLayout(dest_row)
        
        self.btn_run_merge = QPushButton("Execute Multi-Merge")
        self.btn_run_merge.setObjectName("ActionButton")
        self.btn_run_merge.setMinimumHeight(40)
        self.btn_run_merge.clicked.connect(self.run_merge)
        merge_layout.addWidget(self.btn_run_merge)
        
        layout.addWidget(merge_box)

        # --- SECTION 2: DATA EXTRACTION TOOL ---
        # Converts binary PCAPs into easy-to-read formats like Excel/CSV or JSON.
        extract_box = QGroupBox("PCAP Data Extraction (JSON / CSV / Parquet)")
        extract_layout = QVBoxLayout(extract_box)
        extract_layout.setSpacing(12)
        
        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("Source File:"))
        self.edit_extract_source = QLineEdit()
        self.edit_extract_source.textChanged.connect(self.auto_suggest_extract_out)
        file_row.addWidget(self.edit_extract_source, 1)
        btn_browse_src = QPushButton("Browse"); btn_browse_src.setMaximumWidth(80)
        btn_browse_src.clicked.connect(self.browse_extract_source)
        file_row.addWidget(btn_browse_src)
        extract_layout.addLayout(file_row)
        
        format_row = QHBoxLayout()
        format_row.addWidget(QLabel("Target Format:"))
        self.radio_json = QRadioButton("JSON"); self.radio_json.setChecked(True)
        self.radio_csv = QRadioButton("CSV")
        self.radio_parquet = QRadioButton("PARQUET")
        self.format_group = QButtonGroup(self)
        self.format_group.addButton(self.radio_json); self.format_group.addButton(self.radio_csv); self.format_group.addButton(self.radio_parquet)
        format_row.addWidget(self.radio_json); format_row.addWidget(self.radio_csv); format_row.addWidget(self.radio_parquet)
        
        self.check_detailed = QCheckBox("Detailed Extraction (GACC Super-Set / Hex)")
        self.check_detailed.setStyleSheet("color: #00ff7f; font-weight: bold;")
        format_row.addWidget(self.check_detailed)
        extract_layout.addLayout(format_row)
        
        self.edit_extract_out = QLineEdit()
        self.edit_extract_out.setReadOnly(True)
        extract_layout.addWidget(QLabel("Full Output Path:"))
        extract_layout.addWidget(self.edit_extract_out)
        
        self.btn_run_extract = QPushButton("Execute Data Extraction")
        self.btn_run_extract.setObjectName("ActionButton")
        self.btn_run_extract.setMinimumHeight(40)
        self.btn_run_extract.clicked.connect(self.run_extract)
        extract_layout.addWidget(self.btn_run_extract)
        layout.addWidget(extract_box)

        # --- SECTION 3: ADVANCED QUERY ENGINE ---
        # Let's you search through packet files using filters.
        query_box = QGroupBox("Advanced Multi-Format Query Engine")
        query_layout = QVBoxLayout(query_box)
        
        self.query_tabs = QTabWidget()
        # Sub-tab for raw PCAPs
        pcap_tab = QWidget(); pcap_layout = QVBoxLayout(pcap_tab)
        self.edit_pcap_in = QLineEdit(); pcap_layout.addWidget(QLabel("Source PCAP:")); pcap_layout.addWidget(self.edit_pcap_in)
        self.edit_pcap_filter = QTextEdit(); pcap_layout.addWidget(QLabel("TShark Filter:")); pcap_layout.addWidget(self.edit_pcap_filter)
        self.btn_run_pcap_query = QPushButton("Run PCAP Query"); self.btn_run_pcap_query.clicked.connect(self.run_pcap_query)
        pcap_layout.addWidget(self.btn_run_pcap_query)
        self.query_tabs.addTab(pcap_tab, "Raw PCAP")
        
        query_layout.addWidget(self.query_tabs)
        self.table_query_results = QTableWidget(0, 0)
        self.table_query_results.setMinimumHeight(280)
        query_layout.addWidget(self.table_query_results)
        layout.addWidget(query_box)

        # --- SECTION 4: AI TOKEN COUNTER ---
        # Helps analysts know if a file is small enough for an LLM to read.
        token_box = QGroupBox("AI Token Counter")
        token_layout = QVBoxLayout(token_box)
        self.edit_token_in = QLineEdit(); token_layout.addWidget(self.edit_token_in)
        self.btn_run_token_count = QPushButton("Calculate AI Tokens"); self.btn_run_token_count.clicked.connect(self.run_token_count)
        self.label_token_result = QLabel("Tokens: 0"); token_layout.addWidget(self.btn_run_token_count); token_layout.addWidget(self.label_token_result)
        layout.addWidget(token_box)
        
        layout.addStretch()

    # --- LOGIC: UTILITIES ---
    def add_to_pool(self):
        """Adds files to the merge pool."""
        files, _ = QFileDialog.getOpenFileNames(self, "Select PCAPs", "", "PCAPs (*.pcap *.pcapng)")
        for f in files:
            if f not in self.utility_pool:
                self.utility_pool.append(f)
                row = self.table_pool.rowCount(); self.table_pool.insertRow(row)
                self.table_pool.setItem(row, 0, QTableWidgetItem(os.path.basename(f)))
                self.table_pool.setItem(row, 1, QTableWidgetItem("OriginLabel"))
                self.table_pool.setItem(row, 2, QTableWidgetItem(f))

    def clear_pool(self):
        """Clears the merge pool."""
        self.utility_pool = []; self.table_pool.setRowCount(0)

    def run_merge(self):
        """Combines all files in the pool into a single PCAP file."""
        if len(self.utility_pool) < 2: return
        input_data = []
        for row in range(self.table_pool.rowCount()):
            input_data.append({"path": self.table_pool.item(row, 2).text(), "alias": self.table_pool.item(row, 1).text()})
        self.status_update.emit("Merging PCAPs...", True, "#00ff7f")
        self.merge_thread = MergePcapsThread(input_data, self.edit_merge_out.text(), self.check_add_origin.isChecked())
        self.merge_thread.finished_signal.connect(lambda s, m: self.status_update.emit("Merge Done", False, "#00ff7f"))
        self.merge_thread.start()

    def run_extract(self):
        """Starts the background process to convert PCAP data to CSV/JSON/Parquet."""
        fmt = "json" if self.radio_json.isChecked() else ("parquet" if self.radio_parquet.isChecked() else "csv")
        self.extract_thread = ExtractDataThread(self.edit_extract_source.text(), self.edit_extract_out.text(), fmt, self.check_detailed.isChecked())
        self.extract_thread.finished_signal.connect(lambda s, m: self.status_update.emit("Extraction Done", False, "#00ff7f"))
        self.extract_thread.start()

    def run_pcap_query(self):
        """Searches a PCAP file using a display filter."""
        self.pcap_thread = QueryPcapThread(self.edit_pcap_in.text(), self.edit_pcap_filter.toPlainText())
        self.pcap_thread.finished_signal.connect(self.on_query_done)
        self.pcap_thread.start()

    def on_query_done(self, success, df, msg):
        """Displays search results in a table."""
        if success:
            self.table_query_results.setColumnCount(len(df.columns))
            self.table_query_results.setHorizontalHeaderLabels(df.columns)
            for i, row in df.head(100).iterrows(): # Show first 100 results
                r = self.table_query_results.rowCount(); self.table_query_results.insertRow(r)
                for c, val in enumerate(row): self.table_query_results.setItem(r, c, QTableWidgetItem(str(val)))

    def run_token_count(self):
        """Calculates how many AI tokens are in the selected file."""
        self.token_thread = TokenCounterThread(self.edit_token_in.text())
        self.token_thread.finished_signal.connect(lambda s, c, m: self.label_token_result.setText(f"Tokens: {c:,}"))
        self.token_thread.start()

    # --- HELPERS ---
    def browse_merge_out(self):
        f, _ = QFileDialog.getSaveFileName(self, "Save Merged PCAP", "", "PCAPNG (*.pcapng)")
        if f: self.edit_merge_out.setText(f)

    def browse_extract_source(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Source", "", "PCAPs (*.pcap *.pcapng)")
        if f: self.edit_extract_source.setText(f)

    def auto_suggest_extract_out(self):
        # Automatically predicts where to save the extracted data
        in_path = self.edit_extract_source.text()
        if in_path:
            ext = ".json" if self.radio_json.isChecked() else (".parquet" if self.radio_parquet.isChecked() else ".csv")
            self.edit_extract_out.setText(in_path + ext)
