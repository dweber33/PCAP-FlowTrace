"""
dashboard_view.py - The Diagnostic Workspace
-------------------------------------------
This file creates the main 'Dashboard' tab of the application. 
It is the 'Command Center' where users manage their PCAP files, 
sync them up, and discover network flows.

Think of this as the main workspace where the forensic investigation happens.
"""

import os
import subprocess
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QComboBox, QButtonGroup, QTextEdit, QMenu,
                             QSizePolicy, QGroupBox, QLineEdit, QFileDialog, QProgressBar,
                             QCheckBox, QFrame, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QGuiApplication
from widgets import TimelineWidget
from engine_logic import (SessionSummaryThread, MultiNodeCropThread, 
                          Stage2DiscoveryThread, Stage2CorrelationThread)
from logger import get_logger
from config_manager import ConfigManager

# Get our helper to record what the app is doing
logger = get_logger()

class UnifiedDashboard(QWidget):
    """
    The main UI class for the Diagnostic Workspace.
    It manages the layout and logic for adding files, syncing them, and discovering flows.
    """
    # Signals are like 'events' that this widget can send to other parts of the app
    status_update = pyqtSignal(str, bool, str) # Sends (message, show_progress, color)
    export_finished = pyqtSignal(bool)

    def __init__(self, job_info, parent=None):
        super().__init__(parent)
        self.job_info = job_info # Information about the current incident/user
        self.session_pool = [] # List of files currently in the workspace
        self.normalized_map = {} # Maps original files to their 'synced' versions
        self.last_correlation_outputs = {} # Stores paths of the most recent exports
        self.setup_ui()

    def setup_ui(self):
        """Creates all the buttons, tables, and charts on the screen."""
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setSpacing(25)
        self.main_layout.setContentsMargins(16, 16, 16, 16)
        
        # --- SECTION 1: SESSION POOL ---
        # Where the user adds their raw PCAP files
        pool_container = QFrame()
        pool_layout = QVBoxLayout(pool_container)
        pool_layout.setContentsMargins(0, 0, 0, 0)
        pool_layout.addWidget(QLabel("<h2>1. Session Pool & PCAP Management</h2>"))
        
        self.pool_table = QTableWidget(0, 3)
        self.pool_table.setMinimumHeight(220)
        self.pool_table.setHorizontalHeaderLabels(["Filename", "Full Path", "Action"])
        self.pool_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.pool_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.pool_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.pool_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.pool_table.customContextMenuRequested.connect(self.show_pool_menu)
        pool_layout.addWidget(self.pool_table)
        
        btn_layout = QHBoxLayout()
        btn_add = QPushButton("Add PCAP(s)...")
        btn_add.setMinimumWidth(150); btn_add.setMinimumHeight(36)
        btn_add.clicked.connect(self.add_to_pool)
        btn_layout.addWidget(btn_add)
        btn_clear = QPushButton("Clear Pool")
        btn_clear.setMinimumHeight(36)
        btn_clear.clicked.connect(self.clear_pool)
        btn_layout.addWidget(btn_clear)
        btn_layout.addStretch()
        pool_layout.addLayout(btn_layout)
        self.main_layout.addWidget(pool_container)

        # --- SECTION 2: TEMPORAL ALIGNMENT ---
        # The visual timeline and the 'Normalize' button
        analysis_container = QFrame()
        analysis_layout = QVBoxLayout(analysis_container)
        analysis_layout.setContentsMargins(0, 0, 0, 0)
        analysis_layout.setSpacing(15)
        analysis_layout.addWidget(QLabel("<h2>2. Temporal Alignment & Diagnostics</h2>"))
        
        self.timeline = TimelineWidget()
        self.timeline.setMinimumHeight(280)
        analysis_layout.addWidget(self.timeline)

        analysis_layout.addWidget(QLabel("<b>Original Capture Baseline</b>"))
        self.table_original = self.create_summary_table()
        analysis_layout.addWidget(self.table_original)

        self.btn_normalize = QPushButton("Normalize All Timelines")
        self.btn_normalize.setObjectName("ActionButton")
        self.btn_normalize.setMinimumHeight(50)
        self.btn_normalize.clicked.connect(self.run_normalization)
        analysis_layout.addWidget(self.btn_normalize)

        norm_header_layout = QHBoxLayout()
        norm_header_layout.addWidget(QLabel("<b>Normalized Diagnostic Outputs</b>"))
        norm_header_layout.addStretch()
        self.norm_loading = QProgressBar()
        self.norm_loading.setRange(0, 0)
        self.norm_loading.setVisible(False)
        self.norm_loading.setMaximumWidth(200)
        self.norm_loading.setFixedHeight(12)
        norm_header_layout.addWidget(self.norm_loading)
        analysis_layout.addLayout(norm_header_layout)

        self.table_normalized = self.create_summary_table()
        analysis_layout.addWidget(self.table_normalized)
        self.main_layout.addWidget(analysis_container)

        # --- SECTION 3: FLOW DISCOVERY & DEEP-ANALYSIS ---
        # Where users find specific TCP/UDP streams
        discovery_container = QFrame()
        discovery_layout = QVBoxLayout(discovery_container)
        discovery_layout.setContentsMargins(0, 0, 0, 0)
        discovery_layout.setSpacing(15)
        discovery_layout.addWidget(QLabel("<h2>3. Deep-Flow Discovery & Correlation</h2>"))
        
        selector_layout = QHBoxLayout()
        selector_layout.setSpacing(12)
        selector_layout.addWidget(QLabel("Seed Source:"))
        self.combo_seed = QComboBox()
        self.combo_seed.setMinimumWidth(250); self.combo_seed.setMinimumHeight(32)
        selector_layout.addWidget(self.combo_seed, 1)
        selector_layout.addWidget(QLabel("Target Pivot:"))
        self.combo_target = QComboBox()
        self.combo_target.setMinimumWidth(250); self.combo_target.setMinimumHeight(32)
        selector_layout.addWidget(self.combo_target, 1)
        btn_refresh = QPushButton("Discover Flows")
        btn_refresh.setMinimumHeight(36)
        btn_refresh.clicked.connect(self.refresh_discovery)
        selector_layout.addWidget(btn_refresh)
        discovery_layout.addLayout(selector_layout)

        proto_layout = QHBoxLayout()
        self.btn_tcp = QPushButton("TCP")
        self.btn_udp = QPushButton("UDP")
        self.btn_tcp.setCheckable(True); self.btn_udp.setCheckable(True)
        self.btn_tcp.setMinimumHeight(32); self.btn_udp.setMinimumHeight(32)
        self.proto_group = QButtonGroup(self)
        self.proto_group.addButton(self.btn_tcp); self.proto_group.addButton(self.btn_udp)
        self.btn_tcp.setChecked(True)
        proto_layout.addWidget(self.btn_tcp); proto_layout.addWidget(self.btn_udp)
        proto_layout.addStretch()
        discovery_layout.addLayout(proto_layout)

        self.flow_table = QTableWidget(0, 5)
        self.flow_table.setMinimumHeight(200)
        self.flow_table.setHorizontalHeaderLabels(["Src IP", "Src Port", "Dst IP", "Dst Port", "Packets"])
        self.flow_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.flow_table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        self.flow_table.itemSelectionChanged.connect(self.build_query_from_selection)
        self.flow_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.flow_table.customContextMenuRequested.connect(self.show_flow_menu)
        discovery_layout.addWidget(self.flow_table)
        
        discovery_layout.addWidget(QLabel("<b>Correlation Filter Preview</b>"))
        self.filter_preview = QTextEdit()
        self.filter_preview.setPlaceholderText("Select flows to generate DNA filter...")
        self.filter_preview.setMinimumHeight(80); self.filter_preview.setMaximumHeight(100)
        discovery_layout.addWidget(self.filter_preview)

        # --- SECTION 4: EXPORT CONFIGURATION ---
        export_box = QGroupBox("Enterprise Export Configuration")
        export_layout = QVBoxLayout(export_box)
        export_layout.setSpacing(12); export_layout.setContentsMargins(16, 20, 16, 16)
        
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Target Directory:"))
        self.edit_dest = QLineEdit(self.job_info.get("output_dir", ""))
        row1.addWidget(self.edit_dest)
        btn_b = QPushButton("Browse"); btn_b.setMaximumWidth(80)
        btn_b.clicked.connect(self.browse_dest)
        row1.addWidget(btn_b)
        export_layout.addLayout(row1)
        
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Job Prefix:"))
        self.edit_prefix = QLineEdit(f"{self.job_info.get('incident_id', 'JOB')}_")
        self.edit_prefix.setMaximumWidth(250)
        row2.addWidget(self.edit_prefix)
        
        self.check_export_seed = QCheckBox("Export Seed File")
        self.check_export_seed.setChecked(True)
        self.check_export_match = QCheckBox("Export Match File")
        self.check_export_match.setChecked(True)
        row2.addWidget(self.check_export_seed)
        row2.addWidget(self.check_export_match)
        row2.addStretch()
        export_layout.addLayout(row2)

        discovery_layout.addWidget(export_box)
        self.main_layout.addWidget(discovery_container)
        
        # --- SECTION 5: FINAL ACTIONS ---
        final_action_layout = QHBoxLayout()
        final_action_layout.addStretch()
        self.btn_execute = QPushButton("Execute Deep-Flow Export")
        self.btn_execute.setObjectName("ActionButton")
        self.btn_execute.setProperty("state", "success")
        self.btn_execute.setMinimumHeight(44)
        self.btn_execute.setMinimumWidth(280)
        self.btn_execute.clicked.connect(self.run_export)
        final_action_layout.addWidget(self.btn_execute)
        self.main_layout.addLayout(final_action_layout)
        
        self.main_layout.addStretch()

    def create_summary_table(self):
        """Helper to create the standardized information tables used in the app."""
        table = QTableWidget(0, 5)
        table.setMinimumHeight(180)
        table.setHorizontalHeaderLabels(["Version", "Filename", "Start Time (UTC)", "End Time (UTC)", "Top Protocols"])
        header = table.horizontalHeader()
        for i in range(4): header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self.show_summary_menu)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.MinimumExpanding)
        return table

    # --- LOGIC: POOL & NORMALIZATION ---
    def add_to_pool(self):
        """Opens a file dialog so the user can add PCAP files to the workspace."""
        files, _ = QFileDialog.getOpenFileNames(self, "Add PCAPs", "", "PCAPs (*.pcap *.pcapng)")
        if not files: return
        for f in files:
            if f not in self.session_pool:
                self.session_pool.append(f)
                self.add_pool_row(f)
        # Automatically update the UI with the new files' information
        self.auto_sync()

    def add_pool_row(self, path):
        """Adds a single row to the Session Pool table."""
        row = self.pool_table.rowCount()
        self.pool_table.insertRow(row)
        self.pool_table.setItem(row, 0, QTableWidgetItem(os.path.basename(path)))
        self.pool_table.setItem(row, 1, QTableWidgetItem(path))
        btn = QPushButton("Remove"); btn.setStyleSheet("color: #ff3333; font-weight: bold;")
        btn.clicked.connect(lambda: self.remove_from_pool(path))
        self.pool_table.setCellWidget(row, 2, btn)

    def remove_from_pool(self, path):
        """Removes a file from the workspace."""
        if path in self.session_pool:
            self.session_pool.remove(path)
            self.pool_table.setRowCount(0)
            for p in self.session_pool: self.add_pool_row(p)
        self.auto_sync()

    def clear_pool(self):
        """Clears all files and resets the dashboard to a blank state."""
        self.session_pool = []; self.pool_table.setRowCount(0)
        self.table_original.setRowCount(0); self.table_normalized.setRowCount(0)
        self.timeline.set_data([]); self.combo_seed.clear(); self.combo_target.clear()
        self.status_update.emit("Ready", False, "#888888")

    def auto_sync(self):
        """Starts a background task to gather metadata for all files in the pool."""
        if len(self.session_pool) < 1:
            self.status_update.emit("Ready", False, "#888888"); return
        self.status_update.emit("Auto-Syncing Metadata...", True, "#00ff7f")
        self.btn_normalize.setEnabled(False)
        # We use a Thread (SessionSummaryThread) so the UI doesn't freeze
        self.summary_thread = SessionSummaryThread(self.session_pool)
        self.summary_thread.summary_signal.connect(self.populate_summary)
        self.summary_thread.start()

    def populate_summary(self, results):
        """Takes the metadata gathered in the background and puts it into the tables."""
        self.table_original.setRowCount(0); self.table_normalized.setRowCount(0)
        self.status_update.emit(f"Synchronized ({len(results)} items)", False, "#888888")
        self.btn_normalize.setEnabled(True)
        
        # Calculate the shared 'Overlap' window for the timeline chart
        all_starts = [r["start_epoch"] for r in results if r["start_epoch"] > 0]
        all_ends = [r["end_epoch"] for r in results if r["end_epoch"] > 0]
        overlap = (max(all_starts), min(all_ends)) if len(results) >= 2 and all_starts and all_ends and max(all_starts) < min(all_ends) else None
        
        # Update the visual timeline
        self.timeline.set_data(results, overlap)
        
        for s in results:
            is_norm = s["filename"].startswith("NORM_")
            table = self.table_normalized if is_norm else self.table_original
            row = table.rowCount(); table.insertRow(row)
            v_item = QTableWidgetItem("NORMALIZED" if is_norm else "ORIGINAL")
            v_item.setForeground(QColor("#00ff7f") if is_norm else QColor("#aaaaaa"))
            v_item.setData(Qt.ItemDataRole.UserRole, s["path"])
            table.setItem(row, 0, v_item)
            table.setItem(row, 1, QTableWidgetItem(s["filename"]))
            table.setItem(row, 2, QTableWidgetItem(s["start"]))
            table.setItem(row, 3, QTableWidgetItem(s["end"]))
            table.setItem(row, 4, QTableWidgetItem(", ".join(s["protocols"])))
        self.populate_selectors()

    def run_normalization(self):
        """
        Triggers the 'N-Way Sync'. 
        It will crop all files to the exact same shared time window.
        """
        if len(self.session_pool) < 2: logger.log("ERROR", "Need 2+ files to normalize."); return
        if self.timeline.overlap is None:
            if QMessageBox.warning(self, "Sanity Check", "0% Temporal Overlap detected. Proceed?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.No: return
        self.btn_normalize.setEnabled(False)
        self.norm_loading.setVisible(True)
        self.status_update.emit("Executing N-Way Sync...", True, "#00ff7f")
        # Run the cropping logic in a background thread
        self.norm_thread = MultiNodeCropThread(self.session_pool, prefix=self.job_info.get("incident_id", "FLOWTRACE"))
        self.norm_thread.finished_signal.connect(self.on_normalization_done)
        self.norm_thread.start()

    def on_normalization_done(self, success, msg, results):
        """Handles the completion of the normalization process."""
        if success:
            self.normalized_map = results.get("map", {}); clist = []
            for f in self.session_pool:
                clist.append(f)
                if f in self.normalized_map: clist.append(self.normalized_map[f])
            # Refresh all metadata once the files have been cropped
            self.summary_thread = SessionSummaryThread(clist)
            self.summary_thread.summary_signal.connect(self.on_final_normalization_complete)
            self.summary_thread.start()
        else: 
            self.btn_normalize.setEnabled(True); self.norm_loading.setVisible(False)
            self.status_update.emit("Sync Failed", False, "#ff3333")

    def on_final_normalization_complete(self, results):
        self.populate_summary(results)
        self.btn_normalize.setEnabled(True); self.norm_loading.setVisible(False)
        self.status_update.emit("Normalization Complete", False, "#00ff7f")

    # --- LOGIC: DISCOVERY & EXPORT ---
    def populate_selectors(self):
        """Updates the dropdown menus (Seed/Target) with the current files."""
        cs = self.combo_seed.currentData(); ct = self.combo_target.currentData()
        self.combo_seed.clear(); self.combo_target.clear()
        added_paths = set()
        for f in self.session_pool:
            if f not in added_paths:
                self.combo_seed.addItem(f"ORIGINAL: {os.path.basename(f)}", f)
                self.combo_target.addItem(f"ORIGINAL: {os.path.basename(f)}", f)
                added_paths.add(f)
        for orig, norm in self.normalized_map.items():
            if norm and norm not in added_paths:
                self.combo_seed.addItem(f"NORMALIZED: {os.path.basename(norm)}", norm)
                self.combo_target.addItem(f"NORMALIZED: {os.path.basename(norm)}", norm)
                added_paths.add(norm)
        # Restore previous selections if they still exist
        idx_s = self.combo_seed.findData(cs); idx_t = self.combo_target.findData(ct)
        if idx_s >= 0: self.combo_seed.setCurrentIndex(idx_s)
        if idx_t >= 0: self.combo_target.setCurrentIndex(idx_t)
        elif self.combo_target.count() > 1: self.combo_target.setCurrentIndex(1)

    def refresh_discovery(self):
        """Harvests the list of TCP/UDP conversations from the selected 'Seed' file."""
        seed = self.combo_seed.currentData()
        if not seed: return
        logger.log("INFO", f"Harvesting flows from {os.path.basename(seed)}...")
        self.discovery_thread = Stage2DiscoveryThread(seed, "TCP" if self.btn_tcp.isChecked() else "UDP")
        self.discovery_thread.flows_signal.connect(self.populate_flows); self.discovery_thread.start()

    def populate_flows(self, flows):
        """Populates the flow discovery table with conversation pairs."""
        self.flow_table.setRowCount(0)
        for f in flows:
            row = self.flow_table.rowCount(); self.flow_table.insertRow(row)
            for i, k in enumerate(["src_ip", "src_port", "dst_ip", "dst_port", "pkts"]): 
                self.flow_table.setItem(row, i, QTableWidgetItem(f[k]))
        # Adjust table height to fit content
        self.flow_table.setMinimumHeight(max(150, min(len(flows) * 28 + 40, 600)))

    def run_export(self):
        """
        Executes the 'Deep-Flow Correlation' export. 
        It extracts specific flows from both the Seed and Target files based on 
        the user's selection.
        """
        query = self.filter_preview.toPlainText().strip()
        if not query: logger.log("ERROR", "No flow selected."); return
        exp_seed, exp_match = self.check_export_seed.isChecked(), self.check_export_match.isChecked()
        if not exp_seed and not exp_match: logger.log("ERROR", "No export targets selected."); return
        
        seed_path, target_path = self.combo_seed.currentData(), self.combo_target.currentData()
        dest_dir, prefix = self.edit_dest.text(), self.edit_prefix.text()
        
        def get_clean_name(path):
            base = os.path.basename(path)
            if base.startswith("NORM_"):
                parts = base.split("_")
                if len(parts) > 3: return "_".join(parts[3:])
            return base
            
        oc = {}
        if exp_seed: oc["seed_out"] = os.path.join(dest_dir, f"FlowTrace_{prefix}{get_clean_name(seed_path)}")
        if exp_match: oc["match_out"] = os.path.join(dest_dir, f"FlowTrace_{prefix}{get_clean_name(target_path)}")
        
        self.last_correlation_outputs = oc
        self.status_update.emit("Executing Correlation Export...", True, "#00ff7f")
        
        # Run the correlation logic in a background thread
        self.thread = Stage2CorrelationThread(seed_path, target_path, "TCP" if self.btn_tcp.isChecked() else "UDP", query, {}, oc)
        self.thread.finished_signal.connect(self.on_export_done); self.thread.start()

    def on_export_done(self, success, msg):
        """Handles completion of the flow export."""
        self.export_finished.emit(success)
        if success:
            self.status_update.emit("Export Complete - Auto-Chaining...", False, "#00ff7f")
            # If both files were exported, automatically add them back to the workspace for further analysis
            if "seed_out" in self.last_correlation_outputs and "match_out" in self.last_correlation_outputs:
                self.chain_correlation()
        else:
            self.status_update.emit("Export Failed", False, "#ff3333")
            logger.log("ERROR", msg)

    def chain_correlation(self):
        """Automatically adds newly exported 'FlowTrace' files back into the Session Pool."""
        seed = self.last_correlation_outputs.get("seed_out")
        match = self.last_correlation_outputs.get("match_out")
        if not seed or not match: return
        if seed not in self.session_pool: self.session_pool.append(seed); self.add_pool_row(seed)
        if match not in self.session_pool: self.session_pool.append(match); self.add_pool_row(match)
        self.normalized_map[seed] = seed; self.normalized_map[match] = match
        self.populate_selectors()
        self.combo_seed.setCurrentIndex(self.combo_seed.findData(seed))
        self.combo_target.setCurrentIndex(self.combo_target.findData(match))
        self.filter_preview.clear(); self.refresh_discovery()
        logger.log("SYNC", "Chaining Complete.")

    def browse_dest(self):
        """Opens a folder picker for the export destination."""
        d = QFileDialog.getExistingDirectory(self, "Select Destination")
        if d: self.edit_dest.setText(d)

    def build_query_from_selection(self):
        """Converts selected rows in the flow table into a Wireshark-style filter string."""
        items = self.flow_table.selectedItems()
        if not items: self.filter_preview.clear(); return
        p = "tcp" if self.btn_tcp.isChecked() else "udp"
        m = {0: "ip.src", 1: f"{p}.srcport", 2: "ip.dst", 3: f"{p}.dstport"}
        row_map = {}
        for item in items:
            r, c = item.row(), item.column()
            if c in m:
                if r not in row_map: row_map[r] = []
                row_map[r].append(f"{m[c]} == {item.text()}")
        row_filters = []
        for r in sorted(row_map.keys()):
            f_str = " and ".join(row_map[r])
            row_filters.append(f"({f_str})" if len(row_map[r]) > 1 else f_str)
        self.filter_preview.setText(" or ".join(row_filters))

    def show_pool_menu(self, pos):
        """Shows a right-click menu for files in the Session Pool."""
        item = self.pool_table.itemAt(pos)
        if not item: return
        path = self.pool_table.item(item.row(), 1).text()
        menu = QMenu(self); menu.addAction("Open in Wireshark").triggered.connect(lambda: self.open_wireshark(path))
        menu.exec(self.pool_table.viewport().mapToGlobal(pos))

    def show_summary_menu(self, pos):
        """Shows a right-click menu for files in the Summary tables."""
        table = self.sender()
        item = table.itemAt(pos)
        if not item: return
        path = table.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self); menu.addAction("Open in Wireshark").triggered.connect(lambda: self.open_wireshark(path))
        menu.exec(table.viewport().mapToGlobal(pos))

    def show_flow_menu(self, pos):
        """Shows a right-click menu for the Flow Discovery table."""
        if not self.flow_table.itemAt(pos): return
        menu = QMenu(self)
        menu.addAction("Copy Filter").triggered.connect(lambda: QGuiApplication.clipboard().setText(self.filter_preview.toPlainText()))
        menu.addAction("Open Stream in Wireshark").triggered.connect(self.open_selected_in_wireshark)
        menu.exec(self.flow_table.viewport().mapToGlobal(pos))

    def open_selected_in_wireshark(self):
        """Opens the selected network flow directly in the Wireshark application."""
        wireshark = ConfigManager.get_binary_path("wireshark")
        if wireshark: subprocess.Popen([wireshark, "-r", self.combo_seed.currentData(), "-Y", self.filter_preview.toPlainText()])

    def open_wireshark(self, path):
        """Launches the Wireshark application for a specific file."""
        wireshark = ConfigManager.get_binary_path("wireshark")
        if wireshark: subprocess.Popen([wireshark, "-r", path])
