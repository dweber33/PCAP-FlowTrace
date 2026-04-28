"""
This module contains custom user interface components (widgets) used throughout the app.
The main component is the TimelineWidget, which provides a visual 'map' of 
multiple PCAP files to show when they were captured relative to each other.
"""

from PyQt6.QtWidgets import QWidget, QLabel
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QFont, QPen

class TimelineWidget(QWidget):
    """
    A custom-drawn chart that shows the time span of different PCAP files.
    
    It helps analysts see if there is an 'overlap' between captures from 
    different sources (like a Load Balancer and a Server).
    """
    
    def __init__(self):
        """
        Sets up the basic properties of the timeline.
        """
        super().__init__()
        self.setMinimumHeight(240)
        self.files_data = [] # Stores information about each PCAP file
        self.overlap = None   # Stores the start and end of the shared time window

    def set_data(self, files_data, overlap=None):
        """
        Updates the timeline with new file information and triggers a redraw.
        
        Inputs:
            files_data (list): A list of dictionaries, each describing a PCAP.
            overlap (tuple, optional): A (start_epoch, end_epoch) tuple for the shared window.
        """
        self.files_data = files_data
        self.overlap = overlap
        
        # We need to decide how tall the widget should be based on how many files we show.
        originals = [f for f in self.files_data if not f["filename"].startswith("NORM_")]
        normalized = [f for f in self.files_data if f["filename"].startswith("NORM_")]
        
        h = 40 # Space for the top title
        if originals:
            h += 15 + (len(originals) * 34) # 34 pixels per file lane
        if normalized:
            h += 45 + (len(normalized) * 34)
        h += 50 # Space for the ruler at the bottom
        
        self.setMinimumHeight(max(240, h))
        # Trigger the 'paintEvent' to redraw the widget
        self.update()

    def paintEvent(self, event):
        """
        The 'artist' of the widget. This function is called automatically 
        whenever the widget needs to be drawn or updated.
        """
        if not self.files_data:
            return
            
        painter = QPainter(self)
        # Antialiasing makes lines look smoother
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width = self.width()
        
        # --- 1. COORDINATE SYSTEM ---
        # Find the very first start and very last end time to set the scale.
        all_starts = [f["start_epoch"] for f in self.files_data if f["start_epoch"] > 0]
        all_ends = [f["end_epoch"] for f in self.files_data if f["end_epoch"] > 0]
        if not all_starts or not all_ends:
            return
        
        min_time = min(all_starts)
        max_time = max(all_ends)
        total_dur = max_time - min_time
        if total_dur <= 0:
            total_dur = 1.0

        # Define margins so the text labels don't get cut off
        margin_left = 220 
        margin_right = 40
        draw_width = width - margin_left - margin_right

        # A helper function to convert a 'time' into a 'pixel coordinate'
        def to_x(t):
            return int(((t - min_time) / total_dur) * draw_width) + margin_left

        # A helper to format seconds into MM:SS.S
        def format_time(seconds):
            mins = int(seconds // 60)
            secs = seconds % 60
            return f"{mins:02d}:{secs:04.1f}"

        bar_height = 20
        spacing = 34
        
        # Categorize files for separate grouping in the chart
        originals = [f for f in self.files_data if not f["filename"].startswith("NORM_")]
        normalized = [f for f in self.files_data if f["filename"].startswith("NORM_")]
        
        current_y = 25
        
        # --- 2. THE SYNC WINDOW (BACKGROUND HIGHLIGHT) ---
        if self.overlap:
            o_start, o_end = self.overlap
            xo1, xo2 = to_x(o_start), to_x(o_end)
            win_w = max(2, xo2 - xo1)
            # Draw a very faint green background for the overlap area
            painter.setBrush(QColor(0, 255, 127, 10))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(xo1, 0, win_w, self.height())
            
            # Label the sync window at the top
            painter.setPen(QColor("#00ff7f"))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            painter.drawText(xo1 + 5, 18, f"SYNC WINDOW: {o_end - o_start:.4f}s")

        # --- 3. DRAW ORIGINAL CAPTURES ---
        if originals:
            painter.setPen(QColor("#007acc"))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            painter.drawText(10, current_y, "ORIGINAL CAPTURE BASELINE")
            current_y += 15
            
            for f in originals:
                self.draw_lane(painter, f, current_y, to_x, draw_width, margin_left, bar_height, QColor("#007acc"))
                current_y += spacing

        # --- 4. DRAW DIVIDER AND NORMALIZED CAPTURES ---
        if normalized:
            current_y += 10
            # Draw a subtle horizontal line
            painter.setPen(QColor("#333333"))
            painter.drawLine(30, current_y - 5, width - 30, current_y - 5)
            
            painter.setPen(QColor("#00ff7f"))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            painter.drawText(10, current_y + 10, "NORMALIZED DIAGNOSTIC OUTPUTS")
            current_y += 25
            
            for f in normalized:
                self.draw_lane(painter, f, current_y, to_x, draw_width, margin_left, bar_height, QColor("#00ff7f"))
                current_y += spacing

        # --- 5. THE TIME AXIS (RULER) ---
        axis_y = current_y + 10
        painter.setPen(QColor("#666666"))
        painter.drawLine(margin_left, axis_y, margin_left + draw_width, axis_y)
        # Draw 5 tick marks with time labels
        for i in range(6):
            tx = margin_left + int(i * (draw_width / 5))
            painter.drawLine(tx, axis_y, tx, axis_y + 5)
            tick_val = (i / 5) * total_dur
            painter.setFont(QFont("Segoe UI", 7))
            painter.setPen(QColor("#888888"))
            painter.drawText(tx - 15, axis_y + 18, format_time(tick_val))

    def draw_lane(self, painter, f, y, to_x, draw_width, margin_left, bar_height, color):
        """
        Draws a single 'lane' for one PCAP file, including the bar and labels.
        """
        x1 = to_x(f["start_epoch"])
        x2 = to_x(f["end_epoch"])
        bar_w = max(2, x2 - x1)
        
        # --- FILENAME LABEL ---
        painter.setPen(QColor("#e0e0e0"))
        painter.setFont(QFont("Segoe UI", 8))
        label_text = f["filename"]
        # Shorten the name if it's too long
        if len(label_text) > 40:
            label_text = label_text[:37] + "..."
        painter.drawText(10, y + 14, label_text)
        
        # --- BACKGROUND TRACK (THE 'GROOVE') ---
        painter.setBrush(QColor(25, 25, 25))
        painter.setPen(QPen(QColor(40, 40, 40), 1))
        painter.drawRect(margin_left, y, draw_width, bar_height)
        
        # --- THE ACTUAL DATA BAR ---
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRect(x1, y, bar_w, bar_height)
        
        # --- DURATION LABEL (at the end of the bar) ---
        painter.setPen(QColor("#aaaaaa"))
        painter.setFont(QFont("Segoe UI", 7))
        dur_text = f"{float(f.get('duration', 0)):.3f}s"
        painter.drawText(x2 + 5, y + 14, dur_text)
        
        # --- SYNC HIGHLIGHT ---
        # If there's an overlap, draw a dashed box on the bar to show exactly where it fits
        if self.overlap:
            o_start, o_end = self.overlap
            xo1, xo2 = to_x(o_start), to_x(o_end)
            if xo1 < x2 and xo2 > x1:
                draw_xo1 = max(x1, xo1)
                draw_xo2 = min(x2, xo2)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.setPen(QPen(QColor("#00ff7f"), 1, Qt.PenStyle.DashLine))
                painter.drawRect(draw_xo1, y, max(1, draw_xo2 - draw_xo1), bar_height)


class ClickableLabel(QLabel):
    """
    A special version of a Label that can be clicked like a button.
    """
    clicked = pyqtSignal(int)
    
    def __init__(self, text, index):
        super().__init__(text)
        self.index = index
        # Show a 'hand' cursor when hovering over it
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
    def mousePressEvent(self, event):
        """
        Called when the user clicks the label.
        """
        self.clicked.emit(self.index)
