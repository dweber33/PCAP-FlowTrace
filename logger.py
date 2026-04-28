"""
This module provides a centralized logging system for the PCAP FlowTrace application.
It uses a singleton pattern to ensure that all parts of the application log to the 
same file and can send updates to the user interface in real-time.
"""

import logging
import os
from PyQt6.QtCore import QObject, pyqtSignal

class CentralLogger(QObject):
    """
    A central hub for handling all application logs.
    
    This class manages writing logs to a file ('session.log') and emitting
    signals that the graphical interface can catch to display logs in a console.
    It uses the Singleton pattern, meaning only one instance of this logger 
    exists throughout the app's life.
    """
    # This signal is used to send log messages to the UI.
    # It sends the 'level' (like INFO or ERROR) and the 'message' itself.
    log_signal = pyqtSignal(str, str) # level, message
    
    _instance = None
    
    @classmethod
    def get_instance(cls):
        """
        Provides access to the single, shared instance of the CentralLogger.
        If it doesn't exist yet, it creates it.
        
        Returns:
            CentralLogger: The shared logger instance.
        """
        if cls._instance is None:
            cls._instance = CentralLogger()
        return cls._instance
    
    def __init__(self):
        """
        Initializes the logger, sets up the log file, and configures the format.
        This is called only once due to the Singleton pattern.
        """
        super().__init__()
        self.log_file = "session.log"
        
        # Configure the standard Python logging library
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            filemode='a' # 'a' means append; logs will be added to the end of the file
        )
        self.logger = logging.getLogger("PCAPSentinel")

    def log(self, level, message):
        """
        Records a log message and notifies the UI.
        
        Inputs:
            level (str): The severity of the log (e.g., 'INFO', 'SUCCESS', 'ERROR').
            message (str): The actual text to record.
        """
        level = level.upper()
        
        # Map our custom levels to the standard Python logging levels
        if level == "INFO":
            self.logger.info(message)
        elif level == "SUCCESS":
            self.logger.info(f"SUCCESS: {message}")
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "DEBUG":
            self.logger.debug(message)
        elif level == "SYNC":
            self.logger.info(f"SYNC: {message}")
        
        # Emit the signal so the UI can update its console
        self.log_signal.emit(level, message)

def get_logger():
    """
    A simple helper function to get the global logger instance.
    
    Returns:
        CentralLogger: The shared logger instance.
    """
    return CentralLogger.get_instance()
