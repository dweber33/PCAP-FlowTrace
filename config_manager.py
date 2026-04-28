"""
This module manages the configuration and external tool paths for the application.
It specifically helps find and validate that Wireshark's command-line tools 
(like tshark and editcap) are installed and accessible on the computer.
"""

import os
import shutil
import subprocess

class ConfigManager:
    """
    A utility class to manage paths and environment checks.
    
    It doesn't need to be initialized; all its methods are 'static', 
    meaning they can be used directly from the class.
    """
    
    @staticmethod
    def get_binary_path(binary_name):
        """
        Tries to find where a specific program (binary) is located on the system.
        
        It looks in two places:
        1. The system's 'PATH' (where Windows usually looks for programs).
        2. Common folders where Wireshark is typically installed.
        
        Inputs:
            binary_name (str): The name of the program to find (e.g., 'tshark').
            
        Returns:
            str or None: The full path to the program if found, otherwise None.
        """
        # 1. Check if the program is already in the system's PATH
        path = shutil.which(binary_name)
        if path:
            return path
        
        # 2. Check common Windows installation folders for Wireshark
        common_paths = [
            r"C:\Program Files\Wireshark",
            r"C:\Program Files (x86)\Wireshark",
        ]
        
        for base in common_paths:
            # Check for the executable file (e.g., tshark.exe) in each folder
            full_path = os.path.join(base, f"{binary_name}.exe")
            if os.path.exists(full_path):
                return full_path
        
        # Return None if we couldn't find it anywhere
        return None

    @staticmethod
    def validate_environment():
        """
        Checks if the required Wireshark tools are installed on the computer.
        
        This ensures the application has everything it needs to function correctly.
        
        Returns:
            tuple (bool, str): 
                - A boolean (True if everything is okay, False if something is missing).
                - A message explaining the result.
        """
        tshark = ConfigManager.get_binary_path("tshark")
        editcap = ConfigManager.get_binary_path("editcap")
        
        if not tshark or not editcap:
            missing = []
            if not tshark: missing.append("tshark")
            if not editcap: missing.append("editcap")
            return False, f"Missing binaries: {', '.join(missing)}. Please install Wireshark."
        
        return True, "Environment valid."

    @staticmethod
    def get_tshark_path():
        """
        A quick way to get the path specifically for 'tshark'.
        
        Returns:
            str or None: The path to tshark.
        """
        return ConfigManager.get_binary_path("tshark")

    @staticmethod
    def get_editcap_path():
        """
        A quick way to get the path specifically for 'editcap'.
        
        Returns:
            str or None: The path to editcap.
        """
        return ConfigManager.get_binary_path("editcap")
