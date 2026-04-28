"""
This module is used to package the Python source code into a standalone 
Windows executable (.exe). It uses the 'PyInstaller' library to bundle 
everything (code, icons, and libraries) into a single file so that 
other users can run the app without needing to install Python.
"""

import PyInstaller.__main__
import os
import shutil

def build_pcap_sentinel():
    """
    Executes the PyInstaller build process to create the final application.
    
    This function:
    1. Cleans up any previous build attempts.
    2. Runs PyInstaller with specific settings (onefile, windowed, etc.).
    3. Places the final executable in the 'dist' folder.
    """
    print("🚀 Starting PCAP Sentinel Enterprise Build...")
    
    # 1. Clear previous builds to ensure a fresh start
    # 'dist' contains the final .exe; 'build' contains temporary files
    if os.path.exists("dist"):
        shutil.rmtree("dist")
    if os.path.exists("build"):
        shutil.rmtree("build")
    
    # 2. Run PyInstaller
    # --onefile: Bundle everything into a single .exe
    # --windowed: Do not open a black command-prompt window when the app starts
    # --name: The name of the resulting executable
    # --hidden-import: Ensures specific libraries are included even if not explicitly detected
    # --clean: Clear the PyInstaller cache before building
    PyInstaller.__main__.run([
        'main.py',
        '--onefile',
        '--windowed',
        '--name=PCAP_Sentinel_Enterprise',
        '--hidden-import=PyQt6.QtCore',
        '--hidden-import=PyQt6.QtWidgets',
        '--hidden-import=PyQt6.QtGui',
        '--clean'
    ])
    
    print("\n✅ Build complete! Executable is in the 'dist' folder.")

if __name__ == "__main__":
    # If this file is run directly (not imported), start the build process
    build_pcap_sentinel()
