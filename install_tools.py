#!/usr/bin/env python3

import os
import platform
import subprocess
import sys

def run_command(command, error_message="Error occurred"):
    """Run a shell command and handle potential errors."""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        print(f"Success: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{error_message}: {e.stderr}")
        return False

def install_linux_tools():
    """Install tools on Linux systems."""
    print("Detected Linux system. Installing tools using apt-get...")
    commands = [
        ("sudo apt-get update", "Failed to update package list"),
        ("sudo apt-get install -y aircrack-ng", "Failed to install aircrack-ng"),
        ("sudo apt-get install -y hostapd", "Failed to install hostapd"),
        ("sudo apt-get install -y bluez", "Failed to install bluez for Bluetooth tools"),
        ("sudo apt-get install -y mdk4", "Failed to install mdk4")
    ]
    
    for cmd, err_msg in commands:
        if not run_command(cmd, err_msg):
            return False
    return True

def install_macos_tools():
    """Install tools on macOS systems using Homebrew."""
    print("Detected macOS system. Installing tools using Homebrew...")
    if not run_command("brew -v", "Homebrew not installed"):
        print("Please install Homebrew first from https://brew.sh")
        return False
    
    commands = [
        ("brew install aircrack-ng", "Failed to install aircrack-ng"),
        ("brew install bluez || echo 'bluez not available in Homebrew, install manually'", "Failed to install bluez for Bluetooth tools"),
        ("brew install mdk4 || echo 'mdk4 not available in Homebrew, install manually'", "Failed to install mdk4")
    ]
    
    success = True
    for cmd, err_msg in commands:
        if not run_command(cmd, err_msg):
            success = False
            print(f"Note: If {cmd.split()[1]} is not available in Homebrew, you may need to install it manually.")
    
    print("Note: 'hostapd' is not available in Homebrew. For WiFi flooding functionality, you will need to install 'hostapd' manually.")
    print("You can compile it from source following instructions at: https://w1.fi/hostapd/")
    print("Alternatively, consider running WiFi Marauder on a Linux system where 'hostapd' can be installed via apt-get.")
    return success

def main():
    """Main function to detect OS and install appropriate tools."""
    system = platform.system()
    print(f"Starting WiFi Marauder tools installation on {system}...")
    
    if system == "Linux":
        success = install_linux_tools()
    elif system == "Darwin":  # macOS
        success = install_macos_tools()
    else:
        print(f"Unsupported OS: {system}. This script supports Linux and macOS only.")
        return 1
    
    if success:
        print("All available tools installed successfully! You may still need to install some tools manually.")
        print("Note: Some tools may require additional configuration or kernel modules for full functionality.")
        return 0
    else:
        print("Installation failed for one or more tools or they are not available in the package manager.")
        print("Please check the error messages above and follow manual installation instructions if needed.")
        print("You may need to install some tools manually or ensure you have the necessary permissions.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
