# WiFi Marauder Tutorial

Welcome to WiFi Marauder, a comprehensive tool for wireless network testing and security analysis. This tutorial will guide you through the steps to set up and run the program, with specific instructions for macOS users due to tool availability issues.

## Table of Contents
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running WiFi Marauder](#running-wifi-maurader)
- [Special Considerations for macOS](#special-considerations-for-macos)
- [Features Overview](#features-overview)
- [Troubleshooting](#troubleshooting)

## System Requirements

WiFi Marauder is designed to work on Linux and macOS systems. For full functionality, you will need:

- **Operating System**: Linux (preferred for full tool support) or macOS
- **Hardware**: A WiFi adapter that supports monitor mode (for network scanning and attacks)
- **Permissions**: Root or sudo access for installing tools and running certain commands
- **Tools**: `aircrack-ng`, `hostapd`, `bluez`, `mdk4` (installation instructions below)

## Installation

### Step 1: Clone the Repository
If you haven't already, clone the WiFi Marauder repository to your local machine:

```bash
git clone https://github.com/elithaxxor/WiFi-maurader_iI.git
cd WiFi-maurader_iI
```

### Step 2: Install Dependencies
We've provided a script to help install the necessary tools. Run the following command:

```bash
./install_tools.py
```

This script will attempt to install `aircrack-ng`, `bluez`, `hostapd`, and `mdk4` using your system's package manager (`apt-get` on Linux, `brew` on macOS).

**Note for macOS Users**: Some tools are not available through Homebrew. See the [Special Considerations for macOS](#special-considerations-for-macos) section for manual installation instructions.

### Step 3: Set Up a Virtual Environment (Optional but Recommended)
To avoid conflicts with system-wide Python packages, set up a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # If a requirements file is provided
```

## Running WiFi Marauder

Once the tools are installed, you can run WiFi Marauder with:

```bash
python3 main.py
```

This will launch the GUI application with tabs for network scanning, attacks, logs, analysis, and more.

**Important**: Many features require root privileges to interact with network interfaces and run tools like `aircrack-ng`. On Linux, you may need to run with `sudo`:

```bash
sudo python3 main.py
```

### Configuring Network Interfaces
WiFi Marauder needs to know which network interfaces to use for WiFi and Bluetooth operations. By default, it uses dummy interfaces on macOS for testing. On Linux, ensure your WiFi adapter supports monitor mode. You can check with:

```bash
iwconfig
```

If your interface doesn't support monitor mode, you may need a compatible USB WiFi adapter.

## Special Considerations for macOS

Running WiFi Marauder on macOS comes with limitations due to the unavailability of certain tools in Homebrew. Here's how to address these issues:

### 1. `hostapd` - Not Available in Homebrew
`hostapd` is crucial for creating fake access points in WiFi flooding attacks. Since it's not available in Homebrew:

- **Manual Installation**: Compile `hostapd` from source. Download it from [https://w1.fi/hostapd/](https://w1.fi/hostapd/), and follow the compilation instructions. You'll need Xcode and command-line tools installed (`xcode-select --install`).
- **Alternative**: Consider running WiFi Marauder in a Linux virtual machine or on a separate Linux device where `hostapd` can be installed via `apt-get`.
- **Impact**: Without `hostapd`, WiFi flooding features in the Decoy Networks section will run in mock mode only.

### 2. `bluez` - Not Available in Homebrew
`bluez` is used for Bluetooth operations like fake device flooding:

- **Manual Installation**: Similar to `hostapd`, you may need to compile `bluez` from source. Source code and instructions are available at [http://www.bluez.org/](http://www.bluez.org/).
- **Alternative**: Use a Linux environment for full Bluetooth functionality.
- **Impact**: Without `bluez`, Bluetooth flooding will operate in mock mode.

### 3. `mdk4` - Not Available, Alternative Available
`mdk4` is used for various wireless disruption attacks:

- **Partial Solution**: Homebrew suggests `mdk` as an alternative. Install it with `brew install mdk`. Check if it provides the necessary functionality for WiFi Marauder.
- **Manual Installation**: If `mdk` is insufficient, compile `mdk4` from source or use a Linux system.
- **Impact**: Limited or mock functionality for MDK4-based attacks without the full tool.

### 4. macOS Kernel Limitations
Even with tools installed, macOS does not support monitor mode on built-in WiFi adapters. You'll need an external USB WiFi adapter that supports monitor mode on macOS, and even then, functionality may be limited compared to Linux.

**Recommendation**: For full functionality, run WiFi Marauder on a Linux system (native or via a virtual machine like VirtualBox or VMWare). This avoids most tool installation issues and provides better hardware support for wireless testing.

## Features Overview

WiFi Marauder offers several features for wireless security testing:

- **Dashboard**: Default view with summary widgets for network status, active attacks, filters, and logs.
- **Network Scan**: Scan for nearby networks with interactive visualizations of signal strength and channels.
- **Attacks**: Perform various attacks like Deauthentication, Handshake Capture, and Evil Twin AP with real-time feedback.
- **Decoy Networks**: Create fake WiFi APs and Bluetooth devices (limited on macOS without `hostapd` and `bluez`).
- **Logs & Analysis**: Detailed packet analysis and protocol monitoring with `scapy`.

Each feature may require specific tools; if a tool is missing, the feature will run in mock mode for testing purposes.

## Troubleshooting

- **Tool Not Found Errors**: Ensure all required tools are installed. Run `./install_tools.py` again or install missing tools manually.
- **Permission Denied**: Run the application with `sudo` if it needs access to network interfaces.
- **Interface Not Found**: Check if your WiFi adapter supports monitor mode with `iwconfig` (Linux) or use an external adapter on macOS.
- **Mock Mode**: On macOS, many features run in mock mode due to missing tools. This is expected behavior for testing the UI.

For additional support, refer to the GitHub repository at [https://github.com/elithaxxor/WiFi-maurader_iI](https://github.com/elithaxxor/WiFi-maurader_iI) or open an issue for assistance.

---

*WiFi Marauder is intended for educational and authorized security testing purposes only. Ensure you have permission to test on any network or device you target.*
