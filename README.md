# WiFi Marauder

![WiFi Marauder Logo](logo.png)

**WiFi Marauder** is a comprehensive toolset for WiFi penetration testing and network security analysis. It provides a user-friendly GUI to manage various WiFi-related attacks and anonymity features, designed for security professionals and researchers.

## Table of Contents

- [Overview](#overview)
- [Framework](#framework)
- [Data Flow](#data-flow)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Future Add-ons](#future-add-ons)
- [Contributing](#contributing)
- [License](#license)

## Overview

WiFi Marauder is built to assist in testing WiFi network security by providing tools for anonymity, decoy network creation, automated attack sequences, network filtering, and WPS vulnerability testing. The application is modular, allowing for easy extension and customization.

## Framework

WiFi Marauder is developed using Python with the following key components:

- **GUI Framework**: PyQt5 for a cross-platform user interface.
- **Backend Logic**: Modular Python scripts for each feature, ensuring separation of concerns and ease of maintenance.
- **Environment Compatibility**: Special considerations for macOS with mock functionality where native tools (like `airmon-ng`) are not supported.

## Data Flow

The application follows a clear data flow from user interaction to backend processing and back to the UI for feedback:
```mermaid
flowchart TD
    User -->|Interacts with| GUI[GUI (PyQt5)]
    GUI -->|Sends commands to| Middleware[Middleware (Manager Classes)]
    Middleware -->|Processes and delegates to| Backend[Backend Logic (Feature Modules)]
    Backend -->|Returns results to| Middleware
    Middleware -->|Updates| GUI
    GUI -->|Displays status to| User
```

## Features

- **Anonymity Tools**: Tools to protect user identity during testing, including IP address rotation and VPN integration.
- **Decoy Networks**: Create fake WiFi access points and Bluetooth devices to simulate network environments for testing or diversion.
- **Automated Attack Sequences**: Define and execute chained attack sequences for comprehensive testing.
- **Customizable Network Filters**: Filter network scans to target specific devices or networks.
- **WPS Vulnerability Testing**: Test for WPS vulnerabilities using Pixie Dust and brute force attacks.
- **Packet Crafting and Injection**: Craft and send custom packets using Scapy to test network vulnerabilities or simulate specific types of network traffic.
- **Network Sniffing and Mapping**: Use Scapy to map network topologies by analyzing packet headers to identify active devices, IP addresses, and OS. Integrated into the Network Scan tab for detailed network maps.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/wifi_marauder.git
   cd wifi_marauder
   ```
2. **Set Up Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Application**:
   ```bash
   python main.py
   ```
**Note**: Some features require specific tools like `airmon-ng` and `hostapd` which are not fully supported on macOS. Mock functionality is provided for testing on such platforms.

## Usage

- Launch the application using `python main.py`.
- Navigate through the tabs to access different features.
- Click buttons to initiate actions like IP rotation, VPN connection, or starting a decoy network flood.
- Status indicators on each tab will update to reflect the current state of each feature.

## Future Add-ons

- **Advanced Packet Analysis**: Integration with tools like Wireshark for deeper packet inspection.
- **Machine Learning for Attack Prediction**: Use ML to predict and suggest attack vectors based on network analysis.
- **Cross-Platform Enhancements**: Full support for macOS and Windows with native tools or robust mock implementations.
- **Cloud Integration**: Store attack sequences and filter configurations in the cloud for team collaboration.
- **IoT Device Testing**: Specialized modules for testing vulnerabilities in IoT devices.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. Ensure your code adheres to PEP 8 standards and includes appropriate documentation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
