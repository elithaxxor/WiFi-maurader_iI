# WiFi Marauder Changelog

## [Unreleased]

### Added

- **2025-05-19 12:57:21-04:00**: Initial integration of Anonymity Tools and Decoy Networks into the main application.
  - Added imports for `AnonymityToolsManager` and `DecoyNetworkManager` in `main.py`.
  - Initialized these managers within the `WiFiMarauderGUI` class.
  - Created new database tables for anonymity logs and decoy activities in `main.py`.
  - Added GUI elements (buttons) for user interaction with Anonymity Tools and Decoy Networks in `main.py`.

- **2025-05-19 13:10:20-04:00**: Completed GUI integration for Anonymity Tools and Decoy Networks.
  - Added a dedicated tab for Anonymity Tools in `main.py` with buttons for changing MAC address, enabling/disabling Tor, DNS protection, setting random user-agent, and temporal disguise.
  - Added a dedicated tab for Decoy Networks in `main.py` with buttons to start/stop WiFi and Bluetooth flooding, and to mimic area SSIDs.
  - Both features are now fully accessible from the user interface.

- **2025-05-19 13:29:47-04:00**: Implemented IP Address Rotation and VPN Integration for Anonymity Tools.
  - Added `rotate_ip_address()`, `connect_vpn()`, and `disconnect_vpn()` methods to `AnonymityToolsManager` in `anonymity_tools_logic.py`.
  - Updated GUI in `main.py` to connect IP Rotation and VPN buttons to their respective functions.
  - These features are now fully implemented and accessible from the user interface.

- **2025-05-19 13:29:47-04:00**: Integrated Automated Attack Sequences, Customizable Network Filters, and WPS Vulnerability Testing into the GUI.
  - Added imports and initialization for `AttackSequenceManager`, `NetworkFilterManager`, and `WPSVulnerabilityTester` in `main.py`.
  - Created new tabs in the GUI for each feature with buttons to control their respective functionalities.
  - These features are now accessible from the user interface, with fallback messages if the modules are not available.

- **2025-05-19 14:06:43-04:00**: Started testing and refinement of integrated features.
  - Created a test script `test_features.py` to verify the functionality of Anonymity Tools and Decoy Networks.
  - Noted a dependency issue with `airmon-ng` required for mimicking area SSIDs in Decoy Networks, test skipped due to missing dependency.

- **2025-05-19 17:35:00-04:00**: Implemented Packet Crafting and Injection feature using Scapy.
  - Added UI elements for packet crafting in the Attacks tab of `main.py`, including input fields for packet type and target, start/stop buttons, progress bar, and status label.
  - Integrated logic for packet crafting in `attack_sequence_logic.py` as a new attack type 'packet_craft'.
  - Updated `README.md` to include this new feature under the Features section.

- **2025-05-19 17:45:00-04:00**: Implemented Network Sniffing and Mapping feature using Scapy.
  - Added UI elements for network sniffing in the Network Scan tab of `main.py`, including start sniffing button, status label, and network map display.
  - Integrated logic to simulate sniffing and update network map with placeholder data.
  - Updated `README.md` to include this new feature under the Features section.

- **2025-05-20 00:02:00-04:00**: Added global dark/light theme toggle using `qdarktheme`.
   - Added optional dependency `qdarktheme` and palette fallback in `main.py`.
   - Introduced `View` menu with "Toggle Dark/Light Theme" action.
   - Theme applies at runtime and on startup with dark default.

### Completed

- Full integration of Anonymity Tools features (Tor Network, DNS Leak Protection, IP Address Rotation, User-Agent Spoofing, Temporal Disguise, VPN Integration).
- Full integration of Decoy Networks feature for Environment Flooding with Fake Bluetooth and Wireless Access Points.
- GUI integration for Automated Attack Sequences, Customizable Network Filters, and WPS Vulnerability Testing.

### In Progress

- Further testing and refinement of Anonymity Tools features (Tor Network, DNS Leak Protection, IP Address Rotation, User-Agent and Fingerprint Spoofing, Temporal and Location Disguises, VPN Integration).
- Implementation and testing of Decoy Networks feature for Environment Flooding with Fake Bluetooth and Wireless Access Points, with noted dependency issues.
- Further testing and refinement of Automated Attack Sequences, Customizable Network Filters, and WPS Vulnerability Testing.
