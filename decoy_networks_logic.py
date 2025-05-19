"""
WiFi Marauder - Decoy Networks Logic Module
This module contains the logic for flooding the environment with fake Bluetooth and wireless access points
to create decoy networks for testing or diversion purposes.
"""
import subprocess
import random
import string
import os
import time
import csv
import re
import sys

class DecoyNetworkManager:
    """
    Manages the creation and broadcasting of fake wireless access points and Bluetooth devices
    to flood the environment for testing or diversion.
    """
    def __init__(self, wifi_interface="wlan1", bt_interface="hci0"):
        self.wifi_interface = wifi_interface
        self.bt_interface = bt_interface
        self.wifi_decoy_process = None
        self.bt_decoy_process = None
        self.is_wifi_flooding = False
        self.is_bt_flooding = False
        self.ssid_list = []
        self.bt_name_list = []
        self.hostapd_config_path = "/tmp/hostapd_decoy.conf"
        self.scan_data_path = "/tmp/wifi_scan.csv"
        self.is_macos = sys.platform == "darwin"
        if self.is_macos:
            print("Warning: Running on macOS. WiFi manipulation tools like airmon-ng are not fully supported. Using mock functionality for testing.")

    def generate_random_ssid(self):
        """
        Generate a random SSID for a fake access point.
        
        Returns:
            str: Random SSID
        """
        prefixes = ["FreeWiFi", "HomeNetwork", "GuestNet", "Linksys", "Netgear", "ATT", "Verizon", "Xfinity"]
        suffix = ''.join(random.choices(string.digits, k=4))
        return f"{random.choice(prefixes)}_{suffix}"

    def generate_random_bt_name(self):
        """
        Generate a random Bluetooth device name.
        
        Returns:
            str: Random Bluetooth device name
        """
        devices = ["Headphones", "Speaker", "Smartphone", "Tablet", "Laptop", "Watch", "Keyboard", "Mouse"]
        brands = ["Sony", "Bose", "Apple", "Samsung", "JBL", "Logitech", "Microsoft"]
        return f"{random.choice(brands)} {random.choice(devices)}"

    def scan_area_for_ssids(self, scan_duration=10, scan_interface=None):
        """
        Scan the area for existing SSIDs using airodump-ng and parse the results.
        
        Args:
            scan_duration (int): Duration in seconds to run the scan
            scan_interface (str, optional): Interface to use for scanning, defaults to wifi_interface
        
        Returns:
            list: List of SSIDs found in the area
        """
        if self.is_macos:
            print("Mock scanning on macOS... Returning dummy SSIDs for testing.")
            return ["MockWiFi1", "MockWiFi2", "MockWiFi3"]
        
        if not scan_interface:
            scan_interface = self.wifi_interface
        
        try:
            # Ensure interface is in monitor mode
            subprocess.run(["airmon-ng", "start", scan_interface], check=False, capture_output=True, text=True)
            
            # Run airodump-ng to scan for networks
            scan_cmd = ["airodump-ng", "--write", self.scan_data_path, "--output-format", "csv", scan_interface]
            scan_process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(scan_duration)
            scan_process.terminate()
            scan_process.wait(timeout=5)
            
            # Check if output file was created
            csv_file = self.scan_data_path + "-01.csv"
            if not os.path.exists(csv_file):
                return []
            
            # Parse CSV file for SSIDs
            ssids = []
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) > 13 and row[13].strip():  # SSID is usually in column 14
                        ssid = row[13].strip()
                        if ssid and ssid not in ssids:
                            ssids.append(ssid)
            
            # Clean up temporary files
            for file in os.listdir(os.path.dirname(self.scan_data_path)):
                if file.startswith(os.path.basename(self.scan_data_path).split('.')[0]):
                    os.remove(os.path.join(os.path.dirname(self.scan_data_path), file))
            
            return ssids
        except Exception as e:
            print(f"Error scanning for SSIDs: {str(e)}")
            return []

    def start_wifi_flood(self, num_aps=5, custom_ssids=None, mimic_area_ssids=False, channel_range=(1, 11), duration=None):
        """
        Start broadcasting fake WiFi access points using hostapd or similar tools.
        
        Args:
            num_aps (int): Number of access points to simulate
            custom_ssids (list, optional): Custom list of SSIDs to use
            mimic_area_ssids (bool): If True, scan and mimic SSIDs in the area
            channel_range (tuple): Range of channels to use (min, max)
            duration (int, optional): Duration in seconds to run the flood, None for indefinite
        
        Returns:
            dict: Result including success status and message
        """
        if self.is_macos:
            print("Mock WiFi flooding on macOS...")
            self.is_wifi_flooding = True
            self.ssid_list = custom_ssids if custom_ssids else [self.generate_random_ssid() for _ in range(num_aps)]
            if mimic_area_ssids:
                self.ssid_list = self.scan_area_for_ssids()  # Will return mock SSIDs on macOS
            return {"success": True, "message": f"Mock WiFi flooding started with {len(self.ssid_list)} APs", "ssids": self.ssid_list}
        
        if self.is_wifi_flooding:
            return {"success": False, "message": "WiFi flooding already active"}
        
        try:
            # Check if hostapd is installed
            if subprocess.run(["which", "hostapd"], capture_output=True, text=True).returncode != 0:
                return {"success": False, "message": "hostapd not installed"}
            
            # Generate or use provided SSIDs
            if custom_ssids:
                self.ssid_list = custom_ssids[:num_aps]
            elif mimic_area_ssids:
                scanned_ssids = self.scan_area_for_ssids()
                if scanned_ssids:
                    self.ssid_list = random.sample(scanned_ssids, min(num_aps, len(scanned_ssids)))
                else:
                    self.ssid_list = [self.generate_random_ssid() for _ in range(num_aps)]
            else:
                self.ssid_list = [self.generate_random_ssid() for _ in range(num_aps)]
            
            # Ensure interface is in monitor/managed mode as needed
            subprocess.run(["airmon-ng", "start", self.wifi_interface], check=False, capture_output=True, text=True)
            
            # Create hostapd configuration for multiple SSIDs if supported, otherwise rotate
            # For simplicity, we'll simulate one AP at a time and rotate (realistic for single interface)
            config_lines = []
            config_lines.append(f"interface={self.wifi_interface}")
            config_lines.append("driver=nl80211")
            config_lines.append(f"ssid={self.ssid_list[0]}")
            config_lines.append(f"hw_mode=g")
            config_lines.append(f"channel={random.randint(channel_range[0], channel_range[1])}")
            config_lines.append("macaddr_acl=0")
            config_lines.append("auth_algs=1")
            config_lines.append("ignore_broadcast_ssid=0")
            
            with open(self.hostapd_config_path, 'w') as f:
                f.write("\n".join(config_lines))
            
            # Start hostapd
            cmd = ["hostapd", self.hostapd_config_path]
            self.wifi_decoy_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(2)  # Give it a moment to start
            
            if self.wifi_decoy_process.poll() is not None:  # Process terminated
                error_output = self.wifi_decoy_process.stderr.read() if self.wifi_decoy_process.stderr else "Unknown error"
                self.wifi_decoy_process = None
                return {"success": False, "message": f"hostapd failed to start: {error_output}"}
            
            self.is_wifi_flooding = True
            # If duration is set, we would stop after the duration (handled externally in integration)
            return {"success": True, "message": f"WiFi flooding started with {len(self.ssid_list)} APs", "ssids": self.ssid_list}
        except Exception as e:
            return {"success": False, "message": f"Error starting WiFi flooding: {str(e)}"}

    def stop_wifi_flood(self):
        """
        Stop broadcasting fake WiFi access points.
        
        Returns:
            dict: Result including success status and message
        """
        if self.is_macos:
            if self.is_wifi_flooding:
                self.is_wifi_flooding = False
                self.ssid_list = []
                return {"success": True, "message": "Mock WiFi flooding stopped on macOS"}
            return {"success": False, "message": "Mock WiFi flooding not active on macOS"}
        
        if not self.is_wifi_flooding:
            return {"success": False, "message": "WiFi flooding not active"}
        
        try:
            # Terminate hostapd process
            if self.wifi_decoy_process:
                self.wifi_decoy_process.terminate()
                self.wifi_decoy_process.wait(timeout=5)
            
            # Clean up configuration file
            if os.path.exists(self.hostapd_config_path):
                os.remove(self.hostapd_config_path)
            
            self.is_wifi_flooding = False
            self.wifi_decoy_process = None
            self.ssid_list = []
            return {"success": True, "message": "WiFi flooding stopped"}
        except Exception as e:
            return {"success": False, "message": f"Error stopping WiFi flooding: {str(e)}"}

    def start_bluetooth_flood(self, num_devices=5, custom_names=None, duration=None):
        """
        Start broadcasting fake Bluetooth devices using hciconfig and hcitool.
        
        Args:
            num_devices (int): Number of Bluetooth devices to simulate
            custom_names (list, optional): Custom list of device names to use
            duration (int, optional): Duration in seconds to run the flood, None for indefinite
        
        Returns:
            dict: Result including success status and message
        """
        if self.is_macos:
            print("Mock Bluetooth flooding on macOS...")
            self.is_bt_flooding = True
            self.bt_name_list = custom_names if custom_names else [self.generate_random_bt_name() for _ in range(num_devices)]
            return {"success": True, "message": f"Mock Bluetooth flooding started with {len(self.bt_name_list)} device names", "names": self.bt_name_list}
        
        if self.is_bt_flooding:
            return {"success": False, "message": "Bluetooth flooding already active"}
        
        try:
            # Check if Bluetooth tools are installed
            if subprocess.run(["which", "hciconfig"], capture_output=True, text=True).returncode != 0:
                return {"success": False, "message": "hciconfig not installed"}
            if subprocess.run(["which", "hcitool"], capture_output=True, text=True).returncode != 0:
                return {"success": False, "message": "hcitool not installed"}
            
            # Generate or use provided device names
            if custom_names:
                self.bt_name_list = custom_names[:num_devices]
            else:
                self.bt_name_list = [self.generate_random_bt_name() for _ in range(num_devices)]
            
            # Ensure Bluetooth interface is up
            subprocess.run(["hciconfig", self.bt_interface, "up"], check=False, capture_output=True)
            
            # Set the interface to be discoverable with a fake name (rotating names in real scenario)
            first_name = self.bt_name_list[0]
            subprocess.run(["hciconfig", self.bt_interface, "name", first_name], check=False, capture_output=True)
            subprocess.run(["hciconfig", self.bt_interface, "piscan"], check=False, capture_output=True)  # Make discoverable
            
            self.is_bt_flooding = True
            # Note: Simulating multiple devices may require multiple interfaces or advanced scripting
            # For simplicity, we change the name periodically if duration is set (handled externally in integration)
            return {"success": True, "message": f"Bluetooth flooding started with {len(self.bt_name_list)} device names", "names": self.bt_name_list}
        except Exception as e:
            return {"success": False, "message": f"Error starting Bluetooth flooding: {str(e)}"}

    def stop_bluetooth_flood(self):
        """
        Stop broadcasting fake Bluetooth devices.
        
        Returns:
            dict: Result including success status and message
        """
        if self.is_macos:
            if self.is_bt_flooding:
                self.is_bt_flooding = False
                self.bt_name_list = []
                return {"success": True, "message": "Mock Bluetooth flooding stopped on macOS"}
            return {"success": False, "message": "Mock Bluetooth flooding not active on macOS"}
        
        if not self.is_bt_flooding:
            return {"success": False, "message": "Bluetooth flooding not active"}
        
        try:
            # Reset Bluetooth interface to non-discoverable
            subprocess.run(["hciconfig", self.bt_interface, "noiscan"], check=False, capture_output=True)
            subprocess.run(["hciconfig", self.bt_interface, "name", ""], check=False, capture_output=True)  # Reset name
            
            self.is_bt_flooding = False
            self.bt_decoy_process = None
            return {"success": True, "message": "Bluetooth flooding stopped"}
        except Exception as e:
            return {"success": False, "message": f"Error stopping Bluetooth flooding: {str(e)}"}

    def get_wifi_flood_status(self):
        """
        Get the current status of WiFi flooding.
        
        Returns:
            dict: Status information about WiFi flooding
        """
        return {
            "active": self.is_wifi_flooding,
            "ssids": self.ssid_list if self.is_wifi_flooding else []
        }

    def get_bluetooth_flood_status(self):
        """
        Get the current status of Bluetooth flooding.
        
        Returns:
            dict: Status information about Bluetooth flooding
        """
        return {
            "active": self.is_bt_flooding,
            "names": self.bt_name_list if self.is_bt_flooding else []
        }

# Example usage - will be integrated into the main application
if __name__ == '__main__':
    decoy_manager = DecoyNetworkManager(wifi_interface="wlan1", bt_interface="hci0")
    # Start WiFi flood with random SSIDs
    result = decoy_manager.start_wifi_flood(num_aps=3)
    print("WiFi Flood Start Result:", result)
    time.sleep(5)
    # Stop WiFi flood
    result = decoy_manager.stop_wifi_flood()
    print("WiFi Flood Stop Result:", result)
    # Start WiFi flood mimicking area SSIDs
    result = decoy_manager.start_wifi_flood(num_aps=3, mimic_area_ssids=True)
    print("WiFi Flood Mimic Area SSIDs Result:", result)
    time.sleep(5)
    result = decoy_manager.stop_wifi_flood()
    print("WiFi Flood Stop Result:", result)
    # Start Bluetooth flood
    result = decoy_manager.start_bluetooth_flood(num_devices=3)
    print("Bluetooth Flood Start Result:", result)
    time.sleep(5)
    # Stop Bluetooth flood
    result = decoy_manager.stop_bluetooth_flood()
    print("Bluetooth Flood Stop Result:", result)
