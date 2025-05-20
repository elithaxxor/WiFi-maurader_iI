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
from pathlib import Path
import tempfile

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
        tmp_dir = Path(tempfile.gettempdir())
        self.hostapd_config_path = str(tmp_dir / "hostapd_decoy.conf")
        # airodump appends suffixes automatically, store base path without extension
        self.scan_data_path = str(tmp_dir / "wifi_scan")
        self.is_macos = sys.platform == "darwin"
        if self.is_macos:
            print("Warning: Running on macOS. WiFi manipulation tools like airmon-ng are not fully supported. Using mock functionality for testing.")

    @staticmethod
    def generate_random_ssid():
        """
        Generate a random SSID for a fake access point.
        
        Returns:
            str: Random SSID
        """
        prefixes = ["FreeWiFi", "HomeNetwork", "GuestNet", "Linksys", "Netgear", "ATT", "Verizon", "Xfinity"]
        suffix = ''.join(random.choices(string.digits, k=4))
        return f"{random.choice(prefixes)}_{suffix}"

    @staticmethod
    def generate_random_bt_name():
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
            result = subprocess.run(["airmon-ng", "start", scan_interface], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: Failed to set {scan_interface} to monitor mode: {result.stderr}")
            
            # Run airodump-ng to scan for networks
            scan_cmd = ["airodump-ng", "--write", self.scan_data_path, "--output-format", "csv", scan_interface]
            scan_process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(scan_duration)
            try:
                scan_process.terminate()
                scan_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("Warning: airodump-ng did not terminate in time, forcing kill.")
                scan_process.kill()
                scan_process.wait(timeout=5)
            
            # Find the correct CSV file (airodump-ng appends -01, -02, etc.)
            csv_file = None
            for file in os.listdir(os.path.dirname(self.scan_data_path)):
                if file.startswith(os.path.basename(self.scan_data_path).split('.')[0]) and file.endswith(".csv"):
                    csv_file = os.path.join(os.path.dirname(self.scan_data_path), file)
                    break
            
            if not csv_file or not os.path.exists(csv_file):
                print("Warning: No scan data file found.")
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
                    try:
                        os.remove(os.path.join(os.path.dirname(self.scan_data_path), file))
                    except Exception as e:
                        print(f"Warning: Could not delete temporary file {file}: {str(e)}")
            
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
            self.ssid_list = custom_ssids or [self.generate_random_ssid() for _ in range(num_aps)]
            return {"success": True, "message": f"Mock WiFi flooding started with {num_aps} APs", "ssids": self.ssid_list}
        
        if self.is_wifi_flooding:
            return {"success": False, "message": "WiFi flooding already active"}
        
        try:
            # Generate or use provided SSIDs
            if custom_ssids:
                self.ssid_list = custom_ssids[:num_aps]
                while len(self.ssid_list) < num_aps:
                    self.ssid_list.append(self.generate_random_ssid())
            elif mimic_area_ssids:
                area_ssids = self.scan_area_for_ssids()
                if area_ssids:
                    self.ssid_list = random.sample(area_ssids, min(len(area_ssids), num_aps))
                    while len(self.ssid_list) < num_aps:
                        self.ssid_list.append(self.generate_random_ssid())
                else:
                    self.ssid_list = [self.generate_random_ssid() for _ in range(num_aps)]
            else:
                self.ssid_list = [self.generate_random_ssid() for _ in range(num_aps)]
            
            # Create hostapd configuration for multiple fake APs
            config_lines = []
            min_ch, max_ch = channel_range
            for i, ssid in enumerate(self.ssid_list):
                channel = min_ch + (i % (max_ch - min_ch + 1))
                config_lines.extend([
                    f"interface={self.wifi_interface}",
                    "driver=nl80211",
                    f"ssid={ssid}",
                    f"hw_mode=g",
                    f"channel={channel}",
                    "wpa=0",
                    ""
                ])
            
            with open(self.hostapd_config_path, 'w') as f:
                f.write("\n".join(config_lines))
            
            # Start hostapd to broadcast fake APs
            self.wifi_decoy_process = subprocess.Popen(["hostapd", self.hostapd_config_path],
                                                        stdout=subprocess.PIPE,
                                                        stderr=subprocess.PIPE,
                                                        text=True)
            time.sleep(2)  # Give it a moment to start
            if self.wifi_decoy_process.poll() is not None:
                raise RuntimeError("hostapd failed to start")
            
            self.is_wifi_flooding = True
            return {"success": True, "message": f"WiFi flooding started with {num_aps} APs", "ssids": self.ssid_list}
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
            if self.wifi_decoy_process:
                try:
                    self.wifi_decoy_process.terminate()
                    self.wifi_decoy_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print("Warning: hostapd did not terminate in time, forcing kill.")
                    self.wifi_decoy_process.kill()
                    self.wifi_decoy_process.wait(timeout=5)
            
            # Clean up configuration file
            if os.path.exists(self.hostapd_config_path):
                try:
                    os.remove(self.hostapd_config_path)
                except Exception as e:
                    print(f"Warning: Could not delete hostapd config file: {str(e)}")
            
            self.is_wifi_flooding = False
            self.wifi_decoy_process = None
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
            self.bt_name_list = custom_names or [self.generate_random_bt_name() for _ in range(num_devices)]
            return {"success": True, "message": f"Mock Bluetooth flooding started with {num_devices} devices", "names": self.bt_name_list}
        
        if self.is_bt_flooding:
            return {"success": False, "message": "Bluetooth flooding already active"}
        
        try:
            # Generate or use provided device names
            if custom_names:
                self.bt_name_list = custom_names[:num_devices]
                while len(self.bt_name_list) < num_devices:
                    self.bt_name_list.append(self.generate_random_bt_name())
            else:
                self.bt_name_list = [self.generate_random_bt_name() for _ in range(num_devices)]
            
            # Ensure Bluetooth interface is up
            result = subprocess.run(["hciconfig", self.bt_interface, "up"], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: Failed to bring up Bluetooth interface: {result.stderr}")
            
            # Set the interface to be discoverable with a fake name (rotating names in real scenario)
            first_name = self.bt_name_list[0]
            result = subprocess.run(["hciconfig", self.bt_interface, "name", first_name], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: Failed to set Bluetooth name: {result.stderr}")
            result = subprocess.run(["hciconfig", self.bt_interface, "piscan"], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: Failed to set Bluetooth to discoverable: {result.stderr}")
            
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
            result = subprocess.run(["hciconfig", self.bt_interface, "noiscan"], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: Failed to set Bluetooth to non-discoverable: {result.stderr}")
            result = subprocess.run(["hciconfig", self.bt_interface, "name", ""], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: Failed to reset Bluetooth name: {result.stderr}")
            
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
