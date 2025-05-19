import unittest
import sys
import os
from PySide6.QtWidgets import QApplication

# Add the parent directory to the path so we can import from main.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import WiFiMarauderGUI
from anonymity_tools_logic import AnonymityToolsManager
from decoy_networks_logic import DecoyNetworkManager

class TestWiFiMarauderFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    def setUp(self):
        self.gui = WiFiMarauderGUI()
        self.anonymity_manager = AnonymityToolsManager()
        self.decoy_manager = DecoyNetworkManager()

    def test_anonymity_tools_mac_address_change(self):
        result = self.anonymity_manager.change_mac_address()
        self.assertTrue(result, "MAC address change failed")

    def test_anonymity_tools_tor_enable(self):
        result = self.anonymity_manager.enable_tor()
        self.assertTrue(result, "Tor enable failed")

    def test_anonymity_tools_tor_disable(self):
        result = self.anonymity_manager.disable_tor()
        self.assertTrue(result, "Tor disable failed")

    def test_anonymity_tools_dns_protection_enable(self):
        result = self.anonymity_manager.enable_dns_protection()
        self.assertTrue(result, "DNS protection enable failed")

    def test_anonymity_tools_dns_protection_disable(self):
        result = self.anonymity_manager.disable_dns_protection()
        self.assertTrue(result, "DNS protection disable failed")

    def test_anonymity_tools_ip_rotation(self):
        result = self.anonymity_manager.rotate_ip_address()
        self.assertTrue(result, "IP rotation failed")

    def test_anonymity_tools_vpn_connect(self):
        result = self.anonymity_manager.connect_vpn()
        self.assertTrue(result, "VPN connect failed")

    def test_anonymity_tools_vpn_disconnect(self):
        result = self.anonymity_manager.disconnect_vpn()
        self.assertTrue(result, "VPN disconnect failed")

    def test_anonymity_tools_user_agent_spoofing(self):
        result = self.anonymity_manager.set_user_agent()
        self.assertTrue(result.get('success', False), "User-agent spoofing failed")

    def test_anonymity_tools_temporal_disguise_enable(self):
        result = self.anonymity_manager.enable_temporal_disguise()
        self.assertTrue(result, "Temporal disguise enable failed")

    def test_anonymity_tools_temporal_disguise_disable(self):
        result = self.anonymity_manager.disable_temporal_disguise()
        self.assertTrue(result, "Temporal disguise disable failed")

    def test_decoy_networks_wifi_flood_start(self):
        result = self.decoy_manager.start_wifi_flood()
        self.assertTrue(result, "WiFi flood start failed")

    def test_decoy_networks_wifi_flood_stop(self):
        result = self.decoy_manager.stop_wifi_flood()
        self.assertTrue(result, "WiFi flood stop failed")

    def test_decoy_networks_bluetooth_flood_start(self):
        result = self.decoy_manager.start_bluetooth_flood()
        self.assertTrue(result, "Bluetooth flood start failed")

    def test_decoy_networks_bluetooth_flood_stop(self):
        result = self.decoy_manager.stop_bluetooth_flood()
        self.assertTrue(result, "Bluetooth flood stop failed")

    @unittest.skip("Skipping test for mimicking area SSIDs due to missing airmon-ng dependency")
    def test_decoy_networks_mimic_area_ssids(self):
        result = self.decoy_manager.start_wifi_flood(mimic_area_ssids=True)
        self.assertTrue(result.get('success', False), "Mimic area SSIDs failed")
        result = self.decoy_manager.stop_wifi_flood()
        self.assertTrue(result.get('success', False), "Stop mimic area SSIDs failed")

if __name__ == '__main__':
    unittest.main()
