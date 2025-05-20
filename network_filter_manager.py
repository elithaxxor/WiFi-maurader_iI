"""
WiFi Marauder - Network Filter Logic Module
This module contains the logic for managing customizable network filters for targeted scanning.
"""

class NetworkFilterManager:
    """
    Manages customizable network filters for WiFi Marauder scanning.
    Allows definition, application, and storage of filter profiles for targeted network scans.
    """
    def __init__(self):
        self.filter_profiles = {}
        self.active_profile = None

    def define_filter_profile(self, name, criteria, description=""):
        """
        Define a new filter profile with specific criteria for network scanning.
        
        Args:
            name (str): Name of the filter profile
            criteria (dict): Dictionary of filter criteria
                            Example: {
                                'signal_strength_min': -70,  # dBm
                                'signal_strength_max': -30,  # dBm
                                'encryption_types': ['WPA2', 'WPA3'],
                                'channels': [1, 6, 11],
                                'ssid_pattern': 'Home*',  # Case-insensitive matching
                                'bssid_pattern': '00:11:22:*'
                            }
            description (str): Optional description of the filter profile
        """
        self.filter_profiles[name] = {'criteria': criteria, 'description': description}
        return name

    def apply_filter_profile(self, name):
        """
        Apply a defined filter profile for scanning.
        
        Args:
            name (str): Name of the filter profile to apply
        
        Returns:
            bool: True if profile applied successfully, False if not found
        """
        if name not in self.filter_profiles:
            return False
        self.active_profile = name
        return True

    def get_active_filter(self):
        """
        Get the currently active filter profile's criteria and description.
        
        Returns:
            dict: Details of the active filter profile, or empty dict if none active
        """
        if self.active_profile is None:
            return {}
        return self.filter_profiles[self.active_profile]

    def filter_network(self, network_info):
        """
        Check if a network matches the active filter criteria.
        
        Args:
            network_info (dict): Dictionary containing network information
                                Example: {
                                    'ssid': 'HomeNetwork',
                                    'bssid': '00:11:22:33:44:55',
                                    'signal_strength': -65,
                                    'encryption': 'WPA2',
                                    'channel': 6
                                }
        
        Returns:
            bool: True if network matches active filter criteria, False otherwise
        """
        if self.active_profile is None:
            return True  # No filter active, accept all networks
        
        criteria = self.filter_profiles[self.active_profile]['criteria']
        
        # Check signal strength range
        signal_min = criteria.get('signal_strength_min')
        if signal_min is not None and network_info.get('signal_strength', -100) < signal_min:
            return False
        signal_max = criteria.get('signal_strength_max')
        if signal_max is not None and network_info.get('signal_strength', 0) > signal_max:
            return False
        
        # Check encryption type
        enc_types = criteria.get('encryption_types')
        if enc_types and network_info.get('encryption') not in enc_types:
            return False
        
        # Check channel
        channels = criteria.get('channels')
        if channels and network_info.get('channel') not in channels:
            return False
        
        # Check SSID pattern (case-insensitive with simple wildcard support)
        ssid_pattern = criteria.get('ssid_pattern')
        if ssid_pattern:
            ssid = network_info.get('ssid', '')
            ssid_pattern = ssid_pattern.lower()
            ssid = ssid.lower()
            if '*' in ssid_pattern:
                pattern = ssid_pattern.replace('*', '')
                if not (pattern in ssid):
                    return False
            elif ssid_pattern != ssid:
                return False
        
        # Check BSSID pattern (simple wildcard support)
        bssid_pattern = criteria.get('bssid_pattern')
        if bssid_pattern:
            bssid = network_info.get('bssid', '')
            if '*' in bssid_pattern:
                pattern_parts = bssid_pattern.split(':')
                bssid_parts = bssid.split(':')
                if len(pattern_parts) != len(bssid_parts):
                    return False
                for p, b in zip(pattern_parts, bssid_parts):
                    if p != '*' and p != b:
                        return False
            elif bssid_pattern != bssid:
                return False
        
        return True

    def remove_filter_profile(self, name):
        """
        Remove a defined filter profile.
        
        Args:
            name (str): Name of the profile to remove
        
        Returns:
            bool: True if removed, False if not found or active
        """
        if name not in self.filter_profiles or self.active_profile == name:
            return False
        del self.filter_profiles[name]
        return True

    def list_profiles(self):
        """
        List all defined filter profiles.
        
        Returns:
            list: List of profile names
        """
        return list(self.filter_profiles.keys())

    def get_profile_description(self, name):
        """
        Get the description of a specific filter profile.
        
        Args:
            name (str): Name of the profile
        
        Returns:
            str: Description of the profile, or empty string if not found
        """
        if name not in self.filter_profiles:
            return ""
        return self.filter_profiles[name]['description']

# Example usage - will be integrated into the main application
if __name__ == '__main__':
    manager = NetworkFilterManager()
    # Define sample filter profiles
    manager.define_filter_profile('Strong WPA2', {
        'signal_strength_min': -70,
        'signal_strength_max': -30,
        'encryption_types': ['WPA2'],
        'channels': [1, 6, 11]
    }, "Filters for strong WPA2 networks on common channels")
    manager.define_filter_profile('Home Networks', {
        'ssid_pattern': 'Home*'
    }, "Filters for networks starting with 'Home'")
    # Apply a profile
    manager.apply_filter_profile('Strong WPA2')
    # Test some networks
    test_networks = [
        {'ssid': 'HomeNetwork', 'bssid': '00:11:22:33:44:55', 'signal_strength': -65, 'encryption': 'WPA2', 'channel': 6},
        {'ssid': 'WeakSignal', 'bssid': '00:11:22:33:44:56', 'signal_strength': -80, 'encryption': 'WPA2', 'channel': 1},
        {'ssid': 'Other', 'bssid': '00:11:22:33:44:57', 'signal_strength': -60, 'encryption': 'WEP', 'channel': 6},
        {'ssid': 'HOME_WIFI', 'bssid': '00:11:22:33:44:58', 'signal_strength': -50, 'encryption': 'WPA2', 'channel': 1}
    ]
    for net in test_networks:
        print(f"Network {net['ssid']}: {'Accepted' if manager.filter_network(net) else 'Filtered out'}")
    # Print description
    print(f"Description of 'Home Networks': {manager.get_profile_description('Home Networks')}")
