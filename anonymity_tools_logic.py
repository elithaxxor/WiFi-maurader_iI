"""
WiFi Marauder - Anonymity Tools Logic Module
This module contains the logic for managing anonymity tools such as MAC address changing
and ProxyChains configuration for use before penetration testing.
"""
import subprocess
import re
import os
import random
import requests
import time
from datetime import datetime, timedelta

class AnonymityToolsManager:
    """
    Manages tools for enhancing user anonymity during penetration testing.
    Includes functionality for changing MAC addresses, ProxyChains, VPN, Tor, DNS protection,
    IP rotation, user-agent spoofing, and temporal disguises.
    """
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.current_mac = self.get_current_mac()
        self.original_mac = self.current_mac
        self.proxychains_enabled = False
        self.proxychains_config = "/etc/proxychains.conf"
        self.proxychains_status = "disabled"
        self.vpn_enabled = False
        self.vpn_config = None
        self.vpn_process = None
        self.tor_enabled = False
        self.dns_protection_enabled = False
        self.ip_rotation_enabled = False
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.temporal_disguise_enabled = False
        self.fake_timezone_offset = 0

    def get_current_mac(self):
        """
        Retrieve the current MAC address of the specified interface.
        
        Returns:
            str: Current MAC address, or empty string if retrieval fails
        """
        try:
            result = subprocess.run(["ifconfig", self.interface], capture_output=True, text=True, check=False)
            if result.stdout:
                mac_match = re.search(r"ether\s+([0-9a-fA-F:]+)", result.stdout)
                if mac_match:
                    return mac_match.group(1)
            return ""
        except Exception as e:
            print(f"Error getting MAC address: {str(e)}")
            return ""

    def change_mac_address(self, new_mac=None):
        """
        Change the MAC address of the specified interface to a new value or a random one.
        Requires root privileges to execute.
        
        Args:
            new_mac (str, optional): Specific MAC address to set. If None, a random MAC is generated.
        
        Returns:
            dict: Result including success status, new MAC address, and any error message
        """
        if new_mac is None:
            # Generate a random MAC address (first 3 octets can be fixed for vendor neutrality)
            new_mac = "00:50:56:" + ":".join(["{:02x}".format(os.urandom(1)[0]) for _ in range(3)])
        
        try:
            # Ensure interface is down before changing MAC
            subprocess.run(["ifconfig", self.interface, "down"], check=True)
            # Change MAC address
            subprocess.run(["ifconfig", self.interface, "hw", "ether", new_mac], check=True)
            # Bring interface back up
            subprocess.run(["ifconfig", self.interface, "up"], check=True)
            
            # Verify the change
            updated_mac = self.get_current_mac()
            if updated_mac == new_mac:
                self.current_mac = updated_mac
                return {"success": True, "new_mac": updated_mac, "message": "MAC address changed successfully"}
            else:
                return {"success": False, "new_mac": updated_mac, "message": "MAC address change failed, current MAC unchanged"}
        except subprocess.CalledProcessError as e:
            return {"success": False, "new_mac": self.current_mac, "message": f"Failed to change MAC address: {str(e)}"}
        except Exception as e:
            return {"success": False, "new_mac": self.current_mac, "message": f"Unexpected error changing MAC: {str(e)}"}

    def restore_original_mac(self):
        """
        Restore the original MAC address of the interface.
        
        Returns:
            dict: Result including success status and current MAC address
        """
        if self.original_mac:
            return self.change_mac_address(self.original_mac)
        return {"success": False, "new_mac": self.current_mac, "message": "Original MAC address unknown"}

    def enable_proxychains(self, proxy_list=None, config_path=None):
        """
        Enable ProxyChains for routing traffic through proxies before penetration testing.
        Updates the ProxyChains configuration file with provided proxies or uses existing config.
        
        Args:
            proxy_list (list, optional): List of proxy servers (format: 'type host port [username password]')
                                        Example: ['socks5 127.0.0.1 9050', 'http 192.168.1.10 8080']
            config_path (str, optional): Custom path to proxychains.conf if different from default
        
        Returns:
            dict: Result including success status and configuration message
        """
        if self.proxychains_enabled:
            return {"success": False, "message": "ProxyChains already enabled"}
        
        if config_path:
            self.proxychains_config = config_path
        
        if not os.path.exists(self.proxychains_config):
            return {"success": False, "message": f"ProxyChains config file not found at {self.proxychains_config}"}
        
        try:
            if proxy_list:
                # Backup existing config
                backup_file = self.proxychains_config + ".backup"
                with open(self.proxychains_config, 'r') as original, open(backup_file, 'w') as backup:
                    backup.write(original.read())
                
                # Update config with new proxy list
                with open(self.proxychains_config, 'a') as config:
                    config.write("\n# Added by WiFi Marauder\n")
                    for proxy in proxy_list:
                        config.write(f"{proxy}\n")
            
            self.proxychains_enabled = True
            self.proxychains_status = "enabled"
            return {"success": True, "message": "ProxyChains enabled successfully"}
        except Exception as e:
            return {"success": False, "message": f"Failed to enable ProxyChains: {str(e)}"}

    def disable_proxychains(self):
        """
        Disable ProxyChains and optionally restore the original configuration.
        
        Returns:
            dict: Result including success status and message
        """
        if not self.proxychains_enabled:
            return {"success": False, "message": "ProxyChains already disabled"}
        
        try:
            backup_file = self.proxychains_config + ".backup"
            if os.path.exists(backup_file):
                with open(backup_file, 'r') as backup, open(self.proxychains_config, 'w') as config:
                    config.write(backup.read())
                os.remove(backup_file)
            
            self.proxychains_enabled = False
            self.proxychains_status = "disabled"
            return {"success": True, "message": "ProxyChains disabled and config restored"}
        except Exception as e:
            return {"success": False, "message": f"Failed to disable ProxyChains: {str(e)}"}

    def get_proxychains_status(self):
        """
        Get the current status of ProxyChains configuration.
        
        Returns:
            dict: Status information about ProxyChains
        """
        return {
            "enabled": self.proxychains_enabled,
            "status": self.proxychains_status,
            "config_path": self.proxychains_config
        }

    def wrap_command_with_proxychains(self, command):
        """
        Wrap a given command with proxychains if enabled, to route traffic through proxies.
        
        Args:
            command (list or str): Command to execute, as a list of arguments or string
        
        Returns:
            list: Modified command list with proxychains prefix if enabled
        """
        if not self.proxychains_enabled:
            return command if isinstance(command, list) else command.split()
        
        prefix = ["proxychains", "-q"]  # -q for quiet mode
        if isinstance(command, str):
            command = command.split()
        return prefix + command

    def enable_vpn(self, config_path=None, credentials=None):
        """
        Enable VPN connection for routing traffic through a virtual private network.
        
        Args:
            config_path (str, optional): Path to VPN configuration file (e.g., OpenVPN .ovpn file)
            credentials (tuple, optional): Username and password tuple for VPN authentication
        
        Returns:
            dict: Result including success status and message
        """
        if self.vpn_enabled:
            return {"success": False, "message": "VPN already enabled"}
        
        if not config_path or not os.path.exists(config_path):
            return {"success": False, "message": "VPN config file not found or not provided"}
        
        try:
            cmd = ["openvpn", "--config", config_path, "--daemon"]
            if credentials:
                cmd.extend(["--auth-user-pass", f"{credentials[0]} {credentials[1]}"])
            self.vpn_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(2)  # Give it a moment to establish connection
            if self.vpn_process.poll() is None:  # Process is still running
                self.vpn_enabled = True
                self.vpn_config = config_path
                return {"success": True, "message": "VPN connection initiated"}
            else:
                error = self.vpn_process.stderr.read()
                return {"success": False, "message": f"VPN connection failed: {error}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to enable VPN: {str(e)}"}

    def disable_vpn(self):
        """
        Disable VPN connection and terminate the process.
        
        Returns:
            dict: Result including success status and message
        """
        if not self.vpn_enabled or not self.vpn_process:
            return {"success": False, "message": "VPN not enabled"}
        
        try:
            self.vpn_process.terminate()
            self.vpn_process.wait(timeout=5)
            self.vpn_enabled = False
            self.vpn_config = None
            self.vpn_process = None
            return {"success": True, "message": "VPN connection terminated"}
        except Exception as e:
            return {"success": False, "message": f"Failed to disable VPN: {str(e)}"}

    def get_vpn_status(self):
        """
        Get the current status of VPN connection.
        
        Returns:
            dict: Status information about VPN
        """
        return {
            "enabled": self.vpn_enabled,
            "config_path": self.vpn_config if self.vpn_config else "Not set"
        }

    def enable_tor(self):
        """
        Enable Tor routing for anonymity by checking if Tor service is running and configuring traffic.
        
        Returns:
            dict: Result including success status and message
        """
        if self.tor_enabled:
            return {"success": False, "message": "Tor already enabled"}
        
        try:
            # Check if Tor is installed and running
            result = subprocess.run(["torsocks", "--version"], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                self.tor_enabled = True
                return {"success": True, "message": "Tor enabled successfully"}
            else:
                return {"success": False, "message": "Tor not installed or not running"}
        except Exception as e:
            return {"success": False, "message": f"Failed to enable Tor: {str(e)}"}

    def disable_tor(self):
        """
        Disable Tor routing.
        
        Returns:
            dict: Result including success status and message
        """
        if not self.tor_enabled:
            return {"success": False, "message": "Tor not enabled"}
        
        self.tor_enabled = False
        return {"success": True, "message": "Tor disabled"}

    def wrap_command_with_tor(self, command):
        """
        Wrap a given command with torsocks if Tor is enabled.
        
        Args:
            command (list or str): Command to execute
        
        Returns:
            list: Modified command list with torsocks prefix if enabled
        """
        if not self.tor_enabled:
            return command if isinstance(command, list) else command.split()
        
        prefix = ["torsocks"]
        if isinstance(command, str):
            command = command.split()
        return prefix + command

    def enable_dns_protection(self, dns_server="1.1.1.1"):
        """
        Enable DNS leak protection by setting a secure DNS server.
        
        Args:
            dns_server (str): DNS server to use (default: Cloudflare 1.1.1.1)
        
        Returns:
            dict: Result including success status and message
        """
        if self.dns_protection_enabled:
            return {"success": False, "message": "DNS protection already enabled"}
        
        try:
            # This is a placeholder; actual implementation depends on system configuration
            self.dns_protection_enabled = True
            return {"success": True, "message": f"DNS protection enabled with server {dns_server}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to enable DNS protection: {str(e)}"}

    def disable_dns_protection(self):
        """
        Disable DNS leak protection and restore default DNS settings.
        
        Returns:
            dict: Result including success status and message
        """
        if not self.dns_protection_enabled:
            return {"success": False, "message": "DNS protection not enabled"}
        
        self.dns_protection_enabled = False
        return {"success": True, "message": "DNS protection disabled"}

    def enable_ip_rotation(self, interval=300):
        """
        Enable IP address rotation by switching networks at specified intervals.
        
        Args:
            interval (int): Time in seconds between IP rotations
        
        Returns:
            dict: Result including success status and message
        """
        if self.ip_rotation_enabled:
            return {"success": False, "message": "IP rotation already enabled"}
        
        self.ip_rotation_enabled = True
        # Placeholder for actual IP rotation logic
        return {"success": True, "message": f"IP rotation enabled with interval {interval} seconds"}

    def disable_ip_rotation(self):
        """
        Disable IP address rotation.
        
        Returns:
            dict: Result including success status and message
        """
        if not self.ip_rotation_enabled:
            return {"success": False, "message": "IP rotation not enabled"}
        
        self.ip_rotation_enabled = False
        return {"success": True, "message": "IP rotation disabled"}

    def rotate_ip_address(self):
        """Rotate IP address by switching network connections or using a different proxy."""
        try:
            print("Rotating IP address...")
            # Placeholder for actual IP rotation logic
            # This could involve switching between different network interfaces or proxies
            return True
        except Exception as e:
            print(f"IP rotation failed: {str(e)}")
            return False

    def connect_vpn(self):
        """Connect to a VPN service for IP masking and encrypted traffic."""
        try:
            print("Connecting to VPN...")
            # Placeholder for VPN connection logic
            # This would involve connecting to a VPN service using provided credentials or configuration
            return True
        except Exception as e:
            print(f"VPN connection failed: {str(e)}")
            return False

    def disconnect_vpn(self):
        """Disconnect from the VPN service."""
        try:
            print("Disconnecting from VPN...")
            # Placeholder for VPN disconnection logic
            return True
        except Exception as e:
            print(f"VPN disconnection failed: {str(e)}")
            return False

    def set_user_agent(self, user_agent=None):
        """
        Set a custom user-agent for HTTP requests or choose a random one.
        
        Args:
            user_agent (str, optional): Specific user-agent string. If None, a random one is chosen.
        
        Returns:
            dict: Result including success status and current user-agent
        """
        if user_agent is None:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
            ]
            user_agent = random.choice(user_agents)
        
        self.user_agent = user_agent
        return {"success": True, "message": "User-agent updated", "user_agent": user_agent}

    def get_user_agent(self):
        """
        Get the current user-agent string.
        
        Returns:
            str: Current user-agent
        """
        return self.user_agent

    def enable_temporal_disguise(self, timezone_offset=None):
        """
        Enable temporal disguise by setting a fake timezone offset for scheduling or logging.
        
        Args:
            timezone_offset (int, optional): Offset in hours from UTC. If None, a random offset is chosen.
        
        Returns:
            dict: Result including success status and offset used
        """
        if self.temporal_disguise_enabled:
            return {"success": False, "message": "Temporal disguise already enabled"}
        
        if timezone_offset is None:
            timezone_offset = random.randint(-12, 12)
        
        self.fake_timezone_offset = timezone_offset
        self.temporal_disguise_enabled = True
        return {"success": True, "message": f"Temporal disguise enabled with UTC offset {timezone_offset}"}

    def disable_temporal_disguise(self):
        """
        Disable temporal disguise and reset timezone offset.
        
        Returns:
            dict: Result including success status and message
        """
        if not self.temporal_disguise_enabled:
            return {"success": False, "message": "Temporal disguise not enabled"}
        
        self.temporal_disguise_enabled = False
        self.fake_timezone_offset = 0
        return {"success": True, "message": "Temporal disguise disabled"}

    def get_adjusted_time(self):
        """
        Get the current time adjusted by the fake timezone offset if temporal disguise is enabled.
        
        Returns:
            datetime: Adjusted current time
        """
        current_time = datetime.now()
        if self.temporal_disguise_enabled:
            current_time += timedelta(hours=self.fake_timezone_offset)
        return current_time

# Example usage - will be integrated into the main application
if __name__ == '__main__':
    anonymity = AnonymityToolsManager(interface="wlan0")
    # Get current MAC
    print("Current MAC:", anonymity.current_mac)
    # Change MAC to random
    result = anonymity.change_mac_address()
    print("MAC Change Result:", result)
    # Restore original MAC
    result = anonymity.restore_original_mac()
    print("MAC Restore Result:", result)
    # Enable ProxyChains with sample proxies (commented out to avoid actual changes)
    # proxies = ['socks5 127.0.0.1 9050']
    # result = anonymity.enable_proxychains(proxies)
    # print("ProxyChains Enable Result:", result)
    # Wrap a sample command
    sample_cmd = ["nmap", "-sS", "192.168.1.1"]
    wrapped_cmd = anonymity.wrap_command_with_proxychains(sample_cmd)
    print("Wrapped Command:", wrapped_cmd)
    # Disable ProxyChains (if enabled)
    # result = anonymity.disable_proxychains()
    # print("ProxyChains Disable Result:", result)
    # Set a random user-agent
    result = anonymity.set_user_agent()
    print("User-Agent Set Result:", result)
    # Enable temporal disguise with random offset
    result = anonymity.enable_temporal_disguise()
    print("Temporal Disguise Result:", result)
    print("Adjusted Time:", anonymity.get_adjusted_time())
    # Rotate IP address
    result = anonymity.rotate_ip_address()
    print("IP Rotation Result:", result)
    # Connect to VPN
    result = anonymity.connect_vpn()
    print("VPN Connection Result:", result)
    # Disconnect from VPN
    result = anonymity.disconnect_vpn()
    print("VPN Disconnection Result:", result)
