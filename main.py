import sys
import os
import subprocess
import sqlite3
import json
import random
import csv
import time
from datetime import datetime
from math import cos, sin, pi, log10
from collections import Counter

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QPushButton,
    QFileDialog, QLabel, QLineEdit, QTextEdit, QHBoxLayout, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, QGroupBox, QDateEdit, QInputDialog,
    QGridLayout, QSplitter, QSpinBox, QCheckBox, QListWidget, QProgressBar
)
from PySide6.QtCore import QDate, QTimer, Qt
from PySide6.QtGui import QIcon, QPixmap
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# New imports for integrated features
try:
    from anonymity_tools_logic import AnonymityToolsManager
except ImportError:
    print("Warning: AnonymityToolsManager not available. Functionality will be limited.")
    AnonymityToolsManager = None

try:
    from decoy_networks_logic import DecoyNetworkManager
except ImportError:
    print("Warning: DecoyNetworkManager not available. Functionality will be limited.")
    DecoyNetworkManager = None

try:
    from attack_sequence_logic import AttackSequenceManager
except ImportError:
    print("Warning: AttackSequenceManager not available. Functionality will be limited.")
    AttackSequenceManager = None

try:
    from network_filter_manager import NetworkFilterManager
except ImportError:
    print("Warning: NetworkFilterManager not available. Functionality will be limited.")
    NetworkFilterManager = None

try:
    from wps_vulnerability_tester import WPSVulnerabilityTester
except ImportError:
    print("Warning: WPSVulnerabilityTester not available. Functionality will be limited.")
    WPSVulnerabilityTester = None

class DatabaseManager:
    """
    Encapsulates SQLite database operations for the WiFi Marauder app.
    """

    def __init__(self, db_file="wifi_marauder.db"):
        self.conn = sqlite3.connect(db_file)
        self.create_tables()

    def create_tables(self):
        """
        Creates the necessary tables if they don't exist.
        """
        cursor = self.conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                interface TEXT,
                duration INTEGER,
                output TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                bssid TEXT,
                essid TEXT,
                handshake TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deauths (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                bssid TEXT,
                client TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')

        # New table for anonymity settings logs
        cursor.execute('''CREATE TABLE IF NOT EXISTS anonymity_logs
                        (id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        feature TEXT,
                        status TEXT,
                        details TEXT)''')

        # New table for decoy network activities
        cursor.execute('''CREATE TABLE IF NOT EXISTS decoy_activities
                        (id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        type TEXT,
                        details TEXT)''')

        self.conn.commit()

    def insert_scan(self, interface, duration, output):
        """
        Inserts a new scan record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO scans (timestamp, interface, duration, output) VALUES (?, ?, ?, ?)",
                       (timestamp, interface, duration, output))
        self.conn.commit()
        return cursor.lastrowid

    def insert_capture(self, scan_id, bssid, essid, handshake):
        """
        Inserts a new capture record into the database.
        """
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO captures (scan_id, bssid, essid, handshake) VALUES (?, ?, ?, ?)",
                       (scan_id, bssid, essid, handshake))
        self.conn.commit()

    def insert_deauth(self, scan_id, bssid, client):
        """
        Inserts a new deauthentication record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO deauths (scan_id, bssid, client, timestamp) VALUES (?, ?, ?, ?)",
                       (scan_id, bssid, client, timestamp))
        self.conn.commit()

    def insert_anonymity_log(self, feature, status, details):
        """
        Inserts a new anonymity log record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO anonymity_logs (timestamp, feature, status, details) VALUES (?, ?, ?, ?)",
                       (timestamp, feature, status, details))
        self.conn.commit()

    def insert_decoy_activity(self, activity_type, details):
        """
        Inserts a new decoy activity record into the database.
        """
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO decoy_activities (timestamp, type, details) VALUES (?, ?, ?)",
                       (timestamp, activity_type, details))
        self.conn.commit()

    def get_scan_logs(self):
        """
        Retrieves all scan logs from the database.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
        return cursor.fetchall()

    def get_captures_for_scan(self, scan_id):
        """
        Retrieves all captures for a given scan ID.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM captures WHERE scan_id = ?", (scan_id,))
        return cursor.fetchall()

    def get_deauths_for_scan(self, scan_id):
        """
        Retrieves all deauthentications for a given scan ID.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM deauths WHERE scan_id = ? ORDER BY timestamp", (scan_id,))
        return cursor.fetchall()

    def close(self):
        """
        Closes the database connection.
        """
        self.conn.close()


class WiFiMarauderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Marauder v2.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Load application icon
        icon = QIcon("wifi_marauder.png")
        if icon.isNull():
            print("Warning: Could not load icon 'wifi_marauder.png'. Make sure it exists in the application directory.")
        else:
            self.setWindowIcon(icon)

        # Initialize managers if available
        self.attack_sequence_manager = AttackSequenceManager(self) if AttackSequenceManager else None
        self.network_filter_manager = NetworkFilterManager() if NetworkFilterManager else None
        self.decoy_manager = DecoyNetworkManager() if DecoyNetworkManager else None
        self.anonymity_manager = AnonymityToolsManager() if AnonymityToolsManager else None
        self.wps_tester = WPSVulnerabilityTester() if WPSVulnerabilityTester else None

        self.db_manager = DatabaseManager()
        self.setup_ui()
        
        # Load vendor mapping for MAC address lookup
        self.vendor_mapping = self.load_vendors()
        
        # Detect interfaces on startup
        self.detect_interfaces()
        
    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Create tab widget for different functionalities
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Add tabs for each feature
        tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        tabs.addTab(self.create_scan_tab(), "Network Scan")
        tabs.addTab(self.create_attack_tab(), "Attacks")
        tabs.addTab(self.create_anonymity_tab(), "Anonymity Tools")
        tabs.addTab(self.create_decoys_tab(), "Decoy Networks")
        tabs.addTab(self.create_sequence_tab(), "Attack Sequences")
        tabs.addTab(self.create_filters_tab(), "Network Filters")
        tabs.addTab(self.create_wps_tab(), "WPS Testing")
        tabs.addTab(self.create_logs_tab(), "Logs && Analysis")
        
    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)

        # Network Status Summary
        network_group = QGroupBox("Network Status")
        network_layout = QGridLayout(network_group)
        self.network_status_label = QLabel("Networks Detected: 0")
        network_layout.addWidget(self.network_status_label, 0, 0)
        self.scan_status_label = QLabel("Scan Status: Idle")
        network_layout.addWidget(self.scan_status_label, 0, 1)
        layout.addWidget(network_group)

        # Active Attacks Summary
        attacks_group = QGroupBox("Active Attacks")
        attacks_layout = QGridLayout(attacks_group)
        self.attacks_status_label = QLabel("No active attacks")
        attacks_layout.addWidget(self.attacks_status_label, 0, 0)
        self.sequence_status_summary = QLabel("Sequence Status: Idle")
        attacks_layout.addWidget(self.sequence_status_summary, 1, 0)
        layout.addWidget(attacks_group)

        # Applied Filters Summary
        filters_group = QGroupBox("Applied Filters")
        filters_layout = QGridLayout(filters_group)
        self.filters_status_label = QLabel("No filter applied")
        filters_layout.addWidget(self.filters_status_label, 0, 0)
        layout.addWidget(filters_group)

        # Recent Logs Summary
        logs_group = QGroupBox("Recent Logs")
        logs_layout = QVBoxLayout(logs_group)
        self.recent_logs = QTextEdit()
        self.recent_logs.setReadOnly(True)
        self.recent_logs.setText("No recent logs")
        logs_layout.addWidget(self.recent_logs)
        layout.addWidget(logs_group)

        # Update button
        update_button = QPushButton("Refresh Dashboard")
        update_button.clicked.connect(self.update_dashboard)
        layout.addWidget(update_button)

        layout.addStretch()
        return dashboard_tab

    def create_attack_tab(self):
        attack_tab = QWidget()
        layout = QVBoxLayout()

        # Existing attack types
        deauth_group = QGroupBox("Deauthentication Attack")
        deauth_layout = QGridLayout()
        deauth_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.deauth_bssid = QLineEdit()
        deauth_layout.addWidget(self.deauth_bssid, 0, 1)
        deauth_layout.addWidget(QLabel("Client MAC (optional):"), 1, 0)
        self.deauth_client = QLineEdit()
        deauth_layout.addWidget(self.deauth_client, 1, 1)
        deauth_start = QPushButton("Start Deauth")
        deauth_start.clicked.connect(self.start_deauth_attack)
        deauth_layout.addWidget(deauth_start, 2, 0)
        deauth_stop = QPushButton("Stop Deauth")
        deauth_stop.clicked.connect(self.stop_deauth_attack)
        deauth_layout.addWidget(deauth_stop, 2, 1)
        self.deauth_progress = QProgressBar()
        self.deauth_progress.setValue(0)
        deauth_layout.addWidget(self.deauth_progress, 3, 0, 1, 2)
        deauth_group.setLayout(deauth_layout)
        layout.addWidget(deauth_group)

        handshake_group = QGroupBox("Handshake Capture")
        handshake_layout = QGridLayout()
        handshake_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.handshake_bssid = QLineEdit()
        handshake_layout.addWidget(self.handshake_bssid, 0, 1)
        handshake_start = QPushButton("Start Capture")
        handshake_start.clicked.connect(self.start_handshake_capture)
        handshake_layout.addWidget(handshake_start, 1, 0)
        handshake_stop = QPushButton("Stop Capture")
        handshake_stop.clicked.connect(self.stop_handshake_capture)
        handshake_layout.addWidget(handshake_stop, 1, 1)
        self.handshake_progress = QProgressBar()
        self.handshake_progress.setValue(0)
        handshake_layout.addWidget(self.handshake_progress, 2, 0, 1, 2)
        handshake_group.setLayout(handshake_layout)
        layout.addWidget(handshake_group)

        # New Attack Sequence section
        sequence_group = QGroupBox("Attack Sequences")
        sequence_layout = QGridLayout()
        sequence_layout.addWidget(QLabel("Sequence Name:"), 0, 0)
        self.sequence_name = QLineEdit()
        sequence_layout.addWidget(self.sequence_name, 0, 1)
        sequence_layout.addWidget(QLabel("Steps (JSON format):"), 1, 0)
        self.sequence_steps = QTextEdit()
        self.sequence_steps.setPlaceholderText("[{'type': 'deauth', 'duration': 10, 'target': 'BSSID'}, {'type': 'handshake_capture', 'timeout': 30}]")
        sequence_layout.addWidget(self.sequence_steps, 1, 1, 3, 1)
        define_sequence_btn = QPushButton("Define Sequence")
        define_sequence_btn.clicked.connect(self.define_attack_sequence)
        sequence_layout.addWidget(define_sequence_btn, 4, 0)
        start_sequence_btn = QPushButton("Start Sequence")
        start_sequence_btn.clicked.connect(self.start_attack_sequence)
        sequence_layout.addWidget(start_sequence_btn, 4, 1)
        stop_sequence_btn = QPushButton("Stop Sequence")
        stop_sequence_btn.clicked.connect(self.stop_attack_sequence)
        sequence_layout.addWidget(stop_sequence_btn, 5, 0)
        self.sequence_status = QLabel("Sequence Status: Idle")
        sequence_layout.addWidget(self.sequence_status, 5, 1)
        sequence_group.setLayout(sequence_layout)
        layout.addWidget(sequence_group)

        evilap_group = QGroupBox("Evil Twin AP")
        evilap_layout = QGridLayout()
        evilap_layout.addWidget(QLabel("ESSID to Mimic:"), 0, 0)
        self.evilap_essid = QLineEdit()
        evilap_layout.addWidget(self.evilap_essid, 0, 1)
        evilap_layout.addWidget(QLabel("Password (if any):"), 1, 0)
        self.evilap_password = QLineEdit()
        evilap_layout.addWidget(self.evilap_password, 1, 1)
        evilap_start = QPushButton("Start Evil AP")
        evilap_start.clicked.connect(self.start_evil_ap)
        evilap_layout.addWidget(evilap_start, 2, 0)
        evilap_stop = QPushButton("Stop Evil AP")
        evilap_stop.clicked.connect(self.stop_evil_ap)
        evilap_layout.addWidget(evilap_stop, 2, 1)
        self.evilap_progress = QProgressBar()
        self.evilap_progress.setValue(0)
        evilap_layout.addWidget(self.evilap_progress, 3, 0, 1, 2)
        evilap_group.setLayout(evilap_layout)
        layout.addWidget(evilap_group)

        fakeauth_group = QGroupBox("FakeAuth Attack")
        fakeauth_layout = QGridLayout()
        fakeauth_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.fakeauth_bssid = QLineEdit()
        fakeauth_layout.addWidget(self.fakeauth_bssid, 0, 1)
        fakeauth_start = QPushButton("Start FakeAuth")
        fakeauth_start.clicked.connect(self.start_fakeauth_attack)
        fakeauth_layout.addWidget(fakeauth_start, 1, 0)
        fakeauth_stop = QPushButton("Stop FakeAuth")
        fakeauth_stop.clicked.connect(self.stop_fakeauth_attack)
        fakeauth_layout.addWidget(fakeauth_stop, 1, 1)
        self.fakeauth_progress = QProgressBar()
        self.fakeauth_progress.setValue(0)
        fakeauth_layout.addWidget(self.fakeauth_progress, 2, 0, 1, 2)
        fakeauth_group.setLayout(fakeauth_layout)
        layout.addWidget(fakeauth_group)

        # Enhanced MDK4 Wireless Disruption Tools section
        mdk4_group = QGroupBox("Wireless Disruption Tools (MDK4)")
        mdk4_layout = QGridLayout()
        mdk4_layout.addWidget(QLabel("Target BSSID:"), 0, 0)
        self.mdk4_bssid = QLineEdit()
        mdk4_layout.addWidget(self.mdk4_bssid, 0, 1)
        mdk4_layout.addWidget(QLabel("Attack Mode:"), 1, 0)
        self.mdk4_mode = QComboBox()
        self.mdk4_mode.addItems(["Bandwidth Throttling", "Beacon Flooding", "Authentication DoS", "Deauthentication Flood"])
        mdk4_layout.addWidget(self.mdk4_mode, 1, 1)
        mdk4_layout.addWidget(QLabel("Intensity (1-10):"), 2, 0)
        self.mdk4_intensity = QSpinBox()
        self.mdk4_intensity.setRange(1, 10)
        self.mdk4_intensity.setValue(5)
        mdk4_layout.addWidget(self.mdk4_intensity, 2, 1)
        mdk4_start = QPushButton("Start Attack")
        mdk4_start.clicked.connect(self.start_mdk4_attack)
        mdk4_layout.addWidget(mdk4_start, 3, 0)
        mdk4_stop = QPushButton("Stop Attack")
        mdk4_stop.clicked.connect(self.stop_mdk4_attack)
        mdk4_layout.addWidget(mdk4_stop, 3, 1)
        self.mdk4_progress = QProgressBar()
        self.mdk4_progress.setValue(0)
        mdk4_layout.addWidget(self.mdk4_progress, 4, 0, 1, 2)
        self.mdk4_status = QLabel("MDK4 Attack Status: Idle")
        mdk4_layout.addWidget(self.mdk4_status, 5, 0, 1, 2)
        mdk4_group.setLayout(mdk4_layout)
        layout.addWidget(mdk4_group)

        layout.addStretch()
        attack_tab.setLayout(layout)
        return attack_tab

    def define_attack_sequence(self):
        try:
            name = self.sequence_name.text().strip()
            steps_text = self.sequence_steps.toPlainText().strip()
            if not name or not steps_text:
                QMessageBox.warning(self, "Input Error", "Please provide both a sequence name and steps.")
                return
            steps = json.loads(steps_text)
            if not isinstance(steps, list):
                QMessageBox.warning(self, "Format Error", "Steps must be a list of attack configurations.")
                return
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                self.attack_sequence_manager.define_sequence(name, steps)
                self.log(f"Defined attack sequence: {name}")
                QMessageBox.information(self, "Success", f"Sequence '{name}' defined successfully.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Attack Sequence Manager is not available.")
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "JSON Error", f"Invalid JSON format in steps: {str(e)}")
        except Exception as e:
            self.log(f"Error defining attack sequence: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to define sequence: {str(e)}")

    def start_attack_sequence(self):
        try:
            name = self.sequence_name.text().strip()
            if not name:
                QMessageBox.warning(self, "Input Error", "Please provide a sequence name.")
                return
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                if self.attack_sequence_manager.start_sequence(name):
                    self.log(f"Started attack sequence: {name}")
                    self.sequence_status.setText(f"Sequence Status: Running {name}")
                    # Start a timer to execute steps
                    self.sequence_timer = QTimer(self)
                    self.sequence_timer.timeout.connect(self.execute_sequence_step)
                    self.sequence_timer.start(5000)  # Check every 5 seconds
                else:
                    QMessageBox.warning(self, "Start Failed", f"Sequence '{name}' not found or already active.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Attack Sequence Manager is not available.")
        except Exception as e:
            self.log(f"Error starting attack sequence: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to start sequence: {str(e)}")

    def execute_sequence_step(self):
        try:
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                status = self.attack_sequence_manager.get_sequence_status()
                if status['status'] == 'running':
                    result = self.attack_sequence_manager.execute_current_step()
                    self.log(f"Sequence step result: {result}")
                    if result['status'] == 'complete':
                        self.sequence_status.setText("Sequence Status: Completed")
                        if hasattr(self, 'sequence_timer'):
                            self.sequence_timer.stop()
                    elif result['status'] == 'error':
                        self.sequence_status.setText(f"Sequence Status: Error - {result['message']}")
                        if hasattr(self, 'sequence_timer'):
                            self.sequence_timer.stop()
                else:
                    self.sequence_status.setText("Sequence Status: Idle")
                    if hasattr(self, 'sequence_timer'):
                        self.sequence_timer.stop()
        except Exception as e:
            self.log(f"Error executing sequence step: {str(e)}")
            self.sequence_status.setText(f"Sequence Status: Error - {str(e)}")
            if hasattr(self, 'sequence_timer'):
                self.sequence_timer.stop()

    def stop_attack_sequence(self):
        try:
            if hasattr(self, 'attack_sequence_manager') and self.attack_sequence_manager:
                if self.attack_sequence_manager.stop_sequence():
                    self.log("Stopped attack sequence.")
                    self.sequence_status.setText("Sequence Status: Stopped")
                    if hasattr(self, 'sequence_timer'):
                        self.sequence_timer.stop()
                else:
                    QMessageBox.warning(self, "Stop Failed", "No active sequence to stop.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Attack Sequence Manager is not available.")
        except Exception as e:
            self.log(f"Error stopping attack sequence: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to stop sequence: {str(e)}")

    def create_scan_tab(self):
        scan_tab = QWidget()
        layout = QVBoxLayout()

        scan_group = QGroupBox("WiFi Scan")
        scan_layout = QGridLayout()
        scan_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.scan_interface = QComboBox()
        self.scan_interface.addItems(["wlan0", "wlan1"])
        scan_layout.addWidget(self.scan_interface, 0, 1)
        scan_layout.addWidget(QLabel("Duration (seconds):"), 1, 0)
        self.scan_duration = QSpinBox()
        self.scan_duration.setRange(10, 300)
        self.scan_duration.setValue(30)
        scan_layout.addWidget(self.scan_duration, 1, 1)
        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_scan)
        scan_layout.addWidget(scan_button, 2, 0)
        self.scan_progress = QProgressBar()
        self.scan_progress.setValue(0)
        scan_layout.addWidget(self.scan_progress, 2, 1)
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)

        # New Network Filter section
        filter_group = QGroupBox("Network Filters")
        filter_layout = QGridLayout()
        filter_layout.addWidget(QLabel("Filter Profile Name:"), 0, 0)
        self.filter_name = QLineEdit()
        filter_layout.addWidget(self.filter_name, 0, 1)
        filter_layout.addWidget(QLabel("Criteria (JSON format):"), 1, 0)
        self.filter_criteria = QTextEdit()
        self.filter_criteria.setPlaceholderText("{'signal_strength_min': -70, 'encryption_types': ['WPA2'], 'channels': [1, 6, 11]}")
        filter_layout.addWidget(self.filter_criteria, 1, 1, 3, 1)
        define_filter_btn = QPushButton("Define Filter Profile")
        define_filter_btn.clicked.connect(self.define_filter_profile)
        filter_layout.addWidget(define_filter_btn, 4, 0)
        apply_filter_btn = QPushButton("Apply Filter Profile")
        apply_filter_btn.clicked.connect(self.apply_filter_profile)
        filter_layout.addWidget(apply_filter_btn, 4, 1)
        self.filter_status = QLabel("Filter Status: No filter active")
        filter_layout.addWidget(self.filter_status, 5, 0, 1, 2)
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

        result_group = QGroupBox("Scan Results")
        result_layout = QVBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels(["BSSID", "ESSID", "Signal", "Channel", "Encryption", "Select"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        result_layout.addWidget(self.result_table)
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_networks)
        result_layout.addWidget(select_all_btn)
        set_target_btn = QPushButton("Set as Target")
        set_target_btn.clicked.connect(self.set_as_target)
        result_layout.addWidget(set_target_btn)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        layout.addStretch()
        scan_tab.setLayout(layout)
        return scan_tab

    def define_filter_profile(self):
        try:
            name = self.filter_name.text().strip()
            criteria_text = self.filter_criteria.toPlainText().strip()
            if not name or not criteria_text:
                QMessageBox.warning(self, "Input Error", "Please provide both a filter profile name and criteria.")
                return
            criteria = json.loads(criteria_text)
            if not isinstance(criteria, dict):
                QMessageBox.warning(self, "Format Error", "Criteria must be a dictionary of filter settings.")
                return
            if hasattr(self, 'network_filter_manager') and self.network_filter_manager:
                self.network_filter_manager.define_filter_profile(name, criteria, f"User-defined filter on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.log(f"Defined network filter profile: {name}")
                QMessageBox.information(self, "Success", f"Filter profile '{name}' defined successfully.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Network Filter Manager is not available.")
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "JSON Error", f"Invalid JSON format in criteria: {str(e)}")
        except Exception as e:
            self.log(f"Error defining filter profile: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to define filter profile: {str(e)}")

    def apply_filter_profile(self):
        try:
            name = self.filter_name.text().strip()
            if not name:
                QMessageBox.warning(self, "Input Error", "Please provide a filter profile name.")
                return
            if hasattr(self, 'network_filter_manager') and self.network_filter_manager:
                if self.network_filter_manager.apply_filter_profile(name):
                    self.log(f"Applied network filter profile: {name}")
                    self.filter_status.setText(f"Filter Status: Active - {name}")
                    QMessageBox.information(self, "Success", f"Filter profile '{name}' applied successfully.")
                else:
                    QMessageBox.warning(self, "Apply Failed", f"Filter profile '{name}' not found.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Network Filter Manager is not available.")
        except Exception as e:
            self.log(f"Error applying filter profile: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to apply filter profile: {str(e)}")

    def create_decoys_tab(self):
        decoy_tab = QWidget()
        layout = QVBoxLayout()

        wifi_group = QGroupBox("WiFi Decoy Networks")
        wifi_layout = QGridLayout()
        wifi_layout.addWidget(QLabel("WiFi AP Name:"), 0, 0)
        self.wifi_ap_name = QLineEdit()
        self.wifi_ap_name.setPlaceholderText("Default: WiFi_Marauder")
        wifi_layout.addWidget(self.wifi_ap_name, 0, 1)
        wifi_start = QPushButton("Start WiFi Decoy")
        wifi_start.clicked.connect(self.start_wifi_decoy)
        wifi_layout.addWidget(wifi_start, 1, 0)
        wifi_stop = QPushButton("Stop WiFi Decoy")
        wifi_stop.clicked.connect(self.stop_wifi_decoy)
        wifi_layout.addWidget(wifi_stop, 1, 1)
        self.wifi_decoy_status = QLabel("WiFi Decoy Status: Inactive")
        wifi_layout.addWidget(self.wifi_decoy_status, 2, 0, 1, 2)
        wifi_group.setLayout(wifi_layout)
        layout.addWidget(wifi_group)

        bt_group = QGroupBox("Bluetooth Decoy Devices")
        bt_layout = QGridLayout()
        bt_layout.addWidget(QLabel("Bluetooth Device Name:"), 0, 0)
        self.bt_device_name = QLineEdit()
        self.bt_device_name.setPlaceholderText("Default: BT_Marauder")
        bt_layout.addWidget(self.bt_device_name, 0, 1)
        bt_start = QPushButton("Start Bluetooth Decoy")
        bt_start.clicked.connect(self.start_bt_decoy)
        bt_layout.addWidget(bt_start, 1, 0)
        bt_stop = QPushButton("Stop Bluetooth Decoy")
        bt_stop.clicked.connect(self.stop_bt_decoy)
        bt_layout.addWidget(bt_stop, 1, 1)
        self.bt_decoy_status = QLabel("Bluetooth Decoy Status: Inactive")
        bt_layout.addWidget(self.bt_decoy_status, 2, 0, 1, 2)
        bt_group.setLayout(bt_layout)
        layout.addWidget(bt_group)

        layout.addStretch()
        decoy_tab.setLayout(layout)
        return decoy_tab

    def start_wifi_decoy(self):
        try:
            ap_name = self.wifi_ap_name.text().strip() or "WiFi_Marauder"
            if hasattr(self, 'decoy_manager') and self.decoy_manager:
                if self.decoy_manager.start_wifi_decoy(ap_name):
                    self.log(f"Started WiFi decoy network with name: {ap_name}")
                    self.wifi_decoy_status.setText(f"WiFi Decoy Status: Active - {ap_name}")
                else:
                    QMessageBox.warning(self, "Start Failed", "Failed to start WiFi decoy network.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error starting WiFi decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to start WiFi decoy: {str(e)}")

    def stop_wifi_decoy(self):
        try:
            if hasattr(self, 'decoy_manager') and self.decoy_manager:
                if self.decoy_manager.stop_wifi_decoy():
                    self.log("Stopped WiFi decoy network.")
                    self.wifi_decoy_status.setText("WiFi Decoy Status: Inactive")
                else:
                    QMessageBox.warning(self, "Stop Failed", "No active WiFi decoy network to stop.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error stopping WiFi decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to stop WiFi decoy: {str(e)}")

    def start_bt_decoy(self):
        try:
            device_name = self.bt_device_name.text().strip() or "BT_Marauder"
            if hasattr(self, 'decoy_manager') and self.decoy_manager:
                if self.decoy_manager.start_bluetooth_decoy(device_name):
                    self.log(f"Started Bluetooth decoy device with name: {device_name}")
                    self.bt_decoy_status.setText(f"Bluetooth Decoy Status: Active - {device_name}")
                else:
                    QMessageBox.warning(self, "Start Failed", "Failed to start Bluetooth decoy device.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error starting Bluetooth decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to start Bluetooth decoy: {str(e)}")

    def stop_bt_decoy(self):
        try:
            if hasattr(self, 'decoy_manager') and self.decoy_manager:
                if self.decoy_manager.stop_bluetooth_decoy():
                    self.log("Stopped Bluetooth decoy device.")
                    self.bt_decoy_status.setText("Bluetooth Decoy Status: Inactive")
                else:
                    QMessageBox.warning(self, "Stop Failed", "No active Bluetooth decoy device to stop.")
            else:
                QMessageBox.warning(self, "Feature Unavailable", "Decoy Network Manager is not available.")
        except Exception as e:
            self.log(f"Error stopping Bluetooth decoy: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to stop Bluetooth decoy: {str(e)}")

    def start_mdk4_attack(self):
        try:
            bssid = self.mdk4_bssid.text().strip()
            mode = self.mdk4_mode.currentText()
            intensity = self.mdk4_intensity.value()
            if not bssid:
                QMessageBox.warning(self, "Input Error", "Please provide a target BSSID.")
                return
            # Placeholder for actual MDK4 attack logic based on mode
            self.log(f"Starting {mode} on {bssid} with intensity {intensity}")
            self.mdk4_active = True
            self.mdk4_progress.setValue(0)
            self.mdk4_status.setText(f"MDK4 Attack Status: Running {mode}")
            # Start a timer to simulate progress updates
            self.mdk4_timer = QTimer(self)
            self.mdk4_timer.timeout.connect(self.update_mdk4_progress)
            self.mdk4_timer.start(1000)  # Update every second
            # In a real implementation, we would map the mode to specific MDK4 commands:
            # - Bandwidth Throttling: mdk4 wlan0 d -B <bssid> -s <speed>
            # - Beacon Flooding: mdk4 wlan0 b -n <essid> -c <channel>
            # - Authentication DoS: mdk4 wlan0 a -a <bssid>
            # - Deauthentication Flood: mdk4 wlan0 d -B <bssid>
        except Exception as e:
            self.log(f"Error starting MDK4 attack: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to start attack: {str(e)}")

    def update_mdk4_progress(self):
        if not hasattr(self, 'mdk4_active') or not self.mdk4_active:
            if hasattr(self, 'mdk4_timer'):
                self.mdk4_timer.stop()
            return
        progress = min(100, self.mdk4_progress.value() + 10)
        self.mdk4_progress.setValue(progress)
        if progress == 100:
            if hasattr(self, 'mdk4_timer'):
                self.mdk4_timer.stop()
            self.mdk4_active = False
            self.log("MDK4 attack simulation completed")
            self.mdk4_status.setText("MDK4 Attack Status: Completed")

    def stop_mdk4_attack(self):
        try:
            if hasattr(self, 'mdk4_active') and self.mdk4_active:
                self.mdk4_active = False
                if hasattr(self, 'mdk4_timer'):
                    self.mdk4_timer.stop()
                self.mdk4_progress.setValue(0)
                self.log("Stopped MDK4 attack")
                self.mdk4_status.setText("MDK4 Attack Status: Stopped")
            else:
                QMessageBox.warning(self, "Stop Failed", "No active MDK4 attack to stop.")
        except Exception as e:
            self.log(f"Error stopping MDK4 attack: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to stop attack: {str(e)}")