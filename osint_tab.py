"""PySide6 GUI tab for OSINT integrations (Shodan & Wigle).

This widget is imported by *main.py* and plugged into the app's tab bar.
Searches are run synchronously for now; long-running queries can later be
moved to QThread for non-blocking behaviour.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QTextEdit,
    QMessageBox,
)

# Local wrappers
from osint_integrations import ShodanClient, WigleClient


class OSINTTab(QWidget):
    """Self-contained GUI for OSINT searches."""

    PROVIDERS = [
        ("Shodan – Host Search", "shodan"),
        ("Wigle – SSID Search", "wigle"),
    ]

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Query bar ------------------------------------------------------
        bar = QHBoxLayout()
        self.provider_cb = QComboBox()
        for label, key in self.PROVIDERS:
            self.provider_cb.addItem(label, userData=key)
        bar.addWidget(self.provider_cb)

        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText("Enter search query / SSID …")
        bar.addWidget(self.query_edit, 1)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.execute_search)
        bar.addWidget(self.search_btn)

        layout.addLayout(bar)

        # Results --------------------------------------------------------
        self.results_view = QTextEdit()
        self.results_view.setReadOnly(True)
        layout.addWidget(self.results_view, 1)

        # Status line ----------------------------------------------------
        self.status_lbl = QLabel("Ready")
        layout.addWidget(self.status_lbl)

    # ------------------------------------------------------------------
    # Slot
    # ------------------------------------------------------------------
    def execute_search(self) -> None:  # noqa: D401 – PySide slot
        query = self.query_edit.text().strip()
        if not query:
            QMessageBox.warning(self, "Input required", "Please enter a query / SSID.")
            return

        provider_key: str = self.provider_cb.currentData()
        self.status_lbl.setText(f"Searching {provider_key.capitalize()} …")
        try:
            if provider_key == "shodan":
                results = self._shodan_search(query)
            else:
                results = self._wigle_search(query)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "OSINT Error", str(exc))
            self.status_lbl.setText("Error – see dialog")
            return

        # Pretty-print JSON results
        self.results_view.setPlainText(json.dumps(results, indent=2, sort_keys=True))
        self.status_lbl.setText(f"Done – {len(results)} items")

    # ------------------------------------------------------------------
    # Provider helpers
    # ------------------------------------------------------------------
    def _shodan_search(self, query: str) -> List[Dict[str, Any]]:
        client = ShodanClient()
        return client.search_hosts(query, limit=50)

    def _wigle_search(self, ssid: str) -> Dict[str, Any]:
        client = WigleClient()
        return client.search_networks(ssid=ssid, results_per_page=50)
