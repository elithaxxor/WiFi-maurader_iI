"""OSINT Integration module for WiFi Marauder.

This module provides thin wrappers around popular OSINT data sources.
External API keys must be supplied via **environment variables** so that
secrets never live in source control:

    export SHODAN_API_KEY="<your-shodan-key>"
    export WIGLE_AUTH_TOKEN="<base64(username:password)>"  # see Wigle docs

Any higher-level GUI/CLI code should import these clients and call the
methods as needed. All network calls use ``requests`` with short timeouts
and raise errors on non-200 responses so that callers can react
appropriately (retry, back-off, show message, etc.).
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests


class ShodanClient:
    """Minimal Shodan REST API helper.

    Only implements a couple of endpoints we currently need. Extend as
    required by adding new methods that call ``_get`` or ``_request``.
    """

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: Optional[str] = None, *, timeout: int = 10) -> None:
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        if not self.api_key:
            raise ValueError("Shodan API key not provided or SHODAN_API_KEY env-var missing.")
        self.session = requests.Session()
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    def search_hosts(self, query: str, page: int = 1, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return a list of host matches for *query*.

        ``limit`` caps the number of matches returned (client-side) so GUI
        code can quickly sample results. Shodan returns ``total`` and
        ``matches`` keys in its JSON payload.
        """
        params: Dict[str, Any] = {"query": query, "page": page, "key": self.api_key}
        data = self._get("/shodan/host/search", params=params)
        matches: List[Dict[str, Any]] = data.get("matches", [])
        if limit is not None:
            matches = matches[:limit]
        return matches

    def host_info(self, ip: str) -> Dict[str, Any]:
        """Return detailed information for a single *ip* address."""
        return self._get(f"/shodan/host/{ip}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _get(self, route: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.BASE_URL}{route}"
        params = params or {}
        params.setdefault("key", self.api_key)
        r = self.session.get(url, params=params, timeout=self.timeout)
        self._raise_for_status(r)
        return r.json()

    @staticmethod
    def _raise_for_status(response: requests.Response) -> None:  # noqa: D401
        """Raise with a helpful message on HTTP error."""
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise RuntimeError(f"Shodan API error {response.status_code}: {response.text}") from exc


class WigleClient:
    """Minimal Wigle API helper.

    Wigle uses HTTP Basic auth with *username* and *password/token*.
    To avoid storing credentials in config files, provide a pre-encoded
    ``username:password`` string via the ``WIGLE_AUTH_TOKEN`` env-var or
    pass it directly to the constructor.
    """

    BASE_URL = "https://api.wigle.net/api/v2"

    def __init__(self, auth_token: Optional[str] = None, *, timeout: int = 10) -> None:
        self.auth_token = auth_token or os.getenv("WIGLE_AUTH_TOKEN")
        if not self.auth_token:
            raise ValueError(
                "Wigle auth token not provided; set WIGLE_AUTH_TOKEN env-var with base64(username:password)."
            )
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Basic {self.auth_token}"
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    def search_networks(self, ssid: str, *, results_per_page: int = 100, page: int = 1, only_mine: bool = False) -> Dict[str, Any]:
        """Search for Wi-Fi networks matching *ssid*.

        Returns JSON payload directly. Callers can drill into ``results``.
        ``only_mine`` restricts to networks contributed by the account.
        """
        params: Dict[str, Any] = {
            "ssid": ssid,
            "resultsPerPage": results_per_page,
            "page": page,
            "onlymine": "true" if only_mine else "false",
        }
        return self._get("/network/search", params=params)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _get(self, route: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.BASE_URL}{route}"
        r = self.session.get(url, params=params or {}, timeout=self.timeout)
        self._raise_for_status(r)
        return r.json()

    @staticmethod
    def _raise_for_status(response: requests.Response) -> None:  # noqa: D401
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise RuntimeError(f"Wigle API error {response.status_code}: {response.text}") from exc


__all__ = [
    "ShodanClient",
    "WigleClient",
]
