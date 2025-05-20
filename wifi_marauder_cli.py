#!/usr/bin/env python3
"""WiFi Marauder – Head-less CLI

Provides a minimal command-line interface so WiFi Marauder functionality can be
invoked from scripts / CI and output machine-readable JSON.

Currently supports decoy network actions and SSID scanning. Additional
features can be mapped in over time.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add project root to PYTHONPATH when executed from sibling directory
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from decoy_networks_logic import DecoyNetworkManager
except ImportError as exc:  # pragma: no cover
    print(json.dumps({"success": False, "error": f"Failed to import core modules: {exc}"}))
    sys.exit(1)

try:
    from osint_integrations import ShodanClient, WigleClient
except ImportError as exc:  # pragma: no cover
    print(json.dumps({"success": False, "error": f"Failed to import OSINT modules: {exc}"}))
    sys.exit(1)


def as_json(data):
    """Print *data* as prettified JSON and exit."""
    print(json.dumps(data, indent=2, sort_keys=True))
    sys.exit(0 if data.get("success", True) else 1)


def cmd_scan_ssids(args):
    mgr = DecoyNetworkManager()
    ssids = mgr.scan_area_for_ssids(scan_duration=args.duration)
    as_json({"success": True, "ssids": ssids})


def cmd_start_wifi_flood(args):
    mgr = DecoyNetworkManager()
    res = mgr.start_wifi_flood(
        num_aps=args.num,
        custom_ssids=args.ssids,
        mimic_area_ssids=args.mimic,
        channel_range=(args.channel_min, args.channel_max),
        duration=args.duration,
    )
    as_json(res)


def cmd_stop_wifi_flood(_args):
    mgr = DecoyNetworkManager()
    as_json(mgr.stop_wifi_flood())


def cmd_start_bt_flood(args):
    mgr = DecoyNetworkManager()
    res = mgr.start_bluetooth_flood(
        num_devices=args.num,
        custom_names=args.names,
        duration=args.duration,
    )
    as_json(res)


def cmd_stop_bt_flood(_args):
    mgr = DecoyNetworkManager()
    as_json(mgr.stop_bluetooth_flood())


def cmd_status(_args):
    mgr = DecoyNetworkManager()
    as_json({
        "success": True,
        "wifi": mgr.get_wifi_flood_status(),
        "bluetooth": mgr.get_bluetooth_flood_status(),
    })


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WiFi Marauder CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # SSID scan
    scan = sub.add_parser("scan-ssids", help="Scan area for SSIDs (airodump stub).")
    scan.add_argument("--duration", type=int, default=10, help="Scan duration seconds")
    scan.set_defaults(func=cmd_scan_ssids)

    # WiFi flood
    wf_start = sub.add_parser("start-wifi-flood", help="Start WiFi decoy flood")
    wf_start.add_argument("--num", type=int, default=5, help="Number of fake APs")
    wf_start.add_argument("--ssids", nargs="*", help="Custom SSIDs to broadcast")
    wf_start.add_argument("--mimic", action="store_true", help="Mimic nearby real SSIDs")
    wf_start.add_argument("--channel-min", type=int, default=1)
    wf_start.add_argument("--channel-max", type=int, default=11)
    wf_start.add_argument("--duration", type=int, help="Stop after N seconds (default: indefinite)")
    wf_start.set_defaults(func=cmd_start_wifi_flood)

    sub.add_parser("stop-wifi-flood", help="Stop WiFi decoy flood").set_defaults(func=cmd_stop_wifi_flood)

    # Bluetooth flood
    bt_start = sub.add_parser("start-bt-flood", help="Start Bluetooth decoy flood")
    bt_start.add_argument("--num", type=int, default=5, help="Number of devices")
    bt_start.add_argument("--names", nargs="*", help="Custom BT device names")
    bt_start.add_argument("--duration", type=int, help="Stop after N seconds")
    bt_start.set_defaults(func=cmd_start_bt_flood)

    sub.add_parser("stop-bt-flood", help="Stop Bluetooth decoy flood").set_defaults(func=cmd_stop_bt_flood)

    # Status
    sub.add_parser("status", help="Show decoy flood status").set_defaults(func=cmd_status)

    # OSINT – Shodan search
    shodan = sub.add_parser("shodan-search", help="Search Shodan hosts")
    shodan.add_argument("query", help="Search query string")
    shodan.set_defaults(func=lambda args: as_json({
        "success": True,
        "results": ShodanClient().search_hosts(args.query, limit=100),
    }))

    # OSINT – Wigle search
    wigle = sub.add_parser("wigle-search", help="Search Wigle by SSID")
    wigle.add_argument("ssid", help="SSID string")
    wigle.set_defaults(func=lambda args: as_json({
        "success": True,
        "results": WigleClient().search_networks(args.ssid, results_per_page=100),
    }))

    return p


def main(argv: list[str] | None = None):  # pragma: no cover
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    main()
