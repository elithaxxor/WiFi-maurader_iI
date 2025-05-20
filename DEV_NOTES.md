# WiFi Marauder – Developer Notes

*(Generated 2025-05-19)*

---

## 1  Current Behaviour

WiFi Marauder currently provides:

1. **PySide6 GUI** with tabs
   - Dashboard, Scan, Attacks, Decoys, Logs & Analysis, etc.
2. **SQLite persistence** via `DatabaseManager` (scans, captures, deauths, anonymity logs, decoy activities).
3. **Logic modules** (not fully integrated):
   - `attack_sequence_logic.py`, `network_filter_logic.py`, `wps_vulnerability_logic.py`, `decoy_networks_logic.py`.
4. **Installer & Tutorial** – `install_tools.py` and `TUTORIAL.md`.

---

## 2  Potential Bugs / Stability Issues

| Area | Observation & Impact |
|------|----------------------|
| GUI thread-safety | Long-running subprocesses run in the main thread → UI freeze; move to `QThread`/signals. |
| MDK4 handling | Real commands not yet wired; stop logic missing. |
| Null-object imports | GUI sometimes calls methods even when module import failed. |
| Platform checks | Linux-only cmds executed on macOS; guard with `platform.system()`. |
| Path issues | Uses relative paths; prefer absolute paths based on `__file__`. |
| SQLite concurrency | Potential multi-thread writes; add locking. |
| Timer leaks | `QTimer` objects not stopped on close. |
| Decoy cleanup | File deletion without existence check can raise. |
| Import mismatch | `network_filter_manager` vs `network_filter_logic.py`. |
| Resource files | Missing `wifi_marauder.png` would crash; check existence. |

---

## 3  Feature Backlog (Impact ⟶ Effort order)

1. **Background Process Manager** – unified threaded runner for external tools.
2. **Real MDK4 Integration** – map GUI modes to actual commands.
3. **Interface Auto-Detect** – list NICs and validate monitor-mode capability.
4. **Plugin Loader** – enable/disable optional modules cleanly.
5. **Log Viewer** – rich UI for querying/exporting SQLite data.
6. **Installer UI** – detect missing tools & offer install commands.
7. **Live Channel Heatmap** – real-time 2-D visualisation.
8. **Handshake Auto-Crack Pipeline** – feed captures to aircrack/hashcat.
9. **Remote Control API** – REST/gRPC for automation.
10. **Contextual Help Tab** – embed `TUTORIAL.md` markdown viewer.
11. **Simulation Mode** – safe non-destructive mock for demos.
12. **Auto-Update Checker** – fetch GitHub releases.
13. **Unit & Integration Tests** – PyTest with mocked subprocesses.

### Quick Wins
- Rename/import consistency (`network_filter_logic` ↔ manager).
- Guard all external calls in `try/except`.  
- Use `Path` for file paths.  
- Stop timers in `closeEvent`.  
- Convert helper functions to `@staticmethod`s.

---

Integrating shodan / wiggle for OSNT evaluation . 

🕷️ SpiderFoot / Hunter.io Integration Plan

🔍 Purpose:
	•	Email/Domain Discovery from SSIDs, captive portals, or user input
	•	Subdomain Enumeration, DNS records, breach exposure
	•	Phishing Portal Intelligence: Link domains to known email leaks or targets

🧠 Used In:
	•	OSINT Graph Tab → Automatically expand:
	•	Emails
	•	Subdomains
	•	Linked services
	•	Phishing Portal Logs → Lookup victims or domains for additional context



*End of notes.*