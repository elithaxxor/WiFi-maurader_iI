# Gather contents from the USB_Payload project directory and prepare a full source export for copy/paste
from pathlib import Path
import os

# Define the USB_Payload directory path
# Assuming it's in the current directory, modify this path as needed
usb_root = Path(os.path.dirname(os.path.abspath(__file__)))

source_code_map = {}
for file_path in usb_root.rglob("*"):
    if file_path.is_file() and file_path.suffix in {".py", ".tsx", ".sh", ".command", ".desktop", ".txt"}:
        try:
            content = file_path.read_text(encoding="utf-8")
            relative_path = file_path.relative_to(usb_root)
            source_code_map[str(relative_path)] = content
        except Exception:
            continue

source_code_map

""" 
USB_Payload directory is the same as the directory where the installer script is located. If the USB_Payload is actually in a different location, you would need to modify the path accordingly.

For example, if the USB_Payload is a subdirectory:
"""