# Gather contents from the USB_Payload project directory and prepare a full source export for copy/paste
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
