"""Native Operating-System File Picker for NexSolve PCAP Analysis."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def open_pcap_picker() -> str | None:
    """Open native operating-system file picker for PCAP/PCAPNG capture selection.

    Uses tkinter.filedialog if available with a clean, graceful fallback to
    interactive input when running in headless, terminal-only, or non-GUI environments.

    Returns:
        Absolute file path as a string if selected, or None if cancelled by the user.
    """
    selected_path: str = ""

    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        # Keep dialog on top of the terminal window
        try:
            root.attributes("-topmost", True)
            root.update()
        except Exception:
            pass

        filetypes = [
            ("PCAP files (*.pcap;*.pcapng)", "*.pcap;*.pcapng"),
            ("All files (*.*)", "*.*"),
        ]

        raw_path = filedialog.askopenfilename(
            parent=root,
            title="Open PCAP Capture",
            filetypes=filetypes,
        )
        try:
            root.destroy()
        except Exception:
            pass

        selected_path = (raw_path or "").strip()

    except Exception as exc:
        print(f"Native file picker is unavailable: {exc}")
        try:
            user_input = input("Please enter path to PCAP or PCAPNG capture file (or press Enter to cancel): ").strip()
            # Strip potential surrounding quotes from drag-and-drop or Windows 'Copy as path'
            if (user_input.startswith('"') and user_input.endswith('"')) or (
                user_input.startswith("'") and user_input.endswith("'")
            ):
                user_input = user_input[1:-1].strip()
            selected_path = user_input
        except (EOFError, KeyboardInterrupt):
            return None

    if not selected_path:
        return None

    return str(Path(selected_path).resolve())
