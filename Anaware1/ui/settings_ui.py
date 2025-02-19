import tkinter as tk
import json
import os
from ui.styles import StyleConfig as style
from core.real_time_monitoring import real_time_monitoring
from core.web_security import web_security
from core.auto_quarantine import auto_quarantine
from core.utils import notify_user

class SettingsUI:
    def __init__(self, parent):
        self.parent = parent
        self.settings_file = "settings.json"
        self.settings = self.load_settings()
        self.create_interface()

    def create_interface(self):
        # Header
        header_frame = tk.Frame(self.parent, bg=style.BG_PRIMARY)
        header_frame.pack(fill="x", pady=20)
        tk.Label(header_frame, text="Settings", font=style.HEADER_FONT,
                 bg=style.BG_PRIMARY, fg=style.TEXT_PRIMARY).pack(side="left")

        # Settings Container
        container = tk.Frame(self.parent, bg=style.BG_PRIMARY)
        container.pack(fill="both", expand=True, padx=50)

        # Security Settings Section
        security_frame = tk.LabelFrame(container, text=" Security Settings ", font=style.TITLE_FONT,
                                       bg=style.BG_SECONDARY, fg=style.ACCENT, padx=20, pady=20)
        security_frame.pack(fill="x", pady=10)

        # Security Setting Toggles (Backend-Connected)
        self.real_time_var = tk.BooleanVar(value=self.settings.get("real_time_monitoring", False))
        self.web_security_var = tk.BooleanVar(value=self.settings.get("web_security", False))
        self.auto_quarantine_var = tk.BooleanVar(value=self.settings.get("auto_quarantine", False))

        self.create_setting_switch(security_frame, "Real-Time Monitoring", "Protect against threats in real-time",
                                   self.real_time_var, self.toggle_real_time_monitoring)
        self.create_setting_switch(security_frame, "Web Security", "Block malicious websites",
                                   self.web_security_var, self.toggle_web_security)
        self.create_setting_switch(security_frame, "Auto Quarantine", "Automatically isolate threats",
                                   self.auto_quarantine_var, self.toggle_auto_quarantine)

        # Update Section
        update_frame = tk.LabelFrame(container, text=" Updates ", font=style.TITLE_FONT,
                                     bg=style.BG_SECONDARY, fg=style.ACCENT, padx=20, pady=20)
        update_frame.pack(fill="x", pady=10)

        tk.Label(update_frame, text="Database Version: 2024.1", font=style.BODY_FONT,
                 bg=style.BG_SECONDARY, fg=style.TEXT_SECONDARY).pack(anchor="w")

        tk.Button(update_frame, text="Check for Updates", font=style.BODY_FONT,
                  bg=style.ACCENT, fg="white").pack(pady=10)

    def create_setting_switch(self, parent, text, description, var, command):
        """Creates a toggle switch for settings."""
        frame = tk.Frame(parent, bg=style.BG_SECONDARY)
        frame.pack(fill="x", pady=5)

        cb = tk.Checkbutton(frame, text=text, variable=var, font=style.TITLE_FONT,
                            bg=style.BG_SECONDARY, fg=style.TEXT_PRIMARY,
                            selectcolor=style.ACCENT, command=command)
        cb.pack(side="left", anchor="w")

        tk.Label(frame, text=description, font=style.BODY_FONT,
                 bg=style.BG_SECONDARY, fg=style.TEXT_SECONDARY).pack(side="left", padx=20)

    def load_settings(self):
        """Load settings from a JSON file."""
        if os.path.exists(self.settings_file):
            with open(self.settings_file, "r") as f:
                return json.load(f)
        return {}

    def save_settings(self):
        """Save current settings to a JSON file."""
        with open(self.settings_file, "w") as f:
            json.dump(self.settings, f, indent=4)

    def toggle_real_time_monitoring(self):
        """Handle Real-Time Monitoring toggle."""
        enable = self.real_time_var.get()
        self.settings["real_time_monitoring"] = enable
        self.save_settings()
        try:
            real_time_monitoring(enable)
            status = "enabled" if enable else "disabled"
            notify_user(f"Real-Time Monitoring {status}.")
        except Exception as e:
            notify_user(f"Error toggling Real-Time Monitoring: {e}")

    def toggle_web_security(self):
        """Handle Web Security toggle."""
        enable = self.web_security_var.get()
        self.settings["web_security"] = enable
        self.save_settings()
        try:
            web_security(enable)
        except Exception as e:
            notify_user(f"Error toggling Web Security: {e}")

    def toggle_auto_quarantine(self):
        """Handle Auto Quarantine toggle."""
        enable = self.auto_quarantine_var.get()
        self.settings["auto_quarantine"] = enable
        self.save_settings()
        try:
            auto_quarantine(enable)
            status = "enabled" if enable else "disabled"
            notify_user(f"Auto Quarantine {status}.")
        except Exception as e:
            notify_user(f"Error toggling Auto Quarantine: {e}")
