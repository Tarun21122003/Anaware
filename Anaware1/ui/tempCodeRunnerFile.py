import tkinter as tk
import json
import os
from core.real_time_monitoring import real_time_monitoring
from core.web_security import web_security
from core.auto_quarantine import auto_quarantine

class SettingsUI:
    def __init__(self, parent):
        self.settings_file = "settings.json"
        self.settings = self.load_settings()

        # UI Header
        tk.Label(parent, text="Settings", font=("Arial", 24), fg="white", bg="#222222").pack(pady=20)

        # Real-Time Monitoring
        self.real_time_var = tk.BooleanVar(value=self.settings.get("real_time_monitoring", False))
        real_time_cb = tk.Checkbutton(
            parent,
            text="Enable Real-Time Monitoring",
            variable=self.real_time_var,
            bg="#222222",
            fg="white",
            selectcolor="black",
            command=self.toggle_real_time_monitoring
        )
        real_time_cb.pack(pady=5)

        # Web Security
        self.web_security_var = tk.BooleanVar(value=self.settings.get("web_security", False))
        web_security_cb = tk.Checkbutton(
            parent,
            text="Enable Web Security",
            variable=self.web_security_var,
            bg="#222222",
            fg="white",
            selectcolor="black",
            command=self.toggle_web_security
        )
        web_security_cb.pack(pady=5)

        # Auto Quarantine
        self.auto_quarantine_var = tk.BooleanVar(value=self.settings.get("auto_quarantine", False))
        auto_quarantine_cb = tk.Checkbutton(
            parent,
            text="Auto Quarantine Malicious Files",
            variable=self.auto_quarantine_var,
            bg="#222222",
            fg="white",
            selectcolor="black",
            command=self.toggle_auto_quarantine
        )
        auto_quarantine_cb.pack(pady=5)

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
        except Exception as e:
            print(f"Error toggling Real-Time Monitoring: {e}")

    def toggle_web_security(self):
        """Handle Web Security toggle."""
        enable = self.web_security_var.get()
        self.settings["web_security"] = enable
        self.save_settings()
        try:
            web_security(enable)
        except Exception as e:
            print(f"Error toggling Web Security: {e}")

    def toggle_auto_quarantine(self):
        """Handle Auto Quarantine toggle."""
        enable = self.auto_quarantine_var.get()
        self.settings["auto_quarantine"] = enable
        self.save_settings()
        try:
            auto_quarantine(enable)
        except Exception as e:
            print(f"Error toggling Auto Quarantine: {e}")
