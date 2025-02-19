#this is main_window.py

import tkinter as tk
from ui.malware_scan_ui import MalwareScanUI
from ui.report_ui import ReportUI
from ui.breach_check_ui import BreachCheckUI
from ui.settings_ui import SettingsUI
from ui.styles import StyleConfig as style
from datetime import datetime
from ui.first_time_setup import FirstTimeSetup
import os
import json
import os

class MainWindow:
    def __init__(self, root):
        self.root = root
        if not self.check_config():
            FirstTimeSetup(root)
        self.root.title("Anaware - Malware Analysis Toolkit")
        self.root.geometry("1000x600")
        self.root.configure(bg=style.BG_PRIMARY)
        
        # Initialize scan statistics
        self.scan_stats = {
            'last_scan': 'Never',
            'threats_found': 0,
            'protected_files': 0
        }
        
        # Load previous scan statistics if available
        self.load_scan_stats()
        
        # Configure grid layout
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Navigation Frame
        self.nav_frame = tk.Frame(root, bg=style.BG_SECONDARY, width=200)
        self.nav_frame.grid(row=0, column=0, sticky="nswe")
        
        # Content Frame
        self.content_frame = tk.Frame(root, bg=style.BG_PRIMARY)
        self.content_frame.grid(row=0, column=1, sticky="nswe", padx=20, pady=20)
        
        # Navigation Header
        tk.Label(
            self.nav_frame, text="ANAWARE", 
            font=style.HEADER_FONT, 
            bg=style.BG_SECONDARY, 
            fg=style.ACCENT
        ).pack(pady=40)
        
        # Navigation Buttons
        nav_buttons = [
            ("🛡️Malware Scan", self.show_malware_scan),
            ("📊Reports", self.show_report),
            ("🔓Breach Check", self.show_breach_check),
            ("⚙️Settings", self.show_settings),
        ]
        
        for text, command in nav_buttons:
            btn = tk.Button(
                self.nav_frame, 
                text=text, 
                font=style.BODY_FONT,
                bg=style.BG_SECONDARY, 
                fg=style.TEXT_PRIMARY,
                activebackground=style.ACCENT, 
                activeforeground="white",
                borderwidth=2,
                relief="solid",
                width=18,
                height=2,
                command=command, 
                anchor="w",
                padx=12
            )
            btn.pack(fill="x", pady=5, padx=8)
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=style.BORDER))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=style.BG_SECONDARY))
        
        self.show_dashboard()


    def check_config(self):
        """Check if configuration file exists"""
        config_path = os.path.expanduser('~/.anaware/config.json')
        return os.path.exists(config_path)

    def load_scan_stats(self):
        """Load saved scan statistics from file"""
        stats_file = os.path.join(os.path.dirname(__file__), 'scan_stats.json')
        try:
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    self.scan_stats = json.load(f)
        except Exception as e:
            print(f"Error loading scan stats: {e}")

    def save_scan_stats(self):
        """Save scan statistics to file"""
        stats_file = os.path.join(os.path.dirname(__file__), 'scan_stats.json')
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.scan_stats, f)
        except Exception as e:
            print(f"Error saving scan stats: {e}")

    def update_scan_stats(self, results):
        """Update scan statistics based on scan results"""
        self.scan_stats['last_scan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Count threats
        threats = sum(1 for result in results if isinstance(result, dict) 
                     and result.get('prediction') == 'malicious')
        self.scan_stats['threats_found'] = threats
        
        # Count protected files
        self.scan_stats['protected_files'] = len(results)
        
        # Save updated stats
        self.save_scan_stats()
        
        # Refresh dashboard
        self.show_dashboard()

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        self.clear_content()
        # Dashboard Header
        header_frame = tk.Frame(self.content_frame, bg=style.BG_PRIMARY)
        header_frame.pack(fill="x", pady=20)
        tk.Label(
            header_frame, text="Security Dashboard", 
            font=style.HEADER_FONT,
            bg=style.BG_PRIMARY, fg=style.TEXT_PRIMARY
        ).pack(side="left")
        
        # Status Cards
        status_frame = tk.Frame(self.content_frame, bg=style.BG_PRIMARY)
        status_frame.pack(fill="x", pady=20)
        
        # Calculate time since last scan
        if self.scan_stats['last_scan'] != 'Never':
            last_scan_time = datetime.strptime(self.scan_stats['last_scan'], '%Y-%m-%d %H:%M:%S')
            time_diff = datetime.now() - last_scan_time
            if time_diff.days > 0:
                last_scan_text = f"{time_diff.days} days ago"
            elif time_diff.seconds // 3600 > 0:
                last_scan_text = f"{time_diff.seconds // 3600} hours ago"
            else:
                last_scan_text = f"{time_diff.seconds // 60} minutes ago"
        else:
            last_scan_text = "Never"
        
        status_items = [
            ("Last Scan", last_scan_text, "🔄"),
            ("Threats Found", str(self.scan_stats['threats_found']), "⚠️"),
            ("Protected Files", str(self.scan_stats['protected_files']), "🔒")
        ]
        
        for text, value, icon in status_items:
            card = tk.Frame(status_frame, bg=style.BG_SECONDARY, padx=20, pady=10)
            card.pack(side="left", padx=10, ipadx=20, ipady=10)
            tk.Label(card, text=icon, font=("Arial", 24), bg=style.BG_SECONDARY, fg=style.ACCENT).pack()
            tk.Label(card, text=text, font=style.BODY_FONT, bg=style.BG_SECONDARY, fg=style.TEXT_SECONDARY).pack()
            tk.Label(card, text=value, font=style.TITLE_FONT, bg=style.BG_SECONDARY, fg=style.TEXT_PRIMARY).pack()

    def show_malware_scan(self):
        self.clear_content()
        scan_ui = MalwareScanUI(self.content_frame)
        # Add callback to update dashboard after scan
        scan_ui.set_scan_callback(self.update_scan_stats)
    
    def show_report(self):
        self.clear_content()
        ReportUI(self.content_frame)
    
    def show_breach_check(self):
        self.clear_content()
        BreachCheckUI(self.content_frame)
    
    def show_settings(self):
        self.clear_content()
        SettingsUI(self.content_frame)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()