# first_time_setup.py
import tkinter as tk
from tkinter import ttk, filedialog
from ui.styles import StyleConfig as style
import json
import os

class FirstTimeSetup:
    def __init__(self, root):
        self.dialog = tk.Toplevel(root)
        self.dialog.title("Anaware - First Time Setup")
        self.dialog.geometry("600x500")
        self.dialog.configure(bg=style.BG_PRIMARY)
        
        # Make dialog modal
        self.dialog.transient(root)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f'{width}x{height}+{x}+{y}')
        
        self.create_widgets()
        
    def create_widgets(self):
        # Welcome message
        tk.Label(
            self.dialog,
            text="Welcome to Anaware!",
            font=(style.HEADER_FONT[0], 20, "bold"),
            bg=style.BG_PRIMARY,
            fg=style.TEXT_PRIMARY
        ).pack(pady=20)
        
        tk.Label(
            self.dialog,
            text="Please configure your VM settings to get started",
            font=style.BODY_FONT,
            bg=style.BG_PRIMARY,
            fg=style.TEXT_SECONDARY
        ).pack(pady=(0, 20))
        
        # Create main frame for inputs
        main_frame = tk.Frame(self.dialog, bg=style.BG_PRIMARY)
        main_frame.pack(padx=40, fill="both", expand=True)
        
        # VM Configuration inputs
        self.vm_inputs = {}
        fields = [
            ("VM IP Address", "host", "172.16.95.128"),
            ("VM Username", "username", "user"),
            ("VM Password", "password", "password"),
            ("Remote Directory", "remote_dir", "C:\\ReceivedFiles"),
            ("VMware Fusion Path", "vmrun_path", "/Applications/VMware Fusion.app/Contents/Library/vmrun"),
            ("Dataset Directory", "dataset_dir", os.path.expanduser("~/Desktop/DataBenign"))
        ]
        
        for label, key, default in fields:
            frame = tk.Frame(main_frame, bg=style.BG_PRIMARY)
            frame.pack(fill="x", pady=5)
            
            tk.Label(
                frame,
                text=label + ":",
                font=style.BODY_FONT,
                bg=style.BG_PRIMARY,
                fg=style.TEXT_PRIMARY
            ).pack(anchor="w")
            
            if key == "password":
                entry = ttk.Entry(frame, show="*")
            else:
                entry = ttk.Entry(frame)
            entry.insert(0, default)
            entry.pack(fill="x", pady=2)
            self.vm_inputs[key] = entry
        
        # VMX file selection
        frame = tk.Frame(main_frame, bg=style.BG_PRIMARY)
        frame.pack(fill="x", pady=5)
        tk.Label(
            frame,
            text="VM File Path (VMX):",
            font=style.BODY_FONT,
            bg=style.BG_PRIMARY,
            fg=style.TEXT_PRIMARY
        ).pack(anchor="w")
        
        vmx_frame = tk.Frame(frame, bg=style.BG_PRIMARY)
        vmx_frame.pack(fill="x", pady=2)
        
        self.vmx_entry = ttk.Entry(vmx_frame)
        self.vmx_entry.pack(side="left", fill="x", expand=True)
        
        ttk.Button(
            vmx_frame,
            text="Browse",
            command=self.browse_vmx
        ).pack(side="right", padx=5)
        
        # Save button
        tk.Button(
            self.dialog,
            text="Save and Continue",
            font=style.BODY_FONT,
            bg=style.ACCENT,
            fg="white",
            padx=30,
            pady=10,
            command=self.save_config
        ).pack(pady=30)
        
    def browse_vmx(self):
        filename = filedialog.askopenfilename(
            title="Select VMX file",
            filetypes=[("VMX files", "*.vmx"), ("All files", "*.*")]
        )
        if filename:
            self.vmx_entry.delete(0, tk.END)
            self.vmx_entry.insert(0, filename)
    
    def save_config(self):
        config = {
            'host': self.vm_inputs['host'].get(),
            'port': 22,  # Default SSH port
            'username': self.vm_inputs['username'].get(),
            'password': self.vm_inputs['password'].get(),
            'remote_dir': self.vm_inputs['remote_dir'].get(),
            'vmx_path': self.vmx_entry.get(),
            'snapshot': 'clear',  # Default snapshot name
            'vmrun_path': self.vm_inputs['vmrun_path'].get(),
            'dataset_dir': self.vm_inputs['dataset_dir'].get()
        }
        
        # Create config directory if it doesn't exist
        config_dir = os.path.expanduser('~/.anaware')
        os.makedirs(config_dir, exist_ok=True)
        
        # Save configuration
        config_path = os.path.join(config_dir, 'config.json')
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        
        self.dialog.destroy()