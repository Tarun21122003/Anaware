import tkinter as tk
from core.report_generator import ReportGenerator

class ReportUI:
    def __init__(self, parent):
        tk.Label(parent, text="Reports", font=("Arial", 24), fg="white", bg="#222222").pack(pady=20)
        
        tk.Button(
            parent, text="View Scan History", 
            command=ReportGenerator.show_scan_history,
            bg="#4CAF50", fg="white", font=("Arial", 12)
        ).pack(pady=10)
