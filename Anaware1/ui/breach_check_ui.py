import tkinter as tk
from tkinter import ttk
from core.breach_checker import BreachChecker
from ui.styles import StyleConfig as style
import webbrowser
from urllib.parse import quote

class BreachCheckUI:
    def __init__(self, parent):
        self.parent = parent
        self.create_interface()
        
    def create_interface(self):
        # Clear any existing widgets in the parent frame
        for widget in self.parent.winfo_children():
            widget.destroy()
            
        # Main container with padding
        main_container = tk.Frame(self.parent, bg=style.BG_PRIMARY, padx=40, pady=30)
        main_container.pack(fill="both", expand=True)
        
        # Header section
        header_frame = tk.Frame(main_container, bg=style.BG_PRIMARY)
        header_frame.pack(fill="x", pady=(0, 30))
        
        title = tk.Label(header_frame, 
                        text="Data Breach Check", 
                        font=(style.HEADER_FONT[0], 24, "bold"),
                        bg=style.BG_PRIMARY, 
                        fg=style.TEXT_PRIMARY)
        title.pack()
        
        subtitle = tk.Label(header_frame,
                          text="Check if your email has been compromised in data breaches",
                          font=(style.BODY_FONT[0], 12),
                          bg=style.BG_PRIMARY,
                          fg=style.TEXT_SECONDARY)
        subtitle.pack(pady=(5, 0))
        
        # Email input section
        input_frame = tk.Frame(main_container, bg=style.BG_PRIMARY)
        input_frame.pack(fill="x", pady=20)
        
        email_label = tk.Label(input_frame, 
                             text="Email Address:", 
                             font=style.BODY_FONT,
                             bg=style.BG_PRIMARY, 
                             fg=style.TEXT_SECONDARY)
        email_label.pack(anchor="w")
        
        self.email_entry = ttk.Entry(input_frame,
                                   font=style.BODY_FONT,
                                   width=40)
        self.email_entry.pack(fill="x", pady=(5, 15))
        
        # Check button
        check_btn = tk.Button(input_frame, 
                            text="Check Now", 
                            font=(style.BODY_FONT[0], 12, "bold"),
                            bg=style.ACCENT, 
                            fg="white",
                            padx=30,
                            pady=10,
                            border=0,
                            cursor="hand2",
                            command=self.check_breaches)
        check_btn.pack()
        
        # Information section
        info_frame = tk.Frame(main_container, bg=style.BG_PRIMARY)
        info_frame.pack(fill="x", pady=(30, 0))
        
        info_title = tk.Label(info_frame,
                            text="Why Check for Data Breaches?",
                            font=(style.BODY_FONT[0], 14, "bold"),
                            bg=style.BG_PRIMARY,
                            fg=style.TEXT_PRIMARY)
        info_title.pack(anchor="w")
        
        info_points = [
            "• Protect your online accounts from unauthorized access",
            "• Find out if your passwords have been compromised",
            "• Discover which services have experienced data breaches",
            "• Take immediate action to secure your accounts"
        ]
        
        for point in info_points:
            tk.Label(info_frame,
                    text=point,
                    font=style.BODY_FONT,
                    bg=style.BG_PRIMARY,
                    fg=style.TEXT_SECONDARY,
                    justify="left").pack(anchor="w", pady=5)
        
        # Footer with powered by text
        footer_frame = tk.Frame(main_container, bg=style.BG_PRIMARY)
        footer_frame.pack(fill="x", pady=(30, 0))
        
        powered_by = tk.Label(footer_frame,
                            text="Powered by HaveIBeenPwned",
                            font=(style.BODY_FONT[0], 10),
                            bg=style.BG_PRIMARY,
                            fg=style.TEXT_SECONDARY)
        powered_by.pack(side="right")
        
    def check_breaches(self):
        email = self.email_entry.get()
        if email:
            encoded_email = quote(email)
            url = f"https://haveibeenpwned.com/account/{encoded_email}"
            webbrowser.open(url)
        else:
            # Show error message if email is empty
            error_window = tk.Toplevel(self.parent.winfo_toplevel())
            error_window.title("Error")
            error_window.geometry("300x100")
            error_window.configure(bg=style.BG_PRIMARY)
            error_window.transient(self.parent.winfo_toplevel())  # Make it modal
            error_window.grab_set()  # Make it modal
            
            tk.Label(error_window,
                    text="Please enter an email address",
                    font=style.BODY_FONT,
                    bg=style.BG_PRIMARY,
                    fg=style.TEXT_PRIMARY).pack(pady=20)
            
            tk.Button(error_window,
                     text="OK",
                     command=error_window.destroy,
                     bg=style.ACCENT,
                     fg="white",
                     font=style.BODY_FONT).pack()