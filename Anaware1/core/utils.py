# utils.py
import tkinter as tk
from tkinter import messagebox

def notify_user(message, notifications_text_widget=None):
    """
    Display a notification in the given Text widget and as a popup.
    """
    if notifications_text_widget:
        notifications_text_widget.config(state=tk.NORMAL)
        notifications_text_widget.insert(tk.END, f"{message}\n")
        notifications_text_widget.see(tk.END)
        notifications_text_widget.config(state=tk.DISABLED)
    messagebox.showinfo("Notification", message)
