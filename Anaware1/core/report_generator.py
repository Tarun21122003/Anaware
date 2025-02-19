import json
import random
from datetime import datetime
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt


class ReportGenerator:
    def __init__(self, scan_history_file='data/scan_history.json'):
        self.scan_history_file = scan_history_file

    def load_scan_history(self):
        """Loads scan history from a JSON file."""
        try:
            with open(self.scan_history_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return []

    def generate_system_scan_report(self, output_file='system_scan_report.pdf'):
        """Generates a system scan report in PDF format."""
        scan_history = self.load_scan_history()
        if not scan_history:
            raise ValueError("No scan history found to generate a report.")

        c = canvas.Canvas(output_file)
        c.setFont("Helvetica", 12)
        c.drawString(100, 750, "System Scan Report")
        c.drawString(100, 735, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        y = 700
        for scan in scan_history[:10]:  # Limit to 10 scans for brevity
            c.drawString(100, y, f"File: {scan['file']}")
            c.drawString(100, y - 15, f"Status: {scan['status']}")
            if scan['status'] == 'malicious':
                c.drawString(100, y - 30, f"Threat: {scan['threat_name']} (Severity: {scan['severity']})")
            y -= 50
            if y < 100:
                c.showPage()
                y = 750

        c.save()

    def generate_visual_report(self, output_file='visual_report.png'):
        """Generates a visual report as a PNG file."""
        scan_history = self.load_scan_history()
        if not scan_history:
            raise ValueError("No scan history found to generate a report.")

        severities = ['High', 'Medium', 'Low']
        severity_counts = {severity: 0 for severity in severities}
        for scan in scan_history:
            if scan.get('severity') in severities:
                severity_counts[scan['severity']] += 1

        # Plotting
        labels = list(severity_counts.keys())
        counts = list(severity_counts.values())

        plt.bar(labels, counts, color=['red', 'orange', 'yellow'])
        plt.title("Threat Severity Distribution")
        plt.xlabel("Severity")
        plt.ylabel("Count")
        plt.savefig(output_file)
        plt.close()
