import requests
from scapy.all import sniff, DNS, DNSQR
import threading
import time
from core.utils import notify_user
from scapy.config import conf
conf.use_pcap = True  # Explicitly tell Scapy to use Npcap/WinPcap


VIRUSTOTAL_API_KEY = "31d3ff2faf7e0fee36de1584bddad11fd66c8c5ddedf4352d9c9908fd8b24a9f"
sniffing = False
sniff_thread = None
last_alerts = {}  # Dictionary to store the last alert timestamp for each domain
ALERT_THRESHOLD = 5  # Time threshold in seconds between alerts for the same domain

def check_virus_total(domain, notifications_text_widget=None):
    """
    Check the domain against VirusTotal's database using the API.
    """
    global last_alerts
    current_time = time.time()

    # Check if the domain was recently alerted
    if domain in last_alerts and (current_time - last_alerts[domain] < ALERT_THRESHOLD):
        return  # Skip if the alert was sent within the threshold

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if malicious > 0:
                message = f"ALERT: {domain} is flagged as MALICIOUS ({malicious} detections)"
                print(message)
                notify_user(message, notifications_text_widget)
                last_alerts[domain] = current_time  # Update the last alert timestamp
            else:
                print(f"SAFE: {domain} is not flagged as malicious.")
        else:
            print(f"Error checking {domain}: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Error checking VirusTotal for {domain}: {e}")

def process_packet(packet, notifications_text_widget=None):
    """
    Process captured DNS packets.
    """
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # qr == 0 means it's a query
        domain = packet[DNSQR].qname.decode('utf-8').strip('.')  # Extract the queried domain
        print(f"DNS Query: {domain}")
        check_virus_total(domain, notifications_text_widget)

def start_sniffing(notifications_text_widget=None):
    """
    Start sniffing DNS traffic on UDP port 53.
    """
    global sniffing
    sniffing = True
    print("🌐 Web Security Enabled. Monitoring DNS queries...")
    try:
        sniff(
            filter="udp port 53",
            prn=lambda packet: process_packet(packet, notifications_text_widget),
            store=False,
            stop_filter=lambda _: not sniffing
        )
    except Exception as e:
        print(f"Error during sniffing: {e}")

def stop_sniffing():
    """
    Stop sniffing DNS traffic.
    """
    global sniffing
    sniffing = False
    print("❌ Web Security Disabled. DNS monitoring stopped.")

def web_security(enable: bool, notifications_text_widget=None):
    global sniff_thread
    if enable:
        if sniff_thread is None or not sniff_thread.is_alive():
            sniff_thread = threading.Thread(target=start_sniffing, args=(notifications_text_widget,), daemon=True)
            sniff_thread.start()
        else:
            print("Web Security is already enabled.")
    else:
        stop_sniffing()
