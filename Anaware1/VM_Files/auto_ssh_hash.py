import os
import paramiko
import time
import sys
import logging
import shutil
import json
from pathlib import Path
from datetime import datetime

# Import analysis functions
from StaticF import analyze_files
from APIDLL import monitor_malware_file
from MonitorProc import analyze_malware_file
from FileSysMod import monitor_file_execution
from RegChange import analyze_file
from NetTraff import monitor_file

# Configure logging
logging.basicConfig(
    filename='C:/scripts/malware_analysis_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configuration
MAC_IP = "172.18.35.15"
MAC_USER = "tarun"
MAC_PASSWORD = "yoyo54321"
WATCH_DIR = Path("C:/ReceivedFiles")
PROCESSED_DIR = WATCH_DIR / "Processed"
RESULTS_DIR = Path("C:/scripts/results")  # Changed to lowercase 'results' to match Mac expectations

def setup_directories():
    """Ensure required directories exist."""
    print(f"Setting up directories...")
    for directory in [WATCH_DIR, PROCESSED_DIR, RESULTS_DIR]:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"Directory exists or created: {directory}")
        except Exception as e:
            print(f"ERROR creating directory {directory}: {e}")
            logging.error(f"Directory creation error: {e}")
            raise

def get_absolute_file_path(file_path):
    """Convert file path to absolute Windows path."""
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    # Ensure the path is absolute
    if not file_path.is_absolute():
        file_path = WATCH_DIR / file_path
    
    # Convert to Windows-style path
    abs_path = str(file_path.resolve())
    # Ensure Windows-style path separators
    abs_path = abs_path.replace('/', '\\')
    
    print(f"Resolved absolute path: {abs_path}")
    return abs_path

def save_json_results(filename, data):
    """Save analysis results to JSON file."""
    output_path = RESULTS_DIR / filename
    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Results saved to {output_path}")
    except Exception as e:
        print(f"Error saving results to {output_path}: {e}")
        logging.error(f"Failed to save results: {e}")

def analyze_malware(file_path):
    """Run all analysis functions on the malware file."""
    try:
        print(f"\nAnalyzing file: {file_path}")
        
        # Get the absolute path
        abs_file_path = get_absolute_file_path(file_path)
        print(f"Using absolute path for analysis: {abs_file_path}")
        
        # Verify file exists before analysis
        if not os.path.exists(abs_file_path):
            raise FileNotFoundError(f"File not found: {abs_file_path}")
        
        # Create results directory if it doesn't exist
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Dictionary to store all results
        results = {}
        
        # Run all analysis functions with absolute path
        try:
            print("Running network traffic analysis...")
            network_results = monitor_file(abs_file_path, duration=10, interface="Ethernet")
            save_json_results("NetTraff.json", network_results)
            results['network'] = network_results
        except Exception as e:
            print(f"Network analysis failed: {e}")
            logging.error(f"Network analysis error: {e}")
        
        try:
            print("Running API/DLL analysis...")
            api_results = monitor_malware_file(abs_file_path)
            save_json_results("APIDLL.json", api_results)
            results['api_dll'] = api_results
        except Exception as e:
            print(f"API/DLL analysis failed: {e}")
            logging.error(f"API/DLL analysis error: {e}")
        
        try:
            print("Running static analysis...")
            static_results = analyze_files([abs_file_path])
            save_json_results("StaticF.json", static_results)
            results['static'] = static_results
        except Exception as e:
            print(f"Static analysis failed: {e}")
            logging.error(f"Static analysis error: {e}")
        
        try:
            print("Running process analysis...")
            process_results = analyze_malware_file(abs_file_path, 10)
            save_json_results("MonitorProc.json", process_results)
            results['process'] = process_results
        except Exception as e:
            print(f"Process analysis failed: {e}")
            logging.error(f"Process analysis error: {e}")
        
        try:
            print("Running registry analysis...")
            registry_results = analyze_file(abs_file_path)
            save_json_results("RegMod.json", registry_results)
            results['registry'] = registry_results
        except Exception as e:
            print(f"Registry analysis failed: {e}")
            logging.error(f"Registry analysis error: {e}")
        
        try:
            print("Running file system analysis...")
            filesystem_results = monitor_file_execution(abs_file_path, duration=10)
            save_json_results("FileMod.json", filesystem_results)
            results['filesystem'] = filesystem_results
        except Exception as e:
            print(f"File system analysis failed: {e}")
            logging.error(f"File system analysis error: {e}")
        
        return True
        
    except Exception as e:
        print(f"ERROR during analysis: {e}")
        logging.error(f"Analysis error: {e}")
        return False

def move_to_processed(file_path):
    """Move file to processed directory with proper error handling."""
    try:
        # Ensure the processed directory exists
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename if file already exists
        processed_path = PROCESSED_DIR / file_path.name
        if processed_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            processed_path = PROCESSED_DIR / f"{file_path.stem}_{timestamp}{file_path.suffix}"
        
        # Use shutil.move instead of Path.rename for cross-device moves
        shutil.move(str(file_path), str(processed_path))
        print(f"Successfully moved file to: {processed_path}")
        logging.info(f"File moved to processed directory: {processed_path}")
        return True
        
    except Exception as e:
        print(f"ERROR moving file to processed directory: {e}")
        logging.error(f"Failed to move file {file_path}: {e}")
        return False

def send_results_to_mac():
    """Send all analysis results back to Mac."""
    print("\nAttempting to send results to Mac...")
    
    result_files = [
        "APIDLL.json",
        "FileMod.json",
        "MonitorProc.json",
        "NetTraff.json",
        "RegMod.json",
        "StaticF.json"
    ]
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print("Connecting to Mac via SSH...")
        ssh.connect(MAC_IP, username=MAC_USER, password=MAC_PASSWORD, timeout=10)
        print("SSH connection established")
        
        with ssh.open_sftp() as sftp:
            for filename in result_files:
                local_path = RESULTS_DIR / filename
                remote_path = f"/Users/{MAC_USER}/Desktop/Dataset/{filename}"
                
                if local_path.exists():
                    print(f"Transferring {filename} to Mac...")
                    sftp.put(str(local_path), remote_path)
                    print(f"Transferred {filename} successfully")
                else:
                    print(f"Warning: {filename} not found")
            
        logging.info("All analysis results sent successfully")
        print("Results successfully sent to Mac")
        
    except Exception as e:
        print(f"ERROR sending results to Mac: {e}")
        logging.error(f"Failed to send results: {e}")
        raise
    finally:
        ssh.close()
        print("SSH connection closed")

def process_new_files():
    """Process any new files in the watch directory, ignoring .DS_Store files."""
    print(f"\nChecking for new files in {WATCH_DIR}")
    try:
        # Filter out .DS_Store files
        files = [f for f in WATCH_DIR.iterdir() if f.is_file() and f.name != '.DS_Store']
        
        if not files:
            print("No new files found")
            return False

        print(f"Found {len(files)} files to process")
        
        for file_path in files:
            print(f"\nProcessing {file_path.name}")
            
            # Verify file exists and is accessible
            if not file_path.exists():
                print(f"File no longer exists: {file_path}")
                continue
                
            if not os.access(str(file_path), os.R_OK):
                print(f"No read access to file: {file_path}")
                continue
            
            # Run analysis
            if analyze_malware(file_path):
                # Wait for all analysis to complete
                time.sleep(5)
                
                # Send results to Mac
                send_results_to_mac()
                
                # Move processed file
                if not move_to_processed(file_path):
                    print(f"Failed to move file {file_path} to processed directory")
                    continue
            
        return True
        
    except Exception as e:
        print(f"ERROR processing files: {e}")
        logging.error(f"Error processing files: {e}")
        return False

def main():
    """Main monitoring loop."""
    print("\n=== Starting Windows Malware Analysis Monitor ===")
    setup_directories()
    logging.info("Starting file monitor...")
    print("Monitoring for new files...")
    
    while True:
        try:
            if process_new_files():
                print("\nProcessed new batch of files successfully")
                print("Waiting for next batch...")
            time.sleep(5)
        except Exception as e:
            print(f"ERROR in monitor loop: {e}")
            logging.error(f"Monitor loop error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()

