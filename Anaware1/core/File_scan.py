#this is my previous scan_file.py you have to tell me what changes i need to make in this file so that it can extract vm informations from the first_time_setup.py


import paramiko
import subprocess
import time
import logging
import os
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
import joblib

# Configure logging
logging.basicConfig(
    filename=os.path.expanduser('~/vm_controller.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class VMController:
    def __init__(self):
        # Load configuration from config file
        self.vm_config = self.load_config()

        
        # Ensure dataset directory exists
        Path(self.vm_config['dataset_dir']).mkdir(parents=True, exist_ok=True)
        
        print("\nVM Controller initialized with configuration:")
        print(f"Host: {self.vm_config['host']}")
        print(f"Remote directory: {self.vm_config['remote_dir']}")
        print(f"VMX path: {self.vm_config['vmx_path']}")
        print(f"Dataset directory: {self.vm_config['dataset_dir']}")

    def load_config(self):
        """Load configuration from the config file created by first_time_setup.py"""
        config_path = os.path.join(os.environ['LOCALAPPDATA'], 'Anaware', 'config.json')
        try:
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"Configuration file not found at {config_path}")
            
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Validate required configuration fields
            required_fields = ['host', 'port', 'username', 'password', 'remote_dir', 
                            'vmx_path', 'snapshot', 'vmrun_path', 'dataset_dir']
            
            for field in required_fields:
                if field not in config:
                    raise ValueError(f"Missing required configuration field: {field}")
            
            return config
            
        except Exception as e:
            print(f"ERROR loading configuration: {e}")
            logging.error(f"Configuration loading failed: {str(e)}")
            raise

    def run_vmware_command(self, command, *args):
        """Execute VMware command with provided arguments."""
        print(f"\nExecuting VMware command: {command}")
        cmd = [self.vm_config['vmrun_path'], '-T', 'ws', command, self.vm_config['vmx_path']] + list(args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                print(f"Command failed with return code {result.returncode}")
                print(f"Error output: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
            return result.stdout
        except Exception as e:
            print(f"ERROR executing VMware command: {e}")
            logging.error(f"VMware command failed: {str(e)}")
            raise

    def is_vm_running(self):
        """Check if VM is currently running."""
        try:
            result = subprocess.run(
                [self.vm_config['vmrun_path'], '-T', 'ws', 'list'],
                capture_output=True, text=True, check=False
            )
            return self.vm_config['vmx_path'] in result.stdout
        except Exception as e:
            print(f"ERROR checking VM status: {e}")
            logging.error(f"Error checking VM status: {str(e)}")
            return False

    def manage_vm_state(self):
        """Ensure VM is running without unnecessary restarts."""
        print("\nChecking VM state...")
        try:
            if not os.path.exists(self.vm_config['vmx_path']):
                raise FileNotFoundError(f"VMX file not found at {self.vm_config['vmx_path']}")

            # Check if VM is running
            if self.is_vm_running():
                print("VM is already running, proceeding with file processing...")
                return

            # Start VM only if it's not running
            print("Starting VM...")
            self.run_vmware_command('start')
            time.sleep(10)

            # Check for snapshot only when starting fresh
            snapshots = self.run_vmware_command('listSnapshots')
            if self.vm_config['snapshot'] not in snapshots:
                print("Creating clean snapshot...")
                self.run_vmware_command('snapshot', self.vm_config['snapshot'])

        except Exception as e:
            print(f"ERROR in manage_vm_state: {e}")
            logging.error(f"Error in manage_vm_state: {str(e)}")
            raise

    def wait_for_ssh(self, retries=15, delay=10):
        """Wait for SSH connection to become available."""
        print("\nWaiting for SSH connection...")
        for attempt in range(retries):
            try:
                with paramiko.SSHClient() as ssh:
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(
                        self.vm_config['host'],
                        port=self.vm_config['port'],
                        username=self.vm_config['username'],
                        password=self.vm_config['password'],
                        timeout=10
                    )
                print("SSH connection successful")
                return True
            except Exception as e:
                print(f"SSH attempt {attempt + 1} failed: {e}")
                time.sleep(delay)
        return False

    def create_results_folder(self, file_path):
        """Create folder structure for file results."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = Path(file_path).stem
        folder_path = Path(self.vm_config['dataset_dir']) / f"{filename}_{timestamp}"
        folder_path.mkdir(parents=True, exist_ok=True)
        return folder_path

    def upload_file(self, file_path):
        """Upload single file to Windows VM."""
        print(f"\nUploading file: {file_path}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(
                self.vm_config['host'],
                port=self.vm_config['port'],
                username=self.vm_config['username'],
                password=self.vm_config['password']
            )

            with ssh.open_sftp() as sftp:
                remote_dir = self.vm_config['remote_dir'].replace('\\', '/')
                try:
                    sftp.stat(remote_dir)
                except FileNotFoundError:
                    ssh.exec_command(f'mkdir "{self.vm_config["remote_dir"]}"')

                remote_path = f"{remote_dir}\\{Path(file_path).name}"
                sftp.put(str(file_path), remote_path)
                print(f"File uploaded successfully: {Path(file_path).name}")
                
        finally:
            ssh.close()

    def collect_results(self, results_folder):
        """Collect analysis results from Windows VM."""
        print("\nCollecting analysis results...")
        
        # Define expected result files and their folders
        result_files = {
            "APIDLL.json": "api_dll_analysis",
            "FileMod.json": "filesystem_analysis",
            "MonitorProc.json": "process_analysis",
            "NetTraff.json": "network_analysis",
            "StaticF.json": "static_file_analysis"
        }

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(
                self.vm_config['host'],
                port=22,
                username=self.vm_config['username'],
                password=self.vm_config['password']
            )

            with ssh.open_sftp() as sftp:
                # Create all subfolders
                for subfolder in set(result_files.values()):
                    (results_folder / subfolder).mkdir(exist_ok=True)

                # Check if results directory exists
                remote_results_dir = 'C:/scripts/results'
                try:
                    sftp.stat(remote_results_dir)
                except FileNotFoundError:
                    print(f"Results directory {remote_results_dir} not found")
                    return False

                # Wait for and collect analysis files
                files_collected = False
                for filename, subfolder in result_files.items():
                    remote_path = f"{remote_results_dir}/{filename}"
                    local_path = results_folder / subfolder / filename
                    
                    try:
                        print(f"Checking for {filename}...")
                        sftp.stat(remote_path)
                        print(f"Found {filename}, retrieving...")
                        sftp.get(remote_path, str(local_path))
                        print(f"Saved {filename}")
                        files_collected = True
                    except FileNotFoundError:
                        print(f"{filename} not yet available...")
                    except Exception as e:
                        print(f"Error retrieving {filename}: {e}")
                        logging.error(f"Failed to retrieve {filename}: {e}")

                return files_collected

        except Exception as e:
            print(f"ERROR collecting results: {e}")
            logging.error(f"Results collection failed: {e}")
            return False
        finally:
            ssh.close()

    def wait_for_results(self, file_path, timeout=300):
        """Wait for analysis completion and collect results."""
        results_folder = self.create_results_folder(file_path)
        
        # Add a 60-second initial delay to give VM time to generate all JSON files
        print("\nWaiting 60 seconds for analysis to complete...")
        time.sleep(60)
        
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            print(f"\nChecking for results... (Time elapsed: {int(time.time() - start_time)}s)")
            try:
                if self.collect_results(results_folder):
                    print(f"Results successfully collected and saved to: {results_folder}")
                    return results_folder
                else:
                    print("No results available yet, waiting 10 seconds...")
                    time.sleep(10)
            except Exception as e:
                print(f"Error while collecting results: {e}")
                if (time.time() - start_time) >= timeout:
                    raise TimeoutError(f"Analysis timeout after {timeout} seconds")
                time.sleep(10)
        
        raise TimeoutError(f"Analysis timeout after {timeout} seconds")

    def revert_vm(self):
        """Revert VM to clean snapshot."""
        print("\nReverting VM to clean snapshot...")
        try:
            if self.is_vm_running():
                self.run_vmware_command('stop', 'hard')
            time.sleep(2)
            self.run_vmware_command('revertToSnapshot', self.vm_config['snapshot'])
            print("VM reverted to clean snapshot")
        except Exception as e:
            print(f"ERROR reverting VM: {e}")
            logging.error(f"Error reverting VM: {str(e)}")
            raise

    def process_file(self, file_path):
        """Process a single file through the analysis pipeline."""
        try:
            print(f"\n=== Processing file: {file_path} ===")
            
            # Only manage VM state if necessary
            if not self.is_vm_running():
                self.manage_vm_state()
            
            if not self.wait_for_ssh():
                raise Exception("VM not responding to SSH")

            self.upload_file(file_path)
            results_folder = self.wait_for_results(file_path)
            
            # Extract features and predict
            features_df, additional_info = extract_features(results_folder)
            prediction, confidence = predict(features_df)
            
            # Revert VM
            self.revert_vm()
            
            return {
                'prediction': prediction,
                'confidence': confidence,
                'features': features_df.to_dict('records')[0],
                'additional_info': additional_info
            }

        except Exception as e:
            print(f"ERROR processing file {file_path}: {e}")
            return {'error': str(e)}

def extract_features(results_folder):
    """Extract features from JSON files and return DataFrame"""
    features = {
        'Suspicious API Calls': 0,
        'DLL Injection': 0,
        'Hooks in DLLs': 0,
        'Suspicious File Operations': 0,
        'new_file_creations': 0,
        'file_modifications': 0,
        'file_deletions': 0,
        'permission_changes': 0,
        'unusual_ports_count': 0,
        'number_of_unique_ips': 0,
        'number_of_unique_domains': 0,
        'protocol_anomalies_count': 0,
        'new_process_count': 0,
        'suspicious_location_count': 0,
        'system_process_mimicking': 0,
        'process_injection_count': 0,
        'terminated_process_count': 0,
        'elevated_privilege_count': 0,
        'suspicious_paths_count': 0,
        'entropy': 0.0
    }
    
    additional_info = {}
    
    try:
        # APIDLL.json
        with open(results_folder/'api_dll_analysis/APIDLL.json') as f:
            data = json.load(f)
            features.update({k: data.get(k, 0) for k in features if k in data})
            additional_info['Detected APIs'] = data.get('Detected APIs', [])
            additional_info['Loaded DLLs'] = data.get('Loaded DLLs', [])
        
        # FileMod.json
        with open(results_folder/'filesystem_analysis/FileMod.json') as f:
            data = json.load(f)
            counts = data.get('activity_counts', {})
            features.update({
                'new_file_creations': counts.get('new_file_creations', 0),
                'file_modifications': counts.get('file_modifications', 0),
                'file_deletions': counts.get('file_deletions', 0),
                'permission_changes': counts.get('permission_changes', 0)
            })
        
        # NetTraff.json
        with open(results_folder/'network_analysis/NetTraff.json') as f:
            data = json.load(f)
            summary = data.get('summary', {})
            features.update({
                'unusual_ports_count': summary.get('unusual_ports_count', 0),
                'number_of_unique_ips': len(summary.get('unique_ips', [])),
                'number_of_unique_domains': len(summary.get('unique_domains', [])),
                'protocol_anomalies_count': summary.get('protocol_anomalies_count', 0)
            })
            additional_info['Network IPs'] = summary.get('unique_ips', [])
            additional_info['Network Domains'] = summary.get('unique_domains', [])
        
        # MonitorProc.json
        with open(results_folder/'process_analysis/MonitorProc.json') as f:
            data = json.load(f)
            features.update({k: data.get(k, 0) for k in features if k in data})
            additional_info['Processes'] = data.get('spawned_process_names', [])
        
        # StaticF.json
        with open(results_folder/'static_file_analysis/StaticF.json') as f:
            data = json.load(f)
            if data and isinstance(data, list):
                static = data[0]
                features.update({
                    'suspicious_paths_count': static.get('suspicious_paths_count', 0),
                    'entropy': static.get('entropy', 0.0)
                })
        
        return pd.DataFrame([features]), additional_info
    
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return pd.DataFrame([features]), additional_info

def predict(file_features):
    """Predict using the XGBoost model."""
    model = joblib.load('/Users/tarun/Desktop/Shared/Anaware/core/xgboost_model.pkl')
    encoder = joblib.load('/Users/tarun/Desktop/Shared/Anaware/core/label_encoder.pkl')
    pred = model.predict(file_features)
    proba = model.predict_proba(file_features)
    return encoder.inverse_transform(pred)[0], proba[0][pred[0]]

def analyze_directory(directory_path):
    """Analyze all files in a directory, ignoring .DS_Store files."""
    print(f"\n=== Starting analysis for directory: {directory_path} ===")
    
    try:
        vm = VMController()  # This will now load config from file
        
        directory = Path(directory_path)
        if not directory.exists():
            print(f"ERROR: Directory {directory_path} does not exist")
            return "Error: Directory not found"

        results = []

        # Filter out .DS_Store files and only include regular files
        files = [f for f in directory.iterdir() if f.is_file() and f.name != '.DS_Store']
        total_files = len(files)
        
        print(f"Found {total_files} files to process (excluding .DS_Store)")
        
        for index, file_path in enumerate(files, 1):
            print(f"\nProcessing file {index}/{total_files}: {file_path.name}")
            result = vm.process_file(file_path)
            result['file'] = file_path.name  # Add filename to result
            results.append(result)
        
        return results
        
    except Exception as e:
        print(f"ERROR in analyze_directory: {e}")
        logging.error(f"Directory analysis failed: {str(e)}")
        return [{'error': str(e)}]

if __name__ == "__main__":
    directory = "/Users/tarun/Desktop/Windows OS"
    results = analyze_directory(directory)
    
    print("\nAnalysis Summary:")
    for result in results:
        print(f"{result['file']}: {result['prediction']} ({result['confidence']*100:.2f}% confidence)")