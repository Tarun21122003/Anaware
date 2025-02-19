import psutil
import os
import time
import json
import subprocess
from datetime import datetime
import win32process
import win32con
import win32api
import win32security
import logging
import ctypes

class ProcessMonitor:
    def __init__(self):
        self.system_processes = {
            "svchost.exe", "explorer.exe", "system", "smss.exe",
            "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"
        }
        self.suspicious_locations = [
            "\\temp\\", "\\windows\\temp", "\\appdata\\local\\temp",
            "\\downloads\\", "\\public\\", "\\programdata\\temp"
        ]
        self.setup_logging()
        # Check and request admin privileges
        if not self.is_admin():
            logging.warning("Process not running with admin privileges - some features may be limited")

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _get_process_info(self, pid):
        try:
            proc = psutil.Process(pid)
            proc_info = {
                "pid": pid,
                "name": "unknown",
                "path": "unknown"
            }
            
            try:
                proc_info["name"] = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logging.debug(f"Could not get process name for PID {pid}: {e}")
                
            try:
                proc_info["path"] = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logging.debug(f"Could not get process path for PID {pid}: {e}")
                
            return proc_info
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.debug(f"Could not access process {pid}: {e}")
            return None

    def _is_process_from_suspicious_location(self, proc):
        try:
            exe_path = proc.exe().lower()
            return any(loc in exe_path for loc in self.suspicious_locations)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.debug(f"Could not check suspicious location for PID {proc.pid}: {e}")
            return False

    def _check_process_injection(self, pid):
        if not self.is_admin():
            logging.warning("Process injection detection requires admin privileges")
            return False
            
        try:
            process = psutil.Process(pid)
            suspicious_regions = 0
            try:
                for mmap in process.memory_maps(grouped=False):
                    perms = getattr(mmap, 'perms', None) or getattr(mmap, 'protection', '')
                    if isinstance(perms, str) and 'w' in perms.lower() and 'x' in perms.lower():
                        suspicious_regions += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logging.debug(f"Could not check memory maps for PID {pid}: {e}")
            return suspicious_regions > 0
        except Exception as e:
            logging.debug(f"Process injection check failed for PID {pid}: {e}")
            return False

    def _is_elevated_process(self, pid):
        try:
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION, False, pid)
            if not process_handle:
                logging.debug(f"Could not open process {pid} for elevation check")
                return False
                
            try:
                token_handle = win32security.OpenProcessToken(
                    process_handle, win32con.TOKEN_QUERY)
                if not token_handle:
                    return False
                    
                return bool(win32security.GetTokenInformation(
                    token_handle, win32security.TokenElevation))
            finally:
                win32api.CloseHandle(process_handle)
        except Exception as e:
            logging.debug(f"Elevation check failed for PID {pid}: {e}")
            return False

    def monitor_file(self, file_path, duration=60):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        initial_processes = set(psutil.pids())
        monitored_data = {
            "new_process_count": 0,
            "suspicious_location_count": 0,
            "spawned_process_names": [],
            "system_process_mimicking": 0,
            "process_injection_count": 0,
            "terminated_process_count": 0,
            "elevated_privilege_count": 0,
            "errors": []  # New field to track errors
        }

        try:
            startup_info = subprocess.STARTUPINFO()
            startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            if file_path.endswith('.py'):
                process = subprocess.Popen(['python', file_path], 
                                        startupinfo=startup_info,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                process = subprocess.Popen([file_path], 
                                        shell=True,
                                        startupinfo=startup_info,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
            
            target_pid = process.pid
            start_time = time.time()
            monitored_pids = set()

            while time.time() - start_time < duration:
                try:
                    current_processes = set(psutil.pids())
                    new_pids = current_processes - initial_processes
                    
                    for pid in new_pids:
                        if pid not in monitored_pids:
                            monitored_pids.add(pid)
                            proc_info = self._get_process_info(pid)
                            
                            if proc_info:
                                monitored_data["new_process_count"] += 1
                                monitored_data["spawned_process_names"].append(proc_info["name"])
                                
                                try:
                                    proc = psutil.Process(pid)
                                    if self._is_process_from_suspicious_location(proc):
                                        monitored_data["suspicious_location_count"] += 1
                                        
                                    if any(sys_proc in proc.name().lower() for sys_proc in self.system_processes):
                                        monitored_data["system_process_mimicking"] += 1
                                        
                                    if self._check_process_injection(pid):
                                        monitored_data["process_injection_count"] += 1
                                        
                                    if self._is_elevated_process(pid):
                                        monitored_data["elevated_privilege_count"] += 1
                                        
                                except Exception as e:
                                    error_msg = f"Error monitoring process {pid}: {str(e)}"
                                    monitored_data["errors"].append(error_msg)
                                    logging.debug(error_msg)
                    
                    terminated = initial_processes - current_processes
                    monitored_data["terminated_process_count"] += len(terminated)
                    
                    initial_processes = current_processes
                    time.sleep(0.1)
                    
                except Exception as e:
                    error_msg = f"Error in monitoring loop: {str(e)}"
                    monitored_data["errors"].append(error_msg)
                    logging.error(error_msg)
                    
            process.terminate()
            return monitored_data

        except Exception as e:
            error_msg = f"Critical error during monitoring: {str(e)}"
            monitored_data["errors"].append(error_msg)
            logging.error(error_msg)
            return monitored_data

def analyze_malware_file(file_path: str, duration: int = 5):
    """
    Analyze a potentially malicious file by monitoring its process behavior.
    
    Args:
        file_path (str): Path to the file to analyze
        duration (int): Duration in seconds to monitor the file's execution
        
    Returns:
        dict: Monitoring results including process statistics
    """
    try:
        monitor = ProcessMonitor()
        results = monitor.monitor_file(file_path, duration)
        
        # Ensure output directory exists
        output_dir = os.path.join("C:", "scripts", "results")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "MonitorProc.json")
        
        # Save results
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=4)
        
        print("\n=== Monitoring Results ===")
        print(f"1. New Processes Spawned: {results['new_process_count']}")
        print(f"2. Processes from Suspicious Locations: {results['suspicious_location_count']}")
        print(f"3. Spawned Process Names: {', '.join(results['spawned_process_names'])}")
        print(f"4. System Process Mimicking Attempts: {results['system_process_mimicking']}")
        print(f"5. Process Injection Attempts: {results['process_injection_count']}")
        print(f"6. Terminated Processes: {results['terminated_process_count']}")
        print(f"7. Processes with Elevated Privileges: {results['elevated_privilege_count']}")
        
        if results.get("errors"):
            print("\nErrors encountered during monitoring:")
            for error in results["errors"]:
                print(f"- {error}")
        
        print(f"\nResults saved to: {output_path}")
        return results
        
    except Exception as e:
        logging.error(f"Error in analyze_malware_file: {e}")
        return {
            "new_process_count": 0,
            "suspicious_location_count": 0,
            "spawned_process_names": [],
            "system_process_mimicking": 0,
            "process_injection_count": 0,
            "terminated_process_count": 0,
            "elevated_privilege_count": 0,
            "errors": [f"Critical error: {str(e)}"]
        }

if __name__ == "__main__":
    file_path = input("Enter the path to the file to monitor: ")
    duration = int(input("Enter monitoring duration in seconds: "))
    analyze_malware_file(file_path, duration)