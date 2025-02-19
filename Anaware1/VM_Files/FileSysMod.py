import os
import time
import json
import logging
import win32security
import win32file
import win32api
import win32con
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta
from typing import Set

class FileSystemMonitor(FileSystemEventHandler):
    def __init__(self, watched_paths=None):
        super().__init__()
        self.watched_paths = watched_paths or ["C:\\Windows", "C:\\Program Files", "C:\\Users"]
        
        # Define sensitive directories
        self.sensitive_directories = {
            "system32": "C:\\Windows\\System32",
            "temp": os.environ.get('TEMP'),
            "startup": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "logfiles": "C:\\Windows\\System32\\LogFiles"
        }
        
        # Define sensitive file extensions
        self.executable_extensions = {'.exe', '.dll', '.sys', '.drv', '.scr'}
        self.script_extensions = {'.ps1', '.vbs', '.js', '.bat', '.cmd'}
        self.log_extensions = {'.log', '.evt', '.evtx'}
        
        # Initialize counters
        self.activity_counts = {
            "new_file_creations": 0,
            "file_modifications": 0,
            "file_deletions": 0,
            "permission_changes": 0
        }
        
        self.previous_permissions = {}
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='file_monitor.log'
        )

    def _is_in_sensitive_directory(self, filepath: str) -> bool:
        """Check if file is in a sensitive directory."""
        filepath_lower = filepath.lower()
        return any(
            sensitive_dir.lower() in filepath_lower 
            for sensitive_dir in self.sensitive_directories.values()
        )

    def _is_sensitive_file(self, filepath: str) -> bool:
        """Check if file is sensitive based on extension and location."""
        ext = os.path.splitext(filepath)[1].lower()
        return (ext in self.executable_extensions or 
                ext in self.script_extensions or 
                self._is_in_sensitive_directory(filepath))

    def _is_log_file(self, filepath: str) -> bool:
        """Check if file is a log file."""
        ext = os.path.splitext(filepath)[1].lower()
        return (ext in self.log_extensions or 
                "\\logfiles\\" in filepath.lower())

    def on_created(self, event):
        if event.is_directory:
            return
            
        # Only count if file is created in sensitive directory or is a sensitive file type
        if self._is_in_sensitive_directory(event.src_path) or self._is_sensitive_file(event.src_path):
            self.activity_counts["new_file_creations"] += 1
            logging.warning(f"Sensitive file created: {event.src_path}")
        
        # Store initial permissions
        try:
            self.previous_permissions[event.src_path] = self._get_file_permissions(event.src_path)
        except Exception:
            pass

    def on_modified(self, event):
        if event.is_directory:
            return
            
        # Only count modifications to sensitive files or in sensitive directories
        if self._is_sensitive_file(event.src_path):
            self.activity_counts["file_modifications"] += 1
            logging.warning(f"Sensitive file modified: {event.src_path}")
        
        # Check for permission changes
        try:
            current_permissions = self._get_file_permissions(event.src_path)
            if event.src_path in self.previous_permissions:
                if self._has_dangerous_permission_change(
                    self.previous_permissions[event.src_path],
                    current_permissions,
                    event.src_path
                ):
                    self.activity_counts["permission_changes"] += 1
                    logging.warning(f"Dangerous permission change detected: {event.src_path}")
            self.previous_permissions[event.src_path] = current_permissions
        except Exception as e:
            logging.error(f"Error checking permissions: {str(e)}")

    def on_deleted(self, event):
        if event.is_directory:
            return
            
        # Count deletions of log files or sensitive files
        if self._is_log_file(event.src_path) or self._is_sensitive_file(event.src_path):
            self.activity_counts["file_deletions"] += 1
            logging.warning(f"Sensitive file deleted: {event.src_path}")
        
        self.previous_permissions.pop(event.src_path, None)

    def _get_file_permissions(self, filepath: str) -> dict:
        """Get detailed file permissions."""
        if not os.path.exists(filepath):
            return {}
            
        security_descriptor = win32security.GetFileSecurity(
            filepath, 
            win32security.OWNER_SECURITY_INFORMATION | 
            win32security.GROUP_SECURITY_INFORMATION | 
            win32security.DACL_SECURITY_INFORMATION
        )
        
        dacl = security_descriptor.GetSecurityDescriptorDacl()
        if dacl is None:
            return {}
            
        permissions = []
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            sid = ace[2]
            try:
                name, domain, type = win32security.LookupAccountSid(None, sid)
                permissions.append({
                    "trustee": f"{domain}\\{name}",
                    "access_mask": ace[1],
                    "ace_type": ace[0]
                })
            except:
                continue
                
        return permissions

    def _has_dangerous_permission_change(self, old_perms: dict, new_perms: dict, filepath: str) -> bool:
        """Check for dangerous permission changes."""
        if not old_perms or not new_perms:
            return False
            
        # Check if file became executable
        if not self._is_executable(filepath, old_perms) and self._is_executable(filepath, new_perms):
            return True
            
        # Check for "Everyone" full control
        for perm in new_perms:
            if ("everyone" in perm["trustee"].lower() and 
                perm["access_mask"] & win32con.GENERIC_ALL):
                return True
                
        return False

    def _is_executable(self, filepath: str, permissions: list) -> bool:
        """Check if file has executable permissions."""
        for perm in permissions:
            if perm["access_mask"] & win32con.FILE_EXECUTE:
                return True
        return False

def monitor_file_execution(target_file: str, duration: int = 60) -> dict:
    """Monitor system changes while executing a specific file."""
    if not os.path.exists(target_file):
        raise FileNotFoundError(f"Target file not found: {target_file}")
    
    monitor = FileSystemMonitor()
    observer = Observer()
    
    for path in monitor.watched_paths:
        if os.path.exists(path):
            observer.schedule(monitor, path, recursive=True)
    
    observer.start()
    
    try:
        subprocess.Popen([target_file], shell=True)
        time.sleep(duration)
    except Exception as e:
        logging.error(f"Error executing file {target_file}: {str(e)}")
    finally:
        observer.stop()
        observer.join()
    
    report = {
        "target_file": target_file,
        "monitoring_period": {
            "start": (datetime.now() - timedelta(seconds=duration)).isoformat(),
            "end": datetime.now().isoformat()
        },
        "activity_counts": monitor.activity_counts
    }
    
    os.makedirs("C:\\scripts\\results", exist_ok=True)
    with open('C:\\scripts\\results\\FileMod.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        report = monitor_file_execution(target_file)
        print(f"\nMonitoring Complete! Activity Counts:")
        for activity, count in report['activity_counts'].items():
            print(f"{activity.replace('_', ' ').title()}: {count}")
    else:
        print("Please provide a target file path as argument")