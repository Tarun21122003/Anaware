import os
import json
import time
import winreg
import logging
import subprocess
from collections import defaultdict

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('regmod.log'),
        logging.StreamHandler()
    ]
)

def get_registry_snapshot():
    """
    Takes a snapshot of specific registry keys and their values.
    Returns a dictionary containing registry values from specified paths.
    """
    snapshot = defaultdict(dict)
    
    def scan_registry(key_path, hive=winreg.HKEY_LOCAL_MACHINE):
        """
        Scans a specific registry key and returns its values.
        
        Args:
            key_path (str): Registry path to scan
            hive (int): Registry hive constant (HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER)
            
        Returns:
            list: List of tuples containing (name, value) pairs
        """
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                values = []
                try:
                    i = 0
                    while True:
                        name, value, _ = winreg.EnumValue(key, i)
                        values.append((name, value))
                        i += 1
                except WindowsError:
                    pass
                return values
        except WindowsError as e:
            logging.error(f"Error scanning registry path {key_path}: {str(e)}")
            return []

    # Registry paths to monitor
    REG_PATHS = {
        'HKEY_LOCAL_MACHINE': {
            'startup': [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            ],
            'services': [r"System\CurrentControlSet\Services"],
            'defender': [r"Software\Microsoft\Windows Defender"],
        },
        'HKEY_CURRENT_USER': {
            'startup': [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            ]
        }
    }

    # Scan HKEY_LOCAL_MACHINE paths
    for category, paths in REG_PATHS['HKEY_LOCAL_MACHINE'].items():
        for path in paths:
            full_path = f"HKEY_LOCAL_MACHINE\\{path}"
            values = scan_registry(path, winreg.HKEY_LOCAL_MACHINE)
            if values:
                snapshot[full_path] = dict(values)

    # Scan HKEY_CURRENT_USER paths
    for category, paths in REG_PATHS['HKEY_CURRENT_USER'].items():
        for path in paths:
            full_path = f"HKEY_CURRENT_USER\\{path}"
            values = scan_registry(path, winreg.HKEY_CURRENT_USER)
            if values:
                snapshot[full_path] = dict(values)

    return snapshot

def get_scheduled_tasks():
    """
    Retrieves all scheduled tasks in the system.
    
    Returns:
        str: Output from schtasks command
    """
    try:
        result = subprocess.run(
            ['schtasks', '/query', '/fo', 'LIST', '/v'], 
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            logging.error(f"Error getting tasks: {result.stderr}")
            return ""
        return result.stdout
    except subprocess.TimeoutExpired:
        logging.error("Timeout while getting scheduled tasks")
        return ""
    except Exception as e:
        logging.error(f"Error in get_scheduled_tasks: {str(e)}")
        return ""

def parse_tasks(task_output):
    """
    Parses the scheduled tasks output into a structured format.
    
    Args:
        task_output (str): Raw output from schtasks command
        
    Returns:
        list: List of dictionaries containing task details
    """
    tasks = []
    current_task = {}
    
    for line in task_output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                current_task[key] = value
        elif not line.strip() and current_task:
            if 'TaskName' in current_task:
                tasks.append(current_task)
            current_task = {}
            
    if current_task and 'TaskName' in current_task:
        tasks.append(current_task)
        
    return tasks

def detect_security_changes(report):
    """
    Analyzes changes for security-related modifications.
    
    Args:
        report (dict): Change report from compare_snapshots
        
    Returns:
        int: Number of security-related changes detected
    """
    security_changes = 0
    security_services = {
        "WinDefend", "SecurityHealthService", "wscsvc", "WdNisSvc",
        "Sense", "MpsSvc", "EventLog", "WerSvc"
    }
    
    for key, changes in report['registry_changes'].items():
        if 'services' in key.lower():
            for change_type in ['modified', 'removed']:
                if change_type in changes:
                    for service in changes[change_type]:
                        if any(sec_svc in service for sec_svc in security_services):
                            security_changes += 1
                            logging.warning(f"Security service affected: {service}")
    
    return security_changes

def detect_suspicious(report):
    """
    Analyzes changes for suspicious modifications.
    
    Args:
        report (dict): Change report from compare_snapshots
        
    Returns:
        int: Number of suspicious changes detected
    """
    suspicious_count = 0
    suspicious_commands = {'powershell', 'cmd.exe', 'rundll32', 'regsvr32'}
    
    # Check registry changes
    for key, changes in report['registry_changes'].items():
        if 'defender' in key.lower() or 'security' in key.lower():
            suspicious_count += 1
            logging.warning(f"Suspicious registry key modified: {key}")
        
        for change_type in ['added', 'modified']:
            if change_type in changes:
                for name, value in changes[change_type].items():
                    if isinstance(value, str):
                        value_lower = value.lower()
                        if any(ext in value_lower for ext in ['.exe', '.dll', '.ps1', '.bat', '.cmd']):
                            suspicious_count += 1
                            logging.warning(f"Suspicious value added/modified: {name} = {value}")
    
    # Check task changes
    for task in report['task_changes'].get('added', []):
        cmd = task.get('Task to Run', '').lower()
        if any(c in cmd for c in suspicious_commands):
            suspicious_count += 1
            logging.warning(f"Suspicious task added: {task.get('TaskName', 'Unknown')} - {cmd}")
            
    return suspicious_count

def take_snapshot():
    """
    Takes a complete snapshot of the system state.
    
    Returns:
        dict: System snapshot including registry and scheduled tasks
    """
    logging.info("Taking system snapshot...")
    reg_snap = get_registry_snapshot()
    logging.info(f"Captured {sum(len(v) for v in reg_snap.values())} registry values")
    
    tasks = get_scheduled_tasks()
    parsed_tasks = parse_tasks(tasks)
    logging.info(f"Captured {len(parsed_tasks)} scheduled tasks")
    
    return {
        'registry': reg_snap,
        'tasks': tasks
    }

def compare_snapshots(before, after):
    """
    Compares two system snapshots and identifies changes.
    
    Args:
        before (dict): Initial system snapshot
        after (dict): Post-execution system snapshot
        
    Returns:
        dict: Detailed report of changes
    """
    report = {
        'registry_changes': defaultdict(dict),
        'task_changes': {},
    }

    # Compare registry
    all_keys = set(before['registry'].keys()) | set(after['registry'].keys())
    for key in all_keys:
        before_vals = before['registry'].get(key, {})
        after_vals = after['registry'].get(key, {})
        
        logging.debug(f"\nAnalyzing key: {key}")
        logging.debug(f"Before values: {before_vals}")
        logging.debug(f"After values: {after_vals}")
        
        added = set(after_vals.keys()) - set(before_vals.keys())
        removed = set(before_vals.keys()) - set(after_vals.keys())
        modified = {k for k in before_vals.keys() & after_vals.keys() 
                   if before_vals[k] != after_vals[k]}
        
        changes = defaultdict(dict)
        if added:
            changes['added'] = {k: after_vals[k] for k in added}
            logging.info(f"Added values in {key}: {changes['added']}")
        if removed:
            changes['removed'] = {k: before_vals[k] for k in removed}
            logging.info(f"Removed values in {key}: {changes['removed']}")
        if modified:
            changes['modified'] = {k: after_vals[k] for k in modified}
            logging.info(f"Modified values in {key}: {changes['modified']}")
        
        if changes:
            report['registry_changes'][key] = dict(changes)

    # Compare tasks
    before_tasks = parse_tasks(before['tasks'])
    after_tasks = parse_tasks(after['tasks'])
    
    before_task_names = {t.get('TaskName', ''): t for t in before_tasks}
    after_task_names = {t.get('TaskName', ''): t for t in after_tasks}
    
    added_tasks = [t for name, t in after_task_names.items() 
                  if name and name not in before_task_names]
    removed_tasks = [t for name, t in before_task_names.items() 
                    if name and name not in after_task_names]
    
    if added_tasks or removed_tasks:
        report['task_changes'] = {
            'added': added_tasks,
            'removed': removed_tasks
        }

    return report

def analyze_file(file_path, results_file="RegMod.json", directory="C:\\scripts\\results"):
    """
    Analyzes a file and records system changes.
    
    Args:
        file_path (str): Path to the file to analyze
        results_file (str): Name of the output JSON file
        directory (str): Directory to save results
        
    Returns:
        dict: Analysis report
    """
    try:
        os.makedirs(directory, exist_ok=True)
        full_path = os.path.join(directory, results_file)
        
        logging.info("\n=== Starting Analysis ===")
        logging.info(f"Target file: {file_path}")
        
        # Take initial snapshot
        before = take_snapshot()
        time.sleep(2)
        
        logging.info(f"\nExecuting file: {file_path}")
        
        # Execute the file
        if file_path.lower().endswith('.py'):
            subprocess.run(['python', file_path], check=True)
        else:
            subprocess.run(file_path, shell=True, check=True)
        
        time.sleep(2)
        
        logging.info("\nTaking post-execution snapshot...")
        after = take_snapshot()
        
        logging.info("\nAnalyzing changes...")
        changes = compare_snapshots(before, after)
        
        # Calculate metrics
        registry_changes = sum(
            len(mods.get(change_type, {}))
            for key, mods in changes['registry_changes'].items()
            for change_type in ['added', 'modified', 'removed']
        )
        
        report = {
            'registry_changes': registry_changes,
            'scheduled_task_changes': len(changes['task_changes'].get('added', [])) + 
                                    len(changes['task_changes'].get('removed', [])),
            'suspicious_changes': detect_suspicious(changes),
            'security_processes_affected': detect_security_changes(changes),
            'detailed_changes': changes
        }
        
        # Save results
        with open(full_path, 'w') as f:
            json.dump(report, f, indent=4)
        
        logging.info(f"\nResults saved to {full_path}")
        return report
        
    except Exception as e:
        logging.error(f"Error during analysis: {str(e)}")
        raise

def main():
    """Main entry point for the script."""
    import sys
    if len(sys.argv) > 1:
        file_to_analyze = sys.argv[1]
        try:
            report = analyze_file(file_to_analyze)
            logging.info("\n=== Analysis Summary ===")
            logging.info(f"Registry Changes: {report['registry_changes']}")
            logging.info(f"Task Changes: {report['scheduled_task_changes']}")
            logging.info(f"Suspicious Changes: {report['suspicious_changes']}")
            logging.info(f"Security Processes Affected: {report['security_processes_affected']}")
        except Exception as e:
            logging.error(f"Analysis failed: {str(e)}")
            sys.exit(1)
    else:
        logging.error("Please provide a file path to analyze")
        logging.error("Usage: python regmod.py <file_path>")
        sys.exit(1)

if __name__ == "__main__":
    main()