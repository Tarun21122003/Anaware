import os
import json
import pefile
import ctypes
import win32api
import win32process
import win32con
import win32event
import win32security
from typing import Dict, List, Union
import psutil
import time

def monitor_malware_file(file_path: str) -> Dict[str, Union[int, float, List[str]]]:
    """
    Monitor a file for suspicious API calls, DLL injection, and file operations.
    
    Args:
        file_path: Path to the file to monitor
        
    Returns:
        Dictionary containing analysis results
    """
    
    suspicious_apis = {
        # Process manipulation
        'CreateProcessA', 'CreateProcessW', 'CreateRemoteThread', 'WriteProcessMemory',
        'VirtualAllocEx', 'SetThreadContext', 'NtQueueApcThread',
        
        # File operations
        'CreateFileA', 'CreateFileW', 'WriteFile', 'DeleteFileA', 'DeleteFileW',
        'MoveFileA', 'MoveFileW', 'SetFileAttributes',
        
        # Registry operations
        'RegCreateKeyEx', 'RegSetValueEx', 'RegDeleteKeyEx', 'RegQueryValueEx',
        
        # Network operations
        'InternetOpenUrlA', 'InternetOpenUrlW', 'WSAStartup', 'send', 'recv',
        'connect', 'HttpSendRequestA', 'HttpSendRequestW',
        
        # DLL operations
        'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'LdrLoadDll',
        'NtMapViewOfSection'
    }

    suspicious_dlls = {
        'kernel32.dll', 'ntdll.dll', 'advapi32.dll', 'shell32.dll',
        'ws2_32.dll', 'wininet.dll', 'dbghelp.dll', 'user32.dll',
        'crypt32.dll'
    }

    results = {
        "Suspicious API Calls": 0,
        "DLL Injection": 0,
        "Hooks in DLLs": 0,
        "Suspicious File Operations": 0,
        "Detected APIs": [],
        "Loaded DLLs": [],
        "Suspicious Activities": []
    }

    try:
        # Load the file with pefile if it's a PE file
        if file_path.lower().endswith(('.exe', '.dll', '.sys')):
            pe = pefile.PE(file_path)
            
            # Check for imported functions
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower()
                results["Loaded DLLs"].append(dll_name)
                
                if dll_name in suspicious_dlls:
                    results["Hooks in DLLs"] += 1
                
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode()
                        results["Detected APIs"].append(api_name)
                        
                        if api_name in suspicious_apis:
                            results["Suspicious API Calls"] += 1
                            
                            # Categorize specific types of suspicious activity
                            if api_name in {'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx'}:
                                results["DLL Injection"] += 1
                            elif api_name in {'CreateFileA', 'CreateFileW', 'WriteFile', 'DeleteFileA'}:
                                results["Suspicious File Operations"] += 1

        # If it's a Python file, try to analyze imported modules
        elif file_path.lower().endswith('.py'):
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for suspicious imports
            suspicious_py_imports = [
                'ctypes', 'win32api', 'win32process', 'subprocess',
                'os.system', 'pyinjection', 'winreg'
            ]
            
            for imp in suspicious_py_imports:
                if imp in content:
                    results["Suspicious API Calls"] += 1
                    results["Detected APIs"].append(f"Python: {imp}")
                    
                    if 'ctypes' in imp or 'win32process' in imp:
                        results["DLL Injection"] += 1
                    if 'os.system' in imp or 'subprocess' in imp:
                        results["Suspicious File Operations"] += 1

        # Save results to JSON file
        output_dir = "C:\\scripts\\results"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "APIDLL.json")
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=4)
            
        return results

    except Exception as e:
        error_results = {
            "error": f"Error analyzing file: {str(e)}",
            "Suspicious API Calls": 0,
            "DLL Injection": 0,
            "Hooks in DLLs": 0,
            "Suspicious File Operations": 0
        }
        
        # Save error results to JSON
        output_dir = "C:\\scripts\\results"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "APIDLL.json")
        
        with open(output_path, 'w') as f:
            json.dump(error_results, f, indent=4)
            
        return error_results

if __name__ == "__main__":
    # Example usage
    file_path = input("Enter the path to the file to analyze: ")
    results = monitor_malware_file(file_path)
    print("\nAnalysis Results:")
    print(json.dumps(results, indent=4))