import os
import math
import re
import json
import hashlib
import collections
from pathlib import Path

class FileAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        
    def _calculate_file_hash(self):
        """Calculate SHA-256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(self.file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Error calculating file hash: {e}")
            return None

    def _extract_patterns(self):
        """Extract IPs, domains, URLs, and suspicious paths from file content"""
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
                
            # Regular expressions for pattern matching
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
            suspicious_paths = [
                r'C:\\Windows\\Temp',
                r'/tmp/',
                r'%APPDATA%',
                r'%TEMP%',
                r'System32',
                r'cmd.exe',
                r'powershell.exe'
            ]
            
            # Find matches
            ips = list(set(re.findall(ip_pattern, content)))
            domains = list(set(re.findall(domain_pattern, content)))
            urls = list(set(re.findall(url_pattern, content)))
            
            # Count suspicious paths
            suspicious_count = sum(1 for path in suspicious_paths if path.lower() in content.lower())
            
            return ips, domains, urls, suspicious_count
            
        except Exception as e:
            print(f"Error extracting patterns: {e}")
            return [], [], [], 0

    def calculate_entropy(self):
        """Calculate Shannon entropy of the file"""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
                
            if not data:
                return 0.0
                
            # Calculate frequency of each byte
            byte_counts = collections.Counter(data)
            file_size = len(data)
            
            # Calculate Shannon entropy
            entropy = 0
            for count in byte_counts.values():
                probability = count / file_size
                entropy -= probability * math.log2(probability)
                
            return round(entropy, 2)
            
        except Exception as e:
            print(f"Error calculating entropy: {e}")
            return 0.0

    def analyze_file(self):
        """Analyze file and return specified information"""
        try:
            # Get file hash
            file_hash = self._calculate_file_hash()
            
            # Extract patterns
            ips, domains, urls, suspicious_paths = self._extract_patterns()
            
            # Calculate entropy
            entropy = self.calculate_entropy()
            
            # Create result dictionary
            result = {
                'file_path': self.file_path,
                'sha256': file_hash,
                'ips': ips,
                'domains': domains,
                'urls': urls,
                'suspicious_paths_count': suspicious_paths,
                'entropy': entropy
            }
            
            return result
            
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return None

def analyze_files(files):
    """Analyze multiple files and save results to JSON"""
    results = []
    output_dir = r"C:\scripts\results"
    output_json = os.path.join(output_dir, "StaticF.json")
    
    for file_path in files:
        analyzer = FileAnalyzer(file_path)
        result = analyzer.analyze_file()
        if result:
            results.append(result)
    
    # Save results to JSON
    try:
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Save to JSON file
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {output_json}")
    except Exception as e:
        print(f"Error saving results to JSON: {e}")
    
    return results

if __name__ == "__main__":
    # Example usage
    files_to_analyze = ["sample.exe", "script.py"]
    results = analyze_files(files_to_analyze)