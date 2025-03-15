import os
import time
import pickle
import tkinter as tk
from tkinter import filedialog, ttk
from typing import List, Dict
from datetime import datetime
from flask import Flask, render_template, request, send_file, redirect, url_for, Response
import tempfile

app = Flask(__name__, static_folder="../static", template_folder="../templates")

class KeywordVulnerabilityDetector:
    def __init__(self):
        self.model_path = 'svm_model.pkl'

        self.malicious_keywords = {
            'All Files': {
                'cmd.exe': 3, 'powershell': 3, 'base64': 2, 'wget': 2, 'curl': 2, 'exec': 3, 'system': 3,
                'rundll32': 3, 'schtasks': 3, 'taskkill': 3, 'reg add': 3, 'reg delete': 3, 'sc start': 2,
                'bypass': 2, 'payload': 3, 'keylogger': 3, 'trojan': 3, 'ransomware': 3, 'malware': 3,
                'exploit': 3, 'phishing': 3, 'backdoor': 3, 'adware': 2, 'spyware': 3, 'rootkit': 3,
                'echo off': 1, 'del /F /Q': 3, 'shutdown -s -t 0': 3, 'taskkill /IM': 3, 'net user': 2,
                'regedit': 3, 'wmic': 2, 'bitsadmin': 3, 'bcdedit': 3, 'attrib -h -r -s': 2,
                'cipher /w': 3, 'format C:': 3, 'del /s /q': 3, '<script>alert': 2, '<iframe src': 2, 
                '<meta http-equiv': 2, '<object type': 2, 'document.write': 2, 'setTimeout eval': 3, 
                '<img src onerror': 3, 'eval atob': 3, 'window.location.replace': 2, '/JS exportDataObject': 3, 
                '/OpenAction getURL': 3, '/AA /S /JS': 3, 'Launch /Action': 3, 'JavaScript /Action': 3, 
                'PDF-Exploit': 3, 'PDF Payload': 3, 'JS Injection': 3, 'kernel32.dll': 3, 'CreateRemoteThread': 3, 
                'WriteProcessMemory': 3, 'VirtualAlloc': 3, 'VirtualProtect': 3, 'NtQueryInformationProcess': 3, 
                'ZwMapViewOfSection': 3, 'LoadLibrary': 3, 'GetProcAddress': 3, 'IsDebuggerPresent': 3, 
                'FindWindow': 3, 'SetWindowsHookEx': 3, 'GetAsyncKeyState': 3, 'OpenProcess': 3, 
                'TerminateProcess': 3, 'eval String.fromCharCode': 3, 'window.location.href': 3, 
                'document.cookie': 3, 'fetch': 2, 'XMLHttpRequest open': 3, 'self.location javascript': 3,
                'window.open': 2, 'new ActiveXObject': 3, 'onerror alert': 2
            }
        }
        # Create logs directory if it doesn't exist
        self.logs_dir = "vulnerability_logs"
        os.makedirs(self.logs_dir, exist_ok=True)

    def count_keywords(self):
        """Count keywords by severity level"""
        severity_counts = {1: 0, 2: 0, 3: 0}
        total_count = 0
        
        # Count all keywords and their severity levels
        for keyword, severity in self.malicious_keywords['All Files'].items():
            severity_counts[severity] += 1
            total_count += 1

    def find_vulnerabilities(self, script_path: str) -> List[Dict]:
        vulnerabilities = []
        try:
            with open(script_path, 'r', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

                for line_num, line in enumerate(lines, 1):
                    line_lower = line.lower()

                    for keyword, severity in self.malicious_keywords['All Files'].items():
                        if keyword.lower() in line_lower:
                            vulnerabilities.append({
                                'line_number': line_num,
                                'line_content': line.strip(),
                                'keyword_found': keyword,
                                'severity': severity
                            })
        except Exception as e:
            print(f"Error analyzing script file: {e}")
            
        time.sleep(10)
        return vulnerabilities

    def get_security_status(self, vulnerabilities: List[Dict]) -> str:
        result = "\n" + "="*80 + "\n"
        result += "SECURITY STATUS CHECK\n"
        result += "="*80 + "\n"

        if len(vulnerabilities) == 0:
            result += "\n🟢 STATUS: SECURE\n"
            result += "No vulnerabilities were detected in this file.\n"
        else:
            severity = "🟡 Low" if 1 <= len(vulnerabilities) <= 5 else "🟠 Medium" if 6 <= len(vulnerabilities) <= 10 else "🔴 High"
            result += f"\n🔴 STATUS: VULNERABLE\n"
            result += f"Found {len(vulnerabilities)} potential security issues!\n"
            result += f"Overall Severity: {severity}\n"

        result += "="*80 + "\n"
        return result

    def get_vulnerability_report(self, script_path: str, vulnerabilities: List[Dict]) -> str:
        result = self.get_security_status(vulnerabilities)

        if vulnerabilities:
            result += "\nDETAILED VULNERABILITY REPORT\n"
            result += "="*80 + "\n"
            result += f"Analyzed File: {script_path}\n"
            result += f"Total Vulnerabilities Found: {len(vulnerabilities)}\n"

            result += "-"*60 + "\n"
            for i, vuln in enumerate(vulnerabilities, 1):
                result += f"\n{i}. Line {vuln['line_number']}:\n"
                result += f"   Malicious Keyword: '{vuln['keyword_found']}'\n"
                result += f"   Line Content: {vuln['line_content']}\n"
                result += f"   Severity Level: {vuln['severity']}\n"

        result += "\n" + "="*80 + "\n"
        return result

    def print_vulnerability_report(self, script_path: str, vulnerabilities: List[Dict]) -> None:
        report = self.get_vulnerability_report(script_path, vulnerabilities)
        print(report)
        return report

    def analyze_script(self, script_path: str) -> str:
        print(f"Starting analysis of: {script_path}")

        if not os.path.exists(script_path):
            message = f"Error: File not found: {script_path}"
            print(message)
            return message

        vulnerabilities = self.find_vulnerabilities(script_path)
        report = self.print_vulnerability_report(script_path, vulnerabilities)
        
        # Generate log file with filename and timestamp
        file_name = os.path.basename(script_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file_name = f"{file_name}_{timestamp}.log"
        log_path = os.path.join(self.logs_dir, log_file_name)
        
        # Save the report to the log file using UTF-8 encoding
        try:
            with open(log_path, 'w', encoding='utf-8') as log_file:
                log_file.write(f"Vulnerability Scan Report\n")
                log_file.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"Scanned File: {file_name}\n\n")
                log_file.write(report)
            
            print(f"\nScan results saved to log file: {log_path}")
        except Exception as e:
            print(f"Error writing to log file: {e}")
            
            # Fallback to ASCII-compatible version if UTF-8 fails
            try:
                ascii_report = report.encode('ascii', 'replace').decode('ascii')
                with open(log_path, 'w') as log_file:
                    log_file.write(f"Vulnerability Scan Report\n")
                    log_file.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    log_file.write(f"Scanned File: {file_name}\n\n")
                    log_file.write(ascii_report)
                print(f"\nScan results (ASCII version) saved to log file: {log_path}")
            except Exception as e2:
                print(f"Error writing ASCII log file: {e2}")
        
        return report, log_path

# Flask routes
@app.route('/')
def index():
    return render_template('vul.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return {"error": "No file part"}, 400
    
    file = request.files['file']
    if file.filename == '':
        return {"error": "No selected file"}, 400
    
    # Create temp file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1])
    file.save(temp_file.name)
    temp_file.close()
    
    detector = KeywordVulnerabilityDetector()
    report, log_path = detector.analyze_script(temp_file.name)
    
    # Delete temp file
    os.unlink(temp_file.name)
    
    return {"report": report.replace("\n", "<br>"), "log_path": log_path}


@app.route('/download/<path:filename>')
def download_file(filename):
    # Filename is expected to be a relative path within the logs directory
    log_path = os.path.join(os.path.dirname(__file__), 'vulnerability_logs', os.path.basename(filename))
    if os.path.exists(log_path):
        return send_file(log_path, as_attachment=True)
    else:
        return "File not found", 404

@app.route('/api/placeholder/<int:width>/<int:height>')
def placeholder_image(width, height):
    """Serve the folder.png image resized to requested dimensions."""
    from PIL import Image
    from io import BytesIO
    import os
    
    # Path to your folder.png image
    folder_image_path = os.path.join(app.static_folder, 'images', 'folder.png')
    
    # Check if file exists and log the absolute path for debugging
    if not os.path.exists(folder_image_path):
        print(f"Error: Image file not found at {os.path.abspath(folder_image_path)}")
        # Create a fallback image if original not found
        img = Image.new('RGB', (width, height), color=(200, 200, 200))
    else:
        try:
            # Open and resize the image
            img = Image.open(folder_image_path)
            img = img.resize((width, height), Image.LANCZOS)
            print(f"Successfully loaded image from {folder_image_path}")
        except Exception as e:
            print(f"Error processing image: {e}")
            # Create a fallback image if there was an error
            img = Image.new('RGB', (width, height), color=(255, 0, 0))
    
    # Save the resized image to a bytes buffer
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    # Return the image with the appropriate MIME type
    return send_file(img_io, mimetype='image/png')

if __name__ == "__main__":
    app.run(port=5001, debug=True)