#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import hashlib
import winreg
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import platform

class PersistenceDetector:
    def __init__(self):
        self.os_type = platform.system()
        self.detections = []
        self.suspicious_items = []
        
    def log_detection(self, technique: str, severity: str, location: str, details: str):
        detection = {
            "timestamp": datetime.now().isoformat(),
            "technique": technique,
            "severity": severity,
            "location": location,
            "details": details,
            "os": self.os_type
        }
        self.detections.append(detection)
        print(f"[{severity}] {technique}: {location}")
        print(f"    Details: {details}\n")
    
    def check_windows_registry(self):
        if self.os_type != "Windows":
            return
        
        print("[*] Checking Windows Registry Run Keys...")
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
        ]
        
        for hkey, subkey in run_keys:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        suspicious_indicators = [
                            "powershell", "cmd.exe", "wscript", "cscript",
                            "regsvr32", "rundll32", "mshta", "certutil",
                            "bitsadmin", "temp", "appdata", "programdata"
                        ]
                        
                        if any(ind in value.lower() for ind in suspicious_indicators):
                            self.log_detection(
                                "Registry Run Key",
                                "HIGH",
                                f"{subkey}\\{name}",
                                f"Suspicious command: {value}"
                            )
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except WindowsError:
                pass
    
    def check_windows_services(self):
        if self.os_type != "Windows":
            return
        
        print("[*] Checking Windows Services...")
        try:
            result = subprocess.run(
                ["sc", "query", "state=", "all"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            suspicious_patterns = [
                "powershell", "cmd", "encoded", "bypass",
                "downloadstring", "webclient", "iex"
            ]
            
            for line in result.stdout.lower().split('\n'):
                if any(pattern in line for pattern in suspicious_patterns):
                    self.log_detection(
                        "Suspicious Windows Service",
                        "HIGH",
                        "Windows Services",
                        f"Suspicious service detected: {line.strip()}"
                    )
        except Exception as e:
            print(f"[-] Error checking services: {e}")
    
    def check_windows_scheduled_tasks(self):
        if self.os_type != "Windows":
            return
        
        print("[*] Checking Windows Scheduled Tasks...")
        
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            task_name = ""
            for line in result.stdout.split('\n'):
                if "TaskName:" in line:
                    task_name = line.split(":", 1)[1].strip()
                elif "Task To Run:" in line:
                    command = line.split(":", 1)[1].strip().lower()
                    
                    suspicious_indicators = [
                        "powershell", "cmd", "wscript", "cscript",
                        "encoded", "bypass", "downloadstring"
                    ]
                    
                    if any(ind in command for ind in suspicious_indicators):
                        self.log_detection(
                            "Suspicious Scheduled Task",
                            "HIGH",
                            task_name,
                            f"Suspicious command: {command}"
                        )
        except Exception as e:
            print(f"[-] Error checking scheduled tasks: {e}")
    
    def check_windows_wmi(self):
        if self.os_type != "Windows":
            return
        
        print("[*] Checking WMI Event Subscriptions...")
        
        wmi_queries = [
            "SELECT * FROM __EventFilter",
            "SELECT * FROM __EventConsumer",
            "SELECT * FROM __FilterToConsumerBinding"
        ]
        
        for query in wmi_queries:
            try:
                result = subprocess.run(
                    ["wmic", "path", query.split("FROM")[1].strip(), "get", "/format:list"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.stdout.strip() and len(result.stdout) > 50:
                    self.log_detection(
                        "WMI Event Subscription",
                        "CRITICAL",
                        query,
                        "Active WMI persistence detected"
                    )
            except Exception as e:
                print(f"[-] Error checking WMI: {e}")
    
    def check_linux_cron(self):
        if self.os_type != "Linux":
            return
        
        print("[*] Checking Linux Cron Jobs...")
        
        cron_locations = [
            "/etc/crontab",
            "/etc/cron.d/",
            "/var/spool/cron/",
            "/var/spool/cron/crontabs/"
        ]
        
        for location in cron_locations:
            if os.path.exists(location):
                if os.path.isfile(location):
                    self._check_file_content(location, "Cron Job")
                else:
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            filepath = os.path.join(root, file)
                            self._check_file_content(filepath, "Cron Job")
    
    def check_linux_systemd(self):
        if self.os_type != "Linux":
            return
        
        print("[*] Checking Linux Systemd Services...")
        
        systemd_locations = [
            "/etc/systemd/system/",
            "/lib/systemd/system/",
            "/usr/lib/systemd/system/",
            "~/.config/systemd/user/"
        ]
        
        for location in systemd_locations:
            expanded_path = os.path.expanduser(location)
            if os.path.exists(expanded_path):
                for root, dirs, files in os.walk(expanded_path):
                    for file in files:
                        if file.endswith('.service'):
                            filepath = os.path.join(root, file)
                            self._check_file_content(filepath, "Systemd Service")
    
    def check_linux_rc_local(self):
        if self.os_type != "Linux":
            return
        
        print("[*] Checking RC.local...")
        
        rc_files = ["/etc/rc.local", "/etc/rc.d/rc.local"]
        
        for rc_file in rc_files:
            if os.path.exists(rc_file):
                self._check_file_content(rc_file, "RC.local Script")
    
    def check_linux_bashrc(self):
        if self.os_type != "Linux":
            return
        
        print("[*] Checking Shell Profile Files...")
        
        profile_files = [
            "~/.bashrc",
            "~/.bash_profile",
            "~/.profile",
            "~/.zshrc",
            "/etc/profile",
            "/etc/bash.bashrc"
        ]
        
        for profile in profile_files:
            expanded_path = os.path.expanduser(profile)
            if os.path.exists(expanded_path):
                self._check_file_content(expanded_path, "Shell Profile")
    
    def check_linux_ld_preload(self):
        if self.os_type != "Linux":
            return
        
        print("[*] Checking LD_PRELOAD...")
        preload_files = ["/etc/ld.so.preload", "~/.ld_preload"]
        
        for preload in preload_files:
            expanded_path = os.path.expanduser(preload)
            if os.path.exists(expanded_path):
                with open(expanded_path, 'r') as f:
                    content = f.read()
                    if content.strip():
                        self.log_detection(
                            "LD_PRELOAD Hijacking",
                            "CRITICAL",
                            expanded_path,
                            f"LD_PRELOAD configured: {content[:200]}"
                        )
    
    def _check_file_content(self, filepath: str, technique_type: str):
        suspicious_patterns = [
            "nc ", "netcat", "/dev/tcp/", "bash -i",
            "sh -i", "curl", "wget", "python -c",
            "perl -e", "base64", "eval", "exec",
            "chmod +x", "/tmp/", "downloadstring",
            "invoke-expression", "iex"
        ]
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read().lower()
                
                for pattern in suspicious_patterns:
                    if pattern in content:
                        self.log_detection(
                            f"Suspicious {technique_type}",
                            "HIGH",
                            filepath,
                            f"Suspicious pattern found: {pattern}"
                        )
                        break
        except Exception as e:
            pass
    
    def generate_yara_rules(self):
        yara_rules = """
rule APT_Persistence_Registry_RunKey
{
    meta:
        description = "Detects suspicious registry run key modifications"
        mitre_attack = "T1547.001"
    
    strings:
        $reg1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "wscript" nocase
        $encoded = "-encodedcommand" nocase
        $bypass = "-exec bypass" nocase
    
    condition:
        any of ($reg*) and any of ($cmd*) and (any of ($encoded, $bypass))
}

rule APT_Persistence_Scheduled_Task
{
    meta:
        description = "Detects suspicious scheduled task creation"
        mitre_attack = "T1053.005"
    
    strings:
        $schtasks = "schtasks" nocase
        $create = "/create" nocase
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd" nocase
        $hidden = "-windowstyle hidden" nocase
        $encoded = "-encodedcommand" nocase
    
    condition:
        $schtasks and $create and any of ($cmd*) and any of ($hidden, $encoded)
}

rule APT_Persistence_WMI_Event
{
    meta:
        description = "Detects WMI event subscription persistence"
        mitre_attack = "T1546.003"
    
    strings:
        $wmi1 = "__EventFilter" nocase
        $wmi2 = "__EventConsumer" nocase
        $wmi3 = "__FilterToConsumerBinding" nocase
        $cmd = "CommandLineEventConsumer" nocase
    
    condition:
        2 of them
}

rule APT_Persistence_Linux_Cron
{
    meta:
        description = "Detects suspicious cron job entries"
        mitre_attack = "T1053.003"
    
    strings:
        $cron = "crontab" nocase
        $rev1 = "/dev/tcp/" 
        $rev2 = "bash -i"
        $rev3 = "nc -e"
        $download1 = "curl" nocase
        $download2 = "wget" nocase
    
    condition:
        $cron and (any of ($rev*) or any of ($download*))
}
"""
        return yara_rules
    
    def generate_sigma_rules(self):
        sigma_rules = """
title: Suspicious Registry Run Key Modification
id: apt-persist-001
status: experimental
description: Detects suspicious modifications to registry run keys
references:
    - https://attack.mitre.org/techniques/T1547/001/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains:
            - '\\CurrentVersion\\Run\\'
            - '\\CurrentVersion\\RunOnce\\'
        Details|contains:
            - 'powershell'
            - 'cmd.exe'
            - 'wscript'
            - 'cscript'
    condition: selection
falsepositives:
    - Legitimate software installations
level: high
---
title: WMI Event Subscription Persistence
id: apt-persist-002
status: experimental
description: Detects WMI event subscription for persistence
references:
    - https://attack.mitre.org/techniques/T1546/003/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 20
    condition: selection
level: critical
---
title: Suspicious Scheduled Task Creation
id: apt-persist-003
status: experimental
description: Detects creation of suspicious scheduled tasks
references:
    - https://attack.mitre.org/techniques/T1053/005/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
        TaskContent|contains:
            - 'powershell'
            - '-encodedcommand'
            - '-exec bypass'
            - 'hidden'
    condition: selection
level: high
"""
        return sigma_rules
    
    def generate_edr_test_scenarios(self):
        scenarios = {
            "scenarios": [
                {
                    "name": "Registry Run Key Persistence",
                    "mitre_attack": "T1547.001",
                    "severity": "HIGH",
                    "test_command_windows": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v TestPersistence /t REG_SZ /d "powershell.exe -windowstyle hidden -c Write-Host Test" /f',
                    "cleanup_command": 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v TestPersistence /f',
                    "expected_detection": "EDR should alert on registry modification with PowerShell execution"
                },
                {
                    "name": "Scheduled Task Persistence",
                    "mitre_attack": "T1053.005",
                    "severity": "HIGH",
                    "test_command_windows": 'schtasks /create /tn "TestTask" /tr "powershell.exe -c Write-Host Test" /sc daily /st 12:00',
                    "cleanup_command": 'schtasks /delete /tn "TestTask" /f',
                    "expected_detection": "EDR should alert on scheduled task creation with PowerShell"
                },
                {
                    "name": "WMI Event Subscription",
                    "mitre_attack": "T1546.003",
                    "severity": "CRITICAL",
                    "test_command_windows": 'wmic /namespace:"\\\\root\\subscription" path __EventFilter create Name="TestFilter", EventNamespace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent"',
                    "cleanup_command": 'wmic /namespace:"\\\\root\\subscription" path __EventFilter where Name="TestFilter" delete',
                    "expected_detection": "EDR should alert on WMI event subscription creation"
                },
                {
                    "name": "Linux Cron Job Persistence",
                    "mitre_attack": "T1053.003",
                    "severity": "HIGH",
                    "test_command_linux": 'echo "* * * * * /bin/bash -c \'echo test\'" | crontab -',
                    "cleanup_command": 'crontab -r',
                    "expected_detection": "EDR should alert on crontab modification"
                },
                {
                    "name": "Linux Systemd Service",
                    "mitre_attack": "T1543.002",
                    "severity": "HIGH",
                    "test_command_linux": 'echo -e "[Service]\\nExecStart=/bin/bash -c \'echo test\'\\n[Install]\\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/test.service',
                    "cleanup_command": 'sudo rm /etc/systemd/system/test.service',
                    "expected_detection": "EDR should alert on new systemd service creation"
                },
                {
                    "name": "Linux .bashrc Modification",
                    "mitre_attack": "T1546.004",
                    "severity": "MEDIUM",
                    "test_command_linux": 'echo "# Test persistence" >> ~/.bashrc',
                    "cleanup_command": 'sed -i \'/# Test persistence/d\' ~/.bashrc',
                    "expected_detection": "EDR should monitor shell profile modifications"
                }
            ]
        }
        return json.dumps(scenarios, indent=2)
    
    def run_full_scan(self):
        print("=" * 70)
        print("APT Persistence Detection Framework")
        print(f"Operating System: {self.os_type}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        print()
        
        if self.os_type == "Windows":
            self.check_windows_registry()
            self.check_windows_services()
            self.check_windows_scheduled_tasks()
            self.check_windows_wmi()
        elif self.os_type == "Linux":
            self.check_linux_cron()
            self.check_linux_systemd()
            self.check_linux_rc_local()
            self.check_linux_bashrc()
            self.check_linux_ld_preload()
        
        print("=" * 70)
        print(f"Scan Complete: {len(self.detections)} detections found")
        print("=" * 70)
        
        return self.detections
    
    def export_report(self, filename: str = "persistence_report.json"):
        """Raporu JSON olarak export et"""
        report = {
            "scan_time": datetime.now().isoformat(),
            "operating_system": self.os_type,
            "total_detections": len(self.detections),
            "detections": self.detections,
            "yara_rules": self.generate_yara_rules(),
            "sigma_rules": self.generate_sigma_rules(),
            "edr_test_scenarios": json.loads(self.generate_edr_test_scenarios())
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nReport exported to: {filename}")
        return filename


def main():
    print("""apt persistence detector or smth idk""")
    
    detector = PersistenceDetector()
    detections = detector.run_full_scan()
    detector.export_report()
    
    with open("apt_persistence_yara.yar", 'w') as f:
        f.write(detector.generate_yara_rules())
    print("YARA rules saved to: apt_persistence_yara.yar")
    
    with open("apt_persistence_sigma.yml", 'w') as f:
        f.write(detector.generate_sigma_rules())
    print("Sigma rules saved to: apt_persistence_sigma.yml")
    
    with open("edr_test_scenarios.json", 'w') as f:
        f.write(detector.generate_edr_test_scenarios())
    print("EDR test scenarios saved to: edr_test_scenarios.json")
    
    print(f"\nTotal findings: {len(detections)}")
    
    severity_count = {}
    for detection in detections:
        sev = detection['severity']
        severity_count[sev] = severity_count.get(sev, 0) + 1
    
    print("\nSeverity Summary:")
    for severity, count in severity_count.items():
        print(f"    {severity}: {count}")


if __name__ == "__main__":
    main()
