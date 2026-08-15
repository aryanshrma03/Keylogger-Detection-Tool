# ⌨️ Keylogger Detection Tool

A defensive Windows-focused security utility that detects **potential keylogger behavior** by analyzing process, persistence, and suspicious input-capture indicators.

> **Safety:** This tool is detection-only. It does not capture keystrokes, install hooks, inject code, dump credentials, or create keyloggers.

## 🎯 Detection Signals

The analyzer evaluates observable indicators such as:

- Suspicious process names
- Processes running from unusual user-writable locations
- Known persistence locations
- Startup-folder entries
- Suspicious Run/RunOnce registry entries
- Processes associated with keyboard-hook/input-monitoring behavior when supplied by telemetry
- Multiple indicators occurring together

Every finding receives an explainable risk score.

```text
0–19     NORMAL
20–39    LOW
40–59    MEDIUM
60–79    HIGH
80–100   CRITICAL
```

## 🧠 Architecture

```text
System / Telemetry Data
        │
        ▼
Process + Persistence Collector
        │
        ▼
Indicator Normalization
        │
        ▼
Detection Rules
        │
        ▼
Risk Scoring Engine
        │
        ▼
Explainable Alert Dashboard
```

## 🚀 Features

- 🔎 Suspicious process detection
- 📂 User-writable path analysis
- 🔑 Persistence indicator detection
- 🪟 Startup entry analysis
- 🧾 Safe registry Run/RunOnce inspection on Windows
- 📊 0–100 risk scoring
- 🚦 Normal / Low / Medium / High / Critical
- 🚨 Explainable findings
- 🧪 Safe simulated suspicious activity
- 📄 JSON telemetry import
- 🖥️ CustomTkinter dashboard
- 🧩 Modular architecture
- 🧪 Unit tests
- 📝 GitHub-ready documentation

## 🔒 Safety & Privacy

The application **never records actual keyboard input**.

It does not use:

- `GetAsyncKeyState`
- keyboard hooks
- `pynput` keyboard listeners
- raw keyboard capture
- clipboard capture
- credential collection

The Windows registry collector reads only persistence metadata from standard Run/RunOnce locations.

## 📂 Project Structure

```text
Keylogger-Detection-Tool/
│
├── src/
│   ├── main.py
│   ├── app/
│   │   ├── __init__.py
│   │   └── gui.py
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── indicators.py
│   │   └── engine.py
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── processes.py
│   │   └── persistence.py
│   ├── simulator/
│   │   ├── __init__.py
│   │   └── scenarios.py
│   ├── components/
│   │   ├── __init__.py
│   │   ├── header.py
│   │   ├── controls.py
│   │   ├── risk_meter.py
│   │   └── event_log.py
│   └── config/
│       ├── __init__.py
│       └── theme.py
│
├── tests/
├── .gitignore
├── requirements.txt
└── README.md
```

## 📦 Installation

```bash
git clone https://github.com/aryanshrma03/Keylogger-Detection-Tool.git
cd Keylogger-Detection-Tool

python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Install:

```bash
pip install -r requirements.txt
```

## ▶️ Run

```bash
python src/main.py
```

### Windows system scan

Use **Run System Scan** to inspect currently running processes and common Windows persistence locations.

The tool may require elevated privileges to see some process metadata.

### JSON telemetry

The tool also accepts a safe JSON representation of process/persistence telemetry.

Example:

```json
[
  {
    "name": "example.exe",
    "path": "C:\\Users\\User\\AppData\\Roaming\\example.exe",
    "keyboard_hook": true,
    "persistence": true
  }
]
```

Use **Analyze JSON** from the dashboard.

## 🧪 Safe Simulation

**Simulate Suspicious Activity** creates synthetic telemetry entirely in memory.

It does not:

- Start a process
- Create persistence
- Capture keyboard input
- Modify the registry
- Install hooks

This is included so the detection engine can be demonstrated safely without malware.

## 🔍 Detection Logic

### 1. Suspicious executable location

An executable running from a user-writable location such as:

```text
%APPDATA%
%LOCALAPPDATA%
%TEMP%
```

adds risk because malware frequently abuses these locations.

This is **not proof of malicious activity**.

### 2. Suspicious process naming

The engine can flag configurable names commonly associated with input-monitoring malware.

Names alone should never be considered conclusive.

### 3. Keyboard-hook telemetry

If trusted telemetry reports keyboard-hook behavior, the engine adds a strong signal.

The tool does **not** create or inspect keyboard hooks itself.

### 4. Persistence

A process that both has suspicious behavior and persistence receives additional risk.

### 5. Correlation

Multiple independent indicators produce a substantially higher score than any single weak signal.

## ⚠️ False Positives

Legitimate applications can resemble keylogger behavior.

Examples include:

- Accessibility software
- Password managers
- Hotkey utilities
- Gaming software
- Remote desktop software
- Macro tools
- Security software
- Input method editors

Always investigate the process publisher, signature, path, parent process, hash, and network behavior before declaring malware.

## 🔮 Future Improvements

- [ ] Authenticode signature validation
- [ ] SHA-256 reputation lookup
- [ ] Parent/child process tree
- [ ] ETW-based telemetry
- [ ] Windows Event Log integration
- [ ] Sysmon integration
- [ ] YARA rule support
- [ ] MITRE ATT&CK mapping
- [ ] SQLite investigation history
- [ ] JSON/CSV report export
- [ ] SOC-style incident timeline
- [ ] EDR telemetry ingestion

## 👨‍💻 Author

**Aryan Sharma**

Cybersecurity-focused Python project demonstrating defensive endpoint monitoring and explainable keylogger-behavior detection.
