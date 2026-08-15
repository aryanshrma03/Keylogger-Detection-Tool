from dataclasses import dataclass

@dataclass(frozen=True)
class TelemetryItem:
    name: str
    path: str = ""
    keyboard_hook: bool = False
    persistence: bool = False
    startup_entry: bool = False
    signed: bool | None = None

@dataclass(frozen=True)
class Finding:
    title: str
    detail: str
    weight: int

SUSPICIOUS_NAMES = {
    "keylogger.exe",
    "keylog.exe",
    "keyboardlogger.exe",
    "inputlogger.exe",
}

def analyze_item(item: TelemetryItem) -> list[Finding]:
    findings = []
    name = item.name.lower().strip()
    path = item.path.lower().replace("/", "\\")

    if name in SUSPICIOUS_NAMES:
        findings.append(Finding(
            "Suspicious process name",
            f"Process name matches a configurable keylogger indicator: {item.name}",
            30,
        ))

    user_writable = any(token in path for token in (
        "\\appdata\\roaming\\",
        "\\appdata\\local\\",
        "\\temp\\",
        "\\users\\public\\",
    ))

    if user_writable:
        findings.append(Finding(
            "User-writable execution path",
            f"Executable is located in a commonly user-writable path: {item.path}",
            15,
        ))

    if item.keyboard_hook:
        findings.append(Finding(
            "Keyboard-input telemetry indicator",
            "Telemetry reports keyboard-hook/input-monitoring behavior.",
            40,
        ))

    if item.persistence:
        findings.append(Finding(
            "Persistence indicator",
            "The item is associated with a startup/persistence mechanism.",
            25,
        ))

    if item.startup_entry:
        findings.append(Finding(
            "Startup entry",
            "The item appears in startup execution metadata.",
            20,
        ))

    if item.signed is False:
        findings.append(Finding(
            "Unsigned executable",
            "Telemetry reports that the executable is not digitally signed.",
            10,
        ))

    if item.keyboard_hook and item.persistence:
        findings.append(Finding(
            "Correlated behavior",
            "Input-monitoring telemetry and persistence are present together.",
            20,
        ))

    return findings
