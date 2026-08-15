import json
import customtkinter as ctk
from tkinter import filedialog, messagebox

from components.controls import create_controls
from components.event_log import EventLog
from components.header import create_header
from components.risk_meter import RiskMeter
from config.theme import load_theme
from collectors.processes import collect_processes
from collectors.persistence import collect_windows_persistence
from detector.engine import KeyloggerDetector
from detector.indicators import TelemetryItem
from simulator.scenarios import normal_items, suspicious_items

load_theme()

class KeyloggerDetectorApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Keylogger Detection Tool")
        self.root.geometry("1050x800")
        self.root.minsize(900, 700)

        self.detector = KeyloggerDetector()

        create_header(self.root)

        create_controls(
            self.root,
            self.system_scan,
            self.analyze_json,
            self.simulate_normal,
            self.simulate_suspicious,
            self.reset,
        )

        self.risk = RiskMeter(self.root)
        self.log = EventLog(self.root)

        self.stats = ctk.CTkLabel(
            self.root,
            text="Items: 0 | Suspicious: 0 | Findings: 0",
            text_color="#9aa4b2",
            font=("Segoe UI", 11),
        )
        self.stats.pack(anchor="w", padx=30, pady=(2, 5))

        ctk.CTkLabel(
            self.root,
            text="⚠ Detection-only: this application never records keystrokes or installs keyboard hooks.",
            text_color="#9aa4b2",
            font=("Segoe UI", 11),
        ).pack(anchor="w", padx=30, pady=(0, 18))

        self.reset()

    def system_scan(self):
        try:
            items = collect_processes()
            items.extend(collect_windows_persistence())
        except Exception as exc:
            messagebox.showerror("Scan Error", str(exc))
            return

        self._run_items(items, "SYSTEM SCAN")

    def analyze_json(self):
        path = filedialog.askopenfilename(
            title="Select Telemetry JSON",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as handle:
                records = json.load(handle)

            if not isinstance(records, list):
                raise ValueError("JSON root must be a list of telemetry objects.")

            items = [TelemetryItem(**record) for record in records]
        except Exception as exc:
            messagebox.showerror("JSON Error", str(exc))
            return

        self._run_items(items, "JSON")

    def simulate_normal(self):
        self._run_items(normal_items(), "NORMAL SIMULATION")

    def simulate_suspicious(self):
        self._run_items(suspicious_items(), "SUSPICIOUS SIMULATION")

    def _run_items(self, items, source):
        self.detector.reset()
        self.log.clear()

        if not items:
            self.log.add("[INFO] No telemetry items found.")
            self._update(self.detector.evaluate())
            return

        for item in items:
            result = self.detector.add_item(item)
            self.log.add(
                f"[{source}] {item.name} | "
                f"path={item.path or 'unknown'}"
            )

        self._update(result)

        self.log.add("")
        if result.findings:
            self.log.add(f"[ALERT] Severity: {result.severity}")
            for finding in result.findings:
                self.log.add(
                    f"  • {finding.title}: {finding.detail}"
                )
        else:
            self.log.add("[INFO] No strong keylogger indicators detected.")

    def reset(self):
        self.detector.reset()
        self.log.clear()

        result = self.detector.evaluate()
        self._update(result)

        self.log.add("[INFO] Detector reset and ready.")
        self.log.add("[INFO] Keyboard input is never captured.")

    def _update(self, result):
        self.risk.update(result)
        self.stats.configure(
            text=(
                f"Items: {result.items_analyzed} | "
                f"Suspicious: {result.suspicious_items} | "
                f"Findings: {len(result.findings)}"
            )
        )

    def run(self):
        self.root.mainloop()
