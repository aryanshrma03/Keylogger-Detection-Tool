from detector.indicators import TelemetryItem

def normal_items():
    return [
        TelemetryItem(
            name="explorer.exe",
            path=r"C:\Windows\explorer.exe",
            signed=True,
        ),
        TelemetryItem(
            name="example-helper.exe",
            path=r"C:\Program Files\ExampleApp\example-helper.exe",
            signed=True,
        ),
    ]

def suspicious_items():
    # Synthetic telemetry only. No process is created and no persistence is changed.
    return [
        TelemetryItem(
            name="keylogger.exe",
            path=r"C:\Users\User\AppData\Roaming\keylogger.exe",
            keyboard_hook=True,
            persistence=True,
            startup_entry=True,
            signed=False,
        ),
        TelemetryItem(
            name="input-monitor.exe",
            path=r"C:\Users\User\AppData\Local\input-monitor.exe",
            keyboard_hook=True,
            persistence=True,
            signed=False,
        ),
    ]
