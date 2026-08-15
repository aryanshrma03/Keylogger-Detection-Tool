from detector.indicators import TelemetryItem

RUN_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)

def collect_windows_persistence():
    """Read standard Windows Run/RunOnce metadata.

    This is read-only and does not modify persistence settings.
    """
    import os

    if os.name != "nt":
        return []

    import winreg

    items = []

    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for subkey in RUN_KEYS:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    count = winreg.QueryInfoKey(key)[1]

                    for index in range(count):
                        name, value, _ = winreg.EnumValue(key, index)
                        value_text = str(value)

                        items.append(
                            TelemetryItem(
                                name=name or "registry-startup-item",
                                path=value_text,
                                persistence=True,
                                startup_entry=True,
                            )
                        )
            except (FileNotFoundError, PermissionError, OSError):
                continue

    return items
