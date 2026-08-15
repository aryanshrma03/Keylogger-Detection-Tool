from detector.indicators import TelemetryItem

def collect_processes():
    """Collect passive process metadata using psutil.

    This collector does not read keyboard input or install hooks.
    """
    import psutil

    items = []

    for process in psutil.process_iter(["name", "exe"]):
        try:
            info = process.info
            name = info.get("name") or "unknown"
            path = info.get("exe") or ""

            items.append(
                TelemetryItem(
                    name=name,
                    path=path,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return items
