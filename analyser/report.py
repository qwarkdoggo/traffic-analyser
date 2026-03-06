import os
import json
from datetime import datetime
from aggregator import aggregate_by_source

def save_report(alerts, output_path):
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_alerts": len(alerts),
        "total_risk": sum(a.get("risk", 0) for a in alerts),
        "by_source": aggregate_by_source(alerts),
        "alerts": alerts,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    _secure_file(output_path)


def _secure_file(path):
    """Try to apply restrictive permissions to a file.

    On POSIX this sets mode 0o600. On Windows the call may fail silently but
    it at least attempts to clear write/read access for other users.
    """
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def format_alerts_table(alerts):
    if not alerts:
        return "No alerts to display."

    columns = []
    for alert in alerts:
        for key in alert.keys():
            if key not in columns:
                columns.append(key)

    widths = {col: len(col) for col in columns}
    for alert in alerts:
        for col in columns:
            val = str(alert.get(col, ""))
            widths[col] = max(widths[col], len(val))

    header = " | ".join(col.ljust(widths[col]) for col in columns)
    sep = "-+-".join("-" * widths[col] for col in columns)
    rows = [header, sep]

    for alert in alerts:
        row = " | ".join(str(alert.get(col, "")).ljust(widths[col]) for col in columns)
        rows.append(row)

    summary = [
        f"Total alerts: {len(alerts)}",
    ]

    return "\n".join(summary + [""] + rows)
