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
