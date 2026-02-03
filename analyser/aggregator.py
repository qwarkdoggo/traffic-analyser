from collections import defaultdict

def aggregate_by_source(alerts):
    summary = defaultdict(lambda: {
        "alerts": 0,
        "risk_score": 0,
    })

    for alert in alerts:
        src = alert.get("Source", "UNKNOWN")
        summary[src]["alerts"] += 1
        summary[src]["risk_score"] += alert.get("risk", 0)

    return summary
