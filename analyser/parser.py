import csv

def load_traffic(csv_path):
    packets = []

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packets.append({
                "Protocol": row.get("_ws.col.Protocol", "").strip(),
                "Source": row.get("eth.src", "").strip(),
                "Destination": row.get("eth.dst", "").strip(),
                "Info": row.get("_ws.col.Info", "").strip(),
                "Length": row.get("frame.len", "").strip(),
            })

    return packets
