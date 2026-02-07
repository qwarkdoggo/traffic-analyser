import csv

def load_traffic(csv_path):
    packets = []

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packets.append({
                "Time": float(row.get("frame.time_relative", "0.0")),
                "Protocol": row.get("_ws.col.Protocol", "").strip(),
                "Source": row.get("eth.src", "").strip(),
                "Destination": row.get("eth.dst", "").strip(),
                "Destination Port": row.get("tcp.destport", "").strip(),
                "Info": row.get("_ws.col.Info", "").strip(),
                "Length": row.get("frame.len", "").strip(),
            })

    return packets
