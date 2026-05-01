import csv
import logging

logger = logging.getLogger(__name__)

def load_traffic(csv_path):
    packets = []

    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                logger.error(f"CSV file is empty or malformed: {csv_path}")
                return packets

            for row_num, row in enumerate(reader, start=2):
                try:
                    # Safely convert numeric fields
                    time_val = float(row.get("frame.time_relative", "0.0") or "0.0")

                    packets.append({
                        "Time": time_val,
                        "Protocol": str(row.get("_ws.col.Protocol", "")).strip(),
                        "Source": str(row.get("eth.src", "")).strip(),
                        "Destination": str(row.get("eth.dst", "")).strip(),
                        "Destination Port": str(row.get("tcp.destport", "")).strip(),
                        "Info": str(row.get("_ws.col.Info", "")).strip(),
                        "Length": str(row.get("frame.len", "")).strip(),
                    })
                except (ValueError, TypeError) as e:
                    logger.warning(f"Skipping malformed row {row_num} in {csv_path}: {e}")
                    continue

        logger.info(f"Successfully loaded {len(packets)} packets from {csv_path}")
    except FileNotFoundError:
        logger.error(f"CSV file not found: {csv_path}")
    except Exception as e:
        logger.error(f"Error reading CSV file {csv_path}: {e}")

    return packets
