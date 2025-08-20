import os, json, csv
from datetime import datetime, timezone

class AlertLogger:
    def __init__(self, log_dir, log_format="jsonl"):
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d")
        self.log_format = log_format.lower()
        self.jsonl_path = os.path.join(log_dir, f"alerts_{ts}.jsonl")
        self.csv_path = os.path.join(log_dir, f"alerts_{ts}.csv")
        self.csv_headers = ["ts","rule","src_ip","dst_ip","extra"]

    @staticmethod
    def _ts():
        return datetime.now(timezone.utc).isoformat()

    def log(self, rule, src_ip=None, dst_ip=None, **extra):
        record = {"ts": self._ts(), "rule": rule, "src_ip": src_ip, "dst_ip": dst_ip, "extra": extra}
        # console
        print(f"[ALERT] {record['ts']} | {rule} | src={src_ip} dst={dst_ip} | {extra}")
        # persist
        if self.log_format == "csv":
            write_header = not os.path.exists(self.csv_path)
            with open(self.csv_path, "a", newline='', encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=self.csv_headers)
                if write_header:
                    w.writeheader()
                w.writerow(record)
        else:
            with open(self.jsonl_path, "a", encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
