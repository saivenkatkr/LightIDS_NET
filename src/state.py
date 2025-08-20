from collections import Counter, defaultdict

class IDSState:
    def __init__(self):
        self.total_packets = 0
        self.alert_counts = Counter()
        self.top_talkers = Counter()

    def inc_packets(self):
        self.total_packets += 1

    def count_alert(self, rule, src=None):
        self.alert_counts[rule] += 1
        if src:
            self.top_talkers[src] += 1

    def summary(self):
        return {
            "total_packets": self.total_packets,
            "alert_counts": dict(self.alert_counts),
            "top_talkers": self.top_talkers.most_common(10)
        }
