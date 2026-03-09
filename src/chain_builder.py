from datetime import datetime


def build_attack_chain(events):

    return sorted(
        events,
        key=lambda e: datetime.fromisoformat(e["timestamp"])
    )