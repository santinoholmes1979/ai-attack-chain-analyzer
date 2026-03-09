def normalize_event(event):

    return {
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "user": event.get("user"),
        "event_type": event.get("event_type"),
        "process_name": event.get("process_name"),
        "command_line": event.get("command_line"),
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get("destination_ip"),
        "severity": event.get("severity"),
        "attack_stage": event.get("attack_stage"),
        "technique_id": event.get("technique_id"),
        "technique_name": event.get("technique_name")
    }


def normalize_events(events):

    return [normalize_event(e) for e in events]