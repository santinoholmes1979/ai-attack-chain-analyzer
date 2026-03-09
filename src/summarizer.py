def summarize_chain(events):

    if not events:
        return "No attack chain detected."

    host = events[0].get("host")
    user = events[0].get("user")

    lines = []

    lines.append(f"Attack chain identified on host {host} involving user {user}.")
    lines.append("")
    lines.append("Observed sequence:")

    for i, e in enumerate(events, 1):

        stage = e.get("attack_stage")
        name = e.get("technique_name")
        ts = e.get("timestamp")

        lines.append(f"{i}. {ts} — {stage} — {name}")

    lines.append("")
    lines.append("Assessment: multi-stage intrusion behavior detected.")

    return "\n".join(lines)