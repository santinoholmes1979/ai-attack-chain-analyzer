def score_attack_chain(events):
    score = 0.0
    stages = {e.get("attack_stage") for e in events}

    if "Initial Access" in stages:
        score += 0.15
    if "Execution" in stages:
        score += 0.15
    if "Command and Control" in stages:
        score += 0.20
    if "Credential Access" in stages:
        score += 0.20
    if "Lateral Movement" in stages:
        score += 0.15
    if "Persistence" in stages:
        score += 0.15

    return round(min(score, 1.0), 2)


def confidence_label(score):
    if score >= 0.85:
        return "HIGH"
    if score >= 0.60:
        return "MEDIUM"
    return "LOW"