def reason_about_chain(events):

    stages = {e.get("attack_stage") for e in events}
    event_types = {e.get("event_type") for e in events}

    findings = []
    threat_model = "Suspicious multi-stage intrusion activity."

    if "phishing_link_click" in event_types and "powershell_execution" in event_types:
        findings.append("Phishing likely led to script-based execution on the endpoint.")
        threat_model = "Phishing-initiated intrusion."

    if "c2_beaconing" in event_types:
        findings.append("Command-and-control behavior suggests external attacker communication.")

    if "credential_dump_attempt" in event_types:
        findings.append("Credential access activity indicates possible theft of local or domain credentials.")

    if "lateral_movement_attempt" in event_types:
        findings.append("Lateral movement behavior suggests the attacker attempted to expand access.")

    if "runkey_persistence" in event_types:
        findings.append("Persistence activity suggests the attacker attempted to survive reboot or logon events.")

    if {"Initial Access", "Execution", "Credential Access", "Lateral Movement"}.issubset(stages):
        threat_model = "Phishing-based intrusion progressing toward credential theft and lateral movement."

    return {
        "threat_model": threat_model,
        "findings": findings
    }