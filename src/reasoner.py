def reason_about_chain(events):
    stages = {e.get("attack_stage") for e in events}
    event_types = {e.get("event_type") for e in events}

    findings = []
    threat_model = "Suspicious multi-stage intrusion activity."
    scenario_type = "generic"
    likely_objective = "Unknown attacker objective."
    likely_impact = "Potential security impact requires analyst review."
    recommended_response = "Review affected host activity and validate suspicious events."

    # Phishing / intrusion logic
    if "phishing_link_click" in event_types and "powershell_execution" in event_types:
        findings.append("Phishing likely led to script-based execution on the endpoint.")
        threat_model = "Phishing-initiated intrusion."
        scenario_type = "phishing_intrusion"
        likely_objective = "Establish initial foothold and execute attacker-controlled code."
        likely_impact = "User endpoint compromise with potential follow-on attacker actions."
        recommended_response = "Isolate the host, review email artifacts, and validate user exposure."

    if "malicious_attachment_opened" in event_types and "powershell_execution" in event_types:
        findings.append("A malicious attachment likely triggered script-based execution.")
        threat_model = "Malware delivery sequence consistent with ransomware precursor activity."
        scenario_type = "ransomware_precursor"
        likely_objective = "Establish malware execution and prepare for broader disruption or encryption."
        likely_impact = "Potential ransomware staging with risk to host and adjacent systems."
        recommended_response = "Contain the endpoint immediately, review persistence, and hunt for related activity."

    if "c2_beaconing" in event_types:
        findings.append("Command-and-control behavior suggests external attacker communication.")

    if "credential_dump_attempt" in event_types:
        findings.append("Credential access activity indicates possible theft of local or domain credentials.")
        if scenario_type == "generic":
            scenario_type = "credential_theft"
            likely_objective = "Harvest credentials to expand access."
            likely_impact = "Credential compromise with potential privilege escalation or lateral movement."
            recommended_response = "Reset affected credentials, review authentication logs, and isolate the host if needed."

    if "lateral_movement_attempt" in event_types:
        findings.append("Lateral movement behavior suggests the attacker attempted to expand access.")

    if "runkey_persistence" in event_types:
        findings.append("Persistence activity suggests the attacker attempted to survive reboot or logon events.")

    # Insider misuse logic
    if "bulk_file_access" in event_types:
        findings.append("Bulk file access may indicate suspicious data collection activity.")
        scenario_type = "insider_misuse"
        likely_objective = "Collect sensitive internal information."
        likely_impact = "Unauthorized access to potentially sensitive data."
        recommended_response = "Review user access patterns, validate business need, and preserve logs."

    if "archive_creation" in event_types:
        findings.append("Archive creation suggests possible staging of collected data.")
        scenario_type = "insider_misuse"
        likely_objective = "Stage data for transfer or concealment."
        likely_impact = "Potential data loss or policy violation."
        recommended_response = "Review file archive contents, monitor outbound transfer activity, and notify security leadership."

    if "cloud_upload" in event_types:
        findings.append("Cloud upload activity may indicate data exfiltration over a web service.")
        scenario_type = "insider_misuse"
        likely_objective = "Exfiltrate internal data to an external service."
        likely_impact = "Potential data breach or unauthorized disclosure."
        recommended_response = "Investigate the destination service, preserve evidence, and consider account restriction."

    # Scenario-specific threat models
    if scenario_type == "insider_misuse":
        threat_model = "Potential insider misuse involving collection, staging, and possible exfiltration of data."

    elif scenario_type == "ransomware_precursor":
        threat_model = "Likely ransomware precursor activity involving malicious document execution, external communication, and persistence."

    elif scenario_type == "credential_theft":
        threat_model = "Credential theft activity with signs of follow-on attacker movement."

    elif {"Initial Access", "Execution", "Credential Access", "Lateral Movement"}.issubset(stages):
        threat_model = "Phishing-based intrusion progressing toward credential theft and lateral movement."

    elif {"Execution", "Command and Control", "Persistence"}.issubset(stages) and "Initial Access" not in stages:
        threat_model = "Likely established compromise with ongoing attacker foothold."

    return {
        "threat_model": threat_model,
        "findings": findings,
        "scenario_type": scenario_type,
        "likely_objective": likely_objective,
        "likely_impact": likely_impact,
        "recommended_response": recommended_response
    }