import datetime
import config
from utils.logger import PlaybookLogger
from utils.evidence import EvidenceCollector
from utils.reporter import IncidentReporter

def run(incident_input):
    """
    PLAYBOOK: Compromised Credential Incident Response
    MITRE ATT&CK: T1078 - Valid Accounts
    NIST CSF: Identify → Detect → Respond → Recover
    SEVERITY: P2 — escalates to P1 if lateral movement confirmed

    This playbook automates the response workflow for a
    suspected compromised credential incident. It walks
    through every step a Tier 2 analyst would perform —
    gathering identity evidence, checking login history,
    querying endpoint telemetry, enriching IOCs, executing
    containment actions, and generating the incident report.

    In a real SOAR deployment each step would execute
    against live systems via API. Here we demonstrate
    the complete workflow with realistic simulated data.
    """

    # ── Initialize ───────────────────────────────────────────
    incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    logger = PlaybookLogger(incident_id)
    collector = EvidenceCollector(logger)

    findings = []
    containment_actions = []
    recommendations = []
    severity = incident_input.get("severity", "P2")

    logger.header(f"COMPROMISED CREDENTIAL PLAYBOOK — {incident_id}")
    logger.info("Identify", f"Playbook initiated by {config.ANALYST_NAME}")
    logger.info("Identify", f"Initial severity: {severity}")
    logger.info("Identify", f"Affected account: {incident_input['username']}")

    # ── Phase 1: IDENTIFY ────────────────────────────────────
    logger.header("PHASE 1 — IDENTIFY")

    # Step 1.1 — Check account status
    account = collector.check_account_status(incident_input["username"])

    if account["failed_logins_24h"] > 10:
        findings.append(
            f"High failed login count: {account['failed_logins_24h']} "
            f"failures in 24 hours for {incident_input['username']}"
        )

    # Step 1.2 — Pull login history
    logins = collector.check_recent_logins(incident_input["username"])

    suspicious_logins = [
        l for l in logins
        if "Tor" in l.get("location", "")
        or l.get("source_ip", "").startswith("185.")
    ]

    if suspicious_logins:
        findings.append(
            f"Suspicious login from Tor exit node: "
            f"{suspicious_logins[0]['source_ip']} at "
            f"{suspicious_logins[0]['timestamp']}"
        )
        severity = "P1"
        logger.critical(
            "Identify",
            f"Severity escalated to P1 — Tor login confirmed"
        )

    # Step 1.3 — Check endpoint activity
    if "hostname" in incident_input:
        processes = collector.check_endpoint_processes(
            incident_input["hostname"]
        )
        connections = collector.check_network_connections(
            incident_input["hostname"]
        )

        # Check for lateral movement indicators
        suspicious_procs = [
            p for p in processes
            if p["name"] == "powershell.exe"
            and "winword" in p.get("parent", "").lower()
        ]

        if suspicious_procs:
            findings.append(
                f"PowerShell spawned by Word detected — "
                f"likely macro-based initial access: "
                f"PID {suspicious_procs[0]['pid']}"
            )

    # Step 1.4 — Enrich suspicious IOCs
    logger.header("IOC ENRICHMENT")
    for ioc in incident_input.get("iocs", []):
        collector.enrich_ioc(ioc)

    # ── Phase 2: DETECT ──────────────────────────────────────
    logger.header("PHASE 2 — DETECT")

    logger.info(
        "Detect",
        "Correlating identity, endpoint, and network evidence"
    )

    # Check for complete attack chain
    has_suspicious_login = len(suspicious_logins) > 0
    has_suspicious_process = any(
        p["name"] == "powershell.exe"
        for p in processes
        if "winword" in p.get("parent", "").lower()
    ) if "hostname" in incident_input else False

    if has_suspicious_login and has_suspicious_process:
        logger.critical(
            "Detect",
            "Attack chain confirmed: Credential compromise → "
            "Macro execution → PowerShell payload"
        )
        findings.append(
            "Complete attack chain identified: "
            "Compromised credential used to access system, "
            "malicious Word document executed, "
            "PowerShell payload launched"
        )
        severity = "P1"

    # ── Phase 3: RESPOND ─────────────────────────────────────
    logger.header("PHASE 3 — RESPOND")

    # Step 3.1 — Disable account
    logger.info(
        "Respond",
        f"Disabling account: {incident_input['username']}"
    )
    logger.success(
        "Respond",
        f"Account disabled in Active Directory: "
        f"{incident_input['username']}"
    )
    containment_actions.append(
        f"Account disabled in Active Directory: {incident_input['username']}"
    )

    # Step 3.2 — Revoke active sessions
    logger.info("Respond", "Revoking all active sessions and tokens")
    logger.success("Respond", "Active sessions terminated — SSO tokens invalidated")
    containment_actions.append(
        "All active sessions terminated and SSO tokens revoked"
    )

    # Step 3.3 — Block suspicious IP
    if suspicious_logins:
        suspicious_ip = suspicious_logins[0]["source_ip"]
        logger.info(
            "Respond",
            f"Blocking suspicious IP at perimeter: {suspicious_ip}"
        )
        logger.success(
            "Respond",
            f"IP blocked at firewall: {suspicious_ip}"
        )
        containment_actions.append(
            f"Suspicious IP blocked at perimeter firewall: {suspicious_ip}"
        )

    # Step 3.4 — Isolate endpoint if needed
    if has_suspicious_process and "hostname" in incident_input:
        logger.critical(
            "Respond",
            f"Isolating endpoint from network: {incident_input['hostname']}"
        )
        logger.success(
            "Respond",
            f"Endpoint isolated via EDR: {incident_input['hostname']}"
        )
        containment_actions.append(
            f"Endpoint network-isolated via CrowdStrike Falcon: "
            f"{incident_input['hostname']}"
        )

    # Step 3.5 — Force MFA re-enrollment
    logger.info("Respond", "Triggering MFA re-enrollment for affected account")
    logger.success("Respond", "MFA re-enrollment email sent to account owner")
    containment_actions.append(
        "MFA re-enrollment triggered for affected account"
    )

    # ── Phase 4: RECOVER ─────────────────────────────────────
    logger.header("PHASE 4 — RECOVER")

    logger.info("Recover", "Initiating account recovery workflow")
    logger.info(
        "Recover",
        "Notifying account owner and manager via secure channel"
    )
    logger.success(
        "Recover",
        "Recovery workflow initiated — account owner notified"
    )

    # ── Recommendations ──────────────────────────────────────
    recommendations = [
        "Force password reset for all accounts in same "
        "security group as compromised account",
        "Review and audit all actions taken by compromised "
        "account in the 72 hours before detection",
        "Implement conditional access policy blocking "
        "authentication from Tor exit nodes",
        "Deploy email attachment sandboxing to prevent "
        "macro-enabled document execution",
        "Review VPN access logs for lateral movement "
        "from compromised credential",
        "Consider implementing UEBA baseline for this "
        "user to detect future anomalies"
    ]

    # ── Generate Report ──────────────────────────────────────
    logger.header("GENERATING INCIDENT REPORT")

    incident_data = {
        "id": incident_id,
        "type": "Compromised Credential",
        "severity": severity,
        "status": "Contained",
        "summary": (
            f"Compromised credential incident involving account "
            f"{incident_input['username']}. Suspicious login detected "
            f"from Tor exit node followed by macro-enabled document "
            f"execution and PowerShell payload deployment. "
            f"Account disabled, sessions revoked, endpoint isolated."
        ),
        "affected_assets": [
            f"User Account: {incident_input['username']}",
            f"Endpoint: {incident_input.get('hostname', 'Unknown')}",
            f"Source IP: {suspicious_logins[0]['source_ip'] if suspicious_logins else 'Unknown'}"
        ],
        "findings": findings,
        "containment_actions": containment_actions,
        "recommendations": recommendations,
        "duration": logger.get_duration(),
        "mitre_technique": "T1078 - Valid Accounts",
        "nist_phases": ["Identify", "Detect", "Respond", "Recover"]
    }

    reporter = IncidentReporter(
        incident_data,
        logger.get_actions(),
        collector.get_evidence()
    )

    text_path, json_path = reporter.save_reports()

    logger.success(
        "Recover",
        f"Text report saved: {text_path}"
    )
    logger.success(
        "Recover",
        f"JSON report saved: {json_path}"
    )

    return incident_data