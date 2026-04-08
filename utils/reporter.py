import os
import json
import datetime
import config

class IncidentReporter:
    """
    Generates a complete incident report at the end of
    playbook execution. Produces two formats:

    1. A human-readable text report for the analyst
       and stakeholders
    2. A structured JSON report for SIEM ingestion
       and case management platforms

    In a real environment this would integrate directly
    with your ticketing system — ServiceNow, Jira, or
    PagerDuty — via API to auto-create and populate
    incident tickets.
    """

    def __init__(self, incident_data, actions, evidence):
        self.incident = incident_data
        self.actions = actions
        self.evidence = evidence
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def _format_separator(self, char="─", width=60):
        return char * width

    def generate_text_report(self):
        """
        Generates a clean human-readable incident report.
        Structured to match real SOC incident report format —
        header, timeline, findings, containment actions,
        and recommendations.
        """
        lines = []

        # ── Header ───────────────────────────────────────────
        lines.append("=" * 60)
        lines.append("  INCIDENT RESPONSE REPORT")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"  Incident ID    : {self.incident['id']}")
        lines.append(f"  Type           : {self.incident['type']}")
        lines.append(f"  Severity       : {self.incident['severity']}")
        lines.append(f"  Status         : {self.incident['status']}")
        lines.append(f"  Analyst        : {config.ANALYST_NAME}")
        lines.append(f"  Team           : {config.SOC_TEAM}")
        lines.append(f"  Generated      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Duration       : {self.incident.get('duration', 'N/A')}")
        lines.append("")

        # ── Incident Summary ─────────────────────────────────
        lines.append(self._format_separator())
        lines.append("  INCIDENT SUMMARY")
        lines.append(self._format_separator())
        lines.append("")
        lines.append(f"  {self.incident.get('summary', 'No summary provided')}")
        lines.append("")

        # ── Affected Assets ──────────────────────────────────
        lines.append(self._format_separator())
        lines.append("  AFFECTED ASSETS")
        lines.append(self._format_separator())
        lines.append("")
        for asset in self.incident.get("affected_assets", []):
            lines.append(f"  • {asset}")
        lines.append("")

        # ── NIST CSF Phase Timeline ──────────────────────────
        lines.append(self._format_separator())
        lines.append("  RESPONSE TIMELINE — NIST CSF ALIGNED")
        lines.append(self._format_separator())
        lines.append("")

        # Group actions by NIST phase
        phases = {}
        for action in self.actions:
            phase = action["phase"]
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(action)

        for phase in config.NIST_PHASES:
            if phase in phases:
                lines.append(f"  [{phase.upper()}]")
                for action in phases[phase]:
                    level_marker = {
                        "INFO":     "  →",
                        "SUCCESS":  "  ✓",
                        "WARNING":  "  ⚠",
                        "CRITICAL": "  ✗"
                    }.get(action["level"], "  →")
                    lines.append(
                        f"  {level_marker} [{action['timestamp']}] "
                        f"[{action['level']}] {action['message']}"
                    )
                lines.append("")

        # ── Evidence Summary ─────────────────────────────────
        lines.append(self._format_separator())
        lines.append("  EVIDENCE COLLECTED")
        lines.append(self._format_separator())
        lines.append("")
        for item in self.evidence:
            lines.append(f"  [{item['timestamp']}] {item['type']} — Source: {item['source']}")
        lines.append("")

        # ── Findings ─────────────────────────────────────────
        lines.append(self._format_separator())
        lines.append("  KEY FINDINGS")
        lines.append(self._format_separator())
        lines.append("")
        for finding in self.incident.get("findings", []):
            lines.append(f"  • {finding}")
        lines.append("")

        # ── Containment Actions ──────────────────────────────
        lines.append(self._format_separator())
        lines.append("  CONTAINMENT ACTIONS TAKEN")
        lines.append(self._format_separator())
        lines.append("")
        for action in self.incident.get("containment_actions", []):
            lines.append(f"  • {action}")
        lines.append("")

        # ── Recommendations ──────────────────────────────────
        lines.append(self._format_separator())
        lines.append("  RECOMMENDATIONS")
        lines.append(self._format_separator())
        lines.append("")
        for rec in self.incident.get("recommendations", []):
            lines.append(f"  • {rec}")
        lines.append("")

        # ── Footer ───────────────────────────────────────────
        lines.append("=" * 60)
        lines.append(f"  Report generated by IR Playbook Automation Engine")
        lines.append(f"  Analyst: {config.ANALYST_NAME} — {config.SOC_TEAM}")
        lines.append("=" * 60)

        return "\n".join(lines)

    def save_reports(self):
        """
        Saves both report formats to the reports/ directory.
        Returns the file paths for confirmation.
        """
        os.makedirs(config.REPORT_OUTPUT_DIR, exist_ok=True)

        incident_id = self.incident["id"].replace("-", "_")

        # Save text report
        text_path = os.path.join(
            config.REPORT_OUTPUT_DIR,
            f"{incident_id}_{self.timestamp}.txt"
        )
        text_report = self.generate_text_report()
        with open(text_path, "w", encoding="utf-8") as f:
            f.write(text_report)

        # Save JSON report
        json_path = os.path.join(
            config.REPORT_OUTPUT_DIR,
            f"{incident_id}_{self.timestamp}.json"
        )
        json_report = {
            "incident": self.incident,
            "actions": self.actions,
            "evidence": self.evidence,
            "report_metadata": {
                "analyst": config.ANALYST_NAME,
                "team": config.SOC_TEAM,
                "generated": datetime.datetime.now().isoformat(),
                "framework": "NIST CSF"
            }
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=4)

        return text_path, json_path