import datetime
import requests
import config

class EvidenceCollector:
    """
    Collects and organizes evidence during incident response.
    Each piece of evidence gets a timestamp, a type label,
    a source, and the raw data — structured so it can be
    included directly in the incident report.

    In a real environment this would pull from live systems —
    Active Directory, EDR APIs, SIEM queries, cloud logs.
    Here we simulate those responses to demonstrate the
    workflow without requiring live infrastructure.
    """

    def __init__(self, logger):
        self.logger = logger
        self.evidence = []

    def _add(self, evidence_type, source, data):
        """Adds a timestamped evidence item to the collection"""
        self.evidence.append({
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": evidence_type,
            "source": source,
            "data": data
        })

    # ── Identity Evidence ────────────────────────────────────

    def check_account_status(self, username):
        """
        Checks whether the account is active, locked, or
        disabled. In production this queries Active Directory
        or your IAM platform via API.
        """
        self.logger.info("Identify", f"Checking account status for: {username}")

        # Simulated AD response
        account_data = {
            "username": username,
            "status": "Active",
            "last_login": "2026-04-05 09:23:14",
            "login_count_24h": 47,
            "failed_logins_24h": 23,
            "groups": ["Domain Users", "VPN Users", "Finance"],
            "mfa_enabled": True,
            "password_last_set": "2026-01-15",
            "account_created": "2019-03-22"
        }

        self._add("Account Status", "Active Directory", account_data)

        if account_data["failed_logins_24h"] > 10:
            self.logger.warning(
                "Identify",
                f"High failed login count: {account_data['failed_logins_24h']} "
                f"failures in last 24 hours"
            )
        else:
            self.logger.success(
                "Identify",
                f"Account status retrieved — {account_data['status']}"
            )

        return account_data

    def check_recent_logins(self, username):
        """
        Pulls recent login history including source IPs,
        locations, and whether each login succeeded.
        In production this queries your SIEM or UEBA platform.
        """
        self.logger.info("Identify", f"Pulling recent login history for: {username}")

        login_history = [
            {
                "timestamp": "2026-04-05 09:23:14",
                "source_ip": "192.168.1.45",
                "location": "Dallas, TX — Corporate Network",
                "status": "Success",
                "user_agent": "Windows 10 — Chrome"
            },
            {
                "timestamp": "2026-04-05 02:17:33",
                "source_ip": "185.220.101.45",
                "location": "Germany — Tor Exit Node",
                "status": "Success",
                "user_agent": "Unknown"
            },
            {
                "timestamp": "2026-04-05 02:15:11",
                "source_ip": "185.220.101.45",
                "location": "Germany — Tor Exit Node",
                "status": "Failed",
                "user_agent": "Unknown"
            },
            {
                "timestamp": "2026-04-04 17:45:02",
                "source_ip": "192.168.1.45",
                "location": "Dallas, TX — Corporate Network",
                "status": "Success",
                "user_agent": "Windows 10 — Chrome"
            }
        ]

        self._add("Login History", "SIEM — Authentication Logs", login_history)

        # Flag suspicious logins automatically
        suspicious = [l for l in login_history if "Tor" in l["location"]
                      or l["source_ip"].startswith("185.")]

        if suspicious:
            self.logger.critical(
                "Detect",
                f"Suspicious login detected from Tor exit node: "
                f"{suspicious[0]['source_ip']} at {suspicious[0]['timestamp']}"
            )
        else:
            self.logger.success("Detect", "No suspicious login sources identified")

        return login_history

    # ── Endpoint Evidence ────────────────────────────────────

    def check_endpoint_processes(self, hostname):
        """
        Pulls running processes from the endpoint.
        In production this queries your EDR — CrowdStrike
        Falcon, Microsoft Defender, or Carbon Black.
        """
        self.logger.info(
            "Identify",
            f"Querying endpoint processes on: {hostname}"
        )

        processes = [
            {
                "pid": 4821,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent": "winword.exe",
                "cmdline": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                "user": "DOMAIN\\atijani",
                "started": "2026-04-05 02:18:45"
            },
            {
                "pid": 3201,
                "name": "winword.exe",
                "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "parent": "explorer.exe",
                "cmdline": "WINWORD.EXE /n C:\\Users\\atijani\\Downloads\\Invoice_Q1.docm",
                "user": "DOMAIN\\atijani",
                "started": "2026-04-05 02:17:52"
            },
            {
                "pid": 1204,
                "name": "chrome.exe",
                "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "parent": "explorer.exe",
                "cmdline": "chrome.exe",
                "user": "DOMAIN\\atijani",
                "started": "2026-04-05 08:45:11"
            }
        ]

        self._add("Running Processes", "EDR — CrowdStrike Falcon", processes)

        # Flag suspicious process relationships
        for proc in processes:
            if proc["name"] == "powershell.exe" and "winword" in proc["parent"].lower():
                self.logger.critical(
                    "Detect",
                    f"PowerShell spawned by Word — likely macro execution: "
                    f"PID {proc['pid']} — {proc['cmdline'][:60]}..."
                )
            elif "-enc" in proc["cmdline"].lower() or "-encoded" in proc["cmdline"].lower():
                self.logger.warning(
                    "Detect",
                    f"Encoded PowerShell command detected: PID {proc['pid']}"
                )

        return processes

    def check_network_connections(self, hostname):
        """
        Pulls active and recent network connections from endpoint.
        In production this queries EDR network telemetry.
        """
        self.logger.info(
            "Identify",
            f"Checking network connections on: {hostname}"
        )

        connections = [
            {
                "local_ip": "192.168.1.87",
                "local_port": 49823,
                "remote_ip": "185.220.101.45",
                "remote_port": 443,
                "protocol": "HTTPS",
                "status": "ESTABLISHED",
                "process": "powershell.exe",
                "bytes_sent": 2457600
            },
            {
                "local_ip": "192.168.1.87",
                "local_port": 50012,
                "remote_ip": "8.8.8.8",
                "remote_port": 53,
                "protocol": "DNS",
                "status": "CLOSED",
                "process": "svchost.exe",
                "bytes_sent": 128
            }
        ]

        self._add(
            "Network Connections",
            "EDR — CrowdStrike Falcon",
            connections
        )

        for conn in connections:
            if conn["process"] == "powershell.exe" and conn["bytes_sent"] > 1000000:
                self.logger.critical(
                    "Detect",
                    f"Large data transfer from PowerShell: "
                    f"{conn['bytes_sent'] / 1024 / 1024:.1f}MB to "
                    f"{conn['remote_ip']}:{conn['remote_port']}"
                )

        return connections

    # ── Threat Intelligence ──────────────────────────────────

    def enrich_ioc(self, ioc):
        """
        Queries VirusTotal for IOC enrichment.
        Reuses the same pattern from Project 1 —
        demonstrating how tools build on each other.
        """
        self.logger.info("Identify", f"Enriching IOC against VirusTotal: {ioc}")

        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

        if len(ioc) in [32, 40, 64]:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif any(c.isalpha() for c in ioc) and "." in ioc:
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        else:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                result = {
                    "ioc": ioc,
                    "malicious_engines": malicious,
                    "total_engines": sum(stats.values()),
                    "stats": stats
                }
                self._add("Threat Intelligence", "VirusTotal", result)

                if malicious > 5:
                    self.logger.critical(
                        "Identify",
                        f"IOC confirmed malicious: {ioc} — "
                        f"{malicious} engines flagged"
                    )
                elif malicious > 0:
                    self.logger.warning(
                        "Identify",
                        f"IOC flagged by {malicious} engines: {ioc}"
                    )
                else:
                    self.logger.success(
                        "Identify",
                        f"IOC clean on VirusTotal: {ioc}"
                    )
                return result
            else:
                self.logger.warning(
                    "Identify",
                    f"VirusTotal returned status {response.status_code} for {ioc}"
                )
                return None
        except Exception as e:
            self.logger.warning("Identify", f"VirusTotal query failed: {str(e)}")
            return None

    def get_evidence(self):
        """Returns all collected evidence for report generation"""
        return self.evidence