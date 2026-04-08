import sys
from colorama import init, Fore, Style
from playbooks import compromised_credential, malware_execution

# Initialize colorama for Windows
init(autoreset=True)

def print_banner():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}")
    print("=" * 60)
    print("  IR PLAYBOOK AUTOMATION ENGINE")
    print("  NIST CSF Aligned — MITRE ATT&CK Mapped")
    print("  Built by Adesina Tijani — Security Operations")
    print("=" * 60)
    print(Style.RESET_ALL)

def select_playbook():
    """
    Presents the analyst with available playbooks
    and collects incident details before execution.
    """
    print(f"{Fore.WHITE}{Style.BRIGHT}Available Playbooks:{Style.RESET_ALL}\n")
    print(f"  {Fore.CYAN}[1]{Style.RESET_ALL} Compromised Credential")
    print(f"  {Fore.CYAN}[2]{Style.RESET_ALL} Malware Execution")
    print()

    choice = input("Select playbook [1-2]: ").strip()

    if choice == "1":
        return collect_credential_input()
    elif choice == "2":
        return collect_malware_input()
    else:
        print(f"{Fore.RED}Invalid selection. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

def collect_credential_input():
    """Collects incident details for compromised credential playbook"""
    print(f"\n{Fore.WHITE}{Style.BRIGHT}COMPROMISED CREDENTIAL — Incident Details{Style.RESET_ALL}\n")

    username = input("  Affected username: ").strip()
    hostname = input("  Affected hostname (press Enter to skip): ").strip()
    severity = input("  Initial severity [P1/P2/P3] (default P2): ").strip() or "P2"

    print(f"\n  IOCs to investigate (press Enter after each, blank line when done):")
    iocs = []
    while True:
        ioc = input("  IOC: ").strip()
        if not ioc:
            break
        iocs.append(ioc)

    # Use default IOC from evidence if none provided
    if not iocs:
        iocs = ["185.220.101.45"]
        print(f"  {Fore.YELLOW}No IOCs provided — using default from evidence{Style.RESET_ALL}")

    incident_input = {
        "username": username or "atijani",
        "hostname": hostname or "WKSTN-ATIJANI-01",
        "severity": severity,
        "iocs": iocs
    }

    return "compromised_credential", incident_input

def collect_malware_input():
    """Collects incident details for malware execution playbook"""
    print(f"\n{Fore.WHITE}{Style.BRIGHT}MALWARE EXECUTION — Incident Details{Style.RESET_ALL}\n")

    hostname = input("  Affected hostname: ").strip()
    username = input("  Affected username (press Enter to skip): ").strip()
    trigger = input("  Alert trigger description: ").strip()
    severity = input("  Initial severity [P1/P2/P3] (default P2): ").strip() or "P2"

    print(f"\n  IOCs to investigate (press Enter after each, blank line when done):")
    iocs = []
    while True:
        ioc = input("  IOC: ").strip()
        if not ioc:
            break
        iocs.append(ioc)

    if not iocs:
        iocs = ["44d88612fea8a8f36de82e1278abb02f"]
        print(f"  {Fore.YELLOW}No IOCs provided — using default from evidence{Style.RESET_ALL}")

    incident_input = {
        "hostname": hostname or "WKSTN-ATIJANI-01",
        "username": username or "atijani",
        "trigger": trigger or "EDR — Suspicious PowerShell execution detected",
        "severity": severity,
        "iocs": iocs
    }

    return "malware_execution", incident_input

def confirm_execution(playbook_name, incident_input):
    """
    Shows the analyst a summary of what's about to run
    and asks for confirmation before executing.
    This mirrors real SOAR platforms that show a preview
    before executing automated response actions.
    """
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  EXECUTION SUMMARY{Style.RESET_ALL}\n")
    print(f"  Playbook  : {playbook_name.replace('_', ' ').title()}")
    for key, value in incident_input.items():
        if key != "iocs":
            print(f"  {key.title():<12}: {value}")
    if incident_input.get("iocs"):
        print(f"  IOCs      : {', '.join(incident_input['iocs'])}")
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}\n")

    confirm = input(
        f"{Fore.YELLOW}Execute playbook? [y/n]: {Style.RESET_ALL}"
    ).strip().lower()

    return confirm == "y"

def print_summary(result):
    """Prints a clean summary after playbook execution completes"""
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  PLAYBOOK EXECUTION COMPLETE{Style.RESET_ALL}\n")
    print(f"  Incident ID : {result['id']}")
    print(f"  Type        : {result['type']}")
    print(f"  Severity    : {result['severity']}")
    print(f"  Status      : {result['status']}")
    print(f"  Duration    : {result['duration']}")
    print(f"\n  Findings    : {len(result['findings'])}")
    print(f"  Containment : {len(result['containment_actions'])} actions taken")
    print(f"\n  Reports saved to: reports/")
    print(f"{Fore.WHITE}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}\n")

# ── Entry Point ──────────────────────────────────────────────
if __name__ == "__main__":
    print_banner()

    playbook_name, incident_input = select_playbook()

    if not confirm_execution(playbook_name, incident_input):
        print(f"\n{Fore.YELLOW}Execution cancelled.{Style.RESET_ALL}\n")
        sys.exit(0)

    print()

    # Route to correct playbook
    if playbook_name == "compromised_credential":
        result = compromised_credential.run(incident_input)
    elif playbook_name == "malware_execution":
        result = malware_execution.run(incident_input)

    print_summary(result)