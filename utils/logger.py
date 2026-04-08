import datetime
from colorama import init, Fore, Style

# Initialize colorama for Windows color support
init(autoreset=True)

class PlaybookLogger:
    """
    Handles all terminal output and action logging during
    playbook execution. Every action gets a timestamp,
    a severity level, and a NIST CSF phase tag.

    In a real SOAR environment this would write to a
    centralized logging platform like Splunk or Sentinel.
    Here it writes to both the terminal and an in-memory
    log that gets included in the final incident report.
    """

    def __init__(self, incident_id):
        self.incident_id = incident_id
        self.actions = []
        self.start_time = datetime.datetime.now()

    def _timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _log(self, level, phase, message, color):
        timestamp = self._timestamp()
        entry = {
            "timestamp": timestamp,
            "level": level,
            "phase": phase,
            "message": message
        }
        self.actions.append(entry)
        print(f"{color}[{timestamp}] [{level}] [{phase}] {message}{Style.RESET_ALL}")

    def info(self, phase, message):
        """Standard informational action — step executed successfully"""
        self._log("INFO", phase, message, Fore.CYAN)

    def success(self, phase, message):
        """Positive finding or successful containment action"""
        self._log("SUCCESS", phase, message, Fore.GREEN)

    def warning(self, phase, message):
        """Suspicious finding that warrants attention"""
        self._log("WARNING", phase, message, Fore.YELLOW)

    def critical(self, phase, message):
        """High severity finding requiring immediate action"""
        self._log("CRITICAL", phase, message, Fore.RED)

    def header(self, message):
        """Section header to visually separate playbook phases"""
        print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
        print(f"  {message}")
        print(f"{'='*60}{Style.RESET_ALL}\n")

    def get_actions(self):
        """Returns complete action log for report generation"""
        return self.actions

    def get_duration(self):
        """Returns how long the playbook took to run"""
        duration = datetime.datetime.now() - self.start_time
        return str(duration).split(".")[0]