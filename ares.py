#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ARES — AI Defensive Security Agent v1.0                ║
║   Bare-metal Kali NetHunter  ·  Commander: The Priest          ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║   ARES is the symmetric defensive counterpart to ATHENA.         ║
║   Same skeleton, opposite mission: triage, threat-hunt, harden,  ║
║   and respond.  Where Athena attacks, Ares watches, detects,     ║
║   investigates, and remediates.                                  ║
║                                                                  ║
║   v1.0 — INITIAL DEFENSIVE BUILD (forked from Athena v7.2)       ║
║                                                                  ║
║   ARCHITECTURE (carried over from Athena v7.2)                   ║
║   • Tool dispatch with synonym-aware kwargs.  Unknown kwargs     ║
║     become a hard error fed back into the LLM's NEXT prompt.     ║
║   • Sudo escalation: when a command fails with permission        ║
║     denied / requires-root markers, Ares offers to re-run with   ║
║     sudo (one-tap retry).  Read-only by default.                 ║
║   • Tool availability is checked BEFORE dispatch.                ║
║   • Loop-breaker: same shell command twice → forced agent        ║
║     rotation + RED conf override.  Three times → handle_stuck.   ║
║   • Confidence is failure-aware: N consecutive fails on a node   ║
║     forces RED regardless of the LLM's self-rating.              ║
║   • Per-command timeouts: short queries 60s, log scans 300s,     ║
║     forensics jobs (volatility/yara) 1800s.                      ║
║   • Boot lock auto-expires after 6h.                             ║
║                                                                  ║
║   UI                                                             ║
║   • Every turn renders as a stack of titled boxes:               ║
║       ┌─ TURN N · host · agent · findings · ATT&CK · model ─┐    ║
║       ┌─ THOUGHT ─┐                                              ║
║       ┌─ DISPATCH ─┐                                             ║
║       ┌─ COMMAND  conf=GREEN  ATT&CK=T1059 ─┐                    ║
║       ┌─ EXECUTING ─┐ ... ┌─ RESULT ─┐                           ║
║       ┌─ FINDINGS +N ─┐                                          ║
║       ┌─ ⛔ ERROR ─┐  for permission/scope/destructive           ║
║   • Persistent status bar still rendered before each prompt.     ║
║                                                                  ║
║   DEFENSIVE FEATURES                                             ║
║   • Defense Task Tree (DTT) — same shape as Athena's PTT but     ║
║     phases are: triage, hunt, ir, hardening, malware,            ║
║     forensics, identity, network_defense, reporter.              ║
║   • 10 specialist agents, deterministic dispatch:                ║
║     strategist, triage, log_analyst, threat_hunter,              ║
║     network_defender, ir_responder, hardener, malware_analyst,   ║
║     forensics_analyst, identity_defender, reporter.              ║
║   • 28+ structured defensive tool builders.                      ║
║   • MITRE ATT&CK detection auto-tagging.                         ║
║   • Scope / RoE enforcement (only audit hosts you own).          ║
║   • Threat graph (networkx) — IOCs, alerts, lateral hints.       ║
║   • Smart context manager + [NEED] re-fetches.                   ║
║   • Auto IOC fanout (any indicator → propagate to all hunters).  ║
║   • Read-only-by-default safety: kill/quarantine/block require   ║
║     double confirmation.                                         ║
║   • Groq provider chain (same as Athena).                        ║
║   • No on-disk persistence (except scope + logs + reports).      ║
║                                                                  ║
║   PAIRING WITH ATHENA                                            ║
║   Run both side-by-side: Athena finds the path in, Ares          ║
║   verifies you've closed the same path against yourself.         ║
║   Same Groq key works for both.  ~/.ares/ vs ~/.athena/.         ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import json
import time
import getpass
import signal
import inspect
import datetime
import subprocess
import ipaddress
import shutil
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Set

try:
    from groq import Groq
except ImportError:
    print("FATAL: groq package not installed. Run: pip install groq")
    sys.exit(1)

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    print("WARN: networkx not installed — threat graph disabled. "
          "Run: pip install networkx --break-system-packages")

try:
    import readline  # noqa: F401  (enables arrow keys in input())
except ImportError:
    pass


# ═════════════════════════════════════════════════════════════════════
# VERSION & PROVIDER CHAIN  (Groq only, biggest→smallest)
# ═════════════════════════════════════════════════════════════════════

VERSION = "1.0"

# Strict size descending. Compound models last because they have their
# own internal multi-step behaviour that fights our DTT control flow.
PROVIDER_CHAIN = [
    ("openai/gpt-oss-120b",                            "GPT-OSS 120B"),
    ("llama-3.3-70b-versatile",                        "LLaMA 3.3 70B"),
    ("qwen/qwen3-32b",                                 "Qwen3 32B"),
    ("openai/gpt-oss-20b",                             "GPT-OSS 20B"),
    ("meta-llama/llama-4-scout-17b-16e-instruct",      "LLaMA 4 Scout 17B"),
    ("llama-3.1-8b-instant",                           "LLaMA 3.1 8B"),
    ("allam-2-7b",                                     "Allam 2 7B"),
    ("groq/compound",                                  "Groq Compound"),
    ("groq/compound-mini",                             "Compound Mini"),
]


# ═════════════════════════════════════════════════════════════════════
# PATHS, LIMITS, MARKERS
# ═════════════════════════════════════════════════════════════════════

INSTALL_DIR = os.path.expanduser("~/.ares")
LOG_DIR     = os.path.join(INSTALL_DIR, "logs")
SCOPE_FILE  = os.path.join(INSTALL_DIR, "scope.json")
BOOT_LOCK   = "/tmp/ares_session.lock"

# v7.1 — smart context: keep more in memory, send less by default
MAX_HISTORY_MESSAGES   = 32   # how many turns kept in RAM
DEFAULT_HISTORY_SLICE  = 4    # how many sent to API by default
EXPANDED_HISTORY_SLICE = 10   # when stuck/yellow/red conf
MAX_OUTPUT_CHARS       = 5000
MAX_TOKENS_DEFAULT     = 2048
WORKFLOW_DONE          = "WORKFLOW_COMPLETE"

# How many [NEED] re-fetches allowed per turn (prevents runaway loops)
MAX_NEED_FETCHES = 2

# Stuck thresholds
STUCK_THRESHOLD      = 3   # rejects/repeats before pivot
NODE_ATTEMPT_LIMIT   = 4   # attempts on a single PTT node before mark dead-end


# ═════════════════════════════════════════════════════════════════════
# v7.2 — TIMEOUTS, SUDO MARKERS, BOOT LOCK TTL
# ═════════════════════════════════════════════════════════════════════

# Per-command timeout policy.  The bash subprocess is killed if it runs
# longer than the matched ceiling.  Pattern is regex-against-cmd; first
# match wins.  Default ceiling at the bottom.
COMMAND_TIMEOUTS = [
    # Forensics — heavy, slow tools
    (r'\bvolatility(3)?\b',                     1800),    # memory analysis
    (r'\b(yara|yara-scan|yara3)\b',             1800),    # large-scale yara scans
    (r'\b(clamscan|clamdscan)\b',               1800),    # full AV scans
    (r'\b(rkhunter|chkrootkit)\b',               900),
    (r'\blynis\s+audit',                         600),
    (r'\baide(\.wrapper)?\s+(--init|--check)',   900),    # file integrity baselining
    (r'\bdebsums\b',                             600),
    (r'\bbinwalk\s+-e?',                         300),
    (r'\bforemost\b',                            900),    # file carving
    (r'\bphoton\b|\b(autopsy|sleuthkit)\b',      900),
    # Network capture and analysis
    (r'\btcpdump\b.*-c\s+\d{4,}',                300),    # bounded capture
    (r'\btcpdump\b',                             120),
    (r'\b(tshark|wireshark-cli)\b',              300),
    (r'\bzeek\b|\bbro\b',                        600),
    (r'\bsuricata\b.*-r\s',                      900),    # offline pcap replay
    (r'\bnft\s+list\b|\biptables\s+-[LSv]',       30),
    # Log analysis
    (r'\bjournalctl\b.*--since\s',               120),
    (r'\bjournalctl\b',                           60),
    (r'\bgrep\s+-r\b.*\s/var/log',               180),
    (r'\b(ausearch|aureport)\b',                 180),
    (r'\b(last|lastb|lastlog)\b',                 30),
    # Process / network state
    (r'\b(ps|ss|netstat|lsof)\b',                 30),
    (r'\b(getcap|find\s+/.+-perm)',              180),
    # Hash / IOC enrichment
    (r'\b(sha256sum|md5sum|sha1sum)\b',          120),
    (r'\bhashdeep\b',                            300),
    (r'\bcurl\b.*virustotal|\bcurl\b.*abuseipdb', 30),
    (r'\bcurl\b',                                 30),
    # IDS rule mgmt
    (r'\bsuricata-update\b',                     180),
    (r'\b(sigma|chainsaw|hayabusa)\b',           600),
    # OSINT / external intel (kept short)
    (r'\b(whois|dig|host|nslookup)\b',            20),
]
DEFAULT_COMMAND_TIMEOUT = 300  # 5 min ceiling on anything else

# Markers in stdout/stderr that mean "needs root".  When detected after
# a non-sudo command, Ares offers an automatic sudo retry.
SUDO_RETRY_MARKERS = [
    "operation not permitted",
    "permission denied",
    "you don't have permission",
    "you must be root",
    "must be run as root",
    "must be root",
    "requires root",
    "are you root",
    "cap_net_raw",
    "cap_net_admin",
    "cap_dac_read_search",
    "(may need root)",
    "raw sockets",
    "couldn't open device",
    "bind: permission denied",
    "socket: operation not permitted",
]

# Boot-check lock TTL.  Re-run the system check if older than this.
BOOT_LOCK_TTL_SECONDS = 6 * 3600   # 6 hours

# v7.2 — kwarg synonym map for ToolBuilder.  When the LLM emits an arg
# that doesn't match the builder signature, we try one of these
# synonyms BEFORE giving up.  Maps {builder_name: {wrong_name: right_name}}.
# A right_name of None means "drop silently — this is a no-op alias".
KWARG_SYNONYMS = {
    "journalctl": {
        "service":    "unit",
        "svc":        "unit",
        "from":       "since",
        "start":      "since",
        "to":         "until",
        "end":        "until",
        "n_lines":    "lines",
        "tail":       "lines",
    },
    "ss_listening": {
        "ipv":        "ip_version",
        "show_pids":  "processes",
        "with_procs": "processes",
    },
    "ps_tree": {
        "show_threads": "threads",
        "all":          "show_all",
    },
    "lsof_net": {
        "tcp_only":    "_proto",
        "udp_only":    "_proto",
        "user":        "user_filter",
        "uid":         "user_filter",
    },
    "auth_log_grep": {
        "since":       "since_when",
        "from":        "since_when",
        "n_results":   "max_results",
    },
    "find_recent_files": {
        "newer_than":  "minutes",
        "ago":         "minutes",
        "extension":   "ext",
        "ext_filter":  "ext",
    },
    "find_suid": {
        "include_perms": "show_perms",
        "all_uids":      "_drop",
    },
    "find_caps": {
        "all":         "_drop",
    },
    "yara_scan": {
        "ruleset":     "rules",
        "rules_file":  "rules",
        "dir":         "path",
        "target":      "path",
    },
    "clamscan": {
        "dir":         "path",
        "target":      "path",
        "infected_only": "only_infected",
    },
    "tcpdump_capture": {
        "iface":       "interface",
        "if":          "interface",
        "count":       "max_packets",
        "n_packets":   "max_packets",
        "out":         "output_file",
        "save":        "output_file",
        "expression":  "bpf_filter",
        "filter":      "bpf_filter",
    },
    "tshark_read": {
        "file":        "pcap",
        "input":       "pcap",
        "expression":  "display_filter",
        "filter":      "display_filter",
    },
    "suricata_replay": {
        "file":        "pcap",
        "rules_dir":   "rules",
        "out":         "log_dir",
    },
    "lynis_audit": {
        "fast":        "quick",
        "tests":       "test_groups",
    },
    "rkhunter_scan": {
        "skip_keypress": "skip_prompts",
    },
    "auditd_search": {
        "key":         "key_filter",
        "from":        "start_time",
        "to":          "end_time",
        "uid":         "user",
    },
    "volatility_run": {
        "memfile":     "image",
        "dump":        "image",
        "profile":     "_legacy_profile",   # vol2 profile -> vol3 ignores
        "module":      "plugin",
        "cmd":         "plugin",
    },
    "curl_basic": {
        "head":        "head_only",
        "ua":          "user_agent",
        "useragent":   "user_agent",
        "username":    "user",
        "passwd":      "password",
    },
    "hashid": {
        "hash":        "hash_or_file",
        "file":        "hash_or_file",
    },
    # Tools without aliases just inherit empty {}
}


# ═════════════════════════════════════════════════════════════════════
# SAFETY LISTS  (carried over from v6.1 — these work)
# ═════════════════════════════════════════════════════════════════════

BANNED_COMMANDS = [
    "apt upgrade", "apt full-upgrade",
    "apt-get upgrade", "apt-get full-upgrade", "apt dist-upgrade",
]
BANNED_UPGRADE_PACKAGES = ["phosh", "lightdm", "xfce", "x11", "gnome-shell"]

DESTRUCTIVE_COMMANDS = [
    r'\brm\s+-rf\s+/',
    r'\brm\s+-rf\s+\*',
    r'\brm\s+-rf\s+~',
    r'\bdd\s+if=',
    r'\bmkfs\b',
    r'>\s*/dev/sd[a-z]',
    r':\(\)\{.*\|.*&.*\};:',
    r'\bchmod\s+-R\s+777\s+/',
    r'\bchown\s+-R.*\s+/',
    r'\bshutdown\b',
    r'\bhalt\b',
    r'\binit\s+0',
    r'\binit\s+6',
    r'\bpoweroff\b',
]

DOUBLE_CONFIRM = [
    # System service control — defenders sometimes need to stop a
    # compromised service, but a typo here can take prod down.
    r'systemctl\s+(stop|disable|mask|kill)',
    r'service\s+\S+\s+stop',
    # Firewall flush / disable — never want to do this by accident
    r'iptables\s+-F',
    r'iptables\s+-X',
    r'\bnft\s+(flush|delete)',
    r'ufw\s+(disable|reset)',
    r'fail2ban-client\s+(unban|stop)',
    # Process termination — quarantine workflow
    r'\bkill\s+-9',
    r'\bkillall\b',
    r'\bpkill\b',
    # Filesystem / config writes (only ones we'd legitimately do mid-IR)
    r'>\s*/etc/',
    r'sed\s+-i.*\s+/etc/',
    r'echo.*>>\s*/etc/',
    r'echo.*>\s*/etc/',
    # Account control — defender might lock a compromised account
    r'\busermod\s+-L',
    r'\bpasswd\s+-l',
    r'\busermod\s+--lock',
    r'\buserdel\b',
    r'\busermod\s+-(s|-shell)\s+/(usr/)?sbin/nologin',
    # File quarantine / removal during IR
    r'\bchmod\s+\+s\s+',
    r'\bchattr\s+\+i',
    r'\bauditctl\s+-D',
    # IDS rule mutation
    r'\bsuricatasc\s+',
    r'suricata-update.*--no-sources',
]

INTERACTIVE_BLOCKED = {
    "msfconsole":   "Ares is defensive — msfconsole shouldn't be needed. Use [CMD] for ad-hoc.",
    "mysql -u":     "Use: mysql -u USER -pPASS -e 'QUERY;' for non-interactive query",
    "psql":         "Use: psql -c 'QUERY;' for non-interactive query",
    "telnet":       "Use: nc -nv [IP] [PORT] for one-shot banner grab",
    "nc -l":        "Listener blocked — would hang Ares. Run in separate terminal.",
    "ncat -l":      "Listener blocked — would hang Ares. Run in separate terminal.",
    "vim ":         "Use: cat or sed for non-interactive file ops",
    "vi ":          "Use: cat or sed for non-interactive file ops",
    "nano ":        "Use: cat or sed for non-interactive file ops",
    "less ":        "Use: cat or head/tail for non-interactive viewing",
    "more ":        "Use: cat or head/tail for non-interactive viewing",
    "top":          "Use: ps aux --sort=-%cpu for non-interactive process list",
    "htop":         "Use: ps aux for non-interactive process list",
    "ssh ":         "SSH interactive — use sshpass -p PASS ssh user@host 'CMD' instead",
    "ftp ":         "FTP interactive — use curl ftp://user:pass@host/file instead",
    "gdb ":         "GDB interactive — use gdb -batch -ex 'cmd' instead",
    "wireshark":    "Wireshark GUI blocked — use tshark -r FILE -Y FILTER instead",
    "tcpdump -w -": "Stdout pcap blocked — write to a file: -w /tmp/cap.pcap",
    "watch ":       "watch loops forever — Ares does its own polling. Drop the wrapper.",
    "tail -f":      "tail -f hangs — use journalctl --since '1 hour ago' or tail -n 200 instead.",
    "journalctl -f": "journalctl -f hangs — use --since '1 hour ago' or -n 200 instead.",
    "volatility -i": "vol3 lacks interactive mode — pick a plugin: 'volatility -f IMG plugin'.",
}


# ═════════════════════════════════════════════════════════════════════
# COMPREHENSIVE KALI TOOL REGISTRY
#
# Ares uses this both to (a) tell the AI what's available so it stops
# proposing tools that don't exist, and (b) auto-install missing tools
# on demand.  Categorised for quick lookup by phase.
# ═════════════════════════════════════════════════════════════════════

KALI_TOOLS = {
    "log_analysis": [
        "journalctl", "ausearch", "aureport", "auditctl", "last", "lastb",
        "lastlog", "logwatch", "rsyslog", "syslog-ng", "fluent-bit",
        "grep", "awk", "sed", "jq", "logger",
    ],
    "process_state": [
        "ps", "pstree", "top", "htop", "pgrep", "pidof", "lsof", "ss",
        "netstat", "iotop", "vmstat", "fuser", "pmap", "smem",
        "atop", "glances",
    ],
    "host_hardening": [
        "lynis", "tiger", "chkrootkit", "rkhunter", "debsums", "aide",
        "tripwire", "samhain", "ossec", "wazuh-agent",
        "auditd", "audispd-plugins", "apparmor-utils", "selinux-utils",
        "openscap-utils", "scap-security-guide",
    ],
    "ids_ips": [
        "suricata", "suricata-update", "snort", "zeek", "bro",
        "fail2ban-client", "psad", "portsentry", "fwknop",
        "ufw", "iptables", "nftables", "nft", "iptables-save",
    ],
    "network_capture": [
        "tcpdump", "tshark", "dumpcap", "ngrep", "tcpflow", "tcpick",
        "tcpreplay", "argus", "ra", "rwfilter",
        "wireshark-cli", "termshark", "netsniff-ng",
    ],
    "network_state": [
        "ss", "netstat", "ip", "iproute2", "iftop", "nethogs",
        "bmon", "vnstat", "iptraf-ng", "nstat", "nload",
    ],
    "memory_forensics": [
        "volatility3", "vol", "volatility", "rekall", "lime-forensics",
        "avml", "memdump", "yara", "yarac",
    ],
    "disk_forensics": [
        "sleuthkit", "fls", "icat", "ils", "mmls", "fsstat", "tsk_recover",
        "autopsy", "foremost", "scalpel", "bulk_extractor",
        "testdisk", "photorec", "guymager", "dc3dd", "dcfldd",
        "ddrescue", "ewfacquire", "ewfverify",
    ],
    "malware_triage": [
        "yara", "yarac", "clamav", "clamscan", "freshclam", "clamdscan",
        "loki", "thor-lite", "capa", "die", "trid",
        "binwalk", "strings", "file", "exiftool", "pev",
        "objdump", "readelf", "nm", "ldd", "checksec",
    ],
    "ioc_enrichment": [
        "curl", "wget", "jq", "dig", "host", "whois", "abuseipdb-cli",
        "vt-cli", "shodan", "censys", "passivetotal-cli",
        "mitre-attack-cli", "stix-shifter",
    ],
    "identity_audit": [
        "getent", "id", "groups", "passwd", "chage", "faillog",
        "pwck", "grpck", "userdbctl", "loginctl",
        "ldapsearch", "samba-tool", "krb5-user",
    ],
    "file_integrity": [
        "aide", "tripwire", "samhain", "afick",
        "sha256sum", "sha512sum", "md5sum", "hashdeep",
        "debsums", "rpm", "pacman", "diff", "rsync",
    ],
    "siem_query": [
        "chainsaw", "hayabusa", "sigma-cli", "sigmac",
        "elasticsearch-cli", "logstash", "filebeat", "winlogbeat",
        "splunk-cli", "wazuh-cli",
    ],
    "container_audit": [
        "docker", "podman", "kubectl", "kube-bench", "trivy", "grype",
        "syft", "dockle", "clair", "anchore-cli",
        "falco", "tetragon", "crictl",
    ],
    "secrets_audit": [
        "trufflehog", "gitleaks", "detect-secrets", "ripsecrets",
        "ggshield", "git-secrets",
    ],
    "configuration_audit": [
        "openscap", "oscap", "lynis", "kube-bench",
        "checkov", "tfsec", "kics", "terrascan", "scoutsuite",
        "prowler", "cloudsploit",
    ],
    "rootkit_hunters": [
        "rkhunter", "chkrootkit", "lynis", "unhide", "tiger",
        "samhain", "aide", "debsums",
    ],
    "ssl_tls": [
        "sslscan", "sslyze", "testssl.sh", "openssl", "ssh-audit",
        "tlsx", "cipherscan",
    ],
    "dns_defense": [
        "dig", "host", "nslookup", "dnstop", "dnsmonster",
        "passivedns", "dnsrecon",
    ],
    "binary_inspection": [
        "strings", "file", "exiftool", "binwalk", "ldd",
        "objdump", "readelf", "nm", "checksec", "die",
        "radare2", "rizin", "ghidra-server", "r2",
    ],
    "live_response": [
        "lime-forensics", "avml", "fmem", "memdump",
        "lsof", "ss", "ps", "find", "stat",
        "getent", "last", "w", "who",
    ],
    "exfil_detection": [
        "tcpdump", "tshark", "zeek", "suricata", "argus",
        "rita", "passivedns", "joy",
    ],
    "kernel_audit": [
        "sysctl", "modprobe", "lsmod", "dmesg", "auditctl",
        "kernsec", "checksec", "kernel-hardening-checker",
    ],
    "misc_useful": [
        "curl", "wget", "nc", "ncat", "socat", "tmux", "screen",
        "jq", "tee", "xxd", "hexdump", "base64", "openssl",
        "tshark", "tcpdump", "git", "python3", "pip3",
        "sed", "awk", "grep", "find", "xargs",
    ],
}


def all_kali_tools_flat() -> List[str]:
    seen = set()
    flat = []
    for cat, tools in KALI_TOOLS.items():
        for t in tools:
            if t not in seen:
                seen.add(t)
                flat.append(t)
    return flat


def kali_tool_summary_for_prompt() -> str:
    """Compressed list for system prompts so AI knows what's available."""
    parts = []
    for cat, tools in KALI_TOOLS.items():
        # Trim to the most important per category to save tokens
        parts.append(f"  {cat}: {', '.join(tools[:10])}")
    return "KALI ARSENAL AVAILABLE:\n" + "\n".join(parts)


# ═════════════════════════════════════════════════════════════════════
# FINDING PATTERNS — strict, context-aware
#
# Lessons from v6.1: regex like `(?:password|pass)[:\s=]+(\S+)` matches
# the AI's own thinking ("...try password: helper...") and pollutes
# state.  v7.0 only runs these on raw subprocess stdout, never on the
# model's text.  Patterns are also tightened so noise like "200:not"
# (which came from "user:200, pass:not" in the AI's prose) can't match.
# ═════════════════════════════════════════════════════════════════════

FINDING_PATTERNS = {
    # IPv4 addresses (still useful — IOC IPs)
    "ip":        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',

    # Listening ports from ss/netstat: "tcp LISTEN ... :22 ..."
    "port":      r'(?:LISTEN|0\.0\.0\.0:|\*:|\[::\]:)(\d{1,5})\b',

    # Service+version on listening sockets via ss -tlnp output
    "svc":       r'users:\(\("([A-Za-z][A-Za-z0-9_\-]{1,40})"',

    # Suspicious user creation / login: "user X" tagged as account hits
    "account":   r'(?:^|\n|\s)(?:user|account|login|sAMAccountName|uid)[:\s=]+([a-zA-Z][a-zA-Z0-9_\.\-]{2,32})\b',

    # Hash values picked up while reviewing files (could be IOC or local)
    "hash":      r'(?:^|\n|\s|:|=)([a-fA-F0-9]{32,64})(?:\s|$|:)',

    # CVEs surfaced by audit tools (lynis / wesng / openscap)
    "cve":       r'\b(CVE-\d{4}-\d{4,7})\b',

    # Domains (broad — IOC enrichment / suspicious DNS)
    "domain":    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b',

    # URLs (often IOCs in pcap / log analysis)
    "url":       r'(https?://[^\s\'"<>]+)',

    # MITRE ATT&CK technique IDs surfaced by sigma/chainsaw/hayabusa
    "attack_id": r'\b(T1[0-9]{3}(?:\.\d{3})?)\b',

    # YARA matches: "RuleName matched at /path/to/file"
    "yara_hit":  r'^([A-Za-z_][A-Za-z0-9_]+)\s+(/\S+)',

    # ClamAV / signature-based AV: "/path/file: Win.Trojan.Foo FOUND"
    "av_hit":    r'(/[\w\.\-/]+):\s+([A-Za-z][\w\.\-]+)\s+FOUND',

    # Suspicious processes (output of pstree / ps with embedded warnings)
    "suspicious_proc": r'(?:^|\s)((?:python\d?|bash|sh|perl|nc|ncat|socat)\s+-[ce]\s+["\']?[^"\'\s]{16,})',

    # Suricata fast.log alert format
    "suricata_alert": r'\[\*\*\]\s+\[(?:\d+:){2}\d+\]\s+(.+?)\s+\[\*\*\]',

    # Cron entries — look for schedules in non-standard files
    "cron_entry": r'^(?:\*|[0-9]{1,2}|[0-9]{1,2}-[0-9]{1,2}|\*/[0-9]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$',

    # SUID files (find -perm -4000 output)
    "suid":      r'^(/\S+)\s.*-rw[sx]r-[sx]r-[sx]',

    # Capabilities (getcap output: "/path/file = cap_xxx")
    "cap_grant": r'^(/\S+)\s+=\s+(cap_\w[\w\,\+\=]*)',

    # Failed auth events (sshd / pam)
    "auth_fail": r'(?:Failed password|authentication failure|Invalid user)\s+(?:for\s+)?(\S+)',

    # Successful sudo escalations (could be benign or IOC)
    "sudo_use":  r'sudo:\s+(\w+)\s+:\s+TTY=\S+\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=',

    # Persistence — systemd unit files in non-standard locations
    "persistence": r'((?:/etc/systemd/system/|/lib/systemd/system/|/home/\S+/\.config/systemd/user/)[\w\-\.@]+\.(?:service|timer))',

    # Docker container IDs (suspicious or unauthorized)
    "container": r'\b([a-f0-9]{12,64})\s+\S+\s+(?:/|"\$/|\b(?:bash|sh|/bin)',

    # Email addresses (in logs — could be IOC or compromised user)
    "email":     r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b',

    # SSH private key markers (CRITICAL if found exposed)
    "ssh_key":   r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)',

    # AWS-style keys (DLP / secrets exposure)
    "aws_key":   r'\b(AKIA[0-9A-Z]{16})\b',
}

# These IPs are noise — don't add them as findings
IP_NOISE = {
    '0.0.0.0', '127.0.0.1', '255.255.255.255',
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
    '169.254.169.254',  # cloud metadata — noted elsewhere, not a finding
}

# Domains that are noise (shown in command outputs but not real findings)
DOMAIN_NOISE = {
    'localhost', 'example.com', 'google.com', 'cloudflare.com',
    'localdomain', 'arpa', 'in-addr.arpa',
}


# Sensitive paths to flag as "exposed_path" findings if found in output
SENSITIVE_PATH_PATTERNS = [
    r'\.ssh/',
    r'\.bash_history',
    r'\.bashrc\b',
    r'\.git/',
    r'\.env\b',
    r'\.aws/',
    r'wp-config\.php',
    r'config\.php',
    r'/etc/passwd',
    r'/etc/shadow',
    r'/etc/hosts',
    r'id_rsa\b',
    r'id_ed25519\b',
    r'id_ecdsa\b',
    r'authorized_keys',
    r'\.htpasswd',
    r'web\.config',
    r'database\.yml',
    r'application\.properties',
    r'\.npmrc\b',
    r'\.docker/config\.json',
    r'\.kube/config',
]


# Common locations for defensive rulesets — used as defaults when the
# AI requests a yara / sigma run and doesn't specify a path.
YARA_RULE_PATHS = [
    "/usr/share/yara/rules",
    "/var/lib/yara",
    "/opt/yara-rules",
    "/etc/yara",
]

SIGMA_RULE_PATHS = [
    "/usr/share/sigma/rules",
    "/opt/sigma/rules",
    "/var/lib/sigma",
]

CLAMAV_DB_PATHS = [
    "/var/lib/clamav",
    "/var/clamav",
]

# Known noisy / benign processes — don't flag these as suspicious_proc
PROCESS_BENIGN = {
    "systemd", "init", "kthreadd", "kworker", "ksoftirqd", "rcu_sched",
    "migration", "watchdog", "sshd", "rsyslogd", "cron", "dhclient",
    "NetworkManager", "wpa_supplicant", "polkitd", "udevd",
    "snapd", "agetty", "login", "bash", "zsh", "fish", "dbus-daemon",
}

# Critical paths — alerts if writes detected here without authorization
CRITICAL_WATCHED_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/root/.ssh/authorized_keys",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/etc/ld.so.preload",
    "/etc/pam.d/",
    "/etc/security/",
    "/etc/iptables/",
    "/etc/nftables.conf",
]


# ═════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING (v7.1)
#
# Auto-tag commands and findings with technique IDs so reports can be
# grouped by ATT&CK technique — the professional standard for pentest
# deliverables.  Pattern-based: command substring or finding type
# triggers the tag.  First match wins.
# ═════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES = [
    # (regex / substring pattern, technique_id, technique_name, tactic)
    # Tags fire when a defender command targets evidence of that technique.
    # Same TTP IDs as Athena, but tagged from the detection / hunt side.

    # Discovery — defender enumerating their own surface
    (r'\bss\s+-[tu]\S*l',                 "T1046",     "Network Service Discovery (audit)",  "Discovery"),
    (r'\bnetstat\s+-[tu]?l',              "T1046",     "Network Service Discovery (audit)",  "Discovery"),
    (r'\barp\s+-an?\b|\bip\s+neigh\b',    "T1018",     "Remote System Discovery (audit)",    "Discovery"),

    # Credential Access — detection
    (r'/etc/(passwd|shadow)',             "T1003.008", "/etc/passwd & shadow access",        "Credential Access"),
    (r'\blsof\s+.*lsass',                 "T1003.001", "LSASS Memory access",                "Credential Access"),
    (r'\b(volatility|vol)\b.*hashdump',   "T1003",     "OS Credential Dumping (forensics)",  "Credential Access"),

    # Persistence — hunting for it
    (r'\bcrontab\b|\b/etc/cron\.|/var/spool/cron','T1053.003', "Cron job hunt",              "Persistence"),
    (r'\bsystemctl\s+list-unit-files|\b/etc/systemd/system','T1543.002', "systemd unit hunt", "Persistence"),
    (r'\bauthorized_keys\b',              "T1098.004", "SSH Authorized Keys hunt",           "Persistence"),
    (r'/etc/ld\.so\.preload',             "T1574.006", "Dynamic Linker Hijack hunt",         "Persistence"),
    (r'\blsmod\b|\bmodinfo\b|\b/etc/modules-load',"T1547.006","Kernel Modules hunt",         "Persistence"),
    (r'\bautorunsc?\b|HKLM.+CurrentVersion\\Run', "T1547.001","Run Keys hunt",                "Persistence"),
    (r'wmic.+__EventFilter|root\\subscription','T1546.003',"WMI Subscription hunt",          "Persistence"),

    # Privilege Escalation — detection
    (r'find.*-perm.*4000',                "T1548.001", "SUID hunt",                          "Privilege Escalation"),
    (r'\bgetcap\b',                       "T1548",     "Capabilities hunt",                  "Privilege Escalation"),
    (r'\bsudo\s+-l\b|/etc/sudoers',       "T1548.003", "Sudo audit",                         "Privilege Escalation"),

    # Defense Evasion — detection
    (r'\b(rkhunter|chkrootkit)\b',        "T1014",     "Rootkit hunt",                       "Defense Evasion"),
    (r'\baide\s+--check\b|\bdebsums\b',   "T1070",     "File Integrity check (defender)",    "Defense Evasion"),
    (r'\bauditctl\s+-[lD]',               "T1562.006", "Indicator Blocking audit",           "Defense Evasion"),
    (r'\b(yara|capa)\b',                  "T1027",     "Obfuscation / packer hunt",          "Defense Evasion"),

    # Credential Access — defender side
    (r'\bauth_log_grep\b|grep.*Failed.*passwd','T1110.001', "Brute Force detection",         "Credential Access"),
    (r'fail2ban-client\s+status',         "T1110",     "Brute Force monitoring",             "Credential Access"),

    # Lateral movement — detection
    (r'\b(last|lastlog|w|who)\b',         "T1078",     "Valid Accounts audit",               "Defense Evasion"),

    # Command & Control — network defender
    (r'\btshark\b|\btcpdump\b|\bzeek\b',  "T1071",     "Application Layer Protocol (capture)","Command and Control"),
    (r'\bsuricata\b|\bsuricatasc\b',      "T1071",     "C2 detection (IDS)",                  "Command and Control"),

    # Discovery — forensic timeline
    (r'\b(fls|mactime|tsk_recover)\b',    "T1083",     "File and Directory timeline",         "Discovery"),

    # Memory forensics — process hollowing / injection detection
    (r'\b(vol|volatility)\b.*malfind',    "T1055",     "Process Injection detection",         "Defense Evasion"),
    (r'\b(vol|volatility)\b.*pstree',     "T1057",     "Process Discovery (memory)",          "Discovery"),
    (r'\b(vol|volatility)\b.*netscan',    "T1049",     "System Network Connections (memory)","Discovery"),

    # Hardening / config audit
    (r'\blynis\b|\boscap\b',              "T1518",     "Software & Config Discovery (audit)","Discovery"),

    # Forced authentication / cred theft on host
    (r'/proc/[0-9]+/maps',                "T1003",     "Process Memory inspection",          "Credential Access"),

    # Web shell hunt
    (r'/var/www.*\.php.*(eval|base64_decode|assert)','T1505.003',"Web Shell hunt",            "Persistence"),

    # IOC enrichment / threat intel pivots — no ATT&CK ID, just C2 awareness
    (r'virustotal|abuse\.ch|abuseipdb',   "T1071",     "IOC enrichment lookup",              "Command and Control"),
]

# Tag findings by their type when no command pattern matched
MITRE_BY_FINDING = {
    "ip":        ("T1018",     "Remote System Discovery",         "Discovery"),
    "port":      ("T1046",     "Network Service Discovery",       "Discovery"),
    "svc":       ("T1592.002", "Software",                        "Reconnaissance"),
    "account":   ("T1078",     "Valid Accounts",                  "Persistence"),
    "hash":      ("T1003",     "OS Credential Dumping",           "Credential Access"),
    "cve":       ("T1190",     "Exploit Public-Facing App",       "Initial Access"),
    "ssh_key":   ("T1552.004", "Private Keys",                    "Credential Access"),
    "aws_key":   ("T1552.001", "Credentials In Files",            "Credential Access"),
    "email":     ("T1589.002", "Email Addresses",                 "Reconnaissance"),
    "domain":    ("T1590.002", "DNS",                             "Reconnaissance"),
    "url":       ("T1595",     "Active Scanning",                 "Reconnaissance"),
    "yara_hit":  ("T1059",     "Command and Scripting Interpreter","Execution"),
    "av_hit":    ("T1204.002", "Malicious File",                  "Execution"),
    "suspicious_proc": ("T1059", "Command and Scripting Interpreter","Execution"),
    "suricata_alert":  ("T1071", "Application Layer Protocol",   "Command and Control"),
    "cron_entry": ("T1053.003","Scheduled Task: Cron",            "Persistence"),
    "suid":      ("T1548.001", "SUID/SGID",                       "Privilege Escalation"),
    "cap_grant": ("T1548",     "Abuse Elevation Control",         "Privilege Escalation"),
    "auth_fail": ("T1110.001", "Brute Force: Password Guessing",  "Credential Access"),
    "sudo_use":  ("T1548.003", "Sudo and Sudo Caching",           "Privilege Escalation"),
    "persistence": ("T1543.002","Systemd Service",                "Persistence"),
    "container": ("T1610",     "Deploy Container",                "Defense Evasion"),
    "attack_id": ("",          "MITRE ATT&CK technique surfaced", ""),
}


def attack_id_for_command(cmd: str) -> Optional[Tuple[str, str, str]]:
    """Return (technique_id, name, tactic) for a command, or None."""
    if not cmd:
        return None
    for pattern, tid, name, tactic in MITRE_TECHNIQUES:
        try:
            if re.search(pattern, cmd, re.IGNORECASE):
                return (tid, name, tactic)
        except re.error:
            continue
    return None


def attack_id_for_finding(ftype: str) -> Optional[Tuple[str, str, str]]:
    """Return (technique_id, name, tactic) for a finding type, or None."""
    return MITRE_BY_FINDING.get(ftype)


# Exit-code semantics for run_command return values
EXEC_SESSION_EXIT       = "__SESSION_EXIT__"
EXEC_INTERACTIVE_BLOCKED = "__INTERACTIVE_BLOCKED__"
EXEC_REJECTED           = "__COMMAND_REJECTED__"
EXEC_DESTRUCTIVE        = "__DESTRUCTIVE_REFUSED__"


# ═════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE — extended from v6.1 with Ares-specific patterns
# ═════════════════════════════════════════════════════════════════════

KB = {}

KB[1] = r"""
S1 DEFENDER MINDSET:
Assume breach.  Hunt for the attacker, don't wait for the alarm.  Every
investigation has three parallel tracks: WHAT happened (timeline),
WHERE it happened (scope), and WHO did it (attribution — usually last,
sometimes never).  Cheap, broad checks first; expensive, narrow checks
last.  ps/ss/journalctl before volatility.  grep/awk before chainsaw.
Read the log, don't query the SIEM.  When you find one IOC, fanout
across every other host you defend.  A finding is only verified once
its source command and timestamp are recorded — no AI hallucinations
enter the case file.  Pre-compromise: harden, monitor, drill.
Post-compromise: contain, eradicate, recover, learn."""

KB[2] = r"""
S2 TRIAGE & LIVE IR (Linux host):
Identity check:    id; whoami; hostname -f; uname -a; uptime
Active sessions:   w; who; last -n 50; lastlog | head; loginctl
Listening sockets: ss -tlnp; ss -ulnp; ss -ntp state established
Process tree:      ps auxf; pstree -ap; ps -eo pid,ppid,user,etime,cmd --sort=-etime
Recently modified: find /etc /usr/local /opt -mmin -1440 -type f 2>/dev/null
                   find / -mmin -60 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null
SUID/SGID drift:   find / -perm -4000 -type f 2>/dev/null > /tmp/suid_now.txt
                   diff <(sort /var/lib/aide/suid.baseline) /tmp/suid_now.txt
Cron sweep:        ls -la /etc/cron.* /var/spool/cron/ /etc/cron.d/
                   for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null; done
systemd units:     systemctl list-unit-files --state=enabled
                   systemctl list-units --type=service --state=running
                   find /etc/systemd /lib/systemd -name '*.service' -newer /var/log/install.log
Open files / FDs:  lsof -p PID; lsof +L1 (deleted-but-held files = classic backdoor)
Network state:     ip -4 -o addr; ip route; arp -an; ss -i (per-socket details)
TIMELINE FAST:     journalctl --since '24 hours ago' | grep -iE 'fail|error|denied|sudo|new session'"""

KB[3] = r"""
S3 LOG ANALYSIS (Linux):
Journal:           journalctl -u sshd --since '7 days ago'
                   journalctl _SYSTEMD_UNIT=cron.service -p warning
                   journalctl --since 'today' --until '1 hour ago' -p err
Auth events:       grep -E 'Failed|Accepted|Invalid user' /var/log/auth.log
                   awk '/Failed password/ {print $9, $11}' /var/log/auth.log | sort | uniq -c | sort -rn | head
Sudo abuse:        grep 'sudo:' /var/log/auth.log | grep -v 'COMMAND=/usr/bin/whoami'
Login history:     last -F -n 100; lastb -F -n 100 (failed); lastlog | awk '$2 != "**Never"'
Audit framework:   auditctl -l (show rules); auditctl -s (status)
                   ausearch -k key_name --start today
                   ausearch -m USER_AUTH,USER_LOGIN,USER_LOGOUT --start today
                   aureport -au --summary; aureport -l --summary; aureport --tty
Web server logs:   awk '$9 >= 400' /var/log/nginx/access.log | tail -50
                   grep -E 'POST|PUT|DELETE' /var/log/apache2/access.log | tail
Time-window grep:  journalctl --since '2026-05-04 08:00' --until '2026-05-04 12:00'
Quick anomaly:     awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
Rsyslog tail:      tail -n 1000 /var/log/syslog | grep -iE 'oom|segfault|killed|kernel'"""

KB[4] = r"""
S4 NETWORK DETECTION (defender pcap + IDS):
Live capture (bounded — never -w with no -c on production):
  tcpdump -i IFACE -nn -c 1000 -w /tmp/cap.pcap
  tcpdump -i IFACE -nn 'host SUSPECT_IP and not port 22'
Read pcap:
  tshark -r cap.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
  tshark -r cap.pcap -q -z conv,ip | head -20      # top talkers
  tshark -r cap.pcap -q -z dns,tree                # DNS queries summary
  tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e ip.dst -e tls.handshake.extensions_server_name
Suricata (offline replay against pcap):
  suricata -r cap.pcap -l /tmp/suri/ -c /etc/suricata/suricata.yaml
  cat /tmp/suri/fast.log
Suricata (live alerts):
  tail -n 200 /var/log/suricata/fast.log
  jq -c 'select(.event_type=="alert")' /var/log/suricata/eve.json | head
  suricata-update list-sources; suricata-update; suricatasc -c reload-rules
Zeek (rich protocol metadata):
  zeek -C -r cap.pcap                              # produces conn.log, dns.log, http.log, ssl.log
  cat http.log | zeek-cut id.orig_h id.resp_h host uri
  cat ssl.log | zeek-cut id.resp_h server_name issuer subject | sort -u
Beacon hunting (rough):
  zeek-cut id.orig_h id.resp_h ts duration < conn.log \
    | awk '{print $1,$2}' | sort | uniq -c | sort -rn | head
  rita import; rita show-beacons (if installed)
ARP / L2 anomalies:  arp -an; ip neigh; tcpdump -i IFACE arp -nn
DNS exfil clue:      domains over 50 chars, base32/64-shaped subdomains, abnormal TXT volumes"""

KB[5] = r"""
S5 LINUX PERSISTENCE HUNTING:
Cron:              ls -la /etc/cron.{hourly,daily,weekly,monthly,d}
                   ls -la /var/spool/cron/crontabs
                   for u in $(cut -d: -f1 /etc/passwd); do echo "==$u=="; crontab -u $u -l 2>/dev/null; done
                   grep -rE '^[^#]' /etc/cron.d /etc/crontab 2>/dev/null
At jobs:           atq; for j in $(atq | awk '{print $1}'); do at -c $j; done
systemd:           systemctl list-unit-files --state=enabled --no-pager
                   find /etc/systemd /usr/lib/systemd /lib/systemd -name '*.service' -mtime -30
                   systemctl --user list-unit-files (per-user services!)
                   systemd-analyze security --no-pager (units ranked by exposure)
Init scripts:      ls -la /etc/init.d /etc/rc*.d /etc/profile.d
Login hooks:       cat /etc/profile /etc/bash.bashrc /etc/zsh/zshrc
                   for u in $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do
                     ls -la $u/.bashrc $u/.profile $u/.bash_profile $u/.zshrc 2>/dev/null
                   done
SSH backdoors:     find / -name authorized_keys -exec stat -c '%n %y %U' {} \; 2>/dev/null
                   grep -rE 'PermitRootLogin|AuthorizedKeysFile|ForceCommand' /etc/ssh/
LD_PRELOAD:        cat /etc/ld.so.preload  (almost always EMPTY on a clean box)
                   find / -name 'ld.so.preload' 2>/dev/null
Kernel modules:    lsmod | sort; cat /etc/modules; ls /etc/modules-load.d
                   modinfo MODULE  (check for unsigned/suspicious origins)
PAM tampering:     grep -r 'pam_unix\|pam_exec' /etc/pam.d/  (look for .so paths outside /lib/)
                   ls -la /etc/pam.d/  (recent mtimes = red flag)
Web shells:        find /var/www -name '*.php' -mtime -30 -exec grep -l 'eval\|base64_decode\|assert\|gzinflate' {} \;
                   find /var/www -size +100k -name '*.php'  (suspicious large php = often packed shell)
APT/dpkg hooks:    ls /etc/apt/apt.conf.d/ /var/lib/dpkg/info/*.{preinst,postinst}
                   debsums -c  (show files modified since install — fast integrity sweep)"""

KB[6] = r"""
S6 WINDOWS PERSISTENCE HUNTING (when Ares triages a Win endpoint):
Registry Run keys: reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                   reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
                   reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
                   reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell\ Folders
Scheduled tasks:   schtasks /query /fo LIST /v | findstr /i "Task To Run"
                   Get-ScheduledTask | where State -eq 'Ready' | select TaskName,TaskPath,Actions
Services:          sc query state= all
                   wmic service get name,pathname,startmode,startname /format:csv
                   Get-Service | where Status -eq 'Running' | where {$_.StartType -eq 'Automatic'}
WMI subscriptions: Get-WmiObject -Namespace root\subscription -Class __EventFilter
                   Get-WmiObject -Namespace root\subscription -Class __EventConsumer
                   Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
Startup folders:   dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
                   dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
LSA / SSP:         reg query HKLM\System\CurrentControlSet\Control\Lsa  (Authentication Packages, Security Packages)
AppInit DLLs:      reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
Image File Exec:   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s
DLL search hijack: PowerShell:  Get-Process | foreach { $_.Modules } | where Path -notlike 'C:\Windows\*' -and Path -notlike 'C:\Program*'
Recent persistence: autorunsc.exe -accepteula -nobanner -t -h -s   (Sysinternals — best single tool)
Event-based hunt:  Get-WinEvent -LogName Security -MaxEvents 500 | where Id -in 4624,4625,4672,4688
                   Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where Id -in 1,3,7,11,13"""

KB[7] = r"""
S7 MEMORY FORENSICS (volatility3 — replaced vol2):
Acquire on Linux:  insmod lime.ko 'path=/tmp/mem.lime format=lime'
                   avml /tmp/mem.dump   (alternative)
Identify image:    vol -f IMG.lime banners.Banners        (kernel banner — picks symbols)
                   vol -f IMG.lime windows.info           (Windows)
                   vol -f IMG.lime linux.bash             (recent bash history!)
Process tree:      vol -f IMG windows.pstree
                   vol -f IMG linux.pstree
                   vol -f IMG windows.pslist | grep -iE 'powershell|cmd|rundll32|regsvr32'
Hidden processes:  vol -f IMG windows.psscan       (raw scan vs API)
                   vol -f IMG linux.psaux          (full cmdline)
Network:           vol -f IMG windows.netscan     (open + closed sockets)
                   vol -f IMG linux.sockstat
                   vol -f IMG linux.bash          (commands run while in memory!)
DLLs / modules:    vol -f IMG windows.dlllist --pid PID
                   vol -f IMG windows.ldrmodules --pid PID  (unlinked DLLs = injection)
                   vol -f IMG linux.lsmod
Code injection:    vol -f IMG windows.malfind     (RWX regions, no PE header, etc)
                   vol -f IMG windows.hollowprocesses
                   vol -f IMG windows.threads --pid PID  (look for new threads from non-image bases)
Reg/event extract: vol -f IMG windows.registry.hivelist
                   vol -f IMG windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
Strings dump:      vol -f IMG -o /tmp/dump windows.dumpfiles --virtaddr ADDR
                   strings -e l /tmp/dump/*.dat | grep -iE 'http|cmd|powershell'
File carving:      vol -f IMG windows.filescan | grep -i suspicious
                   vol -f IMG windows.dumpfiles --physaddr 0xPHYS"""

KB[8] = r"""
S8 DISK FORENSICS (sleuthkit + foremost + autopsy):
Image acquisition: dd_rescue /dev/sdX /mnt/evidence/disk.img  (or dc3dd / ewfacquire)
                   ewfacquire /dev/sdX -t /mnt/evidence/disk -c best -f encase6
                   sha256sum /mnt/evidence/*.{img,E01} > /mnt/evidence/HASH.txt
Layout:            mmls disk.img                    (partition table)
                   fsstat -o OFFSET disk.img        (filesystem details)
File listing:      fls -r -m / -o OFFSET disk.img > body.txt   (timeline body file)
                   mactime -b body.txt -d > timeline.csv
                   awk -F, '$1>"2026-05-01"' timeline.csv | head -50
Recover deleted:   fls -d -o OFFSET disk.img        (deleted entries)
                   icat -o OFFSET disk.img INODE > recovered.bin
                   tsk_recover -o OFFSET disk.img /mnt/recovered/
File carving:      foremost -i disk.img -o /tmp/carved -t pdf,jpg,doc,zip
                   scalpel -c scalpel.conf -o /tmp/scalpel disk.img
                   bulk_extractor -o /tmp/bulk disk.img   (emails, URLs, IPs, ccards)
Mount RO:          losetup -fP --read-only disk.img
                   mount -o ro,loop,offset=$((SECTOR*512)) disk.img /mnt/img
USN / journal:     fls -o OFFSET disk.img INODE_OF_USN | head      (NTFS USN journal)
Browser artifacts: cp /home/USER/.mozilla/firefox/*.default*/places.sqlite /tmp/
                   sqlite3 /tmp/places.sqlite 'select datetime(visit_date/1000000,"unixepoch"), url from moz_places mp join moz_historyvisits mh on mh.place_id=mp.id order by 1 desc limit 50'
Shell history:     for u in /home/* /root; do
                     for f in .bash_history .zsh_history .python_history .mysql_history; do
                       [ -f "$u/$f" ] && echo "==$u/$f==" && cat "$u/$f"; done; done"""

KB[9] = r"""
S9 MALWARE STATIC TRIAGE (no execution, no sandbox here):
First five always:
  file SAMPLE                                   # ELF? PE? script? compressed?
  sha256sum SAMPLE                              # IOC pivot
  exiftool SAMPLE                               # PE compile time, original filename
  strings -n 8 SAMPLE | head -200               # urls, ips, command artifacts
  strings -e l SAMPLE | head -100               # UTF-16 strings (Windows binaries)
ELF deeper:        readelf -h SAMPLE            # arch, entry point, type
                   readelf -d SAMPLE            # dynamic section / RPATH / RUNPATH
                   objdump -d SAMPLE | head -200
                   nm -D SAMPLE                 # imported symbols (CSP capabilities)
                   ldd SAMPLE   (NEVER on untrusted samples — it can execute via DT_AUDIT — use readelf instead)
PE deeper:         pefile / pev / die / capa SAMPLE
                   pesec SAMPLE                  # sigchecks, ASLR/DEP flags
                   capa SAMPLE                   # MITRE ATT&CK capability mapping
Packers / obfusc:  Sections with high entropy + tiny imports = packed
                   capstone disasm of entry vs disasm of imports
YARA:              yara /usr/share/yara/rules/index.yar SAMPLE
                   yara -r RULES_DIR DIR_TO_SCAN
                   yara -s RULE SAMPLE                       # show matched strings
                   capa --rules /opt/capa-rules SAMPLE       # capability mapping
ClamAV:            clamscan -ri --no-summary SAMPLE
                   clamdscan --multiscan --fdpass DIR
Hash lookup:       curl -s "https://www.virustotal.com/api/v3/files/$HASH" -H "x-apikey:$VT_KEY" | jq
                   curl -s "https://mb-api.abuse.ch/api/v1/" --data 'query=get_info&hash='$HASH
Document triage:   olevba SAMPLE.doc            # macros / VBA stomping
                   oledump.py SAMPLE.doc
                   pdfid.py SAMPLE.pdf; pdf-parser SAMPLE.pdf
Script triage:     base64 -d / xxd / unhexlify chains; deobfuscate before reading"""

KB[10] = r"""
S10 MITRE ATT&CK DETECTION QUICKREF (most-fired techniques):
Initial Access     T1190 exploit-public-app    →  spike in 4xx → 200 on /admin endpoints
                   T1566 phishing              →  inbound .exe/.lnk; outbound to fresh-registered domains
Execution          T1059.001 PowerShell        →  EID 4104 ScriptBlockLogging; -enc / -e / FromBase64String
                   T1059.003 cmd               →  EID 4688 cmd.exe spawning unusual children
                   T1053 scheduled tasks       →  EID 4698/4702 + suspicious /create
                   T1569.002 service execution →  EID 7045 new service / EID 4697
Persistence        T1547.001 Run keys          →  Sysmon EID 13 RegistryValueSet on Run/RunOnce
                   T1543.003 Windows service   →  EID 4697 + servicename mismatch
                   T1543.002 systemd           →  new .service file in /etc/systemd; auditd execve of systemctl enable
                   T1505.003 webshell          →  new .php in /var/www with eval/base64_decode
Privilege Escal    T1548.003 sudo abuse        →  /var/log/auth.log sudo command outside policy
                   T1068 kernel exploit        →  uname jump; kernel.taint nonzero
                   T1134 token impersonation   →  EID 4624 logon type 9 (NewCredentials)
Defense Evasion    T1070.004 file deletion     →  auditd PATH events with delete + recent file
                   T1027 obfuscated payload    →  EID 4104 base64 / FromBase64String / -nop -w hidden
                   T1562.001 disable security  →  EID 4719 audit policy change; service stop on sysmon/AV
Credential Access  T1003 credential dumping    →  lsass touched by non-svchost; secretsdump signatures
                   T1110 brute force           →  auth.log Failed password rate; EID 4625 burst
Discovery          T1046 service scan          →  sudden TCP SYN burst from one src; nmap UA in HTTP
                   T1083 file/dir enum         →  find/dir/ls bursts shortly after foothold
Lateral Movement   T1021.002 SMB/admin shares  →  EID 5140 share access; ipc$ + admin$ from non-admin
                   T1021.006 WinRM             →  TCP 5985/5986 from non-mgmt host
Command & Control  T1071 protocol abuse        →  long-lived TLS to fresh-registered SNI; beacon timing
                   T1090 proxy                 →  outbound to known proxy ports / TOR exits
Exfil              T1041 over C2               →  byte-volume anomaly in baseline
                   T1048.003 over alt-protocol →  unexpected DNS TXT volume; ICMP w/ payload
SIGMA conversion:  sigma convert -t splunk RULE.yml
                   chainsaw hunt -s rules/ -m mapping.yml /mnt/evidence/EVTX/
                   hayabusa csv-timeline -d /mnt/evidence/EVTX/ -o timeline.csv"""

KB[11] = r"""
S11 HARDENING BASELINES & AUDIT (defender configs you should verify):
Lynis:             lynis audit system --quick                  # fast pass
                   lynis audit system --tests-from-group authentication,malware
                   cat /var/log/lynis-report.dat | grep -E 'warning|suggestion'
OpenSCAP:          oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
                       --report report.html /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
SSH baseline:      grep -E '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding|MaxAuthTries|ClientAliveInterval)' /etc/ssh/sshd_config
                   ssh-audit localhost                          # cipher / KEX / MAC audit
sysctl hardening:  sysctl -a | grep -E 'kernel.kptr_restrict|kernel.dmesg_restrict|kernel.yama.ptrace_scope|net.ipv4.conf.all.rp_filter|net.ipv4.tcp_syncookies'
Kernel hardening:  /proc/sys/kernel/randomize_va_space     (=2 on hardened systems)
                   /sys/kernel/security/lockdown            (integrity / confidentiality)
                   kernel-hardening-checker -c /proc/config.gz
File perms drift:  debsums -c                              # changed package files
                   rpm -Va                                  # RHEL equivalent
                   aide --check                             # vs baseline
                   find / -nouser -o -nogroup 2>/dev/null   # orphaned files
World-writable:    find / -xdev -type f -perm -002 2>/dev/null
                   find / -xdev -type d -perm -002 ! -perm -1000 2>/dev/null   (no sticky bit)
SUID/SGID:         find / -perm -4000 -type f 2>/dev/null
                   find / -perm -2000 -type f 2>/dev/null
Capabilities:      getcap -r / 2>/dev/null
                   capsh --print
PAM / login:       grep -E 'pam_(faillock|tally2|wheel|securetty)' /etc/pam.d/*
                   grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|UMASK)' /etc/login.defs
Firewall:          ufw status verbose
                   nft list ruleset
                   iptables -L -n -v --line-numbers
fail2ban:          fail2ban-client status
                   fail2ban-client status sshd"""

KB[12] = r"""
S12 IDENTITY / ACCOUNT DEFENSE:
Local account audit:
  awk -F: '$3<1000' /etc/passwd                # system accounts — should be tiny, all /sbin/nologin
  awk -F: '($3>=1000)&&($1!="nobody"){print $1,$6,$7}' /etc/passwd   # human users
  awk -F: '$2==""' /etc/shadow                  # EMPTY PASSWORD = critical
  awk -F: '$2~/^!|^\*/ {next} {print $1}' /etc/shadow   # accounts with set passwords
  for u in $(awk -F: '$3>=1000 {print $1}' /etc/passwd); do
    chage -l $u | grep -E 'expires|change'
  done
sudo / wheel:      grep -E '^(wheel|sudo|admin|adm):' /etc/group
                   getent group sudo wheel
                   visudo -c                                  # syntax + risky directives
                   cat /etc/sudoers.d/*                       # NOPASSWD entries are red flags
SSH key audit:     for u in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
                     [ -f "$u" ] && stat -c '%n %y %U' $u && cat $u; done
                   ls -la /etc/ssh/sshd_config.d/             # drop-in overrides
LDAP / SSSD:       sssctl user-checks USER
                   getent passwd USER
                   ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config "(objectClass=olcOverlayConfig)"
Kerberos:          klist -ke /etc/krb5.keytab; kadmin.local listprincs
                   ksu -n -c 'klist'
Active Directory (defender side, via samba-tool / ldapsearch):
                   samba-tool user list                       (privileged users)
                   samba-tool group listmembers 'Domain Admins'
                   samba-tool user list --base-dn=OU=Service,DC=corp,DC=local
                   ldapsearch -H ldap://DC -D 'corp\admin' -W -b 'CN=Users,DC=corp,DC=local' '(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)'
Account anomaly:   last -F | awk '{print $1,$3}' | sort | uniq -c | sort -rn   (login frequency by source)
                   awk -F, '$NF==1' /var/log/audit/audit.log | head             (auth failures via auditd)
Lockout policy:    grep -E 'deny|unlock_time|fail_interval' /etc/pam.d/common-auth /etc/pam.d/system-auth"""

KB[13] = r"""
S13 CLOUD / CONTAINER DEFENSE:
Docker host:       docker ps; docker ps -a
                   docker images --digests
                   for c in $(docker ps -q); do docker inspect $c | jq '.[]|{Name,Mounts,Privileged:.HostConfig.Privileged,CapAdd:.HostConfig.CapAdd,SecurityOpt:.HostConfig.SecurityOpt}'; done
                   docker version --format '{{.Server.Version}}'
Risky containers:  any with --privileged, CAP_SYS_ADMIN, /var/run/docker.sock mounted, host pid/net
Image scan:        trivy image IMAGE:TAG --severity HIGH,CRITICAL
                   grype IMAGE:TAG
                   syft IMAGE:TAG -o spdx > sbom.json
                   dockle IMAGE:TAG
Runtime detection: falco --validate /etc/falco/falco_rules.yaml
                   falco -r /etc/falco/falco_rules.yaml -o json_output=true
Kubernetes:        kubectl get pods -A -o wide
                   kubectl auth can-i --list --as=system:serviceaccount:NS:SA
                   kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[]|select(.subjects[]?.kind=="ServiceAccount")'
                   kube-bench run                           # CIS K8s benchmark
                   kube-hunter --remote CLUSTER_IP
                   kubectl get networkpolicy -A
                   kubectl get psp,Constraints -A 2>/dev/null
Cloud (AWS):       aws iam list-users; aws iam list-roles
                   aws cloudtrail lookup-events --max-items 20
                   prowler -g cislevel1
                   scoutsuite aws --profile PROFILE
Cloud (GCP/Azure): scoutsuite gcp/azure ...; prowler --provider PROVIDER
Container escape signs:
  /proc/1/cgroup shows '/' (instead of /docker/HASH)  → broken-out container OR host
  capsh --print on host should NOT show CapInh including CAP_SYS_ADMIN unexpectedly
  unexpected mount of host /var/run/docker.sock inside containers"""

KB[14] = r"""
S14 DECISION TREES (when stuck, pivot here):
Triage stuck → run lynis quick → ss listening → ps tree → recent /etc mtime →
   journalctl errors today → SUID drift → cron sweep → systemd new units
Suspected compromise but no clear IOC →
   collect bash_history (every user) → /tmp + /var/tmp recent files →
   listening ports vs expected → cap_dac_read_search outside /usr/bin →
   memory image (avml) → volatility psscan/malfind → sweep with chainsaw
Persistence found, scope unknown →
   timestamp of artifact → grep that timestamp in auth.log + journalctl →
   check WHO had session at that time → IPs from auth.log → cross-host
   queries via ssh -o BatchMode=yes (own infra only) → repeat sweep
Network IDS alert but no host indicator →
   tshark -r pcap -Y "ip.addr==SUSPECT" → ss on dst host for matching pid →
   lsof -i :PORT on host → ps -p PID -o user,cmd → file /proc/PID/exe →
   yara /opt/rules /proc/PID/exe (or the on-disk path)
Malware found, want family/IOCs →
   strings + capa + yara → VT/MalwareBazaar hash lookup → MITRE technique map →
   pivot on C2 hostname/IP → block at firewall → search SIEM for same hash
Hardening failure (lynis warning) → identify benchmark control →
   plan change → snapshot → apply → re-run lynis → diff
Web breach suspected → access.log 4xx→200 for /admin/login →
   sudden new files in webroot newer than deploy timestamp →
   webshell yara scan → systemd service for php-fpm if injected →
   db audit log for risky queries"""

KB[15] = r"""
S15 TLS / ENCRYPTION HYGIENE (defender side):
Audit own surface: sslscan --no-failed HOST:443
                   testssl.sh --severity HIGH HOST:443
                   sslyze --regular HOST:443
                   ssh-audit HOST:22                    # SSH protocol audit
Cert chain check:  openssl s_client -connect HOST:443 -showcerts -servername HOST </dev/null
                   openssl x509 -in cert.pem -noout -text -fingerprint -sha256
Look for:          weak ciphers (RC4, 3DES, EXPORT, NULL),
                   old protocols (TLSv1.0/1.1, SSLv2/3),
                   weak DH params (<2048 bits),
                   self-signed where CA expected,
                   expired/expiring (<30d) certs,
                   SAN mismatch / wildcard sprawl,
                   compression on (CRIME),
                   no HSTS / weak HSTS header,
                   missing OCSP stapling.
Hardened defaults: TLS 1.2/1.3 only · ECDHE+AEAD · HSTS max-age>=31536000 · prefer X25519
SSH baseline:      KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,...
                   Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,...
                   MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,...
Cert monitoring:   ct-watch / certstream subscriptions for own domains
                   crt.sh JSON: curl -s 'https://crt.sh/?q=%25.YOURDOMAIN&output=json' | jq '.[].name_value' | sort -u"""

KB[16] = r"""
S16 THREAT INTEL & IOC ENRICHMENT:
Hash lookup:       curl -s "https://www.virustotal.com/api/v3/files/$HASH" -H "x-apikey:$VT_KEY" | jq '.data.attributes.last_analysis_stats'
                   curl -s "https://mb-api.abuse.ch/api/v1/" --data 'query=get_info&hash='$HASH
IP reputation:     curl -s "https://api.abuseipdb.com/api/v2/check" \
                     -H "Key:$ABUSEIPDB_KEY" -d "ipAddress=$IP&maxAgeInDays=90" | jq
                   whois $IP                       (registration / org)
                   curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general"
Domain analysis:   whois $DOMAIN                   (registrar / registrant / created date)
                   curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/general"
                   dig +short $DOMAIN; dig $DOMAIN MX TXT NS
                   curl -s "https://crt.sh/?q=$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u
Passive DNS:       passivetotal-cli p $DOMAIN      (if you have RiskIQ)
                   security trails / circl pdns api endpoints
URL scanner:       curl -s "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN" | jq
File reputation:   capa SAMPLE → MITRE ATT&CK capability map
                   yara -r /opt/yara/rules SAMPLE
MISP / TAXII:      misp-feed-fetcher; opentaxii client to ingest stix bundles
Sigma / TTP:       sigma-cli convert -t elasticsearch RULE.yml
                   chainsaw hunt -s SIGMA_RULES /mnt/evidence/EVTX/
ATT&CK Navigator:  layer JSON in /opt/attack-navigator → import own findings
Quick blocklist:   sudo ufw deny from $BAD_IP
                   sudo nft add element inet filter blackhole \{ $BAD_IP \}
                   echo "0.0.0.0 $BAD_DOMAIN" >> /etc/hosts (host-level)"""


WORKFLOW_KB_MAP = {
    "1":  [2, 3, 14],          # Triage / Health Check
    "2":  [2, 5, 7, 8, 14],    # Live IR — Suspected Compromise
    "3":  [11, 14],            # Hardening Audit
    "4":  [5, 14],             # Linux Persistence Hunt
    "5":  [3, 4, 14],          # Process / Network Anomaly Hunt
    "6":  [3, 12, 14],         # Auth Failure Analysis
    "7":  [9, 14],             # Malware Static Triage
    "8":  [4, 16, 14],         # PCAP Analysis
    "9":  [7, 14],             # Memory Forensics
    "10": [8, 14],             # Disk Forensics
    "11": [3, 10, 14],         # Log Review
    "12": [15, 14],            # TLS / SSL Audit
    "13": [12, 14],            # Account Audit
    "14": [11, 5, 14],         # SUID / Capability Audit
    "15": [2, 11],             # Service Exposure Audit
    "16": [2, 5, 14],          # Linux Post-Compromise IR
    "17": [13, 11, 14],        # Container / Cloud Audit
    "18": [11, 8, 14],         # File Integrity Check
    "19": [4, 10, 14],         # Suricata / Zeek Alert Review
    "20": [4, 10],             # IDS Rule Tuning
    "21": [11, 4],             # Firewall Audit
    "22": [8, 14],             # Forensics Evidence Collection
    "23": [5, 11, 14],         # Rootkit Hunt
}

KEYWORD_KB_MAP = {
    "log|journal|syslog|audit|auth\\.log|auditd|ausearch|aureport": [3, 10],
    "persistence|cron|systemd|backdoor|rootkit|webshell|ld\\.so": [5, 14],
    "windows|registry|sysmon|wmi|powershell|schtasks|evtx|wineve": [6, 10],
    "memory|volatility|lime|avml|ram|core dump|psaux|psscan": [7, 14],
    "disk|forens|sleuth|fls|mactime|carve|foremost|scalpel|pcap-image": [8, 14],
    "yara|malware|sample|virustotal|abuse\\.ch|capa|olevba|pdfid": [9, 16],
    "mitre|attack|sigma|chainsaw|hayabusa|d3fend|navigator|t1[0-9]": [10],
    "hardening|lynis|cis|openscap|baseline|sysctl|kernel\\.": [11],
    "account|user|sudo|passwd|shadow|sssd|kerberos|samba-tool": [12],
    "docker|kubectl|kubernetes|k8s|trivy|falco|kube-bench|container": [13],
    "ssl|tls|cipher|heartbleed|certificate|sslscan|testssl|ssh-audit": [15],
    "ioc|threat\\s+intel|virustotal|abuseipdb|otx|alienvault|crt\\.sh": [16],
    "tcpdump|tshark|zeek|suricata|snort|pcap|wireshark|fast\\.log": [4],
    "triage|incident|breach|compromise|alert|ioc|response": [2, 14],
}


def get_kb_sections(workflow_key: Optional[str] = None,
                    prompt_text: str = "",
                    agent_role: str = "") -> str:
    """Return only the KB sections relevant to this workflow / agent / prompt."""
    section_nums = {1}  # mindset always

    if workflow_key and workflow_key in WORKFLOW_KB_MAP:
        section_nums.update(WORKFLOW_KB_MAP[workflow_key])

    # Agent-role-driven KB selection
    role_map = {
        "triage":             [2, 3, 5, 14],
        "log_analyst":        [3, 10, 14],
        "threat_hunter":      [5, 6, 7, 10, 14],
        "network_defender":   [4, 10, 16],
        "ir_responder":       [2, 5, 7, 8, 14],
        "hardener":           [11, 15, 12],
        "malware_analyst":    [9, 10, 16],
        "forensics_analyst":  [7, 8, 14],
        "identity_defender":  [12, 11, 14],
        "reporter":           [10, 14],
        "strategist":         [1, 14],
    }
    if agent_role in role_map:
        section_nums.update(role_map[agent_role])

    if prompt_text and len(section_nums) <= 2:
        lower = prompt_text.lower()
        for pattern, nums in KEYWORD_KB_MAP.items():
            if re.search(pattern, lower):
                section_nums.update(nums)

    if len(section_nums) == 1:
        section_nums.update([2, 14])

    parts = []
    for num in sorted(section_nums):
        if num in KB:
            parts.append(KB[num])
    return "\n\n".join(parts)


# ═════════════════════════════════════════════════════════════════════
# AGENT SPECIFICATIONS
#
# Each agent is a specialist system-prompt fragment.  Ares's
# dispatcher picks one based on the current PTT node's phase.
# Picking a specialist is NOT a separate LLM call — the dispatcher
# is deterministic, so this is "multi-agent" in design without paying
# the rate-limit cost of multi-agent at runtime.
# ═════════════════════════════════════════════════════════════════════

AGENT_SPECS = {

    "strategist": {
        "name": "STRATEGIST",
        "icon": "♛",
        "color": "35",  # magenta
        "persona": (
            "You are Ares' Strategist agent.  Your job is to read the "
            "Defense Task Tree (DTT) and decide which child node to attack "
            "next, OR add a new child node when an alert/finding reveals "
            "a new investigation path.  You do NOT write commands.  You "
            "output a routing decision."
        ),
        "extra_rules": (
            "OUTPUT FORMAT:\n"
            "[THOUGHT]<one paragraph reasoning over DTT state>[/THOUGHT]\n"
            "[NEXT_NODE]<node id from DTT, e.g. 1.2.3>[/NEXT_NODE]\n"
            "[AGENT]<one of: triage, log_analyst, threat_hunter, "
            "network_defender, ir_responder, hardener, malware_analyst, "
            "forensics_analyst, identity_defender, reporter>[/AGENT]\n"
            "[CONF]<green|yellow|red>[/CONF]\n"
            "Use WORKFLOW_COMPLETE in [NEXT_NODE] when the root goal is met."
        ),
    },

    "triage": {
        "name": "TRIAGE SPECIALIST",
        "icon": "🚨",
        "color": "33",  # yellow
        "persona": (
            "You are Ares' Triage specialist.  First-30-minutes of an "
            "investigation: rapid host health check, listening sockets, "
            "running processes, recent file changes, sudo/auth bursts.  "
            "Quiet, READ-ONLY, broad coverage.  You decide whether the "
            "host is healthy, suspicious, or actively compromised."
        ),
        "extra_rules": (
            "Default to: id, ss -tlnp, ps auxf, journalctl --since '24 hours ago' "
            "-p err, find /etc /usr/local -mmin -1440 -type f, last -n 50, "
            "lastb -n 30, getent passwd | wc -l, lsof +L1 (deleted-but-held).  "
            "When you have a verdict (healthy / suspicious / compromised) say "
            "WORKFLOW_COMPLETE or hand off via [HANDOFF]<role>[/HANDOFF].  "
            "Never run commands that modify system state."
        ),
    },

    "log_analyst": {
        "name": "LOG ANALYST",
        "icon": "📜",
        "color": "36",  # cyan
        "persona": (
            "You are Ares' Log Analyst.  journalctl, /var/log, auditd, "
            "rsyslog, web server access logs.  You correlate events across "
            "sources to build timelines and surface anomalies."
        ),
        "extra_rules": (
            "Always pin a time window first ('--since', '--until').  Prefer "
            "ausearch/aureport over raw audit.log.  Sort -u and uniq -c "
            "for frequency analysis.  When you spot bursts of failures or "
            "novel sources, propagate to threat_hunter via [HANDOFF].  "
            "Flag every successful auth from a new geography or off-hours."
        ),
    },

    "threat_hunter": {
        "name": "THREAT HUNTER",
        "icon": "🩻",
        "color": "31",  # red
        "persona": (
            "You are Ares' Threat Hunter.  Active hunting for persistence, "
            "lateral movement, and dormant implants.  ATT&CK-driven, "
            "hypothesis-led.  You assume breach and look for what triage "
            "missed."
        ),
        "extra_rules": (
            "Cycle through: cron, systemd units, login hooks, ld.so.preload, "
            "kernel modules, PAM tampering, web shells, deleted-but-running, "
            "WMI subscriptions (Win), Run keys (Win).  For each hypothesis "
            "name the ATT&CK technique you're testing.  No execution, "
            "no quarantine — only evidence collection.  Hand findings to "
            "ir_responder when containment is appropriate."
        ),
    },

    "network_defender": {
        "name": "NETWORK DEFENDER",
        "icon": "🌐",
        "color": "34",  # blue
        "persona": (
            "You are Ares' Network Defender.  Suricata, Zeek, tshark, "
            "tcpdump, firewalls.  You analyse pcaps, tune IDS rules, "
            "validate egress controls, and triage network-layer alerts."
        ),
        "extra_rules": (
            "Always bound captures (tcpdump -c N or -G N -W M).  Read pcaps "
            "with tshark -r FILE -Y 'filter' rather than launching wireshark.  "
            "For Suricata alerts use jq on eve.json, then pivot to host-side "
            "via lsof/ss to attribute the PID.  When proposing rule changes, "
            "always test offline against a pcap first."
        ),
    },

    "ir_responder": {
        "name": "INCIDENT RESPONDER",
        "icon": "🛟",
        "color": "91",  # bright red
        "persona": (
            "You are Ares' Incident Responder.  Containment, eradication, "
            "recovery.  You actually touch the system — kill processes, "
            "block IPs, revoke sessions, quarantine files — but every "
            "destructive action goes through DOUBLE-CONFIRM."
        ),
        "extra_rules": (
            "Order: contain → preserve evidence → eradicate → recover.  "
            "BEFORE killing a process, capture: ps -p PID -o user,pid,etime,cmd, "
            "lsof -p PID, cat /proc/PID/maps, /proc/PID/exe -> readlink.  "
            "BEFORE quarantining a file, sha256sum + cp to evidence dir.  "
            "BEFORE blocking an IP, log it to /var/log/ares/blocks.log.  "
            "Never disable logging or audit rules during an incident."
        ),
    },

    "hardener": {
        "name": "HARDENING AUDITOR",
        "icon": "🛡",
        "color": "32",  # green
        "persona": (
            "You are Ares' Hardening Auditor.  Lynis, OpenSCAP, sysctl, "
            "PAM, SSH, firewall, file perms.  You compare current config "
            "against CIS / DISA STIG baselines and surface drift."
        ),
        "extra_rules": (
            "Run lynis --quick first for a fast pass, then drill into the "
            "warning categories.  Always capture before/after when proposing "
            "changes — defensive paranoia.  Prefer reading config files "
            "directly (grep -E on sshd_config, login.defs, sysctl.conf) "
            "over running parsers.  No changes without DOUBLE-CONFIRM."
        ),
    },

    "malware_analyst": {
        "name": "MALWARE ANALYST",
        "icon": "🧬",
        "color": "35",  # magenta
        "persona": (
            "You are Ares' Malware Analyst.  Static-only triage: file, "
            "strings, exiftool, readelf, capa, yara, clamav.  You never "
            "execute samples — that's a sandbox's job, not Ares'."
        ),
        "extra_rules": (
            "First five always: file, sha256sum, exiftool, strings -n 8, "
            "strings -e l (UTF-16).  Then capa for capability map and yara "
            "for family ID.  Pivot the hash through VirusTotal / abuse.ch / "
            "OTX.  Output an IOC bundle: hashes, network indicators, "
            "host-based artifacts, ATT&CK techniques."
        ),
    },

    "forensics_analyst": {
        "name": "FORENSICS ANALYST",
        "icon": "🔬",
        "color": "94",
        "persona": (
            "You are Ares' Forensics specialist.  Memory (volatility3) and "
            "disk (sleuthkit, foremost, autopsy).  Evidence handling, "
            "chain of custody, timeline reconstruction."
        ),
        "extra_rules": (
            "ALWAYS hash the image before and after analysis (sha256sum).  "
            "Mount disk images READ-ONLY (mount -o ro,loop).  Build "
            "timelines via fls + mactime.  For memory: vol -f IMG <plugin> "
            "where plugin is one of: pstree, psscan, malfind, netscan, "
            "ldrmodules, dumpfiles.  Capture original commands in evidence."
        ),
    },

    "identity_defender": {
        "name": "IDENTITY DEFENDER",
        "icon": "🪪",
        "color": "33",
        "persona": (
            "You are Ares' Identity / Account specialist.  Local users, "
            "sudoers, SSH keys, Kerberos, SSSD, LDAP, AD (defender side)."
        ),
        "extra_rules": (
            "Always check: shadow entries with empty password, sudoers "
            "NOPASSWD, world-readable authorized_keys, last-login age, "
            "stale accounts (chage), wheel/sudo group membership.  For AD: "
            "samba-tool / ldapsearch in read-only queries.  Never lock an "
            "account without DOUBLE-CONFIRM and an evidence record."
        ),
    },

    "reporter": {
        "name": "REPORTING / CLEANUP",
        "icon": "📋",
        "color": "97",
        "persona": (
            "You are Ares' Reporter agent.  You consolidate findings, drop "
            "unverified noise, and write a clean engagement report."
        ),
        "extra_rules": (
            "Output structure: Executive Summary, Confirmed Findings (by "
            "MITRE ATT&CK technique), Timeline, Containment Actions Taken, "
            "Remaining Risks, Recommended Hardening.  Drop anything flagged "
            "unverified.  Every finding must cite the source command."
        ),
    },
}


# Phase → preferred agent role mapping (used by deterministic dispatcher)
PHASE_TO_AGENT = {
    # Triage / health
    "triage":           "triage",
    "health":           "triage",
    "initial":          "triage",
    # Logs
    "log":              "log_analyst",
    "logs":             "log_analyst",
    "audit_log":        "log_analyst",
    "auth_log":         "log_analyst",
    # Hunt
    "hunt":             "threat_hunter",
    "threat_hunt":      "threat_hunter",
    "persistence":      "threat_hunter",
    "anomaly":          "threat_hunter",
    # Network defence
    "network_defense":  "network_defender",
    "ids":              "network_defender",
    "ips":              "network_defender",
    "pcap":             "network_defender",
    "suricata":         "network_defender",
    "zeek":             "network_defender",
    # IR
    "ir":               "ir_responder",
    "incident":         "ir_responder",
    "containment":      "ir_responder",
    "eradication":      "ir_responder",
    # Hardening
    "hardening":        "hardener",
    "audit":            "hardener",
    "baseline":         "hardener",
    "config_audit":     "hardener",
    # Malware
    "malware":          "malware_analyst",
    "static_triage":    "malware_analyst",
    "yara":             "malware_analyst",
    # Forensics
    "forensics":        "forensics_analyst",
    "memory":           "forensics_analyst",
    "disk":             "forensics_analyst",
    "timeline":         "forensics_analyst",
    # Identity
    "identity":         "identity_defender",
    "account":          "identity_defender",
    "ad_defense":       "identity_defender",
    # Reporting
    "report":           "reporter",
}


# ═════════════════════════════════════════════════════════════════════
# PENTESTING TASK TREE (PTT)
#
# Hierarchical state.  Each node tracks status / confidence / findings /
# attempts / tool / parent / children.  Replaces v6.1's flat findings
# dict.  The whole tree gets serialised to natural language for system
# prompts so the LLM sees the entire engagement state every turn.
# ═════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Source-tagged finding.  Phantoms can't sneak in because every
    finding records the exact subprocess command that produced it.
    v7.1: now carries optional MITRE ATT&CK technique tag."""
    fid:       int
    value:     str
    ftype:     str               # ip, port, user, hash, cred, cve, ...
    source_cmd: str              # the shell command that produced this
    node_id:    str              # which PTT node was active
    verified:   bool = False
    notes:      str = ""
    timestamp:  str = ""
    attack_id:  str = ""         # v7.1 — MITRE ATT&CK technique ID
    attack_name: str = ""        # v7.1 — human-readable name
    attack_tactic: str = ""      # v7.1 — tactic category

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PTTNode:
    nid:        str               # dotted id, e.g. "1.2.3"
    title:      str
    phase:      str               # recon, enum, web, ad, linux_post, ...
    status:     str = "todo"      # todo, in_progress, done, dead_end, skipped
    confidence: str = "green"     # green, yellow, red
    parent_id:  Optional[str] = None
    children:   List[str] = field(default_factory=list)
    findings:   List[int] = field(default_factory=list)
    attempts:   int = 0
    last_cmd:   str = ""
    notes:      str = ""

    @property
    def depth(self) -> int:
        return self.nid.count(".")


class PTT:
    """Defense Task Tree (DTT).

    Provides:
      - hierarchical task state
      - findings storage with source-tagging
      - natural-language serialiser for LLM prompts
      - terminal renderer for the REPL
      - dead-end detection + sibling lookup for backtracking
    """

    STATUS_GLYPH = {
        "todo":         "○",
        "in_progress":  "◐",
        "done":         "●",
        "dead_end":     "✗",
        "skipped":      "─",
    }
    CONF_COLOR = {
        "green":  "32",
        "yellow": "33",
        "red":    "31",
    }

    def __init__(self, goal: str = "Compromise target"):
        self.nodes: Dict[str, PTTNode] = {}
        self.findings: List[Finding] = []
        self._next_finding_id = 1
        self.root_id = "0"
        # Root node represents the overall mission
        self.nodes[self.root_id] = PTTNode(
            nid=self.root_id, title=goal, phase="root", status="in_progress"
        )

    # ─── Tree construction ─────────────────────────────────────────

    def add_node(self, parent_id: str, title: str, phase: str,
                 status: str = "todo") -> str:
        if parent_id not in self.nodes:
            raise ValueError(f"Unknown parent: {parent_id}")
        parent = self.nodes[parent_id]
        idx = len(parent.children) + 1
        nid = f"{parent_id}.{idx}" if parent_id != self.root_id else str(idx)
        node = PTTNode(nid=nid, title=title, phase=phase,
                       status=status, parent_id=parent_id)
        self.nodes[nid] = node
        parent.children.append(nid)
        return nid

    # ─── Status & status helpers ────────────────────────────────────

    def set_status(self, nid: str, status: str):
        if nid in self.nodes:
            self.nodes[nid].status = status

    def set_confidence(self, nid: str, conf: str):
        if nid in self.nodes and conf in ("green", "yellow", "red"):
            self.nodes[nid].confidence = conf

    def increment_attempts(self, nid: str):
        if nid in self.nodes:
            self.nodes[nid].attempts += 1

    def set_last_cmd(self, nid: str, cmd: str):
        if nid in self.nodes:
            self.nodes[nid].last_cmd = cmd[:200]

    # ─── Active node + frontier selection ──────────────────────────

    def find_in_progress(self) -> Optional[PTTNode]:
        for n in self.nodes.values():
            if n.status == "in_progress" and n.nid != self.root_id:
                return n
        return None

    def find_next_pending(self) -> Optional[PTTNode]:
        """Depth-first: return first todo node, preferring deeper subtrees."""
        # Sort by depth descending so deepest todos go first when their
        # parents are in_progress (we want to finish current branch).
        active = self.find_in_progress()
        if active:
            # Look at children of the active node first
            for cid in active.children:
                cn = self.nodes.get(cid)
                if cn and cn.status == "todo":
                    return cn
        # Otherwise just return any todo, shallow-first
        todos = [n for n in self.nodes.values()
                 if n.status == "todo" and n.nid != self.root_id]
        if not todos:
            return None
        todos.sort(key=lambda n: (n.depth, n.nid))
        return todos[0]

    def find_pending_siblings(self, nid: str) -> List[PTTNode]:
        n = self.nodes.get(nid)
        if not n or not n.parent_id:
            return []
        parent = self.nodes[n.parent_id]
        return [self.nodes[cid] for cid in parent.children
                if cid != nid and self.nodes[cid].status == "todo"]

    def all_done(self) -> bool:
        for n in self.nodes.values():
            if n.nid == self.root_id:
                continue
            if n.status in ("todo", "in_progress"):
                return False
        return True

    # ─── Findings ──────────────────────────────────────────────────

    def add_finding(self, value: str, ftype: str, source_cmd: str,
                    node_id: str, verified: bool = False,
                    notes: str = "") -> int:
        # de-dup by (ftype, value)
        for f in self.findings:
            if f.ftype == ftype and f.value == value:
                # Promote verification status if this run verified it
                if verified and not f.verified:
                    f.verified = True
                    f.source_cmd = source_cmd
                if node_id not in [f.node_id]:
                    pass  # keep first node that found it
                return f.fid
        fid = self._next_finding_id
        self._next_finding_id += 1
        f = Finding(fid=fid, value=value, ftype=ftype,
                    source_cmd=source_cmd, node_id=node_id,
                    verified=verified, notes=notes,
                    timestamp=datetime.datetime.now().isoformat(timespec="seconds"))
        self.findings.append(f)
        if node_id in self.nodes:
            self.nodes[node_id].findings.append(fid)
        return fid

    def get_findings_by_type(self, ftype: str,
                             only_verified: bool = False) -> List[Finding]:
        result = []
        for f in self.findings:
            if f.ftype != ftype:
                continue
            if only_verified and not f.verified:
                continue
            result.append(f)
        return result

    def get_unverified(self) -> List[Finding]:
        return [f for f in self.findings if not f.verified]

    def get_verified(self) -> List[Finding]:
        return [f for f in self.findings if f.verified]

    def drop_unverified(self):
        """Cleanup pass: remove findings that were never verified.
        Called once at report-generation time."""
        kept = [f for f in self.findings if f.verified]
        self.findings = kept

    # ─── Serialisation for LLM prompts ─────────────────────────────

    def to_natural_language(self, max_chars: int = 2000) -> str:
        """Render the tree as nested bullets for the system prompt.
        Compact form; deeper nodes get less verbose status."""
        lines = ["PENTESTING TASK TREE:"]
        root = self.nodes[self.root_id]
        lines.append(f"[{self.root_id}] {root.title}")
        for cid in root.children:
            self._serialise_subtree(cid, lines, indent=1)
        text = "\n".join(lines)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... [tree truncated for context]"
        return text

    def _serialise_subtree(self, nid: str, lines: List[str], indent: int):
        n = self.nodes.get(nid)
        if not n:
            return
        glyph = self.STATUS_GLYPH.get(n.status, "?")
        prefix = "  " * indent
        line = f"{prefix}{glyph} [{n.nid}] {n.title} ({n.phase}, status={n.status}"
        if n.attempts:
            line += f", attempts={n.attempts}"
        if n.findings:
            line += f", findings={len(n.findings)}"
        line += ")"
        lines.append(line)
        for cid in n.children:
            self._serialise_subtree(cid, lines, indent + 1)

    # ─── Terminal renderer (pretty print) ──────────────────────────

    def to_terminal(self) -> str:
        """Coloured tree for the REPL."""
        out = []
        root = self.nodes[self.root_id]
        out.append(f"\033[35m\033[1m  ♔ MISSION: {root.title}\033[0m")
        for i, cid in enumerate(root.children):
            is_last = (i == len(root.children) - 1)
            self._render_subtree(cid, out, prefix="  ", is_last=is_last)
        return "\n".join(out)

    def _render_subtree(self, nid: str, out: List[str],
                        prefix: str, is_last: bool):
        n = self.nodes.get(nid)
        if not n:
            return
        connector = "└─" if is_last else "├─"
        glyph = self.STATUS_GLYPH.get(n.status, "?")
        conf_color = self.CONF_COLOR.get(n.confidence, "37")

        # Color glyph by status
        status_colors = {
            "todo":        "90",
            "in_progress": "33",
            "done":        "32",
            "dead_end":    "31",
            "skipped":     "90",
        }
        gc = status_colors.get(n.status, "37")

        line = (
            f"{prefix}{connector}\033[{gc}m{glyph}\033[0m "
            f"\033[{conf_color}m[{n.nid}]\033[0m "
            f"\033[97m{n.title}\033[0m "
            f"\033[90m({n.phase})\033[0m"
        )
        if n.findings:
            line += f" \033[36m·{len(n.findings)}f\033[0m"
        if n.attempts:
            line += f" \033[90m·a{n.attempts}\033[0m"
        out.append(line)

        new_prefix = prefix + ("   " if is_last else "│  ")
        for i, cid in enumerate(n.children):
            child_last = (i == len(n.children) - 1)
            self._render_subtree(cid, out, new_prefix, child_last)

    # ─── Aggregate views (replaces v6.1 flat findings dict) ────────

    def findings_by_type_dict(self,
                              only_verified: bool = False) -> Dict[str, List[str]]:
        """Backward-compat view: legacy code expects a dict."""
        d: Dict[str, List[str]] = {}
        for f in self.findings:
            if only_verified and not f.verified:
                continue
            d.setdefault(f.ftype, []).append(f.value)
        return d


# ═════════════════════════════════════════════════════════════════════
# UTILITIES
# ═════════════════════════════════════════════════════════════════════

def get_lhost() -> str:
    try:
        r = subprocess.run(
            "hostname -I | awk '{print $1}'",
            shell=True, capture_output=True, text=True
        )
        ip = r.stdout.strip()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def ensure_yara_rules() -> Optional[str]:
    """Return the first YARA rule directory that exists on the system,
    or None if no ruleset is installed.  Mirrors Athena's ensure_rockyou
    pattern but for defensive rulesets.  Caller (ToolBuilder.yara_scan)
    falls back to scanning without rules if this returns None."""
    for path in YARA_RULE_PATHS:
        if os.path.isdir(path):
            return path
    return None


def cmd_exists(cmd: str) -> bool:
    try:
        r = subprocess.run(f"which {cmd} 2>/dev/null", shell=True,
                           capture_output=True, text=True)
        return bool(r.stdout.strip())
    except Exception:
        return False


def get_default_yara_rules() -> Optional[str]:
    """Find a sensible default rules file or directory.  Used when the
    LLM emits a yara_scan call without specifying `rules`."""
    return ensure_yara_rules()


def get_default_sigma_rules() -> Optional[str]:
    for path in SIGMA_RULE_PATHS:
        if os.path.isdir(path):
            return path
    return None


def install_if_missing(tool: str) -> bool:
    if cmd_exists(tool):
        return True
    try:
        print(f"\033[33m   Auto-installing {tool}...\033[0m")
        subprocess.run(
            f"sudo apt install -y {tool} 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=90
        )
        return cmd_exists(tool)
    except Exception:
        return False


def detect_sensitive_paths(output: str) -> List[str]:
    found = []
    for pattern in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, output):
            cleaned = pattern.replace('\\', '').strip('/')
            if cleaned not in found:
                found.append(cleaned)
    return found


# ─── Source-tagged finding extraction ─────────────────────────────────
#
# Critical fix from v6.1: ONLY runs against raw subprocess stdout.
# Never against AI's prose.  Every finding records the command that
# produced it.  Strict context-aware patterns prevent the "200:not"
# style phantom credentials.
# ─────────────────────────────────────────────────────────────────────

def extract_findings_from_stdout(output: str,
                                 source_cmd: str,
                                 ptt: PTT,
                                 active_node_id: str) -> int:
    """Run regex patterns over RAW subprocess stdout only.

    Returns: number of new findings added.
    """
    if not output or len(output) < 20:
        return 0

    # Strip ANSI codes — they confuse regex
    clean = re.sub(r'\033\[[0-9;]*m', '', output)
    clean = re.sub(r'\x1b\[[0-9;]*m', '', clean)

    new_count = 0

    for ftype, pattern in FINDING_PATTERNS.items():
        try:
            matches = re.findall(pattern, clean, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        if not matches:
            continue

        for m in matches:
            if isinstance(m, tuple):
                # Tuple from groups — pick the first non-empty
                items = [x for x in m if x and len(str(x).strip()) > 1]
            else:
                items = [m] if m else []

            for raw in items:
                val = str(raw).strip().rstrip('.,;:)\'')

                # Quick noise filter
                if len(val) < 2:
                    continue

                if ftype == "ip" and val in IP_NOISE:
                    continue

                if ftype == "domain":
                    if val.lower() in DOMAIN_NOISE:
                        continue
                    # Filter noise like "etc.local", "1.2.3.4"
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', val):
                        continue
                    if "." not in val:
                        continue

                if ftype == "account":
                    # Drop generic placeholders that show up in prose / docs
                    if val.lower() in {"user", "username", "admin", "test",
                                       "example", "yourname"}:
                        continue
                    if len(val) < 3:
                        continue

                if ftype == "hash":
                    # Make sure this is hex-only and right length
                    if not re.fullmatch(r'[a-fA-F0-9]+', val):
                        continue
                    if len(val) not in (32, 40, 56, 64):
                        continue

                # Add to PTT (auto de-dups)
                fid_before = ptt._next_finding_id
                fid = ptt.add_finding(value=val, ftype=ftype,
                                source_cmd=source_cmd,
                                node_id=active_node_id)
                if ptt._next_finding_id > fid_before:
                    new_count += 1
                    # Auto-tag with ATT&CK technique
                    # Prefer command-based pattern, fall back to ftype-based
                    tag = attack_id_for_command(source_cmd) or attack_id_for_finding(ftype)
                    if tag and ptt.findings:
                        f_obj = ptt.findings[-1]
                        if f_obj.fid == fid:
                            f_obj.attack_id, f_obj.attack_name, f_obj.attack_tactic = tag

    # Detect critical-path writes / exposures separately
    for path in detect_sensitive_paths(clean):
        fid_before = ptt._next_finding_id
        ptt.add_finding(value=path, ftype="persistence",
                        source_cmd=source_cmd, node_id=active_node_id,
                        notes="critical path touched")
        if ptt._next_finding_id > fid_before:
            new_count += 1
            tag = attack_id_for_finding("persistence")
            if tag and ptt.findings:
                f_obj = ptt.findings[-1]
                f_obj.attack_id, f_obj.attack_name, f_obj.attack_tactic = tag

    return new_count


def auto_cve_lookup(output: str) -> str:
    """When a CVE appears in output, surface defender-relevant advisories
    rather than offensive exploit code.  Looks up the local NVD cache via
    the lynis cvelookup helper if present; otherwise just normalises the
    CVE for the operator's [THOUGHT] block."""
    cve_matches = re.findall(r'CVE-\d{4}-\d+', output, re.IGNORECASE)
    if not cve_matches:
        return ""
    seen = set()
    results = []
    for cve in cve_matches[:5]:
        cve = cve.upper()
        if cve in seen:
            continue
        seen.add(cve)
        # Defender advisory — keep it short.  Real lookup happens via
        # the AI agent issuing a curl to NVD or Vulners.
        results.append(
            f"\n\033[34m[CVE TO TRIAGE: {cve}]\033[0m\n"
            f"  Patch?    apt list --upgradable | grep -E 'security|cve' "
            f"or check vendor advisory.\n"
            f"  Detect?   sigma-cli rule search '{cve}' | "
            f"chainsaw against EVTX.\n"
            f"  Lookup:   curl -s "
            f"'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}' | jq '.vulnerabilities[0].cve.descriptions[0].value'"
        )
    return "".join(results)


def analyze_and_suggest_exploit(cve: str, target: str, lhost: str) -> str:
    """Defensive variant of Athena's exploit-suggestion helper.  Instead
    of proposing an attack, it surfaces detection rules and patch
    guidance for the CVE.  Signature kept for compatibility with the
    session loop that calls this when a CVE finding lands."""
    if not cve:
        return ""
    cve = cve.upper().strip()
    out  = f"\n\033[34m{'='*60}\033[0m\n"
    out += f"\033[34m🛡  DEFENSIVE TRIAGE: {cve}\033[0m\n"
    out += f"\033[34m{'='*60}\033[0m\n"
    out += "\n\033[33m[DETECT]\033[0m  Look for IOCs / sigma rule matches:\n"
    out += f"  curl -s 'https://otx.alienvault.com/api/v1/indicators/cve/{cve}/general' | jq\n"
    out += f"  sigma-cli rule search '{cve}'\n"
    out += "\n\033[33m[PATCH]\033[0m  Check whether a fixed version is available:\n"
    out += "  apt list --upgradable 2>/dev/null | grep -i security\n"
    out += "  debsums -c | head\n"
    out += "\n\033[33m[MITIGATE]\033[0m  If patch unavailable, look for compensating\n"
    out += f"  controls — disable feature, restrict via firewall, audit access.\n"
    out += f"\n\033[34m{'='*60}\033[0m\n"
    return out


def compress_output_for_history(output: str,
                                is_exploit_result: bool = False) -> str:
    """Aggressive compression of terminal output for AI context.
    Exploit results are kept intact (creds/shells matter)."""
    if is_exploit_result:
        return output[:MAX_OUTPUT_CHARS]

    output = re.sub(r'\033\[[0-9;]*m', '', output)
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)
    lines = output.split('\n')

    junk = re.compile(r'|'.join([
        r'^Stats: ', r'^SYN Stealth Scan Timing', r'^\s*$',
        r'^Reading database', r'^Preparing to unpack',
        r'^Selecting previously', r'^Unpacking ',
        r'^Setting up ', r'^Processing triggers',
        r'^\(Reading database', r'^Get:\d', r'^Hit:\d', r'^Ign:\d',
        r'^Fetched ', r'^WARNING:.*Cannot open MAC',
        r'^Starting Nmap', r'^Nmap done:', r'^Nmap scan report',
    ]))

    cleaned, last = [], None
    for line in lines:
        line = line.rstrip()
        if junk.search(line):
            continue
        if line == last:
            continue
        if len(line) > 240:
            line = line[:240] + "..."
        cleaned.append(line)
        last = line

    result = '\n'.join(cleaned).strip()
    if len(result) > 1800:
        head = result[:800]
        tail = result[-600:]
        result = f"{head}\n[...{len(result)-1400} chars trimmed...]\n{tail}"
    return result or "(no useful output)"


# ─── Visual helpers ───────────────────────────────────────────────────

def hr(width: int = 64, char: str = "─", color: str = "90") -> str:
    return f"\033[{color}m{char * width}\033[0m"


def header_box(text: str, color: str = "35", width: int = 64) -> str:
    """v7.1 — heavier, two-line title bar that looks like a real UI panel."""
    inner = f" {text} ".center(width - 2)
    return (
        f"\033[{color}m╭{'─'*(width-2)}╮\n"
        f"│\033[1m{inner}\033[0m\033[{color}m│\n"
        f"╰{'─'*(width-2)}╯\033[0m"
    )


def panel(title: str, lines: List[str],
          color: str = "35", width: int = 66) -> str:
    """v7.1 — generic bordered panel with title bar.  Used everywhere
    we want a consistent app-like look."""
    out = []
    title_text = f" {title} "
    pad_left = (width - 2 - len(title_text)) // 2
    pad_right = width - 2 - len(title_text) - pad_left
    out.append(f"\033[{color}m╭{'─'*pad_left}\033[1m{title_text}\033[0m"
               f"\033[{color}m{'─'*pad_right}╮\033[0m")
    for ln in lines:
        # strip ANSI to compute true length
        visible = re.sub(r'\033\[[\d;]*m', '', ln)
        pad = max(0, width - 2 - len(visible))
        out.append(f"\033[{color}m│\033[0m {ln}{' ' * (pad - 1)}\033[{color}m│\033[0m")
    out.append(f"\033[{color}m╰{'─'*(width-2)}╯\033[0m")
    return "\n".join(out)


def status_line(model: str, agent: str, node: str,
                findings: int, verified: int) -> str:
    return (
        f"\033[90m[\033[97mmodel\033[90m] \033[36m{model}  "
        f"\033[90m[\033[97magent\033[90m] \033[33m{agent}  "
        f"\033[90m[\033[97mnode\033[90m] \033[97m{node}  "
        f"\033[90m[\033[97mfindings\033[90m] "
        f"\033[32m{verified}\033[90m/\033[97m{findings}\033[0m"
    )


def status_bar(target: str, agent: str, model: str,
               verified: int, unverified: int,
               techniques: int, scope_on: bool, width: int = 66) -> str:
    """v7.1 — persistent status bar shown at top of certain views.
    Like a window-chrome strip."""
    scope_pill = "\033[32m●SCOPE\033[0m" if scope_on else "\033[90m○scope\033[0m"
    target_short = (target[:14] + "…") if len(target) > 15 else target
    bar = (f"\033[97m▍\033[0m \033[36m{target_short:<15}\033[0m "
           f"\033[90m│\033[0m \033[33m{agent:<8}\033[0m "
           f"\033[90m│\033[0m \033[36m{model[:14]:<14}\033[0m "
           f"\033[90m│\033[0m \033[32m✓{verified}\033[0m\033[90m/\033[33m?{unverified}\033[0m "
           f"\033[90m│\033[0m \033[31mATT&CK ×{techniques}\033[0m "
           f"\033[90m│\033[0m {scope_pill}")
    visible = re.sub(r'\033\[[\d;]*m', '', bar)
    pad = max(0, width - len(visible))
    return f"\033[100m\033[97m {bar} {' '*pad}\033[0m"


def confidence_pill(conf: str) -> str:
    """v7.1 — visually-strong confidence indicator."""
    if conf == "green":
        return "\033[42m\033[97m\033[1m  GREEN ▶ EXECUTE  \033[0m"
    if conf == "yellow":
        return "\033[43m\033[30m\033[1m  YELLOW · CAUTION  \033[0m"
    if conf == "red":
        return "\033[41m\033[97m\033[1m  RED ✕ HOLD  \033[0m"
    return f"\033[100m\033[97m  {conf.upper()}  \033[0m"


def progress_bar(current: int, total: int, width: int = 24,
                 fill: str = "█", empty: str = "░") -> str:
    """v7.1 — text progress bar."""
    if total <= 0:
        return f"\033[90m{empty * width}\033[0m"
    pct = min(1.0, current / total)
    filled = int(pct * width)
    pct_text = f"{int(pct * 100):>3}%"
    return (f"\033[32m{fill * filled}\033[90m{empty * (width - filled)}"
            f"\033[0m \033[97m{pct_text}\033[0m \033[90m({current}/{total})\033[0m")


def kbd(label: str) -> str:
    """v7.1 — keycap-style button for prompts."""
    return f"\033[100m\033[97m {label} \033[0m"


def section(title: str, color: str = "35") -> str:
    """v7.1 — minimal section header with side rules."""
    line = "─" * 4
    return (f"\033[{color}m{line}\033[0m  \033[{color}m\033[1m{title}\033[0m  "
            f"\033[{color}m{'─' * (60 - len(title))}\033[0m")


def finding_card(f: Finding) -> str:
    """One-line card for a finding in the 'findings' command.
    Shows ATT&CK technique tag if present."""
    icon_map = {
        "ip":           "🌐",
        "port":         "🔌",
        "svc":          "⚙",
        "account":      "👤",
        "hash":         "🔐",
        "cve":          "💥",
        "domain":       "🏷",
        "url":          "🔗",
        "yara_hit":     "🧬",
        "av_hit":       "🦠",
        "suspicious_proc": "⚠",
        "suricata_alert":  "🚨",
        "cron_entry":   "⏰",
        "suid":         "🛂",
        "cap_grant":    "🛂",
        "auth_fail":    "🔒",
        "sudo_use":     "👮",
        "persistence":  "📌",
        "container":    "📦",
        "email":        "📧",
        "ssh_key":      "🗝",
        "aws_key":      "☁",
        "attack_id":    "🎯",
    }
    icon = icon_map.get(f.ftype, "•")
    verified_mark = "\033[32m●\033[0m" if f.verified else "\033[90m○\033[0m"
    val_short = f.value[:50] + ("…" if len(f.value) > 50 else "")
    attack_tag = (f" \033[36m{f.attack_id}\033[0m"
                  if f.attack_id else "")
    return (
        f"  {verified_mark} {icon}  \033[97m{f.ftype:<14}\033[0m "
        f"\033[36m{val_short}\033[0m "
        f"\033[90m[{f.node_id}]\033[0m{attack_tag}"
    )


def fancy_header(text: str, color: str = "35") -> str:
    width = max(len(text) + 4, 40)
    line = "─" * width
    padded = text.center(width - 2)
    return (
        f"\033[{color}m╭{line}╮\n"
        f"│ \033[1m{padded}\033[0m\033[{color}m │\n"
        f"╰{line}╯\033[0m"
    )


# ─────────────────────────────────────────────────────────────────────
# v7.2 — boxed UI primitives
#
# Goal: every event a turn produces gets its own titled box, so the
# operator can scan a session log at a glance.  Boxes are 70 cols wide
# (most phone terminals/SSH sessions render this well).  All boxes use
# the `panel()` building block so they share a consistent look.
# ─────────────────────────────────────────────────────────────────────

BOX_W = 70


def _visible_len(s: str) -> int:
    """Length without ANSI escapes."""
    return len(re.sub(r'\033\[[\d;]*m', '', s))


def _wrap_for_box(text: str, inner_width: int) -> List[str]:
    """Wrap a paragraph for box rendering (ANSI-aware)."""
    out: List[str] = []
    for raw_line in str(text).splitlines() or [""]:
        if not raw_line.strip():
            out.append("")
            continue
        # Greedy word-wrap — doesn't account for mid-word ANSI but
        # we only call this on plain text in practice.
        words = raw_line.split(" ")
        cur = ""
        for w in words:
            test = (cur + " " + w).strip() if cur else w
            if _visible_len(test) <= inner_width:
                cur = test
            else:
                if cur:
                    out.append(cur)
                # If a single word is too long, hard-cut
                while _visible_len(w) > inner_width:
                    out.append(w[:inner_width])
                    w = w[inner_width:]
                cur = w
        if cur:
            out.append(cur)
    return out


def _box(title: str, body_lines: List[str], color: str = "35",
         width: int = BOX_W, title_right: str = "") -> str:
    """Generic titled box.  Title on left, optional metadata on right.
    Body lines are taken verbatim (caller wraps if needed)."""
    inner = width - 2
    title_text = f" {title} " if title else ""
    right_text = f" {title_right} " if title_right else ""
    used = len(title_text) + len(right_text)
    fill = max(2, inner - used)
    top = (f"\033[{color}m╭{'─'*1}\033[0m\033[1m{title_text}\033[0m"
           f"\033[{color}m{'─'*fill}\033[0m"
           f"\033[1m{right_text}\033[0m"
           f"\033[{color}m{'─'*1}╮\033[0m")
    out = [top]
    for ln in body_lines:
        vis = _visible_len(ln)
        pad = max(0, inner - 2 - vis)
        out.append(f"\033[{color}m│\033[0m {ln}{' ' * pad} \033[{color}m│\033[0m")
    out.append(f"\033[{color}m╰{'─'*inner}╯\033[0m")
    return "\n".join(out)


def turn_box(turn_no: int, target: str, agent_role: str, model: str,
             verified: int, unverified: int, techniques: int,
             node_id: str, width: int = BOX_W) -> str:
    """v7.2 — header box for each agent turn."""
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["triage"])
    target_short = (target[:18] + "…") if len(target) > 19 else target
    metas = [
        f"target \033[36m{target_short}\033[0m",
        f"node \033[97m{node_id or '—'}\033[0m",
        f"\033[32m✓{verified}\033[0m\033[90m/\033[33m?{unverified}\033[0m",
        f"\033[31mATT&CK ×{techniques}\033[0m",
        f"\033[90m{model}\033[0m",
    ]
    body = ["  " + "  \033[90m·\033[0m  ".join(metas),
            f"  \033[{spec['color']}m\033[1m{spec['icon']} {spec['name']}\033[0m"]
    return _box(f"TURN {turn_no}", body, color="35",
                width=width, title_right=f"v{VERSION}")


def thought_card(thought: str, agent_role: str, width: int = BOX_W) -> str:
    """v7.2 — boxed agent thought block."""
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["triage"])
    inner = width - 4
    lines = _wrap_for_box(thought, inner)
    if not lines:
        lines = ["(no reasoning produced)"]
    body = []
    for ln in lines:
        body.append(f"\033[{spec['color']}m▎\033[0m \033[90m\033[3m{ln}\033[0m")
    return _box("THOUGHT", body, color=spec["color"], width=width)


def dispatch_card(tool: str, shell_str: str, attack_id: str = "",
                  attack_name: str = "", remap_note: str = "",
                  width: int = BOX_W) -> str:
    """v7.2 — boxed structured tool dispatch."""
    inner = width - 4
    body = [f"  \033[36m{tool}\033[0m \033[90m→\033[0m"]
    for ln in _wrap_for_box(shell_str, inner - 2):
        body.append(f"  \033[97m{ln}\033[0m")
    if remap_note:
        body.append(f"  \033[90m\033[3m{remap_note}\033[0m")
    title_right = ""
    if attack_id:
        title_right = f"{attack_id} {attack_name[:22]}"
    return _box("DISPATCH", body, color="36", width=width,
                title_right=title_right)


def command_card(shell_str: str, conf: str = "green", attack_id: str = "",
                 attack_name: str = "", verify: bool = False,
                 width: int = BOX_W) -> str:
    """v7.2 — proposed command, with confidence pill inline."""
    inner = width - 4
    pill_map = {
        "green":  "\033[42m\033[97m\033[1m GREEN ▶ \033[0m",
        "yellow": "\033[43m\033[30m\033[1m YELLOW · \033[0m",
        "red":    "\033[41m\033[97m\033[1m RED ✕ \033[0m",
    }
    pill = pill_map.get(conf, "\033[100m\033[97m  ?  \033[0m")
    body = []
    for ln in _wrap_for_box(shell_str, inner - 2):
        body.append(f"  \033[97m\033[1m{ln}\033[0m")
    body.append("")
    body.append(f"  conf: {pill}")
    title = "VERIFICATION" if verify else "COMMAND"
    color = "31" if verify else "35"
    title_right = ""
    if attack_id:
        title_right = f"{attack_id} {attack_name[:22]}"
    return _box(title, body, color=color, width=width,
                title_right=title_right)


def result_box(output: str, *, lines_shown: int = 12,
               width: int = BOX_W) -> str:
    """v7.2 — boxed command result, with truncation indicator."""
    inner = width - 4
    raw_lines = output.splitlines()
    shown = raw_lines[:lines_shown]
    truncated = len(raw_lines) > lines_shown
    body: List[str] = []
    for ln in shown:
        # Truncate per-line at inner-2 visible chars
        vis = _visible_len(ln)
        if vis > inner - 2:
            ln = ln[:inner - 4] + "…"
        body.append(f"  {ln}")
    if truncated:
        body.append(f"  \033[90m\033[3m… +{len(raw_lines) - lines_shown} "
                    f"more line(s) (full output stored for AI context)\033[0m")
    if not body:
        body = ["  \033[90m(no output)\033[0m"]
    return _box("RESULT", body, color="32", width=width)


def error_alert(title: str, message: str, hint: str = "",
                width: int = BOX_W) -> str:
    """v7.2 — bold red boxed alert for blocked / failed states."""
    inner = width - 4
    body: List[str] = []
    for ln in _wrap_for_box(message, inner - 2):
        body.append(f"  \033[31m{ln}\033[0m")
    if hint:
        body.append("")
        for ln in _wrap_for_box(hint, inner - 2):
            body.append(f"  \033[33m\033[1m▸\033[0m \033[97m{ln}\033[0m")
    return _box(f"⛔ {title}", body, color="31", width=width)


def findings_card(new_count: int, items: List[str], width: int = BOX_W) -> str:
    """v7.2 — boxed summary of newly extracted findings from one cmd."""
    inner = width - 4
    body: List[str] = []
    for it in items[:10]:
        if _visible_len(it) > inner - 2:
            it = it[:inner - 4] + "…"
        body.append(f"  {it}")
    if len(items) > 10:
        body.append(f"  \033[90m… +{len(items) - 10} more\033[0m")
    if not body:
        body = ["  \033[90m(no extractable findings this turn)\033[0m"]
    return _box(f"FINDINGS +{new_count}", body, color="32", width=width)


def thinking_indicator(model_name: str = "") -> str:
    """v7.1 — single-line indicator shown while LLM is thinking."""
    suffix = f" \033[90m· {model_name}\033[0m" if model_name else ""
    return f"\033[35m   ◆ ARES thinking…\033[0m{suffix}"


def boot_sequence_lines() -> List[str]:
    """Cinematic boot lines printed on startup."""
    graph_glyph = "\033[32m✓\033[0m" if HAS_NETWORKX else "\033[33m⚠\033[0m"
    graph_msg = ("\033[32mnetworkx ready\033[0m" if HAS_NETWORKX else
                 "\033[33mnetworkx missing — disabled\033[0m")
    return [
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  loading defensive cognitive matrix",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  initialising Defense Task Tree",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  registering 11 specialist agents",
        f"\033[90m   [boot]\033[0m \033[32m✓\033[0m  registering {len(TOOL_DISPATCH)} structured tools",
        f"\033[90m   [boot]\033[0m \033[32m✓\033[0m  loading {len(MITRE_TECHNIQUES)} ATT&CK detection mappings",
        f"\033[90m   [boot]\033[0m {graph_glyph}  threat graph: {graph_msg}",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  smart-context manager online",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  loop-breaker + sudo-retry armed",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  read-only-by-default safety enabled",
        "\033[90m   [boot]\033[0m \033[32m✓\033[0m  Groq provider chain primed",
    ]


# ═════════════════════════════════════════════════════════════════════
# SPEAKER-ROLE HELPERS (v7.1 user-friendly UX layer)
#
# Every line printed to the operator should answer "who's saying this?"
# at a glance.  Five voices:
#
#   PRIEST  — the operator (you).  Input prompts only.
#   ARES  — the framework itself (target setup, reports, errors).
#   AGENT   — the LLM specialist's reasoning / decision.
#   EXEC    — a command being proposed / executed.
#   SYS     — system-level info (warnings, hints, dim notes).
#
# Each voice has a fixed colour + glyph so the operator knows instantly
# who's talking without parsing whole lines.
# ═════════════════════════════════════════════════════════════════════

# ANSI colour shorthands
_C_PRIEST = "\033[35m"   # magenta — operator
_C_ARES = "\033[96m"   # bright cyan — framework voice
_C_AGENT  = "\033[33m"   # yellow — LLM agent
_C_EXEC   = "\033[97m"   # bright white — commands
_C_SYS    = "\033[90m"   # grey — system/dim notes
_C_OK     = "\033[32m"   # green — success
_C_WARN   = "\033[33m"   # yellow — warning
_C_ERR    = "\033[31m"   # red — error
_C_RESET  = "\033[0m"
_C_BOLD   = "\033[1m"
_C_DIM    = "\033[2m"


def say_ares(message: str, *, indent: int = 3):
    """Framework voice — Ares talking AS the system, not as an agent."""
    pad = " " * indent
    print(f"{pad}{_C_ARES}{_C_BOLD}◈ ARES{_C_RESET}{_C_ARES}  {message}{_C_RESET}")


def say_agent(message: str, agent_role: str = "agent", *, indent: int = 3):
    """Specialist agent voice — the LLM's reasoning."""
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["triage"])
    icon = spec["icon"]
    color = spec["color"]
    pad = " " * indent
    print(f"{pad}\033[{color}m{_C_BOLD}{icon} {spec['name'].split()[0]}{_C_RESET}"
          f"\033[{color}m  {message}{_C_RESET}")


def say_priest_prompt(prompt: str = "") -> str:
    """Render the priest input prompt (returns the formatted string for input())."""
    return f"  {_C_PRIEST}{_C_BOLD}⚔ priest{_C_RESET}{_C_PRIEST} ›{_C_RESET} {prompt}"


def say_sys(message: str, *, color: str = "90", indent: int = 3):
    """Generic system message (warnings, hints, info)."""
    pad = " " * indent
    print(f"{pad}\033[{color}m▸ {message}{_C_RESET}")


def say_dim(message: str, *, indent: int = 3):
    """Faint informational line."""
    pad = " " * indent
    print(f"{pad}{_C_SYS}{message}{_C_RESET}")


def say_ok(message: str, *, indent: int = 3):
    pad = " " * indent
    print(f"{pad}{_C_OK}✓ {message}{_C_RESET}")


def say_warn(message: str, *, indent: int = 3):
    pad = " " * indent
    print(f"{pad}{_C_WARN}⚠ {message}{_C_RESET}")


def say_err(message: str, *, indent: int = 3):
    pad = " " * indent
    print(f"{pad}{_C_ERR}✕ {message}{_C_RESET}")


def say_thought(message: str, agent_role: str = "agent", *, indent: int = 6):
    """The LLM's chain-of-thought.  Distinct from agent decisions —
    this is the dim italic 'thinking aloud' voice."""
    pad = " " * indent
    color = AGENT_SPECS.get(agent_role, AGENT_SPECS["triage"])["color"]
    # Each line of thought gets a small marker
    for line in message.split("\n"):
        line = line.strip()
        if not line:
            continue
        print(f"{pad}\033[{color}m\033[2m│{_C_RESET} \033[90m\033[3m{line}{_C_RESET}")


def speakers_legend() -> str:
    """Tiny legend bar showing what each voice means.  Printed once
    at the top of the help so the operator learns the symbol set."""
    return (
        f"   {_C_SYS}voices:{_C_RESET}  "
        f"{_C_PRIEST}{_C_BOLD}⚔ priest{_C_RESET} {_C_SYS}you{_C_RESET}  "
        f"{_C_ARES}{_C_BOLD}◈ ARES{_C_RESET} {_C_SYS}framework{_C_RESET}  "
        f"{_C_AGENT}{_C_BOLD}🚨 TRIAGE{_C_RESET} {_C_SYS}AI agent{_C_RESET}  "
        f"{_C_EXEC}▌{_C_RESET} {_C_SYS}command{_C_RESET}  "
        f"{_C_OK}✓{_C_RESET} {_C_SYS}ok{_C_RESET}  "
        f"{_C_WARN}⚠{_C_RESET} {_C_SYS}warn{_C_RESET}  "
        f"{_C_ERR}✕{_C_RESET} {_C_SYS}error{_C_RESET}"
    )


# ═════════════════════════════════════════════════════════════════════
# TOOL WRAPPER LAYER  (ToolBuilder)
#
# Typed builders that produce shell strings.  The LLM picks the tool +
# arguments, we build the command.  This kills the v6.1 problem of the
# AI typing `nano`, `msfconsole` (interactive), `ssh user@host`, etc.,
# because the wrappers inherently produce non-interactive forms.
#
# All wrappers return a ready-to-execute shell string.
# ═════════════════════════════════════════════════════════════════════

class ToolBuilder:

    # ── Process & socket inspection (cheap, broad) ────────────────────

    @staticmethod
    def ps_tree(filter_user: Optional[str] = None,
                show_threads: bool = False,
                show_all: bool = True,
                cmd_grep: Optional[str] = None) -> str:
        flags = "auxf" if not show_threads else "auxfH"
        if not show_all:
            flags = flags.replace("a", "")
        cmd = f"ps {flags}"
        if filter_user:
            cmd += f" | grep -E '^{filter_user}\\s'"
        if cmd_grep:
            cmd += f" | grep -E '{cmd_grep}'"
        return cmd

    @staticmethod
    def ss_listening(ip_version: str = "4",
                     processes: bool = True,
                     proto: str = "tcp",
                     numeric: bool = True) -> str:
        flags = ""
        if proto == "tcp":
            flags += "t"
        elif proto == "udp":
            flags += "u"
        else:
            flags += "tu"
        flags += "ln"
        if numeric:
            flags += "n"
        if processes:
            flags += "p"
        ipv = "-4" if ip_version == "4" else "-6" if ip_version == "6" else ""
        return f"ss -{flags} {ipv}".strip()

    @staticmethod
    def ss_established(proto: str = "tcp",
                       processes: bool = True) -> str:
        flags = "t" if proto == "tcp" else "u"
        flags += "np" if processes else "n"
        return f"ss -{flags} state established"

    @staticmethod
    def lsof_net(_proto: Optional[str] = None,
                 user_filter: Optional[str] = None,
                 deleted_only: bool = False) -> str:
        if deleted_only:
            cmd = "lsof +L1 2>/dev/null"
        elif _proto in ("tcp", "TCP"):
            cmd = "lsof -i TCP -n -P"
        elif _proto in ("udp", "UDP"):
            cmd = "lsof -i UDP -n -P"
        else:
            cmd = "lsof -i -n -P"
        if user_filter:
            cmd += f" -u {user_filter}"
        return cmd

    # ── Logs ──────────────────────────────────────────────────────────

    @staticmethod
    def journalctl(unit: Optional[str] = None,
                   since: Optional[str] = "1 hour ago",
                   until: Optional[str] = None,
                   priority: Optional[str] = None,
                   lines: int = 200,
                   grep: Optional[str] = None,
                   reverse: bool = False) -> str:
        parts = ["journalctl", "--no-pager"]
        if unit:
            parts.extend(["-u", unit])
        if since:
            parts.extend(["--since", f"'{since}'"])
        if until:
            parts.extend(["--until", f"'{until}'"])
        if priority:
            parts.extend(["-p", priority])
        if reverse:
            parts.append("-r")
        parts.extend(["-n", str(lines)])
        cmd = " ".join(parts)
        if grep:
            cmd += f" | grep -iE '{grep}'"
        return cmd

    @staticmethod
    def auth_log_grep(pattern: str = "Failed|Invalid|Accepted",
                      since_when: Optional[str] = None,
                      max_results: int = 100,
                      log_path: str = "/var/log/auth.log") -> str:
        if since_when:
            cmd = (f"awk -v d='{since_when}' '$0 >= d' {log_path} "
                   f"| grep -E '{pattern}' | tail -n {max_results}")
        else:
            cmd = f"grep -E '{pattern}' {log_path} | tail -n {max_results}"
        return cmd

    @staticmethod
    def auditd_search(key_filter: Optional[str] = None,
                      message_type: Optional[str] = None,
                      start_time: str = "today",
                      end_time: Optional[str] = None,
                      user: Optional[str] = None) -> str:
        parts = ["ausearch", f"--start {start_time}"]
        if end_time:
            parts.append(f"--end {end_time}")
        if key_filter:
            parts.extend(["-k", key_filter])
        if message_type:
            parts.extend(["-m", message_type])
        if user:
            parts.extend(["-ul", user])
        return " ".join(parts) + " 2>/dev/null"

    @staticmethod
    def aureport_summary(report_type: str = "auth") -> str:
        # report_type: auth, login, exec, key, anomaly, tty
        flag_map = {
            "auth": "-au", "login": "-l", "exec": "-x",
            "key": "-k", "anomaly": "--anomaly", "tty": "--tty",
        }
        flag = flag_map.get(report_type, "-au")
        return f"aureport {flag} --summary -i 2>/dev/null"

    # ── Filesystem checks ─────────────────────────────────────────────

    @staticmethod
    def find_recent_files(path: str = "/etc",
                          minutes: int = 1440,
                          ext: Optional[str] = None,
                          file_type: str = "f") -> str:
        cmd = f"find {path} -mmin -{minutes} -type {file_type} 2>/dev/null"
        if ext:
            cmd += f" -name '*.{ext}'"
        return cmd

    @staticmethod
    def find_suid(path: str = "/",
                  show_perms: bool = True) -> str:
        if show_perms:
            return (f"find {path} -perm -4000 -type f -exec ls -la {{}} \\; "
                    f"2>/dev/null")
        return f"find {path} -perm -4000 -type f 2>/dev/null"

    @staticmethod
    def find_caps(path: str = "/") -> str:
        return f"getcap -r {path} 2>/dev/null"

    @staticmethod
    def find_world_writable(path: str = "/", _drop: bool = False) -> str:
        return (f"find {path} -xdev -type f -perm -002 "
                f"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null")

    @staticmethod
    def cron_sweep() -> str:
        return ("(echo '== /etc/crontab =='; cat /etc/crontab 2>/dev/null; "
                "echo '== /etc/cron.d =='; ls -la /etc/cron.d/ 2>/dev/null; "
                "echo '== /etc/cron.{hourly,daily,weekly,monthly} =='; "
                "ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null; "
                "echo '== per-user crontabs =='; "
                "for u in $(cut -d: -f1 /etc/passwd); do "
                "out=$(crontab -u $u -l 2>/dev/null); "
                "[ -n \"$out\" ] && echo \"--$u--\" && echo \"$out\"; done)")

    @staticmethod
    def systemd_enabled() -> str:
        return ("systemctl list-unit-files --state=enabled --no-pager "
                "--type=service")

    @staticmethod
    def systemd_recent_units(days: int = 30) -> str:
        return (f"find /etc/systemd /usr/lib/systemd /lib/systemd "
                f"-name '*.service' -mtime -{days} 2>/dev/null "
                f"-exec ls -la {{}} \\;")

    # ── File integrity ────────────────────────────────────────────────

    @staticmethod
    def aide_check() -> str:
        return "aide --check 2>&1"

    @staticmethod
    def debsums_check(only_changed: bool = True) -> str:
        return "debsums -c 2>/dev/null" if only_changed else "debsums 2>/dev/null"

    @staticmethod
    def file_hash(path: str, algorithm: str = "sha256") -> str:
        algo_map = {"md5": "md5sum", "sha1": "sha1sum",
                    "sha256": "sha256sum", "sha512": "sha512sum"}
        bin_ = algo_map.get(algorithm, "sha256sum")
        return f"{bin_} {path}"

    # ── Hardening / audit tools ───────────────────────────────────────

    @staticmethod
    def lynis_audit(quick: bool = True,
                    test_groups: Optional[str] = None) -> str:
        cmd = "sudo lynis audit system"
        if quick:
            cmd += " --quick"
        if test_groups:
            cmd += f" --tests-from-group {test_groups}"
        cmd += " 2>&1"
        return cmd

    @staticmethod
    def rkhunter_scan(skip_prompts: bool = True) -> str:
        cmd = "sudo rkhunter --check"
        if skip_prompts:
            cmd += " --skip-keypress"
        cmd += " --report-warnings-only 2>&1"
        return cmd

    @staticmethod
    def chkrootkit_scan() -> str:
        return "sudo chkrootkit -q 2>&1"

    @staticmethod
    def openscap_scan(profile: str = "xccdf_org.ssgproject.content_profile_cis",
                      datastream: str = "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
                      results: str = "/tmp/oscap-results.xml") -> str:
        return (f"sudo oscap xccdf eval --profile {profile} "
                f"--results {results} {datastream}")

    # ── IDS / network capture ─────────────────────────────────────────

    @staticmethod
    def tcpdump_capture(interface: str = "any",
                        max_packets: int = 1000,
                        bpf_filter: Optional[str] = None,
                        output_file: str = "/tmp/ares_capture.pcap",
                        snaplen: int = 96) -> str:
        cmd = (f"sudo tcpdump -i {interface} -nn -c {max_packets} "
               f"-s {snaplen} -w {output_file}")
        if bpf_filter:
            cmd += f" '{bpf_filter}'"
        return cmd

    @staticmethod
    def tshark_read(pcap: str,
                    display_filter: Optional[str] = None,
                    fields: Optional[str] = None,
                    stat: Optional[str] = None) -> str:
        cmd = f"tshark -r {pcap} -n"
        if display_filter:
            cmd += f" -Y '{display_filter}'"
        if fields:
            field_args = " ".join(f"-e {f.strip()}" for f in fields.split(","))
            cmd += f" -T fields {field_args}"
        if stat:
            cmd += f" -q -z {stat}"
        return cmd

    @staticmethod
    def suricata_replay(pcap: str,
                        rules: str = "/etc/suricata/suricata.yaml",
                        log_dir: str = "/tmp/ares_suri") -> str:
        return (f"mkdir -p {log_dir} && "
                f"sudo suricata -r {pcap} -l {log_dir} -c {rules} "
                f"&& cat {log_dir}/fast.log")

    @staticmethod
    def zeek_offline(pcap: str,
                     output_dir: str = "/tmp/ares_zeek") -> str:
        return f"mkdir -p {output_dir} && cd {output_dir} && zeek -C -r {pcap}"

    @staticmethod
    def fail2ban_status(jail: Optional[str] = None) -> str:
        if jail:
            return f"sudo fail2ban-client status {jail}"
        return "sudo fail2ban-client status"

    @staticmethod
    def firewall_show(family: str = "auto") -> str:
        # auto: prefer nft, fall back to iptables, then ufw
        return ("(if command -v nft >/dev/null 2>&1; then "
                "sudo nft list ruleset; "
                "elif command -v iptables >/dev/null 2>&1; then "
                "sudo iptables -L -n -v --line-numbers; sudo iptables -t nat -L -n -v; "
                "elif command -v ufw >/dev/null 2>&1; then "
                "sudo ufw status verbose; "
                "fi)") if family == "auto" else \
               (f"sudo {family} list ruleset" if family == "nft"
                else f"sudo {family} -L -n -v")

    # ── Malware static triage ─────────────────────────────────────────

    @staticmethod
    def yara_scan(path: str,
                  rules: Optional[str] = None,
                  recursive: bool = True,
                  show_strings: bool = False) -> str:
        if rules is None:
            rules = ensure_yara_rules() or ""
        if not rules:
            return ("# yara rules not installed — apt install yara-rules || "
                    "git clone https://github.com/Yara-Rules/rules /opt/yara-rules\n"
                    "echo 'no rules available'")
        flags = ""
        if recursive:
            flags += "r"
        if show_strings:
            flags += "s"
        flag_part = f"-{flags}" if flags else ""
        return f"yara {flag_part} {rules} {path}".replace("  ", " ")

    @staticmethod
    def clamscan(path: str,
                 only_infected: bool = True,
                 recursive: bool = True) -> str:
        flags = ""
        if recursive:
            flags += "r"
        if only_infected:
            flags += "i"
        flag_part = f"-{flags}" if flags else ""
        return f"clamscan {flag_part} --no-summary {path}".replace("  ", " ")

    @staticmethod
    def file_strings(path: str,
                     min_len: int = 8,
                     encoding: str = "ascii") -> str:
        if encoding == "utf16":
            return f"strings -n {min_len} -e l {path}"
        return f"strings -n {min_len} {path}"

    @staticmethod
    def file_inspect(path: str) -> str:
        # Quick triage bundle: file + sha256 + exiftool head + readelf -h
        return (f"file {path}; sha256sum {path}; "
                f"exiftool {path} 2>/dev/null | head -30; "
                f"readelf -h {path} 2>/dev/null | head -20")

    @staticmethod
    def capa_run(path: str,
                 rules_dir: str = "/opt/capa-rules") -> str:
        return f"capa --rules {rules_dir} {path}"

    # ── Memory & disk forensics ───────────────────────────────────────

    @staticmethod
    def volatility_run(image: str,
                       plugin: str,
                       extra_args: Optional[str] = None,
                       _legacy_profile: Optional[str] = None) -> str:
        # Prefer vol3 (`vol`) if installed.
        binary = "vol" if cmd_exists("vol") else "volatility3" if cmd_exists("volatility3") else "vol.py"
        cmd = f"{binary} -f {image} {plugin}"
        if extra_args:
            cmd += f" {extra_args}"
        return cmd

    @staticmethod
    def sleuthkit_fls(image: str,
                      offset: Optional[int] = None,
                      recursive: bool = True,
                      output_body: Optional[str] = None) -> str:
        cmd = "fls"
        if offset is not None:
            cmd += f" -o {offset}"
        if recursive:
            cmd += " -r"
        if output_body:
            cmd += f" -m / {image} > {output_body}"
        else:
            cmd += f" {image}"
        return cmd

    @staticmethod
    def mactime_render(body_file: str,
                       date_filter: Optional[str] = None) -> str:
        cmd = f"mactime -b {body_file} -d"
        if date_filter:
            cmd += f" | awk -F, '$1>=\"{date_filter}\"'"
        return cmd

    @staticmethod
    def foremost_carve(image: str,
                       output_dir: str = "/tmp/ares_carved",
                       file_types: str = "pdf,jpg,doc,zip,exe") -> str:
        return f"foremost -i {image} -o {output_dir} -t {file_types}"

    # ── IOC enrichment / external lookup ──────────────────────────────

    @staticmethod
    def curl_basic(url: str, head_only: bool = False,
                   user_agent: str = "Mozilla/5.0",
                   user: Optional[str] = None,
                   password: Optional[str] = None,
                   silent: bool = True) -> str:
        cmd = "curl"
        if silent:
            cmd += " -s"
        if head_only:
            cmd += " -I"
        cmd += f" -A '{user_agent}'"
        if user and password is not None:
            cmd += f" -u '{user}:{password}'"
        cmd += f" '{url}'"
        return cmd

    @staticmethod
    def virustotal_hash(file_hash: str,
                        api_key_env: str = "VT_API_KEY") -> str:
        return (f"curl -s 'https://www.virustotal.com/api/v3/files/{file_hash}' "
                f"-H \"x-apikey:${api_key_env}\" | jq '.data.attributes.last_analysis_stats // .error'")

    @staticmethod
    def abuseipdb_check(ip: str,
                        max_age_days: int = 90,
                        api_key_env: str = "ABUSEIPDB_KEY") -> str:
        return (f"curl -s 'https://api.abuseipdb.com/api/v2/check' "
                f"-H \"Key:${api_key_env}\" -H 'Accept: application/json' "
                f"-d 'ipAddress={ip}&maxAgeInDays={max_age_days}' | jq")

    @staticmethod
    def crt_sh_lookup(domain: str) -> str:
        return (f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' "
                f"| jq -r '.[].name_value' | sort -u")

    # ── Identity audit ────────────────────────────────────────────────

    @staticmethod
    def shadow_audit() -> str:
        # No-password, locked, and active accounts at a glance — needs root
        return ("(echo '== empty passwords =='; "
                "sudo awk -F: '$2==\"\" {print $1}' /etc/shadow; "
                "echo '== locked accounts (start with !/*) =='; "
                "sudo awk -F: '$2 ~ /^[!*]/ {print $1}' /etc/shadow | head -20; "
                "echo '== set passwords =='; "
                "sudo awk -F: '$2 !~ /^[!*]/ && $2 != \"\" {print $1}' /etc/shadow)")

    @staticmethod
    def sudoers_audit() -> str:
        return ("(echo '== /etc/sudoers =='; sudo cat /etc/sudoers; "
                "echo '== /etc/sudoers.d/ =='; "
                "for f in /etc/sudoers.d/*; do "
                "[ -f \"$f\" ] && echo \"-- $f --\" && sudo cat \"$f\"; done; "
                "echo '== syntax check =='; sudo visudo -c)")

    @staticmethod
    def authorized_keys_sweep() -> str:
        return ("find /home /root -name authorized_keys -exec stat -c "
                "'%n  modified=%y  owner=%U' {} \\; 2>/dev/null")

    # ── SSL/TLS audit ─────────────────────────────────────────────────

    @staticmethod
    def sslscan(target: str) -> str:
        return f"sslscan --no-failed {target}"

    @staticmethod
    def testssl(target: str, severity: str = "MEDIUM") -> str:
        return f"testssl.sh --severity {severity} {target}"

    @staticmethod
    def ssh_audit(target: str = "localhost", port: int = 22) -> str:
        return f"ssh-audit {target}:{port}"

    # ── SIEM / sigma-style hunt ───────────────────────────────────────

    @staticmethod
    def chainsaw_hunt(evidence_path: str,
                      rules_dir: str = "/opt/sigma/rules",
                      mapping: str = "/opt/chainsaw/mappings/sigma-event-logs-all.yml",
                      output_csv: str = "/tmp/chainsaw_hits.csv") -> str:
        return (f"chainsaw hunt {evidence_path} -s {rules_dir} "
                f"--mapping {mapping} --csv --output {output_csv} 2>&1")

    @staticmethod
    def hayabusa_timeline(evtx_dir: str,
                         output_csv: str = "/tmp/hayabusa_timeline.csv") -> str:
        return f"hayabusa csv-timeline -d {evtx_dir} -o {output_csv} 2>&1"

    # ── Misc / DNS & whois (defender-side) ────────────────────────────

    @staticmethod
    def dig_lookup(domain: str, record_type: str = "ANY") -> str:
        return f"dig +short {domain} {record_type}"

    @staticmethod
    def whois_lookup(target: str) -> str:
        return f"whois {target} 2>&1 | head -50"



# ═════════════════════════════════════════════════════════════════════
# TOOL DISPATCH (v7.1)
#
# Maps tool names emitted by the LLM in [TOOL]name[/TOOL] tags to
# ToolBuilder methods.  When the LLM picks a tool here, args are typed
# and the shell string is constructed deterministically — no chance of
# hallucinated flags.  For ad-hoc commands the LLM still falls through
# to the [CMD] path.
# ═════════════════════════════════════════════════════════════════════

TOOL_DISPATCH = {
    # process & socket inspection
    "ps_tree":               ToolBuilder.ps_tree,
    "ss_listening":          ToolBuilder.ss_listening,
    "ss_established":        ToolBuilder.ss_established,
    "lsof_net":              ToolBuilder.lsof_net,
    # logs
    "journalctl":            ToolBuilder.journalctl,
    "auth_log_grep":         ToolBuilder.auth_log_grep,
    "auditd_search":         ToolBuilder.auditd_search,
    "aureport_summary":      ToolBuilder.aureport_summary,
    # filesystem
    "find_recent_files":     ToolBuilder.find_recent_files,
    "find_suid":             ToolBuilder.find_suid,
    "find_caps":             ToolBuilder.find_caps,
    "find_world_writable":   ToolBuilder.find_world_writable,
    "cron_sweep":            ToolBuilder.cron_sweep,
    "systemd_enabled":       ToolBuilder.systemd_enabled,
    "systemd_recent_units":  ToolBuilder.systemd_recent_units,
    # file integrity
    "aide_check":            ToolBuilder.aide_check,
    "debsums_check":         ToolBuilder.debsums_check,
    "file_hash":             ToolBuilder.file_hash,
    # hardening / audit
    "lynis_audit":           ToolBuilder.lynis_audit,
    "rkhunter_scan":         ToolBuilder.rkhunter_scan,
    "chkrootkit_scan":       ToolBuilder.chkrootkit_scan,
    "openscap_scan":         ToolBuilder.openscap_scan,
    # network capture / IDS
    "tcpdump_capture":       ToolBuilder.tcpdump_capture,
    "tshark_read":           ToolBuilder.tshark_read,
    "suricata_replay":       ToolBuilder.suricata_replay,
    "zeek_offline":          ToolBuilder.zeek_offline,
    "fail2ban_status":       ToolBuilder.fail2ban_status,
    "firewall_show":         ToolBuilder.firewall_show,
    # malware static triage
    "yara_scan":             ToolBuilder.yara_scan,
    "clamscan":              ToolBuilder.clamscan,
    "file_strings":          ToolBuilder.file_strings,
    "file_inspect":          ToolBuilder.file_inspect,
    "capa_run":              ToolBuilder.capa_run,
    # forensics
    "volatility_run":        ToolBuilder.volatility_run,
    "sleuthkit_fls":         ToolBuilder.sleuthkit_fls,
    "mactime_render":        ToolBuilder.mactime_render,
    "foremost_carve":        ToolBuilder.foremost_carve,
    # IOC enrichment
    "curl_basic":            ToolBuilder.curl_basic,
    "virustotal_hash":       ToolBuilder.virustotal_hash,
    "abuseipdb_check":       ToolBuilder.abuseipdb_check,
    "crt_sh_lookup":         ToolBuilder.crt_sh_lookup,
    # identity audit
    "shadow_audit":          ToolBuilder.shadow_audit,
    "sudoers_audit":         ToolBuilder.sudoers_audit,
    "authorized_keys_sweep": ToolBuilder.authorized_keys_sweep,
    # SSL/TLS
    "sslscan":               ToolBuilder.sslscan,
    "testssl":               ToolBuilder.testssl,
    "ssh_audit":             ToolBuilder.ssh_audit,
    # SIEM-style hunt
    "chainsaw_hunt":         ToolBuilder.chainsaw_hunt,
    "hayabusa_timeline":     ToolBuilder.hayabusa_timeline,
    # DNS / whois
    "dig_lookup":            ToolBuilder.dig_lookup,
    "whois_lookup":          ToolBuilder.whois_lookup,
}


# Primary binary lookup per tool name.  Used by dispatch to do a
# pre-flight `which` check before generating the shell string.
TOOL_BINARY = {
    # process & socket — should always be there on a real Linux host
    "ps_tree":               "ps",
    "ss_listening":          "ss",
    "ss_established":        "ss",
    "lsof_net":              "lsof",
    # logs
    "journalctl":            "journalctl",
    "auth_log_grep":         "grep",
    "auditd_search":         "ausearch",
    "aureport_summary":      "aureport",
    # filesystem
    "find_recent_files":     "find",
    "find_suid":             "find",
    "find_caps":             "getcap",
    "find_world_writable":   "find",
    "cron_sweep":            None,   # composite of ls/cat/crontab — no single binary
    "systemd_enabled":       "systemctl",
    "systemd_recent_units":  "find",
    # file integrity
    "aide_check":            "aide",
    "debsums_check":         "debsums",
    "file_hash":             "sha256sum",
    # hardening
    "lynis_audit":           "lynis",
    "rkhunter_scan":         "rkhunter",
    "chkrootkit_scan":       "chkrootkit",
    "openscap_scan":         "oscap",
    # network capture / IDS
    "tcpdump_capture":       "tcpdump",
    "tshark_read":           "tshark",
    "suricata_replay":       "suricata",
    "zeek_offline":          None,    # zeek OR bro
    "fail2ban_status":       "fail2ban-client",
    "firewall_show":         None,    # auto-detect nft/iptables/ufw
    # malware
    "yara_scan":             "yara",
    "clamscan":              "clamscan",
    "file_strings":          "strings",
    "file_inspect":          "file",
    "capa_run":              "capa",
    # forensics
    "volatility_run":        None,    # vol OR volatility3 OR vol.py
    "sleuthkit_fls":         "fls",
    "mactime_render":        "mactime",
    "foremost_carve":        "foremost",
    # IOC enrichment
    "curl_basic":            "curl",
    "virustotal_hash":       "curl",
    "abuseipdb_check":       "curl",
    "crt_sh_lookup":         "curl",
    # identity
    "shadow_audit":          None,    # composite
    "sudoers_audit":         None,    # composite
    "authorized_keys_sweep": "find",
    # SSL/TLS
    "sslscan":               "sslscan",
    "testssl":               "testssl.sh",
    "ssh_audit":             "ssh-audit",
    # SIEM
    "chainsaw_hunt":         "chainsaw",
    "hayabusa_timeline":     "hayabusa",
    # DNS
    "dig_lookup":            "dig",
    "whois_lookup":          "whois",
}


def _tool_binary_present(tool_name: str) -> Tuple[bool, str]:
    """Return (present, suggested_install_or_alt)."""
    # Composite tools that resolve at runtime
    if tool_name == "zeek_offline":
        if cmd_exists("zeek") or cmd_exists("bro"):
            return (True, "")
        return (False, "Install: apt install zeek  (or bro on older systems)")
    if tool_name == "volatility_run":
        for b in ("vol", "volatility3", "vol.py"):
            if cmd_exists(b):
                return (True, "")
        return (False, "Install: pipx install volatility3  (or pip install volatility3 --break-system-packages)")
    if tool_name == "firewall_show":
        for b in ("nft", "iptables", "ufw"):
            if cmd_exists(b):
                return (True, "")
        return (False, "No firewall tool found.  Install: apt install nftables iptables ufw")
    if tool_name in ("cron_sweep", "shadow_audit", "sudoers_audit"):
        # Composite — assume base utilities are present
        return (True, "")
    binary = TOOL_BINARY.get(tool_name)
    if binary is None:
        return (True, "")
    if cmd_exists(binary):
        return (True, "")
    # Common alternatives / install hints
    alt_map = {
        "lynis":        "Install: apt install lynis",
        "rkhunter":     "Install: apt install rkhunter",
        "chkrootkit":   "Install: apt install chkrootkit",
        "oscap":        "Install: apt install libopenscap8 ssg-debian",
        "yara":         "Install: apt install yara yara-rules",
        "clamscan":     "Install: apt install clamav && sudo freshclam",
        "capa":         "Install: pipx install flare-capa",
        "fls":          "Install: apt install sleuthkit",
        "mactime":      "Install: apt install sleuthkit",
        "foremost":     "Install: apt install foremost",
        "tshark":       "Install: apt install tshark",
        "suricata":     "Install: apt install suricata && sudo suricata-update",
        "ausearch":     "Install: apt install auditd",
        "aureport":     "Install: apt install auditd",
        "aide":         "Install: apt install aide && sudo aideinit",
        "debsums":      "Install: apt install debsums",
        "fail2ban-client": "Install: apt install fail2ban",
        "ssh-audit":    "Install: pipx install ssh-audit",
        "testssl.sh":   "Install: apt install testssl.sh  (or use 'sslscan' instead)",
        "chainsaw":     "Install: download from github.com/WithSecureLabs/chainsaw/releases",
        "hayabusa":     "Install: download from github.com/Yamato-Security/hayabusa/releases",
    }
    alt = alt_map.get(binary) or f"Install: apt install {binary}"
    return (False, alt)


def _apply_kwarg_synonyms(name: str, args: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Map common LLM-emitted synonyms to the real builder param names.
    Returns (cleaned_args, list_of_remappings_done) for visibility."""
    syn_map = KWARG_SYNONYMS.get(name, {})
    remapped: List[str] = []
    out: Dict[str, Any] = {}
    for k, v in args.items():
        if k in syn_map:
            real = syn_map[k]
            if real is None:
                # silent drop — this is a recognised no-op alias
                remapped.append(f"{k}=<dropped>")
                continue
            # Avoid clobbering an explicit real-name arg
            if real not in args:
                out[real] = v
                remapped.append(f"{k}→{real}")
            else:
                # both supplied — prefer the canonical one already present
                remapped.append(f"{k}=<duplicate of {real}, ignored>")
        else:
            out[k] = v
    return (out, remapped)


def dispatch_tool(name: str, args_json: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a [TOOL]/[ARGS] pair into a shell command.

    Returns (shell_string, msg) tuple:
      • (shell, None)         — clean success
      • (shell, "NOTE: ...")  — success with a note (e.g. synonyms remapped)
      • (None, "ERROR: ...")  — hard failure; caller MUST feed this back
                                 to the LLM in the next prompt so it can
                                 correct rather than loop.
    """
    if name not in TOOL_DISPATCH:
        available = ", ".join(sorted(TOOL_DISPATCH.keys()))
        return (None,
                f"ERROR: unknown tool '{name}'. Available: {available}. "
                f"Use [CMD] for ad-hoc commands.")

    # v7.2 — pre-flight binary check
    present, alt = _tool_binary_present(name)
    if not present:
        return (None,
                f"ERROR: tool '{name}' not installed on this system. "
                f"{alt}  Pivot to a different tool or use [CMD] with "
                f"something already available.")

    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as e:
        return (None,
                f"ERROR: bad JSON in [ARGS] for {name}: {e}. "
                f"Example: [ARGS]{{\"target\":\"10.0.0.5\"}}[/ARGS]")

    if not isinstance(args, dict):
        return (None,
                f"ERROR: [ARGS] must be a JSON object, got "
                f"{type(args).__name__}")

    # v7.2 — apply known synonyms first
    args, remapped = _apply_kwarg_synonyms(name, args)

    # Now check for kwargs that are STILL unknown after synonym mapping.
    fn = TOOL_DISPATCH[name]
    try:
        sig = inspect.signature(fn)
        # Builder methods may use _foo "private" params for synonym
        # forwarding (e.g. _scan_type).  These are valid kwargs.
        valid = set(sig.parameters.keys())
        accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD
                             for p in sig.parameters.values())
        unknown = [k for k in args.keys() if k not in valid] if not accepts_kwargs else []
    except (ValueError, TypeError):
        unknown = []

    if unknown:
        # Hard error fed back to LLM with the actual valid args listed
        try:
            sig = inspect.signature(fn)
            valid_list = []
            for pname, p in sig.parameters.items():
                if pname.startswith("_"):
                    continue  # hidden synonym slots
                if p.default is inspect.Parameter.empty:
                    valid_list.append(pname)
                else:
                    valid_list.append(f"{pname}={p.default!r}")
            valid_str = ", ".join(valid_list)
        except Exception:
            valid_str = "(introspection failed)"
        return (None,
                f"ERROR: {name} got unknown arg(s): {', '.join(unknown)}. "
                f"Valid args: {valid_str}. "
                f"Use [CMD] if {name} doesn't fit your need.")

    try:
        shell_str = fn(**args)
    except TypeError as e:
        # Missing required arg, or other signature problem
        try:
            sig = inspect.signature(fn)
            required = [p for p, info in sig.parameters.items()
                        if info.default is inspect.Parameter.empty
                        and not p.startswith("_")]
            return (None,
                    f"ERROR: bad args for {name}: {e}. Required: "
                    f"{', '.join(required) if required else '(none)'}.")
        except Exception:
            return (None, f"ERROR: bad args for {name}: {e}")
    except Exception as e:
        return (None, f"ERROR: {name} builder error: {e}")

    if not shell_str or not isinstance(shell_str, str):
        return (None, f"ERROR: {name} returned no command string")

    # Soft note for remappings (success path)
    if remapped:
        return (shell_str, f"NOTE: arg synonyms remapped: {', '.join(remapped)}")

    return (shell_str, None)


def tool_registry_for_prompt() -> str:
    """Compact registry summary so the LLM knows what's available
    structured.  Inspects each builder's signature to surface the
    expected args without us hardcoding it twice."""
    lines = ["STRUCTURED TOOLS (use [TOOL]name[/TOOL][ARGS]json[/ARGS]):"]
    for name, fn in sorted(TOOL_DISPATCH.items()):
        try:
            sig = inspect.signature(fn)
            params = []
            for pname, p in sig.parameters.items():
                # v7.2 — hide private synonym-forwarding params
                if pname.startswith("_"):
                    continue
                if p.default is inspect.Parameter.empty:
                    params.append(pname)
                else:
                    default = p.default
                    if isinstance(default, str):
                        params.append(f"{pname}='{default[:25]}'")
                    else:
                        params.append(f"{pname}={default}")
            lines.append(f"  {name}({', '.join(params)})")
        except (ValueError, TypeError):
            lines.append(f"  {name}(...)")
    return "\n".join(lines)


# ═════════════════════════════════════════════════════════════════════
# SCOPE / RoE ENFORCEMENT (v7.1)
#
# Scope is loaded from ~/.ares/scope.json (created on first run if
# missing).  Defines allowed CIDRs, allowed/blocked domains, and time
# windows.  Out-of-scope commands are refused before they hit
# subprocess.  Critical for legitimate engagements bound by SOWs.
# ═════════════════════════════════════════════════════════════════════

DEFAULT_SCOPE = {
    "enabled":  False,
    "allowed_cidrs":   ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "blocked_cidrs":   [],
    "allowed_domains": [],     # ["target.com", "*.target.com"]
    "blocked_domains": [],
    "time_window": {           # ISO-8601 strings; empty = no window
        "start": "",
        "end":   "",
    },
    "note": (
        "Set 'enabled' to true to enforce.  Out-of-scope commands "
        "will be refused before execution.  Wildcards (*.example.com) "
        "supported in domains.  Time window applies in local TZ."
    ),
}


@dataclass
class ScopeConfig:
    enabled: bool = False
    allowed_cidrs:   List[str] = field(default_factory=list)
    blocked_cidrs:   List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    time_start: str = ""
    time_end:   str = ""

    @classmethod
    def load(cls, path: str = SCOPE_FILE) -> "ScopeConfig":
        # Create default if missing
        if not os.path.exists(path):
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    json.dump(DEFAULT_SCOPE, f, indent=2)
            except Exception:
                pass
            return cls()
        try:
            with open(path) as f:
                data = json.load(f)
            tw = data.get("time_window", {}) or {}
            return cls(
                enabled=data.get("enabled", False),
                allowed_cidrs=data.get("allowed_cidrs", []),
                blocked_cidrs=data.get("blocked_cidrs", []),
                allowed_domains=data.get("allowed_domains", []),
                blocked_domains=data.get("blocked_domains", []),
                time_start=tw.get("start", ""),
                time_end=tw.get("end", ""),
            )
        except Exception as e:
            print(f"\033[33m   Scope file error ({e}) — proceeding with no scope\033[0m")
            return cls()

    def _domain_matches(self, host: str, patterns: List[str]) -> bool:
        host = host.lower().strip()
        for pat in patterns:
            pat = pat.lower().strip()
            if pat.startswith("*."):
                if host == pat[2:] or host.endswith(pat[1:]):
                    return True
            elif pat == host:
                return True
        return False

    def _ip_in_cidrs(self, ip: str, cidrs: List[str]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _check_time_window(self) -> Tuple[bool, str]:
        if not self.time_start and not self.time_end:
            return (True, "")
        now = datetime.datetime.now()
        if self.time_start:
            try:
                start = datetime.datetime.fromisoformat(self.time_start)
                if now < start:
                    return (False, f"Before window start ({self.time_start})")
            except ValueError:
                pass
        if self.time_end:
            try:
                end = datetime.datetime.fromisoformat(self.time_end)
                if now > end:
                    return (False, f"After window end ({self.time_end})")
            except ValueError:
                pass
        return (True, "")

    def check(self, cmd: str, target_hint: str = "") -> Tuple[bool, str]:
        """Return (allowed, reason).  If not enabled, always allowed."""
        if not self.enabled:
            return (True, "")

        # Time window first
        ok, reason = self._check_time_window()
        if not ok:
            return (False, f"Outside engagement time window: {reason}")

        # Pull every IP and bare-hostname from the command
        ips = set(re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', cmd))
        # Domains: filter out IPs and noise
        domain_candidates = set(re.findall(
            r'\b([a-zA-Z][a-zA-Z0-9\-_]*(?:\.[a-zA-Z0-9\-_]+)+)\b', cmd))
        domains = set()
        for d in domain_candidates:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
                continue
            if d.lower() in DOMAIN_NOISE:
                continue
            domains.add(d.lower())

        # Add the explicit target hint if any
        if target_hint:
            ip_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_hint)
            if ip_match:
                ips.add(target_hint)
            else:
                domains.add(target_hint.lower())

        # If no targets present, treat as local/utility command — allow
        if not ips and not domains:
            return (True, "")

        # Check blocks first
        for ip in ips:
            if self._ip_in_cidrs(ip, self.blocked_cidrs):
                return (False, f"IP {ip} in blocked_cidrs")
        for d in domains:
            if self._domain_matches(d, self.blocked_domains):
                return (False, f"Domain {d} in blocked_domains")

        # Check allows (only if any allow rules exist)
        # Note: IP_NOISE filter is intentionally NOT applied here —
        # scope enforcement must check every target IP, even if it's
        # something like 8.8.8.8 that we'd normally ignore as noise
        # in finding extraction.
        has_ip_allow = bool(self.allowed_cidrs)
        has_dom_allow = bool(self.allowed_domains)

        if has_ip_allow:
            for ip in ips:
                if not self._ip_in_cidrs(ip, self.allowed_cidrs):
                    return (False, f"IP {ip} not in allowed_cidrs")

        if has_dom_allow:
            for d in domains:
                if not self._domain_matches(d, self.allowed_domains):
                    return (False, f"Domain {d} not in allowed_domains")

        return (True, "")

    def summary(self) -> str:
        lines = []
        state = "\033[32mENABLED\033[0m" if self.enabled else "\033[90mdisabled\033[0m"
        lines.append(f"Scope: {state}")
        if self.allowed_cidrs:
            lines.append(f"  allowed CIDRs:   {', '.join(self.allowed_cidrs)}")
        if self.blocked_cidrs:
            lines.append(f"  blocked CIDRs:   {', '.join(self.blocked_cidrs)}")
        if self.allowed_domains:
            lines.append(f"  allowed domains: {', '.join(self.allowed_domains)}")
        if self.blocked_domains:
            lines.append(f"  blocked domains: {', '.join(self.blocked_domains)}")
        if self.time_start or self.time_end:
            lines.append(f"  time window:     {self.time_start or '(open)'} → {self.time_end or '(open)'}")
        return "\n".join(lines)


# ═════════════════════════════════════════════════════════════════════
# ATTACK GRAPH (v7.1)
#
# Lightweight graph-based memory layered on top of findings.  Hosts,
# services, credentials, hashes, vulns are nodes.  Edges encode
# relationships: "service runs_on host", "cred works_on service",
# "vuln affects service", "host can_pivot_to host".  Used for surfacing
# pivot suggestions the LLM might miss in the flat finding list.
# ═════════════════════════════════════════════════════════════════════

class AttackGraph:
    """Wrapper around networkx.DiGraph with offsec-specific semantics.
    Falls through to no-op stubs if networkx isn't installed so the
    rest of Ares keeps working."""

    NODE_HOST    = "host"
    NODE_SVC     = "service"
    NODE_CRED    = "credential"
    NODE_HASH    = "hash"
    NODE_VULN    = "vuln"
    NODE_USER    = "user"
    NODE_DOMAIN  = "domain"

    EDGE_RUNS_ON = "runs_on"        # service -> host
    EDGE_WORKS   = "works_on"       # cred -> service
    EDGE_FOR     = "for_user"       # cred -> user
    EDGE_AFFECTS = "affects"        # vuln -> service
    EDGE_PIVOT   = "can_pivot_to"   # host -> host
    EDGE_BELONGS = "in_domain"      # host -> domain

    def __init__(self):
        if HAS_NETWORKX:
            self.g = nx.DiGraph()
        else:
            self.g = None

    def _has(self) -> bool:
        return self.g is not None

    def add_host(self, ip: str, **attrs):
        if not self._has() or not ip:
            return
        self.g.add_node(f"host:{ip}", kind=self.NODE_HOST, label=ip, **attrs)

    def add_service(self, host_ip: str, port: int, name: str = "", version: str = ""):
        if not self._has() or not host_ip:
            return
        sid = f"svc:{host_ip}:{port}"
        self.g.add_node(sid, kind=self.NODE_SVC,
                        label=f"{port}/{name}" if name else str(port),
                        version=version, port=port)
        self.g.add_edge(sid, f"host:{host_ip}", kind=self.EDGE_RUNS_ON)

    def add_credential(self, value: str, user: str = "",
                       host: str = "", verified: bool = False):
        if not self._has() or not value:
            return
        cid = f"cred:{value[:24]}"
        self.g.add_node(cid, kind=self.NODE_CRED, label=value[:32],
                        verified=verified)
        if user:
            uid = f"user:{user}"
            self.g.add_node(uid, kind=self.NODE_USER, label=user)
            self.g.add_edge(cid, uid, kind=self.EDGE_FOR)
        if host:
            self.g.add_edge(cid, f"host:{host}", kind=self.EDGE_WORKS)

    def add_hash(self, value: str, htype: str, user: str = ""):
        if not self._has() or not value:
            return
        hid = f"hash:{value[:16]}"
        self.g.add_node(hid, kind=self.NODE_HASH,
                        label=f"{htype}:{value[:12]}…", htype=htype)
        if user:
            uid = f"user:{user}"
            self.g.add_node(uid, kind=self.NODE_USER, label=user)
            self.g.add_edge(hid, uid, kind=self.EDGE_FOR)

    def add_vuln(self, cve: str, host: str = "", service_port: Optional[int] = None):
        if not self._has() or not cve:
            return
        vid = f"vuln:{cve}"
        self.g.add_node(vid, kind=self.NODE_VULN, label=cve)
        if host and service_port:
            self.g.add_edge(vid, f"svc:{host}:{service_port}", kind=self.EDGE_AFFECTS)
        elif host:
            self.g.add_edge(vid, f"host:{host}", kind=self.EDGE_AFFECTS)

    def mark_cred_verified_on(self, cred_value: str, host: str, port: int):
        if not self._has():
            return
        cid = f"cred:{cred_value[:24]}"
        sid = f"svc:{host}:{port}"
        if cid in self.g and sid in self.g:
            self.g.add_edge(cid, sid, kind=self.EDGE_WORKS, verified=True)

    def auth_services(self) -> List[Tuple[str, int, str]]:
        """Return all auth-able services as (host, port, name)."""
        if not self._has():
            return []
        results = []
        AUTH_PORTS = {21, 22, 23, 80, 110, 143, 389, 443, 445, 1433, 1521,
                      3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443,
                      9200, 27017}
        for nid, attrs in self.g.nodes(data=True):
            if attrs.get("kind") != self.NODE_SVC:
                continue
            port = attrs.get("port", 0)
            if port in AUTH_PORTS:
                # parse host from nid svc:HOST:PORT
                parts = nid.split(":")
                if len(parts) >= 3:
                    results.append((parts[1], port, attrs.get("label", "")))
        return results

    def cred_fanout_targets(self, cred_value: str) -> List[Tuple[str, int, str]]:
        """For a given credential, return services it hasn't been
        verified-tested against yet."""
        if not self._has():
            return []
        cid = f"cred:{cred_value[:24]}"
        if cid not in self.g:
            return []
        # Edges out of cid that are 'works_on' AND verified=True
        verified_against = set()
        for _, tgt, attrs in self.g.out_edges(cid, data=True):
            if attrs.get("kind") == self.EDGE_WORKS and attrs.get("verified"):
                verified_against.add(tgt)
        # All auth services minus already-verified
        targets = []
        for host, port, name in self.auth_services():
            sid = f"svc:{host}:{port}"
            if sid not in verified_against:
                targets.append((host, port, name))
        return targets

    def pivot_suggestions(self) -> List[str]:
        """Surface attack-graph queries the LLM should consider."""
        if not self._has():
            return []
        suggestions = []
        # Creds that have never been tested
        for nid, attrs in self.g.nodes(data=True):
            if attrs.get("kind") == self.NODE_CRED and not attrs.get("verified"):
                tested = sum(1 for _, _, e in self.g.out_edges(nid, data=True)
                             if e.get("kind") == self.EDGE_WORKS)
                if tested == 0:
                    suggestions.append(
                        f"Untested credential {attrs.get('label','?')} — "
                        f"try across {len(self.auth_services())} auth services")
        # Vulns without exploit attempt
        vulns = [a.get("label") for n, a in self.g.nodes(data=True)
                 if a.get("kind") == self.NODE_VULN]
        if vulns:
            suggestions.append(f"Known CVEs not yet exploited: {', '.join(vulns[:5])}")
        # Hashes without crack attempt
        hashes = [a.get("label") for n, a in self.g.nodes(data=True)
                  if a.get("kind") == self.NODE_HASH]
        if hashes:
            suggestions.append(f"{len(hashes)} hash(es) in queue — confirm cracking attempted")
        return suggestions

    def summary(self) -> str:
        if not self._has():
            return "Attack graph: networkx not installed (disabled)"
        counts = {}
        for _, attrs in self.g.nodes(data=True):
            k = attrs.get("kind", "unknown")
            counts[k] = counts.get(k, 0) + 1
        parts = [f"{v} {k}{'s' if v != 1 else ''}" for k, v in sorted(counts.items())]
        return f"Attack graph: {len(self.g.nodes)} nodes, {len(self.g.edges)} edges  ({', '.join(parts)})"

    def to_compact_text(self, max_chars: int = 1200) -> str:
        """Compact text representation for prompt injection on demand."""
        if not self._has():
            return "(graph disabled)"
        lines = [self.summary()]
        # Group hosts and their services
        hosts = [(n, a) for n, a in self.g.nodes(data=True)
                 if a.get("kind") == self.NODE_HOST]
        for hid, hattrs in hosts[:8]:
            ip = hattrs.get("label", "?")
            lines.append(f"  HOST {ip}:")
            # Services on this host
            svcs = []
            for src, dst, eattrs in self.g.in_edges(hid, data=True):
                if eattrs.get("kind") == self.EDGE_RUNS_ON:
                    sa = self.g.nodes[src]
                    svcs.append(sa.get("label", "?"))
            if svcs:
                lines.append(f"    services: {', '.join(svcs[:8])}")
        # Pivot suggestions
        sugg = self.pivot_suggestions()
        if sugg:
            lines.append("  PIVOT HINTS:")
            for s in sugg[:5]:
                lines.append(f"    - {s}")
        text = "\n".join(lines)
        return text[:max_chars] + ("..." if len(text) > max_chars else "")


# ═════════════════════════════════════════════════════════════════════
# CONTEXT MANAGER (v7.1) — token-saving smart context
#
# By default each turn ships a MINIMAL system prompt:
#   - active node only (not full PTT)
#   - verified findings (no unverified flood)
#   - last DEFAULT_HISTORY_SLICE turns (not full MAX_HISTORY_MESSAGES)
#   - role-filtered KB (already in v7.0)
#   - tool registry compact form
#
# When the LLM actually needs more, it emits [NEED]target[/NEED] and
# the agent loop re-fetches with that target attached and replays the
# turn.  Targets:
#   [NEED]ptt[/NEED]              full Defense Task Tree
#   [NEED]history[/NEED]          all 32 turns of history
#   [NEED]findings[/NEED]         verified + unverified findings
#   [NEED]graph[/NEED]            attack-graph compact text + pivots
#   [NEED]kb 5[/NEED]             specific KB section by number
#
# Auto-expansion triggers (no [NEED] required):
#   confidence in {yellow, red}  → expanded slice + ptt + graph
#   stuck_counter > 0            → expanded slice
#   new node entered             → ptt summary
# ═════════════════════════════════════════════════════════════════════

class ContextManager:
    """Decides what slice of state to send each turn.  Stateful so it
    can adapt based on confidence / stuck / new-node signals."""

    def __init__(self):
        self.last_node_id: Optional[str] = None
        self.recent_conf: str = "green"
        self.recent_stuck: int = 0
        self.tokens_saved_estimate: int = 0  # crude rolling estimate

    def signal_node_change(self, nid: Optional[str]):
        if nid != self.last_node_id:
            self.last_node_id = nid

    def signal_confidence(self, conf: str):
        self.recent_conf = conf

    def signal_stuck(self, n: int):
        self.recent_stuck = n

    def history_slice_size(self) -> int:
        """How many history turns to include this turn."""
        if self.recent_conf in ("yellow", "red"):
            return EXPANDED_HISTORY_SLICE
        if self.recent_stuck > 0:
            return EXPANDED_HISTORY_SLICE
        return DEFAULT_HISTORY_SLICE

    def should_attach_full_ptt(self) -> bool:
        return self.recent_conf in ("yellow", "red") or self.recent_stuck > 0

    def should_attach_graph(self) -> bool:
        return self.recent_conf in ("yellow", "red") or self.recent_stuck > 0

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Crude estimate: ~4 chars per token."""
        return max(1, len(text) // 4)

    def record_savings(self, full_size: int, sent_size: int):
        if full_size > sent_size:
            self.tokens_saved_estimate += (full_size - sent_size) // 4


# ═════════════════════════════════════════════════════════════════════
# WORKFLOWS — PTT seeders
#
# Each workflow now constructs an initial PTT for a given engagement
# type, instead of just being a fixed prompt.  Ares's loop then
# walks the tree, dispatching the right specialist per phase.
# ═════════════════════════════════════════════════════════════════════

WORKFLOWS = {

    "1": {
        "name": "Triage / Health Check",
        "description": "Identity → sockets → processes → recent /etc → auth bursts",
        "seed": [
            ("Identity & uptime (id/uname/uptime)",         "triage"),
            ("Listening sockets with PIDs (ss -tlnp)",      "triage"),
            ("Process tree (ps auxf, sorted by etime)",      "triage"),
            ("Recently modified /etc + /usr/local",          "triage"),
            ("Auth events last 24h (journalctl + auth.log)", "log_analyst"),
            ("SUID baseline diff",                            "hardener"),
            ("Verdict: healthy / suspicious / compromised",  "triage"),
        ],
    },

    "2": {
        "name": "Live IR — Suspected Compromise",
        "description": "Containment-first IR: triage → hunt → contain → eradicate",
        "seed": [
            ("Snapshot evidence (ps/ss/lsof/last)",          "triage"),
            ("Capture deleted-but-held files (lsof +L1)",    "threat_hunter"),
            ("Hash + collect suspect binaries",               "ir_responder"),
            ("Persistence sweep (cron/systemd/ld.preload)",  "threat_hunter"),
            ("Auth log timeline around incident",             "log_analyst"),
            ("Memory image (avml) for later forensics",       "forensics_analyst"),
            ("Containment: kill / quarantine / block",        "ir_responder"),
            ("Post-IR report",                                "reporter"),
        ],
    },

    "3": {
        "name": "Hardening Audit",
        "description": "Lynis quick → deep dives on warnings → CIS gaps",
        "seed": [
            ("lynis --quick baseline pass",                   "hardener"),
            ("SSH config audit",                              "hardener"),
            ("PAM / login.defs review",                       "hardener"),
            ("sysctl hardening checks",                       "hardener"),
            ("Firewall ruleset review",                       "hardener"),
            ("File-integrity baseline (aide/debsums)",        "hardener"),
            ("Hardening recommendations report",              "reporter"),
        ],
    },

    "4": {
        "name": "Linux Persistence Hunt",
        "description": "Cron → systemd → init → SSH keys → ld.preload → modules",
        "seed": [
            ("Cron + at jobs sweep",                          "threat_hunter"),
            ("systemd units (recently modified)",             "threat_hunter"),
            ("Login hooks (.bashrc/.profile/.zshrc)",         "threat_hunter"),
            ("authorized_keys audit",                         "threat_hunter"),
            ("/etc/ld.so.preload + LD_PRELOAD checks",        "threat_hunter"),
            ("Kernel modules (lsmod, /etc/modules-load.d)",   "threat_hunter"),
            ("PAM tampering check",                           "threat_hunter"),
            ("Web shell hunt (eval/base64_decode in /var/www)","threat_hunter"),
        ],
    },

    "5": {
        "name": "Process / Network Anomaly Hunt",
        "description": "Listening ports → pid → exe → outbound conn → IOC",
        "seed": [
            ("ss -tlnp full listing",                         "threat_hunter"),
            ("ss -tnp state established (top talkers)",       "threat_hunter"),
            ("ps aux + readlink /proc/PID/exe per suspect",   "threat_hunter"),
            ("lsof -i for parent PIDs",                       "threat_hunter"),
            ("yara scan of suspect binaries",                 "malware_analyst"),
            ("VT/abuse.ch lookup of binary hashes",           "malware_analyst"),
            ("If outbound IOC: pcap on dst",                  "network_defender"),
        ],
    },

    "6": {
        "name": "Authentication Failure Analysis",
        "description": "auth.log brute detection → fail2ban verify → spray vs distributed",
        "seed": [
            ("Failed auth frequency table",                   "log_analyst"),
            ("Top source IPs of failures",                    "log_analyst"),
            ("Same-user-multiple-sources test",               "log_analyst"),
            ("fail2ban jail status + bans",                   "identity_defender"),
            ("Successful auth from new sources",              "log_analyst"),
            ("Block recommendation",                          "ir_responder"),
        ],
    },

    "7": {
        "name": "Malware Static Triage",
        "description": "file → hash → strings → capa → yara → IOC pivot",
        "seed": [
            ("Inspect (file/sha256/exiftool/readelf)",        "malware_analyst"),
            ("Strings (ASCII + UTF-16)",                      "malware_analyst"),
            ("capa capability map",                           "malware_analyst"),
            ("yara family identification",                     "malware_analyst"),
            ("clamscan signature check",                      "malware_analyst"),
            ("Hash → VT / abuse.ch lookup",                   "malware_analyst"),
            ("IOC bundle export",                             "reporter"),
        ],
    },

    "8": {
        "name": "PCAP Analysis",
        "description": "Top talkers → DNS → TLS SNI → HTTP → Suricata replay",
        "seed": [
            ("Conversations summary (tshark conv,ip)",        "network_defender"),
            ("DNS query summary (tshark dns,tree)",           "network_defender"),
            ("TLS SNI list (tshark fields server_name)",      "network_defender"),
            ("HTTP host+URI extraction",                       "network_defender"),
            ("Zeek offline replay → conn/dns/http/ssl logs",   "network_defender"),
            ("Suricata replay → fast.log alert review",       "network_defender"),
            ("IOC enrichment of suspicious IPs/domains",       "network_defender"),
        ],
    },

    "9": {
        "name": "Memory Forensics",
        "description": "Banner ID → pstree → malfind → netscan → IOC pivot",
        "seed": [
            ("Identify image (banners.Banners / windows.info)", "forensics_analyst"),
            ("Process tree (linux.pstree / windows.pstree)",   "forensics_analyst"),
            ("Hidden processes (psscan / linux.psaux)",         "forensics_analyst"),
            ("Open sockets (netscan / sockstat)",               "forensics_analyst"),
            ("Code injection (windows.malfind)",                "forensics_analyst"),
            ("Bash history (linux.bash)",                       "forensics_analyst"),
            ("Dump suspect process for static analysis",        "forensics_analyst"),
        ],
    },

    "10": {
        "name": "Disk Forensics",
        "description": "Image hash → mmls → fls → mactime timeline → carve",
        "seed": [
            ("Hash + verify image",                           "forensics_analyst"),
            ("Partition layout (mmls)",                        "forensics_analyst"),
            ("File listing → body file (fls -r -m)",           "forensics_analyst"),
            ("Mactime timeline render",                        "forensics_analyst"),
            ("Window-of-interest analysis",                    "forensics_analyst"),
            ("Browser / shell history extraction",             "forensics_analyst"),
            ("File carving of unallocated (foremost)",         "forensics_analyst"),
        ],
    },

    "11": {
        "name": "Log Review",
        "description": "Time-windowed sweep across journal/auth/audit",
        "seed": [
            ("journalctl errors today",                       "log_analyst"),
            ("auth.log Failed/Accepted breakdown",             "log_analyst"),
            ("auditd ausearch by key",                         "log_analyst"),
            ("aureport summaries (auth/exec/anomaly)",         "log_analyst"),
            ("Web server 4xx → 200 anomalies",                 "log_analyst"),
        ],
    },

    "12": {
        "name": "TLS / SSL Audit",
        "description": "sslscan + testssl + ssh-audit on own services",
        "seed": [
            ("sslscan quick cipher list",                     "hardener"),
            ("testssl HIGH severity",                          "hardener"),
            ("ssh-audit baseline check",                       "hardener"),
            ("Cert chain + expiry review",                     "hardener"),
            ("Hardening diff",                                 "hardener"),
        ],
    },

    "13": {
        "name": "Account Audit",
        "description": "passwd/shadow → sudoers → SSH keys → stale accounts",
        "seed": [
            ("System vs human accounts split",                "identity_defender"),
            ("Empty / locked / set-password split",            "identity_defender"),
            ("sudoers + sudoers.d review",                     "identity_defender"),
            ("authorized_keys sweep across /home + /root",     "identity_defender"),
            ("Stale account check (chage -l)",                 "identity_defender"),
            ("wheel/sudo group membership",                    "identity_defender"),
        ],
    },

    "14": {
        "name": "SUID / Capability Audit",
        "description": "find SUID/SGID → getcap -r → diff vs baseline",
        "seed": [
            ("SUID enumeration (find -perm -4000)",            "hardener"),
            ("SGID enumeration (find -perm -2000)",            "hardener"),
            ("Capability grants (getcap -r /)",                "hardener"),
            ("Diff vs baseline (if AIDE present)",             "hardener"),
            ("World-writable files audit",                     "hardener"),
        ],
    },

    "15": {
        "name": "Service Exposure Audit",
        "description": "ss listening → vs expected → firewall match",
        "seed": [
            ("ss -tlnp full listing",                         "triage"),
            ("Map each listener to systemd unit",              "triage"),
            ("Firewall ruleset (nft/iptables/ufw)",            "hardener"),
            ("Expose vs ruleset reconciliation",               "hardener"),
            ("Recommend deny-by-default",                      "hardener"),
        ],
    },

    "16": {
        "name": "Linux Post-Compromise IR",
        "description": "Containment chain after confirmed breach",
        "seed": [
            ("Evidence snapshot (ps/ss/lsof/last/dmesg)",     "ir_responder"),
            ("Memory image (avml)",                            "forensics_analyst"),
            ("Persistence inventory",                          "threat_hunter"),
            ("Block C2 IPs at firewall",                       "ir_responder"),
            ("Quarantine suspect binaries",                    "ir_responder"),
            ("Disable compromised accounts",                   "identity_defender"),
            ("Rotate credentials/keys",                        "identity_defender"),
            ("IR report",                                      "reporter"),
        ],
    },

    "17": {
        "name": "Container / Cloud Audit",
        "description": "docker ps → privileged containers → trivy → kube-bench",
        "seed": [
            ("docker ps + inspect privileged flag",           "hardener"),
            ("Image scan (trivy/grype)",                       "hardener"),
            ("Falco rules validation",                         "hardener"),
            ("kube-bench CIS K8s benchmark (if K8s)",          "hardener"),
            ("ServiceAccount RBAC review",                     "identity_defender"),
        ],
    },

    "18": {
        "name": "File Integrity Check",
        "description": "AIDE check → debsums → diff /etc",
        "seed": [
            ("aide --check (vs baseline)",                    "hardener"),
            ("debsums -c (changed package files)",             "hardener"),
            ("Diff /etc vs known-good snapshot",               "hardener"),
            ("Identify legitimate vs unexpected changes",      "hardener"),
        ],
    },

    "19": {
        "name": "Suricata / Zeek Alert Review",
        "description": "fast.log triage → pivot to host → IOC enrichment",
        "seed": [
            ("Tail suricata fast.log",                        "network_defender"),
            ("Group alerts by sig + frequency",                "network_defender"),
            ("Pivot to host via lsof on dst port",             "network_defender"),
            ("Zeek conn.log corroboration",                    "network_defender"),
            ("IOC enrichment (VT/abuseipdb)",                  "network_defender"),
        ],
    },

    "20": {
        "name": "IDS Rule Tuning",
        "description": "Test pcap → rule diff → false-positive review",
        "seed": [
            ("Suricata replay against curated pcap",          "network_defender"),
            ("False-positive rate calculation",                "network_defender"),
            ("Rule disable / threshold tuning proposal",       "network_defender"),
            ("suricata-update + reload-rules",                 "network_defender"),
        ],
    },

    "21": {
        "name": "Firewall Audit",
        "description": "Ruleset review → orphan rules → log-and-drop coverage",
        "seed": [
            ("List ruleset (nft/iptables/ufw)",               "hardener"),
            ("Orphaned / contradictory rules",                 "hardener"),
            ("Log-and-drop on default deny verification",      "hardener"),
            ("fail2ban jail status",                           "hardener"),
        ],
    },

    "22": {
        "name": "Forensics Evidence Collection",
        "description": "Hash → image → preserve → chain of custody",
        "seed": [
            ("Pre-collection hash list",                      "forensics_analyst"),
            ("Memory image (avml/lime)",                       "forensics_analyst"),
            ("Disk image (dc3dd/ewfacquire)",                  "forensics_analyst"),
            ("Post-collection hash + verify",                  "forensics_analyst"),
            ("Chain-of-custody log",                           "reporter"),
        ],
    },

    "23": {
        "name": "Rootkit Hunt",
        "description": "rkhunter + chkrootkit + lynis + hidden-pid sweep",
        "seed": [
            ("rkhunter --check",                              "threat_hunter"),
            ("chkrootkit -q",                                  "threat_hunter"),
            ("lynis --tests-from-group malware",                "threat_hunter"),
            ("Hidden PID sweep (unhide / ps vs /proc diff)",   "threat_hunter"),
            ("Kernel module integrity",                        "threat_hunter"),
        ],
    },
}


# ═════════════════════════════════════════════════════════════════════
# CORE RULES embedded in every system prompt
# ═════════════════════════════════════════════════════════════════════

CORE_RULES = (
    "OUTPUT FORMAT (STRICT — emit ONE of either form):\n"
    "  [THOUGHT]<reasoning>[/THOUGHT]\n"
    "  EITHER (preferred for known tools):\n"
    "    [TOOL]<tool_name>[/TOOL][ARGS]<json object of args>[/ARGS]\n"
    "  OR (for ad-hoc commands not in the tool registry):\n"
    "    [CMD]<one shell command, non-interactive>[/CMD]\n"
    "  [CONF]<green|yellow|red>[/CONF]\n"
    "  Optional: [VERIFY]<command to verify a finding>[/VERIFY]\n"
    "  Optional: [HANDOFF]<other agent role>[/HANDOFF]\n"
    "  Optional: [NEED]<ptt|history|findings|graph|kb N>[/NEED]\n"
    "    Use [NEED] when you require more state than the minimal context\n"
    "    provided.  The system will re-call you with that data attached.\n"
    "    Examples: [NEED]ptt[/NEED]   [NEED]graph[/NEED]   [NEED]kb 7[/NEED]\n"
    "\n"
    "TOOL FORMAT EXAMPLES:\n"
    '  [TOOL]ss_listening[/TOOL][ARGS]{"proto":"tcp","processes":true}[/ARGS]\n'
    '  [TOOL]journalctl[/TOOL][ARGS]{"unit":"sshd","since":"24 hours ago","grep":"Failed|Invalid"}[/ARGS]\n'
    '  [TOOL]find_recent_files[/TOOL][ARGS]{"path":"/etc","minutes":1440}[/ARGS]\n'
    '  [TOOL]yara_scan[/TOOL][ARGS]{"path":"/tmp/sample.bin","recursive":false}[/ARGS]\n'
    '  [TOOL]volatility_run[/TOOL][ARGS]{"image":"/mnt/ev/mem.lime","plugin":"linux.pstree"}[/ARGS]\n'
    '  [TOOL]auth_log_grep[/TOOL][ARGS]{"pattern":"Failed password","max_results":50}[/ARGS]\n'
    "\n"
    "WHEN TO USE [TOOL] vs [CMD]:\n"
    " - [TOOL] for any tool listed in the registry — guarantees flag correctness.\n"
    " - [CMD] for: custom awk/jq pipelines, one-off log greps, in-flight calculations,\n"
    "   reading specific files, anything not in the registry.\n"
    "\n"
    "DEFENDER DISCIPLINE:\n"
    " - READ-ONLY by default.  Containment actions (kill, block, quarantine,\n"
    "   account lock, service stop, firewall flush) require explicit GREEN\n"
    "   confidence and will hit a double-confirm gate.\n"
    " - Always preserve evidence BEFORE remediating: hash the binary,\n"
    "   capture ps output, save lsof state.  Never delete first.\n"
    " - Never disable logging, audit rules, or AV during an active incident.\n"
    " - Never repeat a command verbatim.\n"
    " - When you find an IOC, propagate it: search every relevant log/host\n"
    "   for the same indicator before moving on.\n"
    " - Bound captures: tcpdump always with -c N or -G/-W.  No infinite tails.\n"
    " - WORKFLOW_COMPLETE in [CMD] when current node is done.\n"
    " - CONF green = high confidence direct check.\n"
    " - CONF yellow = uncertain, propose pivot.\n"
    " - CONF red = need more info before any command.\n"
    " - Cite ATT&CK technique IDs in [THOUGHT] where relevant.\n"
    " - Reason from real subprocess output only — never from prior assumptions."
)


def build_system_prompt(agent_role: str,
                        target_info: Dict[str, Any],
                        ptt: PTT,
                        active_node: Optional[PTTNode],
                        lhost: str,
                        workflow_key: Optional[str] = None,
                        free_form: str = "",
                        context_mgr: Optional["ContextManager"] = None,
                        graph: Optional["AttackGraph"] = None,
                        scope: Optional["ScopeConfig"] = None,
                        force_full: bool = False,
                        need_attachments: Optional[List[str]] = None) -> str:
    """Compose system prompt for the chosen specialist agent.

    v7.1 — minimal context by default, expanded on demand.
    Includes: agent persona + extra rules + KB sections + active node +
    findings summary + Kali tool registry summary + structured tool
    registry + core rules.  When force_full=True or [NEED] tags trigger,
    extra context is attached.
    """
    spec = AGENT_SPECS.get(agent_role, AGENT_SPECS["triage"])
    need_attachments = need_attachments or []

    # Decide expansion level
    expand_ptt   = force_full or "ptt" in need_attachments
    expand_finds = force_full or "findings" in need_attachments
    expand_graph = force_full or "graph" in need_attachments
    if context_mgr:
        if context_mgr.should_attach_full_ptt():
            expand_ptt = True
        if context_mgr.should_attach_graph():
            expand_graph = True

    # Target block
    target_parts = []
    if target_info.get("ip"):
        target_parts.append(f"Target: {target_info['ip']}")
    if target_info.get("domain"):
        target_parts.append(f"Domain: {target_info['domain']}")
    if target_info.get("notes"):
        target_parts.append(f"Mission: {target_info['notes']}")
    target_block = " | ".join(target_parts) if target_parts else "No target set"

    # Active node context (always present, even in minimal mode)
    node_block = ""
    if active_node:
        node_block = (
            f"CURRENT NODE: [{active_node.nid}] {active_node.title} "
            f"(phase={active_node.phase}, status={active_node.status}, "
            f"attempts={active_node.attempts}, conf={active_node.confidence})"
        )
        if active_node.last_cmd:
            node_block += f"\n  last_cmd: {active_node.last_cmd}"

    # Findings summary — minimal (verified counts) by default
    verified = ptt.get_verified()
    unverified = ptt.get_unverified()

    findings_block = ""
    if expand_finds:
        # Full dump — verified + unverified
        if verified or unverified:
            findings_block = "FINDINGS (FULL):\n"
            if verified:
                v_dict: Dict[str, List[str]] = {}
                for f in verified:
                    v_dict.setdefault(f.ftype, []).append(f.value)
                findings_block += "  VERIFIED:\n"
                for k, vs in v_dict.items():
                    findings_block += f"    {k}: {', '.join(vs[-10:])}\n"
            if unverified:
                u_dict: Dict[str, List[str]] = {}
                for f in unverified:
                    u_dict.setdefault(f.ftype, []).append(f.value)
                findings_block += "  UNVERIFIED (treat as candidates only):\n"
                for k, vs in u_dict.items():
                    findings_block += f"    {k}: {', '.join(vs[-10:])}\n"
    else:
        # Compact — verified only, last 4 per type
        if verified:
            v_dict_c: Dict[str, List[str]] = {}
            for f in verified:
                v_dict_c.setdefault(f.ftype, []).append(f.value)
            findings_block = "VERIFIED FINDINGS:\n"
            for k, vs in v_dict_c.items():
                findings_block += f"  {k}: {', '.join(vs[-4:])}\n"
        if unverified:
            findings_block += f"  ({len(unverified)} unverified — request [NEED]findings[/NEED] if relevant)\n"

    # PTT — minimal (just current branch) or full
    if expand_ptt:
        ptt_block = ptt.to_natural_language(max_chars=2000)
    elif active_node:
        # Just show current node + immediate siblings + parent
        nodes_to_show = {active_node.nid}
        if active_node.parent_id:
            nodes_to_show.add(active_node.parent_id)
            parent = ptt.nodes.get(active_node.parent_id)
            if parent:
                for sib in parent.children:
                    nodes_to_show.add(sib)
        ptt_block_lines = ["PTT (current branch only — request [NEED]ptt[/NEED] for full tree):"]
        for nid in sorted(nodes_to_show):
            n = ptt.nodes.get(nid)
            if n:
                glyph = ptt.STATUS_GLYPH.get(n.status, "?")
                ptt_block_lines.append(f"  {glyph} [{n.nid}] {n.title} ({n.status})")
        ptt_block = "\n".join(ptt_block_lines)
    else:
        ptt_block = "PTT: (empty — set a target first)"

    # Skip directives derived from findings
    skip = []
    fdict = ptt.findings_by_type_dict()
    if fdict.get("port"):
        skip.append("ports already known — skip discovery")
    if fdict.get("ip") and len(fdict["ip"]) > 1:
        skip.append("hosts already known — skip ping sweep")
    if fdict.get("svc"):
        skip.append("services fingerprinted — skip banner grab")
    if fdict.get("user"):
        skip.append("USE known users for spray")
    if fdict.get("cred"):
        skip.append("TEST creds across all services NOW")
    if fdict.get("hash") or fdict.get("hash_ntlm") or fdict.get("krb_hash"):
        skip.append("QUEUE hashes for cracking")
    if fdict.get("cve"):
        skip.append("EXPLOIT known CVEs first")
    skip_block = ""
    if skip:
        skip_block = "PIVOT DIRECTIVES: " + " | ".join(skip)

    # Attack graph block
    graph_block = ""
    if expand_graph and graph is not None:
        graph_block = "ATTACK GRAPH STATE:\n" + graph.to_compact_text(max_chars=1200)
    elif graph is not None:
        graph_block = f"GRAPH: {graph.summary()}  (request [NEED]graph[/NEED] for paths)"

    # Knowledge base — agent-aware
    kb_text = get_kb_sections(workflow_key=workflow_key,
                              prompt_text=free_form,
                              agent_role=agent_role)

    # Apply [NEED]kb N[/NEED] requests
    for att in need_attachments:
        if att.startswith("kb "):
            try:
                num = int(att.split()[1])
                if num in KB:
                    kb_text += "\n\n" + KB[num]
            except (ValueError, IndexError):
                pass

    # Kali tools available (compact)
    tools_block = kali_tool_summary_for_prompt()

    # NEW: structured tool registry for [TOOL]/[ARGS] format
    structured_block = tool_registry_for_prompt()

    # Scope reminder
    scope_block = ""
    if scope and scope.enabled:
        scope_block = "⚠ ENGAGEMENT SCOPE ENFORCED — out-of-scope commands will be refused."

    parts = [
        f"You are Ares, an elite DEFENSIVE security AI assistant on Kali NetHunter.",
        f"You hunt threats, harden systems, triage incidents, and respond to compromise.",
        f"You are READ-ONLY by default.  Containment actions require explicit confirmation.",
        f"Commander: The Priest.  This host: {lhost}",
        "",
        f"=== ACTIVE AGENT: {spec['icon']} {spec['name']} ===",
        spec["persona"],
        spec["extra_rules"],
        "",
        target_block,
    ]
    if scope_block:
        parts.append(scope_block)
    if node_block:
        parts.append(node_block)
    if findings_block:
        parts.append(findings_block.strip())
    if skip_block:
        parts.append(skip_block)
    parts.append(ptt_block)
    if graph_block:
        parts.append(graph_block)
    parts.append(structured_block)
    parts.append(tools_block)
    parts.append("KNOWLEDGE BASE:\n" + kb_text)
    parts.append(CORE_RULES)
    return "\n\n".join(parts)


# ═════════════════════════════════════════════════════════════════════
# RESPONSE PARSING
# ═════════════════════════════════════════════════════════════════════

def parse_specialist_response(text: str) -> Dict[str, Any]:
    """Extract THOUGHT / CMD / TOOL / ARGS / CONF / VERIFY / HANDOFF /
    NEED from model output.  v7.1: TOOL/ARGS/NEED added."""
    out = {
        "thought":  "",
        "cmd":      None,
        "tool":     None,        # v7.1
        "args":     None,        # v7.1
        "conf":     "green",
        "verify":   None,
        "handoff":  None,
        "need":     [],          # v7.1 — list of attachment requests
    }
    if not text:
        return out

    t = re.search(r'\[THOUGHT\](.*?)\[/?THOUGHT\]', text, re.DOTALL | re.IGNORECASE)
    if t:
        out["thought"] = t.group(1).strip()

    c = re.search(r'\[CMD\](.*?)\[/?CMD\]', text, re.DOTALL | re.IGNORECASE)
    if c:
        out["cmd"] = c.group(1).strip()

    # v7.1 — structured tool dispatch
    tool_m = re.search(r'\[TOOL\]\s*([\w_]+)\s*\[/?TOOL\]', text, re.IGNORECASE)
    if tool_m:
        out["tool"] = tool_m.group(1).strip()
    args_m = re.search(r'\[ARGS\](.*?)\[/?ARGS\]', text, re.DOTALL | re.IGNORECASE)
    if args_m:
        out["args"] = args_m.group(1).strip()

    cf = re.search(r'\[CONF\]\s*(green|yellow|red)\s*\[/?CONF\]',
                   text, re.IGNORECASE)
    if cf:
        out["conf"] = cf.group(1).lower()

    v = re.search(r'\[VERIFY\](.*?)\[/?VERIFY\]', text, re.DOTALL | re.IGNORECASE)
    if v:
        out["verify"] = v.group(1).strip()

    h = re.search(r'\[HANDOFF\]\s*(\w+)\s*\[/?HANDOFF\]', text, re.IGNORECASE)
    if h:
        out["handoff"] = h.group(1).strip().lower()

    # v7.1 — multiple [NEED] tags allowed in one response
    needs = re.findall(r'\[NEED\]\s*([^\[\]]+?)\s*\[/?NEED\]', text, re.IGNORECASE)
    if needs:
        # Normalise: lowercase, trim, dedup
        seen = set()
        for n in needs:
            n_clean = n.strip().lower()
            if n_clean and n_clean not in seen:
                seen.add(n_clean)
                out["need"].append(n_clean)

    return out


# ═════════════════════════════════════════════════════════════════════
# ARES SESSION
# ═════════════════════════════════════════════════════════════════════

class AresSession:

    def __init__(self):
        self.target_info: Dict[str, Any] = {}
        self.lhost = "127.0.0.1"
        self.logfile = None
        self.session_start = datetime.datetime.now()
        self.history: List[Dict[str, str]] = []
        self.command_history: List[str] = []
        self.stuck_counter = 0
        self.tools_available: Dict[str, bool] = {}
        self.current_workflow_key: Optional[str] = None
        self.current_agent: str = "triage"

        # PTT replaces the flat findings dict.
        self.ptt = PTT(goal="Mission undefined")

        # v7.1 — scope, threat graph, context manager
        self.scope = ScopeConfig.load()
        self.graph = AttackGraph()
        self.context_mgr = ContextManager()

        # v7.1 — credential fanout queue (creds awaiting service tests)
        self.ioc_fanout_queue: List[Tuple[str, str]] = []  # (ioc_value, ftype)

        # v7.1 — track ATT&CK techniques exercised this session
        self.attack_techniques_used: Dict[str, Dict[str, Any]] = {}

        # Provider state
        self.provider_index = 0
        self.groq_client: Optional[Groq] = None

        os.makedirs(INSTALL_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)

        self._init_provider()
        self._start_log()
        self._run_boot_check()
        self.lhost = get_lhost()
        ensure_yara_rules()

    # ── Provider init ─────────────────────────────────────────────

    def _init_provider(self):
        groq_key = os.environ.get("GROQ_API_KEY")
        if not groq_key:
            print(
                "\n\033[31m   FATAL: GROQ_API_KEY not set.\033[0m\n"
                "   Add to ~/.bashrc:  export GROQ_API_KEY='your_key'\n"
                "   Then: source ~/.bashrc\n"
            )
            sys.exit(1)
        try:
            self.groq_client = Groq(api_key=groq_key)
        except Exception as e:
            print(f"\033[31m   FATAL: Groq init: {e}\033[0m")
            sys.exit(1)
        first = PROVIDER_CHAIN[0]
        print(f"\033[32m   ✅ Groq client OK\033[0m")
        print(f"\033[32m   Active model: {first[1]}\033[0m")

    # ── Logging ───────────────────────────────────────────────────

    def _start_log(self):
        ts = self.session_start.strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(LOG_DIR, f"session_{ts}.txt")
        try:
            self.logfile = open(log_path, "w")
            self.logfile.write(
                f"ARES v{VERSION} LOG\n"
                f"Started: {self.session_start.isoformat()}\n"
                f"{'='*64}\n\n"
            )
            self.logfile.flush()
            print(f"\033[90m   Log: {log_path}\033[0m")
        except Exception as e:
            print(f"\033[33m   Log open failed: {e}\033[0m")

    def _log(self, text: str):
        if self.logfile:
            try:
                clean = re.sub(r'\033\[[0-9;]*m', '', text)
                self.logfile.write(clean + "\n")
                self.logfile.flush()
            except Exception:
                pass

    def _run_boot_check(self):
        # v7.2 — auto-expire the boot lock after BOOT_LOCK_TTL_SECONDS
        try:
            if os.path.exists(BOOT_LOCK):
                age = time.time() - os.path.getmtime(BOOT_LOCK)
                if age < BOOT_LOCK_TTL_SECONDS:
                    return
        except Exception:
            pass

        print()
        say_ares("Boot check…")

        # Pull upgradable list (best-effort; non-fatal if apt unavailable)
        try:
            result = subprocess.run(
                "apt list --upgradable 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=15
            )
            upgrades = result.stdout.lower()
        except Exception:
            upgrades = ""

        # v7.2 — only flag a UI-package upgrade as a "threat" if the
        # package is ACTUALLY INSTALLED on this system.  Substring
        # matching alone produces false positives like 'xfce' matching
        # 'xfce4-something' on a phone where xfce was never installed.
        confirmed_threats: List[str] = []
        for p in BANNED_UPGRADE_PACKAGES:
            if p not in upgrades:
                continue
            try:
                # dpkg-query returns rc 0 when at least one matching
                # package is installed (state starts with 'i').
                check = subprocess.run(
                    f"dpkg-query -W -f='${{Status}}\\n' '{p}*' 2>/dev/null "
                    f"| grep -q '^install ok installed'",
                    shell=True, timeout=5
                )
                if check.returncode == 0:
                    confirmed_threats.append(p)
            except Exception:
                # If dpkg-query failed for some reason, be conservative
                # and DON'T flag — better than false alarms.
                continue

        if confirmed_threats:
            say_warn(f"UI threat blocked: {', '.join(confirmed_threats)} "
                     f"have upgrades pending — apt upgrade is banned.")
        else:
            say_ok("System OK")

        try:
            with open(BOOT_LOCK, "w") as f:
                f.write(f"ok {datetime.datetime.now().isoformat()}")
        except Exception:
            pass

    # ── Provider call & fallback chain ────────────────────────────

    def _call_provider(self, messages: list, model: str,
                       max_tokens: int = MAX_TOKENS_DEFAULT) -> str:
        completion = self.groq_client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.2,
            max_tokens=max_tokens,
        )
        return completion.choices[0].message.content

    def _think_with_fallback(self, messages: list,
                             max_tokens: int = MAX_TOKENS_DEFAULT) -> Optional[str]:
        start_index = self.provider_index
        last_error = None

        for attempt in range(len(PROVIDER_CHAIN)):
            idx = (start_index + attempt) % len(PROVIDER_CHAIN)
            model_id, model_name = PROVIDER_CHAIN[idx]

            try:
                response = self._call_provider(messages, model_id, max_tokens)
                if idx != self.provider_index:
                    self.provider_index = idx
                    print(f"\n\033[33m   ↪ Switched to: {model_name}\033[0m")
                return response

            except Exception as e:
                last_error = e
                err = str(e).lower()
                is_limit = any(x in err for x in [
                    "rate", "limit", "429", "quota",
                    "too many", "queue", "capacity"
                ])
                is_404 = "404" in err or "not_found" in err or "does not exist" in err
                is_cf = "cloudflare" in err

                if is_404:
                    print(f"\033[33m   {model_name} unavailable — skipping\033[0m")
                    continue
                elif is_limit:
                    print(f"\n\033[33m   {model_name} rate-limited — falling to next\033[0m")
                    continue
                elif is_cf:
                    print(f"\n\033[33m   {model_name} blocked by CF — next\033[0m")
                    continue
                else:
                    short = err[:100]
                    print(f"\n\033[31m   {model_name} error: {short}\033[0m")
                    continue

        print(f"\n\033[31m   ⚠  All providers exhausted: {last_error}\033[0m")
        return None

    def _current_model_name(self) -> str:
        if 0 <= self.provider_index < len(PROVIDER_CHAIN):
            return PROVIDER_CHAIN[self.provider_index][1]
        return "Unknown"

    # ── Target setup ──────────────────────────────────────────────

    def set_target(self):
        print()
        say_ares("Set host under investigation. Enter to skip any field.")
        print()
        try:
            ip     = input("   IP / CIDR range : ").strip()
            domain = input("   Hostname        : ").strip()
            notes  = input("   Mission notes   : ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        self.target_info = {
            "ip":     ip or None,
            "domain": domain or None,
            "notes":  notes or None,
        }
        # Refresh the DTT root with the actual defensive goal
        goal = "Defend " + (ip or domain or "this host")
        if notes:
            goal += f" — {notes}"
        self.ptt = PTT(goal=goal)

        if ip or domain:
            summary = " | ".join(filter(None, [ip, domain]))
            print(f"\n\033[32m   Investigating: {summary}\033[0m")
            self._log(f"[TARGET] {summary} | {notes}")
        else:
            print("\n\033[33m   No target set — Ares will default to localhost.\033[0m")

    # ── Command safety gates (carried from v6.1, unchanged) ──────

    def _is_banned(self, cmd: str) -> bool:
        return any(b in cmd.lower() for b in BANNED_COMMANDS)

    def _is_interactive(self, cmd: str) -> Tuple[bool, str]:
        cmd_lower = cmd.lower().strip()
        non_interactive_markers = [
            " -q -r ", " -batch ", " --batch", " -e '", " -c '",
            "sshpass", "<<EOF", "<<<", " -y ", "expect ",
        ]
        if any(m in cmd for m in non_interactive_markers):
            return (False, "")
        for trigger, fix in INTERACTIVE_BLOCKED.items():
            if (cmd_lower.startswith(trigger) or
                f" {trigger}" in cmd_lower or
                f"&& {trigger}" in cmd_lower or
                f"; {trigger}" in cmd_lower):
                # msfconsole with -q -r is fine
                if trigger == "msfconsole" and (" -q -r " in cmd or " -q -x " in cmd):
                    return (False, "")
                return (True, fix)
        return (False, "")

    def _is_destructive(self, cmd: str) -> bool:
        for pattern in DESTRUCTIVE_COMMANDS:
            if re.search(pattern, cmd):
                return True
        return False

    def _needs_double_confirm(self, cmd: str) -> bool:
        for pattern in DOUBLE_CONFIRM:
            if re.search(pattern, cmd):
                return True
        return False

    def _normalize_choice(self, choice: str) -> str:
        c = choice.strip().lower()
        if c in ("y", "yes", "1y", "yy", "yeah", "yep", "ye"):
            return "y"
        if c in ("n", "no", "skip", "nope"):
            return "n"
        if c in ("q", "quit", "exit", "stop"):
            return "q"
        return c

    # ── Command execution (with full y/n gate) ────────────────────

    def _sync_graph_from_recent_findings(self, last_n: int):
        """Push the most recent N findings into the threat graph."""
        if not self.graph._has() or last_n <= 0:
            return
        for f in self.ptt.findings[-last_n:]:
            try:
                if f.ftype == "ip":
                    self.graph.add_host(f.value)
                elif f.ftype == "port":
                    # Port findings often lack host context — try to
                    # associate with the most recently discovered host
                    hosts = [g.value for g in self.ptt.findings if g.ftype == "ip"]
                    host = hosts[-1] if hosts else (
                        self.target_info.get("ip") or "unknown")
                    try:
                        self.graph.add_service(host, int(f.value))
                    except ValueError:
                        pass
                elif f.ftype == "svc":
                    hosts = [g.value for g in self.ptt.findings if g.ftype == "ip"]
                    host = hosts[-1] if hosts else (
                        self.target_info.get("ip") or "unknown")
                    self.graph.add_service(host, 0, name=f.value, version=f.value)
                elif f.ftype == "account":
                    # Account anomalies attach to the host being audited
                    self.graph.add_credential(f.value, user=f.value,
                                              verified=f.verified)
                elif f.ftype == "hash":
                    # Defender side: a hash is an IOC pivot
                    self.graph.add_hash(f.value, htype="ioc")
                elif f.ftype == "cve":
                    host = self.target_info.get("ip") or ""
                    self.graph.add_vuln(f.value, host=host)
                elif f.ftype in ("yara_hit", "av_hit", "suricata_alert"):
                    # Treat as an IOC node tied to the host
                    self.graph.add_hash(f.value[:32], htype=f.ftype)
                elif f.ftype == "domain":
                    pass  # domain nodes optional
            except Exception:
                continue

    def _flush_cred_fanout(self):
        """When IOCs land (suspicious hash, IP, domain), queue follow-up
        sweeps so other agents can hunt for the same indicator across
        every relevant log/host.  Defensive equivalent of Athena's
        credential fanout — same queue mechanism, different intent.
        Called between agent turns; adds DTT subnodes the LLM can pick up."""
        if not self.ioc_fanout_queue:
            return
        parent = self.ptt.find_in_progress() or self.ptt.nodes[self.ptt.root_id]
        for ioc_value, ioc_type in self.ioc_fanout_queue[:5]:
            # Build an "IOC sweep" subnode so the threat hunter can
            # propagate this indicator across logs / hosts / pcaps.
            short = (ioc_value[:32] + "…") if len(ioc_value) > 32 else ioc_value
            fanout_id = self.ptt.add_node(
                parent.nid,
                f"IOC sweep: {ioc_type} '{short}' across logs/pcap/hosts",
                phase="hunt",
                status="todo",
            )
            print(f"\033[33m   ↳ IOC fanout: queued sweep for "
                  f"{ioc_type} '{short}' (node {fanout_id})\033[0m")
        self.ioc_fanout_queue.clear()

    # v7.1 — sudo password handling.  Prompted once via getpass at first
    # sudo command; cached in memory; injected via `sudo -S` (read from
    # stdin) for every sudo run.  This works regardless of TTY because
    # we feed the password through subprocess pipes ourselves.
    _sudo_password: Optional[str] = None
    _sudo_skip_session: bool = False  # user opted out

    def _command_needs_sudo(self, cmd: str) -> bool:
        """Detect if a command starts with sudo or contains 'sudo ' as
        a leading token in any pipeline segment."""
        stripped = cmd.lstrip()
        if stripped.startswith("sudo ") or stripped == "sudo":
            return True
        for sep in [" | ", " && ", " || ", "; "]:
            for seg in cmd.split(sep):
                seg = seg.strip()
                if seg.startswith("sudo "):
                    return True
        return False

    def _needs_sudo_retry(self, output: str) -> bool:
        """v7.2 — scan command output for permission-failure markers
        that indicate the command would have worked with sudo.  Used
        to offer a one-tap retry after a non-sudo command fails."""
        if not output:
            return False
        lo = output.lower()
        return any(marker in lo for marker in SUDO_RETRY_MARKERS)

    def _prime_sudo(self) -> bool:
        """Prompt the user for their sudo password ONCE per session
        (via getpass, no echo) and store it in memory.  After this,
        every sudo call gets `-S` injected and the password fed via
        stdin pipe.  Returns False if the user opts out or auth fails.
        """
        if self._sudo_skip_session:
            return False
        if self._sudo_password is not None:
            # Already cached — verify it still works
            ok = self._sudo_test()
            if ok:
                return True
            # Stale, re-prompt
            self._sudo_password = None

        say_sys("🔐 SUDO required — caching password in memory for this session", color="33")
        say_dim("(stored in RAM only, never written to disk; used via `sudo -S`)")
        try:
            pw = getpass.getpass("   sudo password (or empty to skip): ")
        except (EOFError, KeyboardInterrupt):
            print()
            self._sudo_skip_session = True
            return False
        if not pw:
            self._sudo_skip_session = True
            say_dim("Skipped — Ares will avoid sudo for this session.")
            return False

        # Validate by running `sudo -S -v` with the password piped in
        self._sudo_password = pw
        if self._sudo_test():
            say_ok("sudo password accepted, cached in memory.")
            return True
        else:
            say_err("sudo authentication failed — clearing cached password.")
            self._sudo_password = None
            return False

    def _sudo_test(self) -> bool:
        """Verify the cached password by running `sudo -S -v`."""
        if not self._sudo_password:
            return False
        try:
            r = subprocess.run(
                ["sudo", "-S", "-v"],
                input=self._sudo_password + "\n",
                capture_output=True,
                text=True,
                timeout=10,
            )
            return r.returncode == 0
        except Exception:
            return False

    def _wrap_sudo_with_password(self, cmd: str) -> str:
        """Transform every leading `sudo ` in the command into
        `sudo -S ` so it reads the password from stdin.  We feed the
        password via the subprocess `input` parameter at exec time."""
        if not self._sudo_password:
            return cmd
        # Replace `sudo ` with `sudo -S ` — but only as a leading token,
        # not e.g. `--sudo foo`.  Match start-of-string or after a
        # pipeline separator.
        def _sub(s: str) -> str:
            s = s.lstrip()
            if s.startswith("sudo -S "):
                return s  # already wrapped
            if s.startswith("sudo ") or s == "sudo":
                return "sudo -S " + s[5:] if s.startswith("sudo ") else "sudo -S"
            return s
        # Handle pipelines/sequences
        out_parts: List[str] = []
        # Split on bash separators while keeping them
        parts = re.split(r'(\s\|\s|\s&&\s|\s\|\|\s|;\s)', cmd)
        for p in parts:
            if p.strip() in ("|", "&&", "||", ";"):
                out_parts.append(p)
            else:
                out_parts.append(_sub(p))
        return "".join(out_parts)

    def run_command(self, cmd: str, label: str = "EXEC") -> str:
        if self._is_destructive(cmd):
            print()
            print(error_alert(
                "DESTRUCTIVE COMMAND REFUSED", cmd,
                hint="Ares will not run anything that wipes data, "
                     "kills the system, or creates fork bombs."))
            self._log(f"[DESTRUCTIVE REFUSED] {cmd}")
            return EXEC_DESTRUCTIVE

        # v7.1 — scope / RoE check
        target_hint = (self.target_info.get("ip") or
                       self.target_info.get("domain") or "")
        scope_ok, scope_reason = self.scope.check(cmd, target_hint=target_hint)
        if not scope_ok:
            print()
            print(error_alert(
                "OUT OF SCOPE — REFUSED",
                f"{cmd}\n\nReason: {scope_reason}",
                hint=f"Edit ~/.ares/scope.json to adjust engagement scope."))
            self._log(f"[OUT-OF-SCOPE] {cmd} -- {scope_reason}")
            return EXEC_REJECTED

        is_interactive, fix = self._is_interactive(cmd)
        if is_interactive:
            print()
            print(error_alert(
                "INTERACTIVE COMMAND BLOCKED", cmd,
                hint=f"Fix: {fix}"))
            self._log(f"[INTERACTIVE BLOCKED] {cmd}")
            return EXEC_INTERACTIVE_BLOCKED

        # v7.1 — MITRE ATT&CK pre-tag for the command itself
        attack_tag = attack_id_for_command(cmd)
        attack_label = ""
        if attack_tag:
            tid, tname, tactic = attack_tag
            attack_label = f"  \033[36m▸ {tid} {tname}\033[0m"
            # Track in session-wide technique counter
            if tid not in self.attack_techniques_used:
                self.attack_techniques_used[tid] = {
                    "name": tname, "tactic": tactic, "count": 0, "commands": []
                }
            self.attack_techniques_used[tid]["count"] += 1
            self.attack_techniques_used[tid]["commands"].append(cmd[:120])

        # v7.2 — boxed command card.  Shows the command, ATT&CK tag,
        # and confidence pill all in one panel.  Replaces the v7.1
        # inline rail.
        is_verify = (label == "VERIFY")
        att_id = attack_tag[0] if attack_tag else ""
        att_name = attack_tag[1] if attack_tag else ""
        # Pull the most recent confidence captured by think_turn for the
        # active node (defaults to green if unknown).
        active_for_conf = self.ptt.find_in_progress()
        conf = active_for_conf.confidence if active_for_conf else "green"
        # If we've failed N times on this node, override to red
        if active_for_conf and active_for_conf.attempts >= 2 and conf == "green":
            conf = "yellow"
        if active_for_conf and active_for_conf.attempts >= NODE_ATTEMPT_LIMIT - 1:
            conf = "red"
        print()
        print(command_card(cmd, conf=conf, attack_id=att_id,
                           attack_name=att_name, verify=is_verify))
        print()
        self._log(f"\n[CMD-{label}]{' '+att_id if att_id else ''}\n{cmd}")

        try:
            raw = input(
                f"   {kbd('y')} run   {kbd('n')} skip   {kbd('q')} quit  › "
            )
        except (EOFError, KeyboardInterrupt):
            print()
            return EXEC_SESSION_EXIT

        choice = self._normalize_choice(raw)
        if choice == "q":
            return EXEC_SESSION_EXIT
        if choice != "y":
            print("\033[90m   Skipped.\033[0m")
            self._log("[SKIPPED]")
            return EXEC_REJECTED

        # Double-confirm for system-modifying commands
        if self._needs_double_confirm(cmd):
            print(f"\n\033[33m   ⚠  This modifies system state. Confirm again.\033[0m")
            try:
                second = input("\033[33m   Really execute? [y/n]: \033[0m")
            except (EOFError, KeyboardInterrupt):
                return EXEC_REJECTED
            if self._normalize_choice(second) != "y":
                print("\033[90m   Cancelled.\033[0m")
                self._log("[DOUBLE CONFIRM CANCELLED]")
                return EXEC_REJECTED

        # v7.1 — if command uses sudo, prime the credential cache and
        # transform `sudo X` → `sudo -S X` so the cached password can
        # be fed via stdin.  Works regardless of TTY.
        actual_cmd = cmd
        sudo_pw_input: Optional[str] = None
        if self._command_needs_sudo(cmd):
            if not self._prime_sudo():
                self._log("[SUDO REJECTED]")
                return EXEC_REJECTED
            actual_cmd = self._wrap_sudo_with_password(cmd)
            sudo_pw_input = (self._sudo_password or "") + "\n"

        # v7.2 — pick a timeout based on the command pattern.  Long
        # scans get a generous ceiling; everything else caps at 5 min
        # so a hanging command can't lock the session forever.
        cmd_timeout = DEFAULT_COMMAND_TIMEOUT
        for pat, t in COMMAND_TIMEOUTS:
            if re.search(pat, cmd, re.IGNORECASE):
                cmd_timeout = t
                break

        print()
        print(f"   \033[100m\033[97m\033[1m  ▶ EXECUTING  \033[0m  "
              f"\033[90m\033[3mtimeout={cmd_timeout}s · "
              f"Ctrl+C aborts this command only\033[0m\n")
        output_lines = []
        proc = None
        timed_out = False
        is_exploit = any(kw in cmd.lower() for kw in
                        ["exploit", "msfconsole", "searchsploit -m",
                         "msfvenom", "/tmp/exploit.rc"])

        try:
            # If sudo password is needed, we have to feed it via stdin.
            # Otherwise we use stdin=DEVNULL so commands that read stdin
            # (e.g. ssh) fail fast instead of hanging forever.
            popen_kwargs = dict(
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid,
            )
            if sudo_pw_input is not None:
                popen_kwargs["stdin"] = subprocess.PIPE
            else:
                popen_kwargs["stdin"] = subprocess.DEVNULL

            proc = subprocess.Popen(actual_cmd, **popen_kwargs)
            if sudo_pw_input is not None and proc.stdin:
                try:
                    proc.stdin.write(sudo_pw_input)
                    proc.stdin.flush()
                    proc.stdin.close()
                except Exception:
                    pass

            # v7.2 — non-blocking read loop bounded by cmd_timeout.
            start_t = time.time()
            for line in iter(proc.stdout.readline, ""):
                # Strip the password-prompt line if it leaks through stderr
                if line.strip().startswith("[sudo] password for"):
                    continue
                print(line, end="")
                output_lines.append(line)
                if (time.time() - start_t) > cmd_timeout:
                    timed_out = True
                    break
            if timed_out:
                # Kill the process group cleanly
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                output_lines.append(f"\n[COMMAND TIMED OUT after {cmd_timeout}s — killed]\n")
                print(f"\n\033[31m   ⏱  Command timed out at {cmd_timeout}s "
                      f"and was killed.\033[0m")
            else:
                proc.wait()
        except KeyboardInterrupt:
            print("\n\033[33m   Command aborted by user — returning to Ares\033[0m")
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            output_lines.append("\n[COMMAND ABORTED BY USER]\n")
        except Exception as e:
            err = f"EXECUTION ERROR: {e}"
            print(f"\033[31m{err}\033[0m")
            return err

        raw_output = "".join(output_lines)
        rc = proc.returncode if proc else -1

        # v7.2 — if command failed with a permissions/raw-socket marker
        # AND wasn't already wrapped in sudo, offer a one-tap retry.
        if (rc != 0 and not self._command_needs_sudo(cmd)
                and self._needs_sudo_retry(raw_output)
                and not self._sudo_skip_session):
            print()
            print(error_alert(
                "PERMISSION DENIED — needs root",
                f"`{cmd[:160]}` failed without sudo.",
                hint="Press y to re-run prefixed with sudo (one-time, "
                     "uses cached password)."))
            try:
                ans = input(f"   {kbd('y')} retry as sudo   {kbd('n')} keep failure  › ")
            except (EOFError, KeyboardInterrupt):
                ans = "n"
            if self._normalize_choice(ans) == "y":
                # Recursively run the sudo-prefixed version through the
                # same gate.  We tag the label so the agent loop knows
                # this isn't a fresh proposal.
                say_sys("retrying with sudo prefix…", color="33")
                return self.run_command("sudo " + cmd, label=label + "-SUDO")

        # Auto-CVE lookup on recon-type commands
        if any(kw in cmd for kw in ["nmap", "whatweb", "smbclient",
                                      "nikto", "searchsploit", "nuclei",
                                      "nxc ", "crackmapexec"]):
            cve_extra = auto_cve_lookup(raw_output)
            if cve_extra:
                print(cve_extra)
                # Add to context, but DON'T parse this as findings
                # (those CVEs already came from real output)

        # Auto-exploit suggestion when CVE found
        cve_matches = re.findall(r'CVE-\d{4}-\d+', raw_output, re.IGNORECASE)
        if cve_matches:
            target = (self.target_info.get("ip") or
                      self.target_info.get("domain") or "TARGET")
            for cve in cve_matches[:2]:
                expl = analyze_and_suggest_exploit(cve, target, self.lhost)
                if expl:
                    print(expl)

        self._log(f"[OUTPUT]\n{raw_output}")

        # Source-tagged finding extraction — ONLY on raw subprocess output
        active = self.ptt.find_in_progress()
        active_id = active.nid if active else self.ptt.root_id
        findings_before = len(self.ptt.findings)
        new_count = extract_findings_from_stdout(
            raw_output, source_cmd=cmd, ptt=self.ptt,
            active_node_id=active_id,
        )
        if new_count > 0:
            # v7.2 — boxed findings card with the actual extracted values
            new_findings = self.ptt.findings[findings_before:]
            items = []
            for f in new_findings:
                icon_map = {
                    "ip": "🌐", "port": "🔌", "user": "👤",
                    "hash": "🔐", "hash_ntlm": "🔐", "krb_hash": "🎫",
                    "ntlmv2": "🔐", "cred": "🔑", "cve": "💥",
                    "svc": "⚙", "domain": "🏷", "url": "🔗",
                    "exposed_path": "⚠", "smb_share": "📂",
                    "email": "📧", "ssh_key": "🗝", "aws_key": "☁",
                }
                icon = icon_map.get(f.ftype, "•")
                tag = f" \033[36m{f.attack_id}\033[0m" if f.attack_id else ""
                items.append(
                    f"{icon}  \033[97m{f.ftype:<12}\033[0m "
                    f"\033[36m{f.value[:42]}\033[0m{tag}"
                )
            print()
            print(findings_card(new_count, items))
            # Feed new findings into threat graph
            self._sync_graph_from_recent_findings(new_count)
            # Defensive fanout: when an IOC (suspicious hash, alert,
            # YARA hit, suricata alert, persistence artifact, sus IP)
            # lands, queue it so the threat hunter sweeps every other
            # relevant source for the same indicator.
            IOC_FANOUT_TYPES = {
                "hash", "yara_hit", "av_hit", "suricata_alert",
                "persistence", "suspicious_proc", "ip", "domain", "url",
                "attack_id",
            }
            for f in self.ptt.findings[-new_count:]:
                if (f.ftype in IOC_FANOUT_TYPES and
                    (f.value, f.ftype) not in self.ioc_fanout_queue):
                    self.ioc_fanout_queue.append((f.value, f.ftype))
                    print(f"\033[33m   ↳ IOC queued for fanout: "
                          f"{f.ftype} = {f.value[:40]}\033[0m")

        # Compress for AI context
        compressed = compress_output_for_history(
            raw_output, is_exploit_result=is_exploit
        )
        if (len(raw_output) > 1000 and
            len(compressed) < len(raw_output) * 0.5):
            print(f"\033[90m   [output compressed: "
                  f"{len(raw_output)}→{len(compressed)} chars for AI]\033[0m")

        return compressed.strip() or "(no output)"

    # ── Verification command (PoC validation) ────────────────────

    def attempt_verification(self, verify_cmd: str,
                             finding_value: str,
                             finding_type: str) -> bool:
        """Run a verify-tagged command through the y/n gate.
        On success (zero exit AND useful output), promote the finding
        to verified=True in the PTT.

        Per operator instruction: ALWAYS goes through y/n gate.
        """
        print()
        print(_box(
            "PoC VERIFICATION",
            [f"  Claim: \033[97m{finding_type}={finding_value[:48]}\033[0m",
             f"  Verifier will attempt to confirm this is real."],
            color="31"))

        result = self.run_command(verify_cmd, label="VERIFY")
        if result in (EXEC_REJECTED, EXEC_DESTRUCTIVE,
                      EXEC_INTERACTIVE_BLOCKED, EXEC_SESSION_EXIT):
            return result == EXEC_SESSION_EXIT and False or False

        # Heuristic: verify command output should NOT contain auth-failure
        # markers and SHOULD be non-empty.
        result_lower = result.lower()
        fail_markers = [
            "permission denied", "authentication failed", "access denied",
            "login incorrect", "invalid", "401", "403", "unauthorized",
            "could not connect", "connection refused", "connection timed",
            "not found", "no such", "command not found",
        ]
        if any(m in result_lower for m in fail_markers):
            print()
            print(_box(
                "✗ VERIFICATION FAILED",
                [f"  {finding_type}={finding_value[:48]} stays unverified"],
                color="31"))
            return False

        if not result.strip() or result.strip() == "(no output)":
            print()
            print(_box(
                "? VERIFICATION INCONCLUSIVE",
                ["  Empty output. Try a different verifier."],
                color="33"))
            return False

        # Promote finding to verified
        for f in self.ptt.findings:
            if f.ftype == finding_type and f.value == finding_value:
                f.verified = True
                f.notes = f"Verified by: {verify_cmd[:120]}"
                print(f"\033[32m   ✓ VERIFIED — "
                      f"{finding_type}={finding_value} confirmed real\033[0m")
                # v7.1 — sync to threat graph
                if finding_type == "cred" and self.graph._has():
                    # Try to extract host:port from verify_cmd
                    host_match = re.search(
                        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', verify_cmd)
                    port_match = re.search(r':(\d{2,5})\b', verify_cmd)
                    if host_match:
                        host = host_match.group(1)
                        port = int(port_match.group(1)) if port_match else 0
                        self.graph.mark_cred_verified_on(finding_value, host, port)
                return True

        return False

    # ── Specialist agent dispatch ────────────────────────────────

    def _select_agent(self, node: Optional[PTTNode],
                      free_form: str = "") -> str:
        """Deterministic dispatcher: DTT node phase → specialist role."""
        if node and node.phase in PHASE_TO_AGENT:
            return PHASE_TO_AGENT[node.phase]

        # Fallback: keyword scan over free-form text
        lower = (free_form or "").lower()
        if any(k in lower for k in ["log", "journal", "syslog", "auth.log",
                                     "auditd", "ausearch", "aureport"]):
            return "log_analyst"
        if any(k in lower for k in ["pcap", "tcpdump", "tshark", "zeek",
                                     "suricata", "snort", "ids", "ips",
                                     "wireshark", "fast.log"]):
            return "network_defender"
        if any(k in lower for k in ["malware", "yara", "virus", "sample",
                                     "trojan", "capa", "olevba", "pdfid"]):
            return "malware_analyst"
        if any(k in lower for k in ["memory", "volatility", "lime", "avml",
                                     "disk image", "sleuthkit", "fls",
                                     "mactime", "carve", "foremost"]):
            return "forensics_analyst"
        if any(k in lower for k in ["account", "user", "sudo", "passwd",
                                     "shadow", "kerberos", "ldap",
                                     "samba", "ssh key"]):
            return "identity_defender"
        if any(k in lower for k in ["harden", "lynis", "cis", "openscap",
                                     "baseline", "sysctl", "compliance"]):
            return "hardener"
        if any(k in lower for k in ["incident", "compromise", "contain",
                                     "quarantine", "kill", "block",
                                     "eradicate", "respond"]):
            return "ir_responder"
        if any(k in lower for k in ["hunt", "persistence", "rootkit",
                                     "backdoor", "anomaly", "sigma",
                                     "chainsaw", "hayabusa"]):
            return "threat_hunter"
        if any(k in lower for k in ["report", "summary", "writeup",
                                     "executive"]):
            return "reporter"
        return "triage"

    # ── Two-pass thinking turn ───────────────────────────────────

    def think_turn(self, prompt: str,
                   workflow_key: Optional[str] = None) -> Dict[str, Any]:
        """Single specialist turn.

        Picks specialist agent based on current PTT node, builds the
        appropriate system prompt, calls the LLM with fallback chain,
        parses the response.

        v7.1: handles [TOOL]/[ARGS] dispatch through ToolBuilder, and
        [NEED] tags trigger up to MAX_NEED_FETCHES re-calls with the
        requested context attached.

        Returns dict with: agent, thought, cmd, tool, args, conf,
        verify, handoff, need.
        """
        active = self.ptt.find_in_progress() or self.ptt.find_next_pending()
        if active and active.status == "todo":
            self.ptt.set_status(active.nid, "in_progress")
            active = self.ptt.nodes[active.nid]

        # v7.1 — let context manager track signals
        self.context_mgr.signal_node_change(active.nid if active else None)
        self.context_mgr.signal_stuck(self.stuck_counter)

        agent_role = self._select_agent(active, free_form=prompt)
        self.current_agent = agent_role

        # The NEED loop: build a minimal prompt; if the LLM emits [NEED],
        # rebuild with the requested attachments and call again, up to
        # MAX_NEED_FETCHES times.
        need_attachments: List[str] = []
        parsed: Dict[str, Any] = {}
        for fetch_round in range(MAX_NEED_FETCHES + 1):
            sys_prompt = build_system_prompt(
                agent_role=agent_role,
                target_info=self.target_info,
                ptt=self.ptt,
                active_node=active,
                lhost=self.lhost,
                workflow_key=workflow_key,
                free_form=prompt,
                context_mgr=self.context_mgr,
                graph=self.graph,
                scope=self.scope,
                need_attachments=need_attachments,
            )

            # v7.1 — slice history per context manager
            slice_size = self.context_mgr.history_slice_size()
            # If [NEED]history[/NEED] requested, send the lot
            if "history" in need_attachments:
                slice_size = MAX_HISTORY_MESSAGES
            windowed = self.history[-slice_size:]

            # Compress assistant turns to just their CMD/TOOL block
            compressed_history = []
            for msg in windowed:
                if msg["role"] == "assistant":
                    cm = re.search(r'\[CMD\](.*?)\[/?CMD\]',
                                   msg["content"], re.DOTALL)
                    tm = re.search(r'\[TOOL\](.*?)\[/?TOOL\]',
                                   msg["content"], re.DOTALL)
                    am = re.search(r'\[ARGS\](.*?)\[/?ARGS\]',
                                   msg["content"], re.DOTALL)
                    if tm and am:
                        compressed_history.append({
                            "role": "assistant",
                            "content": (f"[TOOL]{tm.group(1).strip()}[/TOOL]"
                                        f"[ARGS]{am.group(1).strip()}[/ARGS]")
                        })
                    elif cm:
                        compressed_history.append({
                            "role": "assistant",
                            "content": f"[CMD]{cm.group(1).strip()}[/CMD]"
                        })
                    else:
                        compressed_history.append(msg)
                else:
                    compressed_history.append(msg)

            messages = [{"role": "system", "content": sys_prompt}]
            messages.extend(compressed_history)
            messages.append({"role": "user", "content": prompt})

            # Estimate tokens for context savings counter
            sent_size = sum(len(m["content"]) for m in messages)
            full_size_est = sent_size + (
                # estimate of what FULL context would have added
                4000 if not need_attachments else 0
            )
            self.context_mgr.record_savings(full_size_est, sent_size)

            response = self._think_with_fallback(messages,
                                                  max_tokens=MAX_TOKENS_DEFAULT)
            if not response:
                return {"agent": agent_role, "thought": "", "cmd": None,
                        "tool": None, "args": None,
                        "conf": "red", "verify": None, "handoff": None,
                        "need": []}

            parsed = parse_specialist_response(response)
            parsed["agent"] = agent_role

            # If LLM requested more context AND we still have rounds left
            if parsed["need"] and fetch_round < MAX_NEED_FETCHES:
                # Attach the requested context for next round, don't log
                # the [NEED] turn into history (it's a meta-call)
                fresh = [n for n in parsed["need"] if n not in need_attachments]
                if fresh:
                    need_attachments.extend(fresh)
                    print(f"\033[90m   ▸ context-fetch — LLM requested: "
                          f"\033[36m{', '.join(fresh)}\033[0m")
                    continue
            break

        # Only log the FINAL exchange to history (not the NEED-only turns)
        self.history.append({"role": "user", "content": prompt})
        self.history.append({"role": "assistant", "content": response})
        # Trim to MAX_HISTORY_MESSAGES — kept in RAM, only sliced when sending
        if len(self.history) > MAX_HISTORY_MESSAGES * 2:
            self.history = self.history[-(MAX_HISTORY_MESSAGES * 2):]
        self._log(f"[AI:{agent_role}]\n{response}")

        # v7.2 — TOOL dispatch: convert [TOOL]/[ARGS] → shell string.
        # Hard errors are stashed on self._pending_dispatch_error so the
        # agent loop can splice them into the next prompt — that way
        # the LLM actually learns about its bad kwargs instead of
        # looping the same args.
        self._pending_dispatch_error = None
        dispatch_remap_note = ""
        if parsed["tool"]:
            shell, msg = dispatch_tool(parsed["tool"], parsed["args"] or "{}")
            if shell:
                parsed["cmd"] = shell
                if msg and msg.startswith("NOTE:"):
                    dispatch_remap_note = msg
            else:
                # Hard ERROR — feed back to LLM next turn
                self._pending_dispatch_error = (
                    f"Your previous [TOOL]{parsed['tool']}[/TOOL] dispatch "
                    f"failed:\n  {msg}\n"
                    f"Either correct the args, switch tools, or fall back "
                    f"to a [CMD] block."
                )
                if not parsed["cmd"]:
                    parsed["cmd"] = None  # no fallback — agent loop will retry

        # v7.2 — failure-aware confidence.  If we've failed N times
        # already on this node, force a yellow/red regardless of what
        # the LLM said.
        if active and active.attempts >= NODE_ATTEMPT_LIMIT - 1:
            parsed["conf"] = "red"
        elif active and active.attempts >= 2 and parsed["conf"] == "green":
            parsed["conf"] = "yellow"

        # ─── v7.2 BOXED RENDERING ──────────────────────────────────
        target_label = (self.target_info.get("ip") or
                        self.target_info.get("domain") or "no-target")
        self._turn_no = getattr(self, "_turn_no", 0) + 1
        v_count = len(self.ptt.get_verified())
        u_count = len(self.ptt.get_unverified())
        node_label = active.nid if active else "—"
        print()
        print(turn_box(
            turn_no=self._turn_no,
            target=target_label,
            agent_role=agent_role,
            model=self._current_model_name(),
            verified=v_count, unverified=u_count,
            techniques=len(self.attack_techniques_used),
            node_id=node_label,
        ))
        if parsed["thought"]:
            print(thought_card(parsed["thought"], agent_role=agent_role))
        if parsed["tool"] and parsed["cmd"]:
            tool_attack = attack_id_for_command(parsed["cmd"])
            t_id = tool_attack[0] if tool_attack else ""
            t_name = tool_attack[1] if tool_attack else ""
            print(dispatch_card(
                tool=parsed["tool"], shell_str=parsed["cmd"],
                attack_id=t_id, attack_name=t_name,
                remap_note=dispatch_remap_note,
            ))
        elif self._pending_dispatch_error:
            print(error_alert(
                "TOOL DISPATCH FAILED",
                self._pending_dispatch_error,
                hint="The error will be fed back to the AI on the next turn.",
            ))

        if active:
            self.ptt.set_confidence(active.nid, parsed["conf"])

        # v7.1 — feed signals back to context manager
        self.context_mgr.signal_confidence(parsed["conf"])

        return parsed

    # ── PTT seeding from workflow ────────────────────────────────

    def _seed_ptt_from_workflow(self, key: str, target: str):
        wf = WORKFLOWS.get(key)
        if not wf:
            return
        goal = f"{wf['name']}: {target}"
        self.ptt = PTT(goal=goal)
        for title, phase in wf["seed"]:
            self.ptt.add_node(self.ptt.root_id, title, phase, status="todo")

    # ── Stuck recovery ───────────────────────────────────────────

    def _handle_stuck(self):
        """When stuck — ask AI for 3 alternative approaches."""
        print("\n\033[33m   ⚠  Ares is stuck.  Asking AI for 3 alternatives...\033[0m")

        active = self.ptt.find_in_progress() or self.ptt.find_next_pending()
        node_desc = (f"Current node: [{active.nid}] {active.title} "
                     f"(phase={active.phase})") if active else "No active node"

        verified_summary = []
        for f in self.ptt.get_verified()[-10:]:
            verified_summary.append(f"{f.ftype}={f.value}")

        prompt = (
            f"You are stuck.  {node_desc}.\n"
            f"Verified findings: {' | '.join(verified_summary) or 'minimal'}.\n"
            "Output ONLY this format:\n"
            "[OPTIONS]\n"
            "1. <approach 1 — fundamentally different angle, one line>\n"
            "2. <approach 2 — different angle, one line>\n"
            "3. <approach 3 — different angle, one line>\n"
            "[/OPTIONS]\n"
            "Each option must take a totally different approach (e.g. log "
            "review vs persistence hunt vs network capture vs hardening "
            "audit vs forensic timeline)."
        )

        response = self._think_with_fallback([
            {"role": "system",
             "content": "You are Ares, listing pivot options when stuck."},
            {"role": "user", "content": prompt},
        ])
        if not response:
            print("\033[31m   AI unavailable.  Type your own next objective.\033[0m")
            return

        m = re.search(r'\[OPTIONS\](.*?)\[/?OPTIONS\]', response, re.DOTALL)
        opts_text = m.group(1).strip() if m else response

        print(f"\n\033[35m   ARES — 3 ALTERNATIVES:\033[0m\n")
        print(f"\033[97m{opts_text}\033[0m\n")

        try:
            choice = input(
                "\033[90m   Pick [1/2/3] or type own objective: \033[0m"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return

        if choice in ("1", "2", "3"):
            for line in opts_text.split('\n'):
                if line.strip().startswith(choice + "."):
                    new_obj = line.split('.', 1)[1].strip()
                    print(f"\033[32m   Pursuing: {new_obj}\033[0m")
                    # Mark current as dead-end so we don't loop back
                    if active:
                        self.ptt.set_status(active.nid, "dead_end")
                    self._agent_loop(new_obj)
                    return
        elif choice:
            self._agent_loop(choice)

    # ── Main agent loop ──────────────────────────────────────────

    def _agent_loop(self, initial_prompt: str,
                    workflow_key: Optional[str] = None):
        prompt = initial_prompt
        self.current_workflow_key = workflow_key
        self.stuck_counter = 0
        # Track success per node so workflow can't auto-complete a
        # streak of failures (v7.2 fix).
        self._node_success_count: Dict[str, int] = {}

        while True:
            # v7.2 — turn header is now drawn by turn_box() inside
            # think_turn(); no inline header needed here.
            active = self.ptt.find_in_progress() or self.ptt.find_next_pending()

            # v7.2 — if a previous turn produced a hard dispatch error,
            # splice it into the prompt so the LLM sees its own mistake
            # and can correct.  Without this the loop just kept emitting
            # the same kwargs and getting silently dropped.
            pending_err = getattr(self, "_pending_dispatch_error_to_prompt", None)
            if pending_err:
                prompt = (
                    f"DISPATCH ERROR FROM YOUR PREVIOUS TURN:\n"
                    f"{pending_err}\n\n"
                    f"Re-issue with corrected args, switch tools, or "
                    f"use [CMD]. Original task:\n{prompt}"
                )
                self._pending_dispatch_error_to_prompt = None

            parsed = self.think_turn(prompt, workflow_key=workflow_key)
            cmd     = parsed["cmd"]
            conf    = parsed["conf"]
            verify  = parsed["verify"]
            handoff = parsed["handoff"]

            # v7.2 — propagate any fresh dispatch error from think_turn
            # into the next iteration of this loop.
            if getattr(self, "_pending_dispatch_error", None):
                self._pending_dispatch_error_to_prompt = self._pending_dispatch_error
                self._pending_dispatch_error = None

            if cmd is None:
                # v7.1 — instead of bailing, retry up to 2x with a
                # corrective hint.  This recovers from tool-dispatch
                # failures and from the LLM accidentally omitting [CMD].
                no_cmd_retries = getattr(self, "_no_cmd_retries", 0)
                if no_cmd_retries < 2:
                    self._no_cmd_retries = no_cmd_retries + 1
                    say_warn("Agent did not output a [CMD] block — asking again.")
                    prompt = (
                        "Your previous response had no executable command. "
                        "Output a SINGLE [CMD]…[/CMD] line (or [TOOL]…[/TOOL]"
                        "[ARGS]…[/ARGS]) plus [THOUGHT][CONF].  If your "
                        "preferred tool isn't in the structured registry or "
                        "its dispatch failed, fall back to [CMD] with the "
                        "raw shell command."
                    )
                    continue
                else:
                    self._no_cmd_retries = 0
                    say_err("Still no command after 2 retries — bailing.")
                    break
            else:
                self._no_cmd_retries = 0  # reset on success

            # Workflow done check — v7.2 GATED on actual progress
            if WORKFLOW_DONE in cmd.upper() or "WORKFLOW_COMPLETE" in cmd.upper():
                # v7.2 — refuse to auto-complete a node that has zero
                # successful commands AND zero findings.  The LLM can
                # try to bail out of failures with WORKFLOW_COMPLETE;
                # this gate stops that.
                node_findings = 0
                node_successes = 0
                if active:
                    node_findings = len(active.findings)
                    node_successes = self._node_success_count.get(active.nid, 0)
                if active and node_findings == 0 and node_successes == 0:
                    say_warn(f"Refusing WORKFLOW_COMPLETE on node "
                             f"[{active.nid}] — 0 findings, 0 successful "
                             f"commands. Try a different approach.")
                    prompt = (
                        f"You proposed WORKFLOW_COMPLETE but node "
                        f"[{active.nid}] {active.title} has produced no "
                        f"successful commands and no findings yet. "
                        f"You may not skip a node that hasn't yielded "
                        f"any data. Take a fundamentally different "
                        f"approach (different tool, different angle), "
                        f"or [HANDOFF]<other_agent>[/HANDOFF] to escalate."
                    )
                    continue

                if active:
                    self.ptt.set_status(active.nid, "done")
                # Check if we have more pending nodes
                nxt = self.ptt.find_next_pending()
                if nxt:
                    print()
                    print(_box(
                        "✓ NODE COMPLETE",
                        [f"  Moving to: \033[97m[{nxt.nid}] {nxt.title}\033[0m"],
                        color="32"))
                    self.ptt.set_status(nxt.nid, "in_progress")
                    prompt = (f"Previous node complete.  "
                              f"Now work on: {nxt.title} (phase: {nxt.phase}). "
                              f"Output [THOUGHT][CMD][CONF].")
                    continue
                else:
                    print()
                    print(_box(
                        "✓ WORKFLOW COMPLETE",
                        [f"  All nodes done. \033[32m{len(self.ptt.get_verified())}"
                         f"\033[0m verified findings, "
                         f"\033[33m{len(self.ptt.get_unverified())}\033[0m unverified."],
                        color="32"))
                    self._log("[WORKFLOW DONE]")
                    break

            # Handoff request
            if handoff and handoff in AGENT_SPECS:
                print()
                print(_box(
                    "↪ HANDOFF",
                    [f"  → {AGENT_SPECS[handoff]['icon']} "
                     f"{AGENT_SPECS[handoff]['name']}"],
                    color="33"))
                # Add a sibling node for the handoff phase if reasonable
                if active and active.parent_id:
                    self.ptt.add_node(active.parent_id,
                                      f"Handoff to {handoff}",
                                      handoff, status="todo")

            # Banned check
            if self._is_banned(cmd):
                print()
                print(error_alert(
                    "BANNED COMMAND BLOCKED",
                    f"`{cmd}` would change UI / system packages.",
                    hint="Use `which`/`dpkg -l` to check tools instead. "
                         "apt upgrade variants are permanently disabled."))
                prompt = ("That apt upgrade variant is blocked.  Use which "
                          "or dpkg -l to check tools.  Provide alternative "
                          "with [THOUGHT][CMD][CONF].")
                continue

            # v7.2 — Track command for repeat detection.  More aggressive
            # than v7.1: ANY exact repeat in the last 5 commands triggers
            # a forced agent rotation + RED conf override.  This stops
            # the loop where dropped kwargs produced identical shells.
            cmd_norm = re.sub(r'\s+', ' ', cmd.strip().lower())
            if cmd_norm in self.command_history[-5:]:
                print()
                print(error_alert(
                    "LOOP DETECTED",
                    f"You just ran this exact command. Repeating means the "
                    f"previous result didn't change anything you can act on.",
                    hint="Forcing pivot to a different approach now."))
                self.stuck_counter += 1
                if active:
                    self.ptt.increment_attempts(active.nid)
                    self.ptt.set_confidence(active.nid, "red")
                if self.stuck_counter >= STUCK_THRESHOLD:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break
                # v7.2 — give the LLM stronger guidance: name the command,
                # require a *different category* of approach, and bump
                # the agent if possible.
                rotation_hint = ""
                if self.current_agent == "recon":
                    rotation_hint = " Switch from scanning to direct service interaction (whatweb, curl, nxc, smbclient)."
                elif self.current_agent == "web":
                    rotation_hint = " Switch from brute/fuzz to manual probing (curl with payloads) or pivot to network agent."
                prompt = (
                    f"LOOP-BREAKER: you already ran `{cmd}`. The result "
                    f"didn't help. Take a FUNDAMENTALLY DIFFERENT approach: "
                    f"different tool, different angle, different "
                    f"specialist.{rotation_hint} Output [THOUGHT][CMD][CONF]. "
                    f"You may [HANDOFF]<other_agent>[/HANDOFF] to escalate."
                )
                continue

            self.command_history.append(cmd_norm)
            if len(self.command_history) > 25:
                self.command_history = self.command_history[-25:]

            # Confidence handling — the pill already shows in think_turn()
            if conf == "red":
                print()
                print(_box("RED CONFIDENCE — execution skipped",
                           ["  Asking AI for recon to gather missing "
                            "context first."], color="31"))
                prompt = ("Confidence was RED.  Propose a recon command to "
                          "gather the missing context, not the attack.  "
                          "[THOUGHT][CMD][CONF].")
                continue

            # Execute the command (always y/n gated)
            if active:
                self.ptt.increment_attempts(active.nid)
                self.ptt.set_last_cmd(active.nid, cmd)
            output = self.run_command(cmd)

            if output == EXEC_SESSION_EXIT:
                print()
                say_ares("Session ended by The Priest.")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                sys.exit(0)

            if output == EXEC_INTERACTIVE_BLOCKED:
                _, fix = self._is_interactive(cmd)
                prompt = (f"That command would hijack the terminal.  {fix}  "
                          f"Provide non-interactive alternative.  "
                          f"[THOUGHT][CMD][CONF].")
                continue

            if output == EXEC_DESTRUCTIVE:
                prompt = ("That command was destructive and refused.  "
                          "Propose a non-destructive alternative.  "
                          "[THOUGHT][CMD][CONF].")
                continue

            if output == EXEC_REJECTED:
                self.stuck_counter += 1
                if active:
                    if active.attempts >= NODE_ATTEMPT_LIMIT:
                        self.ptt.set_status(active.nid, "dead_end")
                        print()
                        print(_box(
                            "✗ DEAD END",
                            [f"  Node [{active.nid}] {active.title}",
                             f"  Marked dead-end after {active.attempts} attempts."],
                            color="31"))
                if self.stuck_counter >= STUCK_THRESHOLD:
                    self.stuck_counter = 0
                    self._handle_stuck()
                    break

                try:
                    print()
                    say_ares("Alternative approach?", indent=3)
                    raw = input(f"   {kbd('y')} yes   {kbd('n')} no  › ")
                except (EOFError, KeyboardInterrupt):
                    break
                if self._normalize_choice(raw) == "y":
                    prompt = ("The Priest rejected that.  Different approach "
                              "to same goal.  [THOUGHT][CMD][CONF].")
                    continue
                else:
                    break

            # v7.2 — record a successful exec for this node (used by
            # the WORKFLOW_COMPLETE gate above).  We count any non-error
            # return from run_command as a success at the framework
            # level — even if the tool found nothing, the LLM at least
            # got real output to reason from.
            self.stuck_counter = 0
            if active:
                self._node_success_count[active.nid] = (
                    self._node_success_count.get(active.nid, 0) + 1)

            # v7.1 — flush any queued credential fanout work into PTT
            self._flush_cred_fanout()

            # Optional verification
            if verify:
                print()
                print(_box(
                    "PoC VERIFICATION",
                    ["  Agent proposed a verification command — "
                     "running through y/n gate."],
                    color="33"))
                # Try to figure out which finding it's verifying — pick the
                # most recent unverified finding from this node
                if active:
                    candidates = [self.ptt.findings[fid - 1] for fid in active.findings
                                  if fid - 1 < len(self.ptt.findings)]
                else:
                    candidates = []
                target_finding = None
                for f in candidates:
                    if not f.verified:
                        target_finding = f
                        break
                if target_finding is None and self.ptt.get_unverified():
                    target_finding = self.ptt.get_unverified()[-1]

                if target_finding:
                    self.attempt_verification(verify,
                                              target_finding.value,
                                              target_finding.ftype)
                else:
                    # Just run the verify command standalone
                    self.run_command(verify, label="VERIFY")

            # Build pivot prompt with fresh context
            pivot_lines = []
            f_dict = self.ptt.findings_by_type_dict(only_verified=True)
            if f_dict:
                pivot_lines.append("VERIFIED FINDINGS:")
                for k, vs in f_dict.items():
                    pivot_lines.append(f"  {k.upper()}: {', '.join(vs[-4:])}")
            unv = self.ptt.get_unverified()
            if unv:
                u_dict: Dict[str, List[str]] = {}
                for f in unv[-15:]:
                    u_dict.setdefault(f.ftype, []).append(f.value)
                pivot_lines.append("UNVERIFIED CANDIDATES:")
                for k, vs in u_dict.items():
                    pivot_lines.append(f"  {k.upper()}: {', '.join(vs)}")
            pivot = "\n".join(pivot_lines)

            prompt = (
                f"TERMINAL OUTPUT:\n{output}\n\n"
                f"{pivot}\n\n"
                "Analyse with elite reasoning in [THOUGHT].  Pivot on "
                "verified findings.  WORKFLOW_COMPLETE if current node "
                "is done; else next [CMD].  Always include [CONF]."
            )

    # ── Workflow runner ───────────────────────────────────────────

    def _resolve_target(self) -> str:
        target = (self.target_info.get("ip") or
                  self.target_info.get("domain") or "")
        if not target:
            try:
                target = input("\033[90m   Enter target: \033[0m").strip()
            except (EOFError, KeyboardInterrupt):
                target = ""
        return target

    def run_workflow(self, key: str):
        wf = WORKFLOWS.get(key)
        if not wf:
            return
        target = self._resolve_target()
        if not target:
            print("\033[31m   No target.\033[0m")
            return

        print()
        say_ares(f"Workflow: {wf['name']}")
        print()
        self._log(f"[WORKFLOW] {wf['name']}")
        self._seed_ptt_from_workflow(key, target)
        print(self.ptt.to_terminal())
        print()

        prompt = (f"Workflow: {wf['name']}\nTarget: {target}\n\n"
                  f"Walk the PTT one node at a time.  For each node, output "
                  f"[THOUGHT][CMD][CONF].  Mark WORKFLOW_COMPLETE when the "
                  f"current node is done; the system will move you to the next.")
        self._agent_loop(prompt, workflow_key=key)

    def show_workflow_menu(self):
        print(f"\n{header_box('  WORKFLOW MENU  ', color='35')}\n")
        for k, wf in WORKFLOWS.items():
            print(f"   \033[97m[{k:>2}]\033[0m  {wf['name']}")
            print(f"          \033[90m{wf['description']}\033[0m")
        print(f"\n   \033[97m[ 0]\033[0m  Cancel\n")
        try:
            choice = input("\033[90m   Select: \033[0m").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice in WORKFLOWS:
            self.run_workflow(choice)
        elif choice != "0":
            print("\033[33m   Invalid.\033[0m")

    # ── Findings / Tree display ──────────────────────────────────

    def show_findings(self):
        if not self.ptt.findings:
            print("\n\033[90m   No findings yet.\033[0m\n")
            return

        verified = self.ptt.get_verified()
        unverified = self.ptt.get_unverified()

        print(f"\n{header_box('  FINDINGS  ', color='32')}")
        if verified:
            print(f"\n\033[32m   VERIFIED ({len(verified)}):\033[0m")
            for f in verified:
                print(finding_card(f))
        if unverified:
            print(f"\n\033[33m   UNVERIFIED ({len(unverified)}):\033[0m")
            for f in unverified:
                print(finding_card(f))
        print()

    def show_tree(self):
        print(f"\n{header_box('  PENTESTING TASK TREE  ', color='35')}\n")
        print(self.ptt.to_terminal())
        print()
        print(f"  \033[90mLegend:\033[0m  "
              f"○ todo  \033[33m◐\033[0m in_progress  "
              f"\033[32m●\033[0m done  \033[31m✗\033[0m dead-end  "
              f"\033[90m─\033[0m skipped")
        print()

    # ── Report generation (with cleanup pass) ───────────────────

    def _llm_cleanup_pass(self) -> str:
        """Ask the AI to write a clean report from verified findings only.
        This is called at report-generation time.  Returns a markdown body.
        Falls through to a plain dump if the LLM is unavailable.
        """
        verified = self.ptt.get_verified()
        if not verified and not self.ptt.findings:
            return "No findings to report."

        # Prepare context for the LLM
        v_summary = []
        for f in verified:
            v_summary.append(
                f"- {f.ftype}: {f.value} "
                f"(node {f.node_id}, source: `{f.source_cmd[:80]}`)"
            )

        u_summary = []
        for f in self.ptt.get_unverified():
            u_summary.append(f"- {f.ftype}: {f.value} (UNVERIFIED, node {f.node_id})")

        target = (self.target_info.get("ip") or
                  self.target_info.get("domain") or "Unknown")

        sys_prompt = (
            "You are Ares' Reporter agent.  You write professional "
            "defensive engagement reports.  Be concise, factual.  Use "
            "Markdown headers.  Map every finding to a MITRE ATT&CK "
            "technique where applicable.  Never invent findings — only "
            "use what is provided.  Drop unverified findings unless "
            "they are clearly part of the timeline."
        )

        user_prompt = (
            f"Host: {target}\n"
            f"Mission: {self.target_info.get('notes') or '—'}\n\n"
            f"VERIFIED FINDINGS:\n" + ("\n".join(v_summary) or "(none)") +
            "\n\nUNVERIFIED FINDINGS (mention only if part of the timeline):\n" +
            ("\n".join(u_summary) or "(none)") +
            "\n\nWrite a report with sections:\n"
            "## Executive Summary (verdict: healthy / suspicious / compromised)\n"
            "## Confirmed Findings (grouped by ATT&CK technique)\n"
            "## Timeline (chronological)\n"
            "## Containment Actions Taken\n"
            "## Remaining Risks\n"
            "## Recommended Hardening\n"
            "## Appendix: Tooling & Methodology"
        )

        response = self._think_with_fallback([
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ], max_tokens=2048)

        if not response:
            return self._fallback_report_body()
        return response

    def _fallback_report_body(self) -> str:
        lines = ["## Findings\n"]
        verified = self.ptt.get_verified()
        if verified:
            lines.append("### Verified")
            for f in verified:
                lines.append(f"- **{f.ftype}**: `{f.value}` "
                             f"(source: `{f.source_cmd[:100]}`)")
        unv = self.ptt.get_unverified()
        if unv:
            lines.append("\n### Unverified Candidates")
            for f in unv:
                lines.append(f"- **{f.ftype}**: `{f.value}`")
        return "\n".join(lines)

    def _generate_report(self):
        ts = datetime.datetime.now()
        duration = ts - self.session_start
        rpath = os.path.join(
            LOG_DIR,
            f"report_{self.session_start.strftime('%Y%m%d_%H%M%S')}.md"
        )
        target = " | ".join(filter(None, [
            self.target_info.get("ip", ""),
            self.target_info.get("domain", "")
        ]))

        # Get LLM-generated body
        body = self._llm_cleanup_pass()

        # v7.1 — MITRE ATT&CK section: techniques exercised + findings grouped
        mitre_section = self._build_mitre_section()

        # v7.1 — token savings estimate
        savings_line = ""
        if self.context_mgr.tokens_saved_estimate > 0:
            savings_line = (f"- **Tokens saved (smart context):** "
                          f"~{self.context_mgr.tokens_saved_estimate:,}\n")

        try:
            with open(rpath, "w") as f:
                f.write(f"# ARES v{VERSION} DEFENSIVE REPORT\n\n")
                f.write(f"- **Host:** {target or 'Not set'}\n")
                f.write(f"- **Mission:** {self.target_info.get('notes') or '—'}\n")
                f.write(f"- **Commander:** The Priest\n")
                f.write(f"- **Started:** {self.session_start.isoformat(timespec='seconds')}\n")
                f.write(f"- **Duration:** {str(duration).split('.')[0]}\n")
                f.write(f"- **This host:** {self.lhost}\n")
                f.write(f"- **Scope enforced:** {'yes' if self.scope.enabled else 'no'}\n")
                f.write(savings_line)
                f.write(f"\n---\n\n")
                f.write(body)
                f.write(f"\n\n---\n\n")
                f.write(mitre_section)
                f.write(f"\n\n---\n\n")
                f.write(f"## Defense Task Tree (Final State)\n\n```\n")
                f.write(self.ptt.to_natural_language(max_chars=8000))
                f.write(f"\n```\n\n")
                f.write(f"## Threat Graph Summary\n\n```\n")
                f.write(self.graph.to_compact_text(max_chars=4000))
                f.write(f"\n```\n\n")
                f.write(f"## Raw Findings (with provenance + ATT&CK)\n\n")
                for fnd in self.ptt.findings:
                    mark = "✓" if fnd.verified else "?"
                    attack = (f" `{fnd.attack_id} {fnd.attack_name}`"
                              if fnd.attack_id else "")
                    f.write(f"- [{mark}] **{fnd.ftype}** = `{fnd.value}` "
                            f"(node {fnd.node_id}, ts {fnd.timestamp}){attack}\n")
                    f.write(f"  - source: `{fnd.source_cmd[:200]}`\n")
                f.write(f"\n---\n*Generated by Ares v{VERSION}*\n")
            print(f"\n\033[32m   ✓ Report: {rpath}\033[0m")
        except Exception as e:
            print(f"\033[33m   Report failed: {e}\033[0m")

    def _build_mitre_section(self) -> str:
        """v7.1 — MITRE ATT&CK Navigator-friendly section: techniques
        exercised, findings grouped by technique."""
        lines = ["## MITRE ATT&CK Coverage\n"]

        # Techniques exercised (from commands run)
        if self.attack_techniques_used:
            lines.append("### Techniques Exercised\n")
            lines.append("| ID | Technique | Tactic | Times |")
            lines.append("|----|-----------|--------|-------|")
            # Sort by tactic, then by count desc
            sorted_techs = sorted(
                self.attack_techniques_used.items(),
                key=lambda x: (x[1]["tactic"], -x[1]["count"]),
            )
            for tid, info in sorted_techs:
                lines.append(f"| {tid} | {info['name']} | "
                             f"{info['tactic']} | {info['count']} |")
            lines.append("")
        else:
            lines.append("_No ATT&CK techniques recorded._\n")

        # Findings grouped by technique
        by_tech: Dict[str, List[Finding]] = {}
        for fnd in self.ptt.findings:
            if fnd.attack_id:
                by_tech.setdefault(fnd.attack_id, []).append(fnd)

        if by_tech:
            lines.append("### Findings by Technique\n")
            for tid in sorted(by_tech.keys()):
                fs = by_tech[tid]
                first = fs[0]
                lines.append(f"#### {tid} — {first.attack_name} "
                             f"_({first.attack_tactic})_")
                for fnd in fs:
                    mark = "✓" if fnd.verified else "?"
                    lines.append(f"- [{mark}] {fnd.ftype}: `{fnd.value}`")
                lines.append("")

        return "\n".join(lines)

    def save_session(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOG_DIR, f"save_{ts}.txt")
        try:
            with open(path, "w") as f:
                f.write(f"ARES SAVE {ts}\n{'='*60}\n\n")
                for msg in self.history:
                    f.write(f"[{msg['role'].upper()}]\n{msg['content']}\n\n")
            print(f"\033[32m   Saved: {path}\033[0m")
        except Exception as e:
            print(f"\033[31m   Save failed: {e}\033[0m")

    # ── Help, status, tool status ─────────────────────────────────

    def show_model_status(self):
        print(f"\n{header_box('  PROVIDER CHAIN  ', color='35')}\n")
        for i, (model_id, name) in enumerate(PROVIDER_CHAIN):
            mark = "\033[32m▶ ACTIVE\033[0m" if i == self.provider_index else "      "
            print(f"   {mark}  [{i+1}]  \033[97m{name:<22}\033[0m  "
                  f"\033[90m{model_id}\033[0m")
        print()

    def show_tools_status(self):
        print(f"\n{header_box('  KALI ARSENAL — AVAILABILITY  ', color='35')}\n")
        all_tools = all_kali_tools_flat()
        # Cache lookups
        for t in all_tools:
            if t not in self.tools_available:
                self.tools_available[t] = cmd_exists(t)

        # Group by category, show install state
        for cat, tools in KALI_TOOLS.items():
            present = [t for t in tools if self.tools_available.get(t)]
            missing = [t for t in tools if not self.tools_available.get(t)]
            print(f"\n   \033[97m{cat.upper()}\033[0m  "
                  f"\033[32m{len(present)}\033[0m / "
                  f"\033[97m{len(tools)}\033[0m available")
            if present:
                print(f"     \033[32m✓\033[0m {', '.join(present[:8])}"
                      + (f" \033[90m+{len(present)-8} more\033[0m" if len(present) > 8 else ""))
            if missing:
                print(f"     \033[31m✗\033[0m {', '.join(missing[:8])}"
                      + (f" \033[90m+{len(missing)-8} more\033[0m" if len(missing) > 8 else ""))
        print()

        all_missing = [t for t, p in self.tools_available.items() if not p]
        if all_missing:
            try:
                ans = input(f"\033[33m   Install {len(all_missing)} missing tools? [y/n]: \033[0m")
            except (EOFError, KeyboardInterrupt):
                return
            if self._normalize_choice(ans) == "y":
                for t in all_missing:
                    install_if_missing(t)
                    self.tools_available[t] = cmd_exists(t)

    def show_scope(self):
        """v7.1 — display scope / RoE config; allow toggle."""
        print(f"\n{header_box('  ENGAGEMENT SCOPE / RoE  ', color='33')}\n")
        print(f"   {self.scope.summary()}")
        print(f"\n   \033[90mFile: {SCOPE_FILE}\033[0m")
        print(f"   \033[90mEdit that file to set CIDRs, domains, time windows.\033[0m\n")
        try:
            choice = input("   Toggle scope enabled? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "y":
            self.scope.enabled = not self.scope.enabled
            try:
                with open(SCOPE_FILE, "r") as f:
                    data = json.load(f)
            except Exception:
                data = dict(DEFAULT_SCOPE)
            data["enabled"] = self.scope.enabled
            try:
                with open(SCOPE_FILE, "w") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"   \033[33m   Save failed: {e}\033[0m")
            state = ("\033[32menabled\033[0m" if self.scope.enabled
                     else "\033[90mdisabled\033[0m")
            print(f"   Scope is now {state}\n")

    def show_graph(self):
        """v7.1 — display threat graph state."""
        print(f"\n{header_box('  ATTACK GRAPH  ', color='36')}\n")
        if not HAS_NETWORKX:
            print("   \033[33m   networkx not installed.  "
                  "pip install networkx --break-system-packages\033[0m\n")
            return
        print(f"   {self.graph.summary()}\n")
        compact = self.graph.to_compact_text(max_chars=4000)
        for line in compact.split("\n")[1:]:  # skip the summary line
            print(f"   {line}")
        print()
        sugg = self.graph.pivot_suggestions()
        if sugg:
            print(f"   \033[33m\033[1mPIVOT HINTS:\033[0m")
            for s in sugg:
                print(f"     \033[33m›\033[0m {s}")
        print()

    def show_mitre(self):
        """v7.1 — display ATT&CK techniques exercised this session."""
        print(f"\n{header_box('  MITRE ATT&CK COVERAGE  ', color='31')}\n")
        if not self.attack_techniques_used:
            print("   \033[90m   No ATT&CK techniques recorded yet.\033[0m\n")
            return
        # Group by tactic
        by_tactic: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        for tid, info in self.attack_techniques_used.items():
            by_tactic.setdefault(info["tactic"], []).append((tid, info))
        for tactic in sorted(by_tactic.keys()):
            print(f"   \033[31m\033[1m{tactic}\033[0m")
            for tid, info in sorted(by_tactic[tactic],
                                     key=lambda x: -x[1]["count"]):
                print(f"     \033[97m{tid}\033[0m  {info['name']:<42} "
                      f"\033[90m×{info['count']}\033[0m")
            print()
        total = sum(i["count"] for i in self.attack_techniques_used.values())
        print(f"   \033[90m   {len(self.attack_techniques_used)} unique technique(s), "
              f"{total} total invocation(s)\033[0m\n")

    def show_dashboard(self):
        """v7.1 — concise session status panel."""
        v_count = len(self.ptt.get_verified())
        u_count = len(self.ptt.get_unverified())
        nodes_done = sum(1 for n in self.ptt.nodes.values() if n.status == "done")
        nodes_total = len(self.ptt.nodes)
        target = (self.target_info.get("ip") or
                  self.target_info.get("domain") or "—")
        elapsed = datetime.datetime.now() - self.session_start
        elapsed_str = str(elapsed).split(".")[0]
        scope_state = ("\033[32mON\033[0m" if self.scope.enabled
                       else "\033[90moff\033[0m")
        print(f"\n{header_box('  SESSION DASHBOARD  ', color='35')}\n")
        print(f"   \033[97mTarget       :\033[0m {target}")
        print(f"   \033[97mElapsed      :\033[0m {elapsed_str}")
        print(f"   \033[97mAgent        :\033[0m {AGENT_SPECS[self.current_agent]['icon']} "
              f"{AGENT_SPECS[self.current_agent]['name']}")
        print(f"   \033[97mModel        :\033[0m {self._current_model_name()}")
        print(f"   \033[97mPTT progress :\033[0m {nodes_done}/{nodes_total} nodes done")
        print(f"   \033[97mFindings     :\033[0m \033[32m{v_count}\033[0m verified, "
              f"\033[33m{u_count}\033[0m unverified")
        print(f"   \033[97mATT&CK techs :\033[0m {len(self.attack_techniques_used)} unique")
        print(f"   \033[97mGraph        :\033[0m {self.graph.summary()}")
        print(f"   \033[97mScope (RoE)  :\033[0m {scope_state}")
        if self.context_mgr.tokens_saved_estimate > 0:
            print(f"   \033[97mTokens saved :\033[0m "
                  f"~{self.context_mgr.tokens_saved_estimate:,} (smart context)")
        print()

    def show_help(self):
        print(
            f"\n   \033[34m\033[1mARES v{VERSION}\033[0m"
            f"   \033[90mby The Priest\033[0m\n"
            f"   Model      : \033[97m{self._current_model_name()}\033[0m\n"
            f"   This host  : \033[97m{self.lhost}\033[0m\n"
            f"   Agents     : \033[97m{len(AGENT_SPECS)}\033[0m  "
            f"(strategist, triage, log_analyst, threat_hunter, network_defender, "
            f"ir_responder, hardener, malware_analyst, forensics_analyst, "
            f"identity_defender, reporter)\n"
            f"   Workflows  : \033[97m{len(WORKFLOWS)}\033[0m\n"
            f"   Tools      : \033[97m{len(all_kali_tools_flat())}\033[0m  registered, "
            f"\033[97m{len(TOOL_DISPATCH)}\033[0m structured\n"
            f"   Scope RoE  : \033[97m{'enabled' if self.scope.enabled else 'disabled'}\033[0m\n"
            f"   Graph      : \033[97m{'on' if HAS_NETWORKX else 'off (pip install networkx)'}\033[0m\n"
            f"   Mode       : \033[32mread-only by default\033[0m  "
            f"(containment actions require double-confirm)\n\n"
            "   \033[97mworkflow\033[0m  open the workflow menu\n"
            "   \033[97mtarget\033[0m    set or update host under investigation\n"
            "   \033[97mfindings\033[0m  show extracted findings (verified + unverified)\n"
            "   \033[97mtree\033[0m      show the Defense Task Tree\n"
            "   \033[97mgraph\033[0m     show the threat graph state\n"
            "   \033[97mscope\033[0m     show / toggle engagement scope (RoE)\n"
            "   \033[97mmitre\033[0m     show ATT&CK techniques surfaced this session\n"
            "   \033[97mtools\033[0m     show tool availability + auto-install missing\n"
            "   \033[97mmodel\033[0m     show provider chain status\n"
            "   \033[97magent\033[0m     show all agent specialists\n"
            "   \033[97msave\033[0m      save conversation to file\n"
            "   \033[97mreport\033[0m    generate report now\n"
            "   \033[97mclear\033[0m     clear AI memory (DTT preserved)\n"
            "   \033[97mreset\033[0m     reset everything (DTT + findings + history)\n"
            "   \033[97mhelp\033[0m      this menu\n"
            "   \033[97mexit/q\033[0m    end session + report\n\n"
            "   \033[90mOr type any objective in plain English — Ares routes to the right specialist.\033[0m\n"
        )

    def show_agents(self):
        print(f"\n{header_box('  SPECIALIST AGENTS  ', color='34')}\n")
        for role, spec in AGENT_SPECS.items():
            print(f"   \033[{spec['color']}m{spec['icon']}  "
                  f"{spec['name']:<32}\033[0m  \033[90m({role})\033[0m")
        print()

    # ── REPL ──────────────────────────────────────────────────────

    def repl(self):
        # v7.1 — cinematic boot
        print(BANNER)
        for ln in boot_sequence_lines():
            print(ln)
            time.sleep(0.04)
        print()
        print(speakers_legend())
        print()
        self.set_target()
        self.show_help()

        while True:
            # v7.1 — render persistent status bar above each prompt
            target = (self.target_info.get("ip") or
                      self.target_info.get("domain") or "no-target")
            print()
            print(status_bar(
                target=target,
                agent=self.current_agent,
                model=self._current_model_name(),
                verified=len(self.ptt.get_verified()),
                unverified=len(self.ptt.get_unverified()),
                techniques=len(self.attack_techniques_used),
                scope_on=self.scope.enabled,
            ))
            try:
                user_input = input("\033[35m\033[1m  ⚔ priest \033[0m"
                                    "\033[35m›\033[0m ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                say_ares("Session ended.")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                break

            if not user_input:
                continue

            self._log(f"[PRIEST] {user_input}")
            cmd = user_input.lower()

            if cmd in ("exit", "quit", "q"):
                print()
                say_ares("Generating report...")
                self._generate_report()
                if self.logfile:
                    self.logfile.close()
                break
            elif cmd == "help":
                self.show_help()
            elif cmd == "workflow":
                self.show_workflow_menu()
            elif cmd == "target":
                self.set_target()
            elif cmd == "findings":
                self.show_findings()
            elif cmd == "tree":
                self.show_tree()
            elif cmd == "tools":
                self.show_tools_status()
            elif cmd == "model":
                self.show_model_status()
            elif cmd == "agent" or cmd == "agents":
                self.show_agents()
            elif cmd == "save":
                self.save_session()
            elif cmd == "report":
                self._generate_report()
            elif cmd == "clear":
                self.history.clear()
                self.command_history.clear()
                self.current_workflow_key = None
                say_ares("AI memory cleared.  PTT and findings preserved.")
            elif cmd == "reset":
                self.history.clear()
                self.command_history.clear()
                self.current_workflow_key = None
                goal = "Compromise " + (self.target_info.get("ip") or
                                         self.target_info.get("domain") or "target")
                self.ptt = PTT(goal=goal)
                self.graph = AttackGraph()
                self.attack_techniques_used.clear()
                self.ioc_fanout_queue.clear()
                self.context_mgr = ContextManager()
                self.stuck_counter = 0
                # v7.1 — wipe in-memory sudo password on reset
                self._sudo_password = None
                self._sudo_skip_session = False
                say_ares("Full reset.  Fresh PTT, graph, sudo cache wiped, "
                           "no findings, no history.")
            elif cmd == "scope":
                self.show_scope()
            elif cmd == "graph":
                self.show_graph()
            elif cmd == "mitre" or cmd == "attack":
                self.show_mitre()
            elif cmd in ("status", "dashboard", "stat"):
                self.show_dashboard()
            else:
                self._agent_loop(user_input, workflow_key=None)


# ═════════════════════════════════════════════════════════════════════
# BANNER
# ═════════════════════════════════════════════════════════════════════

# Build the banner programmatically so colour escapes are unambiguous
# and we never lose them through editor copies.
def _build_banner() -> str:
    M  = "\033[34m"   # blue frame (defender colour)
    W  = "\033[97m"   # bright white logo
    G  = "\033[90m"   # grey detail
    C  = "\033[36m"   # cyan accent
    Y  = "\033[33m"   # yellow accent
    B  = "\033[1m"    # bold
    R  = "\033[0m"    # reset
    KB = "\033[100m\033[97m"  # keycap inverse
    L  = lambda s: f"{M}│{R} {s}"

    lines = [
        "",
        f"{M}╭─────────────────────────────────────────────────────────────────╮{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f"          {W} █████╗ ██████╗ ███████╗███████╗{M}                       ") + f"{M}│{R}",
        L(f"          {W}██╔══██╗██╔══██╗██╔════╝██╔════╝{M}                       ") + f"{M}│{R}",
        L(f"          {W}███████║██████╔╝█████╗  ███████╗{M}                       ") + f"{M}│{R}",
        L(f"          {W}██╔══██║██╔══██╗██╔══╝  ╚════██║{M}                       ") + f"{M}│{R}",
        L(f"          {W}██║  ██║██║  ██║███████╗███████║{M}                       ") + f"{M}│{R}",
        L(f"          {W}╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝{M}                       ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f"   {B}{W}AI DEFENSIVE SECURITY AGENT{R}{M}  ·  {B}{C}v1.0{R}{M}                       ") + f"{M}│{R}",
        L(f"   {G}Bare-metal Kali NetHunter  ·  Commander: The Priest{M}          ") + f"{M}│{R}",
        L(f"   {G}sister of Athena · offense's mirror{M}                              ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f" {G}╭─{C} defender capabilities {G}─────────────────────────────────╮{M}    ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Triage           {G}fast host health verdict{R}             {G}│{M}    ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Threat Hunt      {G}cron/systemd/preload/web-shell sweep{R} {G}│{M}    ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Network Defense  {G}Suricata · Zeek · tshark · pcap{R}      {G}│{M}    ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ IR Containment   {G}evidence-first, double-confirm gates{R} {G}│{M}    ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Hardening        {G}lynis · OpenSCAP · sysctl · CIS{R}      {G}│{M}    ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ Forensics        {G}volatility3 · sleuthkit · yara{R}       {G}│{M}    ") + f"{M}│{R}",
        L(f" {G}│{R}  {W}⊕ MITRE ATT&CK     {G}detection-tagged findings{R}            {G}│{M}    ") + f"{M}│{R}",
        L(f" {G}╰───────────────────────────────────────────────────────────╯{M}    ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        L(f"   {G}type  {KB} help {R}{G}  for commands  ·  {KB} workflow {R}{G}  for menus{M}     ") + f"{M}│{R}",
        L(f"{' '*65}") + f"{M}│{R}",
        f"{M}╰─────────────────────────────────────────────────────────────────╯{R}",
        "",
    ]
    return "\n".join(lines)


BANNER = _build_banner()


# ═════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        session = AresSession()
        session.repl()
    except KeyboardInterrupt:
        print("\n\033[90mInterrupted.\033[0m")
        sys.exit(130)
