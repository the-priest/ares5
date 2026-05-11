#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   ARES — Read-only System Security Audit  v5.0                   ║
║   Bare-metal Kali NetHunter · Operator: The Priest               ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║   v5.0 — full rewrite, Zeus-style pipeline.                      ║
║   Replaces v1's 50-turn agent loop, specialist routing, and      ║
║   AI-driven shell=True command dispatch.                         ║
║                                                                  ║
║   Flow:   boot → run_checks (parallel) → score → report          ║
║   No AI for routing.  AI only writes the final summary.          ║
║                                                                  ║
║   STRICTLY READ-ONLY.  Ares NEVER:                               ║
║     • installs / removes / upgrades packages                     ║
║     • starts / stops / enables / disables services               ║
║     • adds / removes firewall rules                              ║
║     • edits config files                                         ║
║     • kills processes                                            ║
║     • uses sudo (it skips checks instead of escalating)          ║
║                                                                  ║
║   Designed to run in 30-60s, produce a graded security report,   ║
║   and tell you exactly what to fix yourself.                     ║
║                                                                  ║
║   RAM-only · no disk persistence · scan-only.                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import json
import time
import shutil
import signal
import subprocess
import datetime
import concurrent.futures
from typing import List, Dict, Tuple, Optional, Any, Callable

VERSION = "5.0"

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "openai/gpt-oss-120b",
    "llama-3.1-8b-instant",
]

# ═════════════════════════════════════════════════════════════════════
# CONFIG
# ═════════════════════════════════════════════════════════════════════

TOTAL_TIMEOUT_SEC  = 120
PER_CHECK_TIMEOUT  = 15
PARALLEL_CHECKS    = 6

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[90m"
CYAN, GREEN, YELLOW, RED = "\033[36m", "\033[32m", "\033[33m", "\033[31m"
WHITE, BLUE, MAGENTA = "\033[97m", "\033[34m", "\033[35m"


# ═════════════════════════════════════════════════════════════════════
# SEVERITY MODEL
# ═════════════════════════════════════════════════════════════════════

SEVERITY_WEIGHTS = {
    "info":     0,
    "low":      1,
    "medium":   3,
    "high":     8,
    "critical": 20,
}

class Finding:
    __slots__ = ("check_id", "title", "severity", "evidence",
                 "fix_hint", "raw")
    def __init__(self, check_id: str, title: str, severity: str,
                 evidence: str, fix_hint: str = "", raw: str = ""):
        if severity not in SEVERITY_WEIGHTS:
            severity = "info"
        self.check_id = check_id
        self.title = title
        self.severity = severity
        self.evidence = evidence
        self.fix_hint = fix_hint
        self.raw = raw[:2000] if raw else ""


# ═════════════════════════════════════════════════════════════════════
# READ-ONLY COMMAND RUNNER
# All commands are passed as arg-lists (no shell=True, no sudo).
# ═════════════════════════════════════════════════════════════════════

def run_ro(argv: List[str], timeout: int = PER_CHECK_TIMEOUT) -> Tuple[int, str, str]:
    """Run a read-only command.  Returns (rc, stdout, stderr)."""
    try:
        clean_env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": os.path.expanduser("~"),
        }
        p = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=clean_env,
            text=True,
            errors="replace",
        )
        return (p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired:
        return (124, "", "timeout")
    except FileNotFoundError:
        return (127, "", "not found")
    except PermissionError:
        return (126, "", "permission denied")
    except Exception as e:
        return (1, "", f"error: {type(e).__name__}")


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def read_file(path: str, max_bytes: int = 200_000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════════════
# CHECKS
# Each check returns a list of Findings.  Skip silently if a tool isn't
# available.  Never modify anything.
# ═════════════════════════════════════════════════════════════════════

# ── FIREWALL ────────────────────────────────────────────────────
def check_firewall() -> List[Finding]:
    findings: List[Finding] = []
    fw_active = False

    if have("ufw"):
        rc, out, _ = run_ro(["ufw", "status"])
        if rc == 0 and out:
            if re.search(r'status:\s*active', out, re.IGNORECASE):
                fw_active = True
                findings.append(Finding(
                    "FW-001", "UFW firewall is active",
                    "info",
                    "ufw reports status: active",
                    raw=out,
                ))
            elif re.search(r'status:\s*inactive', out, re.IGNORECASE):
                findings.append(Finding(
                    "FW-002", "UFW firewall is INACTIVE",
                    "high",
                    "ufw is installed but not enabled",
                    fix_hint="sudo ufw default deny incoming "
                             "&& sudo ufw allow ssh && sudo ufw enable",
                    raw=out,
                ))

    if not fw_active and have("iptables"):
        rc, out, _ = run_ro(["iptables", "-S"])
        if rc == 0 and out:
            lines = [l for l in out.splitlines() if l.strip()]
            has_rules = any(
                re.search(r'-P\s+\w+\s+(DROP|REJECT)', l)
                or re.search(r'-A\s+\w+.*-j\s+(DROP|REJECT)', l)
                for l in lines
            )
            if has_rules:
                fw_active = True
                findings.append(Finding(
                    "FW-003", "iptables rules present",
                    "info",
                    f"{len(lines)} iptables rule(s) configured",
                    raw=out[:1500],
                ))

    if not fw_active and have("nft"):
        rc, out, _ = run_ro(["nft", "list", "ruleset"])
        if rc == 0 and out.strip():
            fw_active = True
            findings.append(Finding(
                "FW-005", "nftables rules present",
                "info",
                "nftables ruleset is loaded",
                raw=out[:1500],
            ))

    if not fw_active:
        findings.append(Finding(
            "FW-006", "No firewall detected",
            "high",
            "ufw / iptables / nft all report no active rules",
            fix_hint="sudo apt install ufw && sudo ufw default deny "
                     "incoming && sudo ufw allow ssh && sudo ufw enable",
        ))
    return findings


# ── LISTENING PORTS ─────────────────────────────────────────────
def check_listening_ports() -> List[Finding]:
    findings: List[Finding] = []
    if not have("ss"):
        return findings
    rc, out, _ = run_ro(["ss", "-tlnpu"])
    if rc != 0 or not out:
        return findings

    public_listeners: List[str] = []
    local_listeners: List[str] = []
    for line in out.splitlines()[1:]:
        if not line.strip():
            continue
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 5:
            continue
        local_addr = parts[4]
        proc = " ".join(parts[6:]) if len(parts) > 6 else ""
        if ":" not in local_addr:
            continue
        addr, _, port = local_addr.rpartition(":")
        addr = addr.strip("[]")
        is_public = (
            addr in ("0.0.0.0", "*", "::") or
            (addr and not addr.startswith("127.") and addr != "::1"
             and not addr.startswith("fe80"))
        )
        summary = f"port {port:6s}  {addr:>16s}  {proc[:50]}"
        if is_public:
            public_listeners.append(summary)
        else:
            local_listeners.append(summary)

    if public_listeners:
        sev = "medium" if len(public_listeners) <= 3 else "high"
        findings.append(Finding(
            "NET-001", f"{len(public_listeners)} public-facing port(s)",
            sev,
            "services bound to a public interface (0.0.0.0 / ::)",
            fix_hint="If firewall is active these may still be blocked, but "
                     "unnecessary listeners should bind to 127.0.0.1 only.",
            raw="\n".join(public_listeners),
        ))
    if local_listeners:
        findings.append(Finding(
            "NET-002", f"{len(local_listeners)} localhost listener(s)",
            "info",
            "services bound to localhost only — not network-reachable",
            raw="\n".join(local_listeners[:25]),
        ))
    return findings


# ── SSH CONFIG ──────────────────────────────────────────────────
def check_ssh_config() -> List[Finding]:
    findings: List[Finding] = []
    cfg = read_file("/etc/ssh/sshd_config")
    if cfg is None:
        return findings

    risky = []
    if re.search(r'^\s*PermitRootLogin\s+yes', cfg, re.MULTILINE):
        risky.append(("PermitRootLogin yes",
                      "Direct root SSH login allowed",
                      "high",
                      "Set 'PermitRootLogin no' in /etc/ssh/sshd_config "
                      "then sudo systemctl reload sshd"))
    if re.search(r'^\s*PasswordAuthentication\s+yes', cfg, re.MULTILINE):
        risky.append(("PasswordAuthentication yes",
                      "Password login enabled — vulnerable to brute force",
                      "medium",
                      "Switch to keys: 'PasswordAuthentication no' after "
                      "confirming your key works"))
    if re.search(r'^\s*PermitEmptyPasswords\s+yes', cfg, re.MULTILINE):
        risky.append(("PermitEmptyPasswords yes",
                      "Empty passwords accepted — CRITICAL",
                      "critical",
                      "Set 'PermitEmptyPasswords no' immediately"))
    if re.search(r'^\s*X11Forwarding\s+yes', cfg, re.MULTILINE):
        risky.append(("X11Forwarding yes",
                      "X11 forwarding enabled — minor attack surface",
                      "low",
                      "Disable unless actually used"))

    for setting, desc, sev, fix in risky:
        findings.append(Finding(
            "SSH-" + setting.split()[0],
            desc, sev,
            f"sshd_config: {setting}",
            fix_hint=fix,
        ))
    return findings


# ── SUDO HISTORY ────────────────────────────────────────────────
def check_sudo_history() -> List[Finding]:
    findings: List[Finding] = []
    if not have("journalctl"):
        return findings
    rc, out, _ = run_ro([
        "journalctl", "_COMM=sudo", "--since=24 hours ago",
        "--no-pager", "-n", "100",
    ])
    if rc != 0 or not out.strip():
        return findings

    failed = re.findall(
        r'(?:authentication failure|incorrect password).*?ruser=(\S+)',
        out, re.IGNORECASE)
    if len(failed) >= 3:
        sev = "high" if len(failed) >= 10 else "medium"
        findings.append(Finding(
            "AUTH-001", f"{len(failed)} failed sudo attempt(s) in 24h",
            sev,
            f"users with failed sudo: {sorted(set(failed))}",
            fix_hint="Investigate — could be typos, could be an attacker.",
        ))
    return findings


# ── FAILED SSH LOGINS ───────────────────────────────────────────
def check_failed_logins() -> List[Finding]:
    findings: List[Finding] = []
    if not have("journalctl"):
        return findings
    rc, out, _ = run_ro([
        "journalctl", "_COMM=sshd", "--since=24 hours ago",
        "--no-pager", "-n", "300",
    ])
    if rc != 0 or not out.strip():
        return findings

    invalid = re.findall(r'Invalid user (\S+) from (\S+)', out)
    failed = re.findall(r'Failed password for (?:invalid user )?(\S+) from (\S+)', out)
    total = len(invalid) + len(failed)
    if total >= 10:
        sev = "high" if total >= 100 else "medium"
        ips = set([ip for _, ip in invalid] + [ip for _, ip in failed])
        findings.append(Finding(
            "AUTH-002", f"{total} failed SSH login(s) in 24h",
            sev,
            f"{len(ips)} unique source IP(s) — likely brute force scan",
            fix_hint="Install fail2ban: sudo apt install fail2ban",
            raw="\n".join([f"invalid user: {u}@{i}" for u, i in invalid[:20]]),
        ))
    return findings


# ── UNATTENDED-UPGRADES ─────────────────────────────────────────
def check_unattended_upgrades() -> List[Finding]:
    findings: List[Finding] = []
    if not have("systemctl"):
        return findings
    rc, out, _ = run_ro(["systemctl", "is-enabled", "unattended-upgrades"])
    if rc == 0 and "enabled" in out:
        findings.append(Finding(
            "PATCH-001", "Automatic security updates are enabled",
            "info",
            "unattended-upgrades is enabled",
        ))
    else:
        cfg = read_file("/etc/apt/apt.conf.d/50unattended-upgrades")
        if cfg is None:
            findings.append(Finding(
                "PATCH-002", "Automatic security updates not configured",
                "medium",
                "unattended-upgrades not installed",
                fix_hint="sudo apt install unattended-upgrades && "
                         "sudo dpkg-reconfigure -plow unattended-upgrades",
            ))
    return findings


# ── PENDING SECURITY UPDATES ────────────────────────────────────
def check_pending_updates() -> List[Finding]:
    findings: List[Finding] = []
    if not have("apt"):
        return findings
    rc, out, _ = run_ro(["apt", "list", "--upgradable"], timeout=20)
    if rc != 0:
        return findings
    sec_lines = [l for l in out.splitlines()
                 if re.search(r'security', l, re.IGNORECASE)]
    total = sum(1 for l in out.splitlines() if "/" in l and "upgradable" in l)
    sec = len(sec_lines)
    if sec > 0:
        sev = "high" if sec >= 5 else "medium"
        findings.append(Finding(
            "PATCH-003", f"{sec} pending security update(s)",
            sev,
            f"{sec} security-tagged packages have updates available",
            fix_hint="sudo apt update && sudo apt upgrade",
            raw="\n".join(sec_lines[:15]),
        ))
    elif total > 0:
        findings.append(Finding(
            "PATCH-004", f"{total} pending package update(s) (non-security)",
            "low", f"{total} packages have non-security updates pending",
            fix_hint="sudo apt update && sudo apt upgrade",
        ))
    return findings


# ── SUID FILES IN UNEXPECTED LOCATIONS ─────────────────────────
def check_suid_files() -> List[Finding]:
    findings: List[Finding] = []
    EXPECTED = ("/usr/bin", "/usr/sbin", "/bin", "/sbin",
                "/usr/lib", "/usr/libexec")
    rc, out, _ = run_ro([
        "find", "/usr", "/bin", "/sbin", "/opt",
        "-xdev", "-perm", "-4000", "-type", "f",
        "-not", "-path", "*/proc/*",
        "-not", "-path", "*/sys/*",
    ], timeout=30)
    if rc != 0:
        return findings
    suspicious = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if not any(line.startswith(d + "/") for d in EXPECTED):
            suspicious.append(line)
    if suspicious:
        sev = "high" if len(suspicious) > 2 else "medium"
        findings.append(Finding(
            "PRIV-001", f"{len(suspicious)} SUID file(s) in unusual location(s)",
            sev,
            "SUID binaries outside /usr/bin /usr/sbin /bin /sbin",
            fix_hint="Inspect each. Legitimate ones are rare.",
            raw="\n".join(suspicious[:15]),
        ))
    return findings


# ── WORLD-WRITABLE FILES IN HOME ───────────────────────────────
def check_world_writable_home() -> List[Finding]:
    findings: List[Finding] = []
    home = os.path.expanduser("~")
    if not os.path.isdir(home):
        return findings
    rc, out, _ = run_ro([
        "find", home, "-xdev", "-perm", "-o+w",
        "-not", "-type", "l",
        "-not", "-path", "*/.cache/*",
        "-not", "-path", "*/node_modules/*",
        "-not", "-path", "*/.git/*",
        "-type", "f",
    ], timeout=30)
    if rc != 0:
        return findings
    files = [l.strip() for l in out.splitlines() if l.strip()]
    if files:
        sev = "low" if len(files) < 5 else "medium"
        findings.append(Finding(
            "PERM-001", f"{len(files)} world-writable file(s) in $HOME",
            sev,
            "files in your home directory are world-writable",
            fix_hint="Inspect and:  chmod o-w <file>",
            raw="\n".join(files[:10]),
        ))
    return findings


# ── MAC FRAMEWORK ──────────────────────────────────────────────
def check_mac() -> List[Finding]:
    findings: List[Finding] = []
    if have("aa-status"):
        rc, out, _ = run_ro(["aa-status"])
        if rc == 0 and "apparmor module is loaded" in out.lower():
            m = re.search(r'(\d+)\s+profiles are in enforce mode', out)
            n = m.group(1) if m else "?"
            findings.append(Finding(
                "MAC-001", f"AppArmor active ({n} enforce profiles)",
                "info", "AppArmor mandatory access control active",
            ))
            return findings
    if have("getenforce"):
        rc, out, _ = run_ro(["getenforce"])
        if rc == 0:
            mode = out.strip()
            if mode == "Enforcing":
                findings.append(Finding(
                    "MAC-002", f"SELinux is {mode}",
                    "info", "SELinux mandatory access control active",
                ))
                return findings
            elif mode == "Permissive":
                findings.append(Finding(
                    "MAC-003", "SELinux is Permissive",
                    "low", "logs violations but doesn't block them",
                    fix_hint="Set SELINUX=enforcing in /etc/selinux/config",
                ))
                return findings
            elif mode == "Disabled":
                findings.append(Finding(
                    "MAC-004", "SELinux is Disabled",
                    "medium", "no SELinux mandatory access control",
                ))
                return findings
    findings.append(Finding(
        "MAC-005", "No MAC framework active",
        "medium",
        "no apparmor / selinux mandatory access control detected",
        fix_hint="Kali ships with apparmor — check it's enabled.",
    ))
    return findings


# ── DISK ENCRYPTION ────────────────────────────────────────────
def check_disk_encryption() -> List[Finding]:
    findings: List[Finding] = []
    if not have("lsblk"):
        return findings
    rc, out, _ = run_ro(["lsblk", "-f", "-J"])
    if rc != 0:
        return findings
    try:
        data = json.loads(out)
    except Exception:
        return findings

    def walk(node, in_crypto=False):
        results = []
        fst = node.get("fstype")
        mp = node.get("mountpoint")
        if fst and fst.startswith("crypto_LUKS"):
            in_crypto = True
        if mp in ("/", "/home"):
            results.append((node.get("name"), mp, in_crypto, fst))
        for c in node.get("children", []) or []:
            results.extend(walk(c, in_crypto))
        return results

    statuses = []
    for d in data.get("blockdevices", []):
        statuses.extend(walk(d))
    if not statuses:
        return findings

    root_enc = any(mp == "/" and enc for _, mp, enc, _ in statuses)
    if not root_enc:
        findings.append(Finding(
            "CRYPTO-001", "Root filesystem is not encrypted",
            "medium",
            "no LUKS encryption on root volume",
            fix_hint="Disk encryption is install-time only. Note for next reinstall.",
        ))
    else:
        findings.append(Finding(
            "CRYPTO-002", "Root filesystem is LUKS-encrypted",
            "info", "LUKS encryption protecting / partition",
        ))
    return findings


# ── CRON / TIMER JOBS ──────────────────────────────────────────
def check_cron_jobs() -> List[Finding]:
    findings: List[Finding] = []
    cron_entries = []
    rc, out, _ = run_ro(["crontab", "-l"])
    if rc == 0 and out.strip():
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                cron_entries.append(("user", line))
    for d in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
              "/etc/cron.weekly", "/etc/cron.monthly"):
        try:
            for name in os.listdir(d):
                cron_entries.append((d, name))
        except Exception:
            continue
    if cron_entries:
        findings.append(Finding(
            "CRON-001", f"{len(cron_entries)} scheduled job(s)",
            "info", "review for unfamiliar entries",
            raw="\n".join(f"{src}: {entry[:120]}"
                          for src, entry in cron_entries[:20]),
        ))
    if have("systemctl"):
        rc, out, _ = run_ro(["systemctl", "list-timers",
                             "--no-pager", "--all"])
        if rc == 0 and out.strip():
            lines = [l for l in out.splitlines()
                     if l.strip() and not l.lower().startswith(
                         ("next ", "n/a", "timers listed"))]
            if lines:
                findings.append(Finding(
                    "CRON-002", f"{len(lines)-1} systemd timer(s)",
                    "info", "systemd timer units active",
                    raw="\n".join(lines[:15]),
                ))
    return findings


# ── ROOT-OWNED SERVICES ────────────────────────────────────────
def check_root_services() -> List[Finding]:
    findings: List[Finding] = []
    if not have("ps"):
        return findings
    rc, out, _ = run_ro(["ps", "-eo", "user,pid,comm,cmd", "--no-headers"])
    if rc != 0:
        return findings
    root_procs = []
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        user, pid, comm, cmd = parts
        if user != "root":
            continue
        if any(s in comm for s in (
            "sshd", "nginx", "apache", "httpd", "mysqld",
            "postgres", "redis", "mongod", "named", "smbd",
            "vsftpd", "lighttpd", "tomcat",
        )):
            root_procs.append(f"{comm:15s} pid={pid}  {cmd[:80]}")
    if root_procs:
        findings.append(Finding(
            "PROC-001", f"{len(root_procs)} network service(s) running as root",
            "low",
            "consider running services under dedicated users where possible",
            raw="\n".join(root_procs[:10]),
        ))
    return findings


# ── KERNEL ─────────────────────────────────────────────────────
def check_kernel() -> List[Finding]:
    findings: List[Finding] = []
    if not have("uname"):
        return findings
    rc, running, _ = run_ro(["uname", "-r"])
    running = running.strip()
    if not running:
        return findings
    findings.append(Finding(
        "KERN-001", f"Running kernel: {running}",
        "info", "current kernel version",
    ))
    if have("dpkg"):
        rc, out, _ = run_ro(["dpkg", "--list", "linux-image-*"])
        if rc == 0:
            installed = []
            for line in out.splitlines():
                m = re.match(r'ii\s+linux-image-([\d\.\-\w]+)', line)
                if m:
                    installed.append(m.group(1))
            def kver(v):
                return tuple(int(x) if x.isdigit() else 0
                             for x in re.findall(r'\d+', v)[:4])
            newer = []
            try:
                run_ver = kver(running)
                newer = [k for k in installed if kver(k) > run_ver]
            except Exception:
                pass
            if newer:
                findings.append(Finding(
                    "KERN-002",
                    f"Newer kernel installed but not booted: {newer[0]}",
                    "medium",
                    "you have a newer kernel installed than the one running",
                    fix_hint="Reboot to load the newer kernel.",
                ))
    return findings


# ── RECENT LOGINS ──────────────────────────────────────────────
def check_logins() -> List[Finding]:
    findings: List[Finding] = []
    if not have("last"):
        return findings
    rc, out, _ = run_ro(["last", "-n", "10", "-F"])
    if rc != 0 or not out.strip():
        return findings
    sessions = [l for l in out.splitlines()
                if l.strip() and not l.startswith("wtmp begins")]
    if sessions:
        findings.append(Finding(
            "AUTH-003", f"Last {len(sessions)} login session(s)",
            "info",
            "review for unexpected sources",
            raw="\n".join(sessions[:10]),
        ))
    return findings


# ── SHELL HISTORY ──────────────────────────────────────────────
def check_shell_history() -> List[Finding]:
    findings: List[Finding] = []
    home = os.path.expanduser("~")
    histories = {
        ".bash_history": "bash",
        ".zsh_history":  "zsh",
        ".local/share/fish/fish_history": "fish",
    }
    for rel, shell in histories.items():
        path = os.path.join(home, rel)
        if not os.path.exists(path):
            continue
        try:
            sz = os.path.getsize(path)
        except Exception:
            continue
        if sz == 0:
            findings.append(Finding(
                "AUDIT-001", f"{shell} history is empty",
                "low",
                f"{path} is zero bytes — could mean wipe, "
                f"or that shell isn't your daily driver",
            ))
    return findings


# ── RKHUNTER LOG ───────────────────────────────────────────────
def check_rootkit_scanners() -> List[Finding]:
    findings: List[Finding] = []
    if have("rkhunter"):
        cfg = read_file("/var/log/rkhunter.log", max_bytes=50_000)
        if cfg:
            warnings = re.findall(r'Warning:\s+(.+)', cfg)
            if warnings:
                findings.append(Finding(
                    "RKHUNT-001",
                    f"{len(warnings)} rkhunter warning(s) in last scan",
                    "medium",
                    "review /var/log/rkhunter.log",
                    raw="\n".join(warnings[:10]),
                ))
    return findings


# ── ROUTING TABLE / DNS ────────────────────────────────────────
def check_dns() -> List[Finding]:
    findings: List[Finding] = []
    resolv = read_file("/etc/resolv.conf")
    if resolv:
        servers = re.findall(r'^\s*nameserver\s+(\S+)', resolv, re.MULTILINE)
        # Suspicious DNS — non-loopback, non-RFC1918, non-major-public
        KNOWN_GOOD = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                       "9.9.9.9", "149.112.112.112",
                       "208.67.222.222", "208.67.220.220",
                       "127.0.0.1", "127.0.0.53", "::1"}
        unusual = [s for s in servers
                   if s not in KNOWN_GOOD
                   and not s.startswith(("10.", "192.168.", "172."))
                   and not s.startswith(("fe80", "fc", "fd"))]
        if unusual:
            findings.append(Finding(
                "DNS-001", f"Unusual DNS server(s) configured",
                "low",
                f"resolvers not in the well-known public set: {unusual}",
                fix_hint="Verify these are intentional. Attackers "
                         "sometimes rewrite /etc/resolv.conf.",
            ))
    return findings


# ── REGISTRY ───────────────────────────────────────────────────
CHECKS: List[Tuple[str, str, Callable[[], List[Finding]]]] = [
    ("FW",      "Firewall status",          check_firewall),
    ("NET",     "Listening ports",          check_listening_ports),
    ("SSH",     "SSH server config",        check_ssh_config),
    ("AUTH-A",  "Failed sudo attempts",     check_sudo_history),
    ("AUTH-B",  "Failed SSH logins",        check_failed_logins),
    ("PATCH-A", "Unattended upgrades",      check_unattended_upgrades),
    ("PATCH-B", "Pending security updates", check_pending_updates),
    ("PRIV",    "SUID file audit",          check_suid_files),
    ("PERM",    "Home dir permissions",     check_world_writable_home),
    ("MAC",     "AppArmor / SELinux",       check_mac),
    ("CRYPTO",  "Disk encryption",          check_disk_encryption),
    ("CRON",    "Scheduled jobs",           check_cron_jobs),
    ("PROC",    "Root-owned services",      check_root_services),
    ("KERN",    "Kernel version",           check_kernel),
    ("AUTH-C",  "Recent logins",            check_logins),
    ("HIST",    "Shell history hygiene",    check_shell_history),
    ("RKHUNT",  "Rootkit scanner log",      check_rootkit_scanners),
    ("DNS",     "DNS resolver config",      check_dns),
]


# ═════════════════════════════════════════════════════════════════════
# UI
# ═════════════════════════════════════════════════════════════════════

def banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════════════╗
║      █████╗ ██████╗ ███████╗███████╗                     ║
║     ██╔══██╗██╔══██╗██╔════╝██╔════╝                     ║
║     ███████║██████╔╝█████╗  ███████╗  🛡️                  ║
║     ██╔══██║██╔══██╗██╔══╝  ╚════██║                     ║
║     ██║  ██║██║  ██║███████╗███████║                     ║
║     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝                     ║
║                                                          ║
║   {BOLD}Read-only System Audit · v{VERSION}{RESET}{RED}                    ║
║   {DIM}scan only · no changes · no sudo writes · RAM-only{RED}    ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def progress(stage: str, done: int, total: int, label: str = ""):
    pct = int(100 * done / total) if total else 0
    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
    line = f"\r{CYAN}[{stage}]{RESET} {bar} {pct:3}% {DIM}{label[:40]}{RESET}"
    sys.stdout.write(line.ljust(80))
    sys.stdout.flush()
    if done >= total:
        print()


# ═════════════════════════════════════════════════════════════════════
# PIPELINE
# ═════════════════════════════════════════════════════════════════════

def _safe_run(fn: Callable[[], List[Finding]]) -> Tuple[List[Finding], float]:
    t0 = time.time()
    try:
        out = fn()
    except Exception:
        out = []
    return (out or [], time.time() - t0)


def run_audit() -> Dict[str, Any]:
    t0 = time.time()
    all_findings: List[Finding] = []
    check_status: List[Tuple[str, str, int, float]] = []

    print(f"{CYAN}[BOOT]{RESET} starting {len(CHECKS)} read-only check(s)...")
    print()

    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_CHECKS) as ex:
        future_to_check = {
            ex.submit(_safe_run, fn): (cid, title)
            for cid, title, fn in CHECKS
        }
        done = 0
        total = len(future_to_check)
        for fut in concurrent.futures.as_completed(
                future_to_check, timeout=TOTAL_TIMEOUT_SEC):
            cid, title = future_to_check[fut]
            try:
                findings, elapsed = fut.result()
            except Exception:
                findings, elapsed = ([], 0)
            done += 1
            progress("AUDIT", done, total, title)
            check_status.append((cid, title, len(findings), elapsed))
            all_findings.extend(findings)

    return {
        "findings": all_findings,
        "check_status": check_status,
        "elapsed_sec": time.time() - t0,
    }


# ═════════════════════════════════════════════════════════════════════
# SCORING
# ═════════════════════════════════════════════════════════════════════

def score_grade(findings: List[Finding]) -> Tuple[int, str]:
    total = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    if total == 0:
        return (0, "A+")
    elif total <= 3:
        return (total, "A")
    elif total <= 8:
        return (total, "B")
    elif total <= 16:
        return (total, "C")
    elif total <= 30:
        return (total, "D")
    else:
        return (total, "F")


# ═════════════════════════════════════════════════════════════════════
# AI SUMMARY
# ═════════════════════════════════════════════════════════════════════

def write_ai_summary(bundle: Dict[str, Any]) -> Optional[str]:
    if not GROQ_AVAILABLE:
        return None
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None
    findings = bundle["findings"]
    if not findings:
        return None

    lines = ["FACTUAL AUDIT FINDINGS (every item below was observed via "
             "read-only system commands):"]
    for f in findings[:30]:
        lines.append(f"- [{f.severity}] {f.check_id} {f.title}: {f.evidence}")
    score, grade = score_grade(findings)
    lines.append(f"\nOverall: score={score} grade={grade}")

    prompt = (
        "You are Ares, a defensive security analyst.  Below are findings "
        "from a read-only audit.  Write a 4-6 sentence executive summary.  "
        "STRICTLY factual — do not invent details.  Prioritise highest-"
        "severity items first.  End with one concrete recommendation.  "
        "Plain prose, no headings.\n\n" + "\n".join(lines)
    )
    try:
        client = Groq(api_key=api_key)
        for model in GROQ_MODELS:
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=400,
                    temperature=0.3,
                )
                text = resp.choices[0].message.content
                if text and text.strip():
                    return text.strip()
            except Exception:
                continue
    except Exception:
        return None
    return None


# ═════════════════════════════════════════════════════════════════════
# REPORT
# ═════════════════════════════════════════════════════════════════════

SEVERITY_COLORS = {
    "critical": "\033[41m\033[97m",
    "high":     RED,
    "medium":   YELLOW,
    "low":      CYAN,
    "info":     DIM,
}
SEVERITY_ICONS = {
    "critical": "🔥",
    "high":     "⚠ ",
    "medium":   "● ",
    "low":      "· ",
    "info":     "i ",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _wrap(text: str, width: int = 80) -> List[str]:
    words = text.split()
    lines: List[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            if cur:
                lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w) if cur else w
    if cur:
        lines.append(cur)
    return lines


def render_report(bundle: Dict[str, Any]) -> None:
    findings = bundle["findings"]
    check_status = bundle["check_status"]
    elapsed = bundle["elapsed_sec"]
    score, grade = score_grade(findings)

    W = 70
    bar = "═" * W
    thin = "─" * W

    print()
    print(f"{RED}╔{bar}╗{RESET}")
    title = f"  ARES v{VERSION}  ·  SYSTEM SECURITY AUDIT REPORT"
    print(f"{RED}║{RESET}{BOLD}{WHITE}{title}{' ' * (W - len(title))}{RESET}{RED}║{RESET}")
    print(f"{RED}╚{bar}╝{RESET}")
    print()

    pill_bg = "\033[42m\033[97m" if grade in ("A+", "A", "B") else (
              "\033[43m\033[30m" if grade in ("C", "D") else "\033[41m\033[97m")
    print(f"  {pill_bg}{BOLD}  SECURITY GRADE: {grade}  (score: {score})  {RESET}")
    print()

    hostname = os.uname().nodename
    print(f"  {WHITE}Host:{RESET}       {CYAN}{hostname}{RESET}")
    print(f"  {WHITE}Kernel:{RESET}     {os.uname().release}")
    print(f"  {WHITE}Time:{RESET}       {int(elapsed)}s")
    print(f"  {WHITE}Checks:{RESET}     {len(check_status)} run, "
          f"{sum(1 for _,_,c,_ in check_status if c > 0)} produced findings")
    print()

    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity] += 1
    sev_line = "  "
    for sev in SEVERITY_ORDER:
        n = by_sev[sev]
        if n > 0:
            sev_line += f"{SEVERITY_COLORS[sev]}{BOLD} {n} {sev} {RESET}  "
    if sev_line.strip():
        print(sev_line)
        print()

    for sev in SEVERITY_ORDER:
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        c = SEVERITY_COLORS[sev]
        icon = SEVERITY_ICONS[sev]
        print(f"{c}{BOLD}  ── {icon}{sev.upper()} ({len(sev_findings)}) ──{RESET}")
        print()
        for f in sev_findings:
            print(f"    {c}{f.check_id:12s}{RESET}  {WHITE}{f.title}{RESET}")
            if f.evidence:
                ev = re.sub(r'\s+', ' ', f.evidence).strip()
                if len(ev) > 90:
                    ev = ev[:87] + "..."
                print(f"       {DIM}what:{RESET}   {ev}")
            if f.fix_hint:
                fix = f.fix_hint
                if len(fix) > 80:
                    for line in _wrap(fix, 80):
                        print(f"       {DIM}fix:{RESET}    {line}")
                else:
                    print(f"       {DIM}fix:{RESET}    {fix}")
            if f.raw:
                raw_lines = f.raw.strip().splitlines()[:6]
                for rl in raw_lines:
                    rl = rl.rstrip()
                    if len(rl) > 80:
                        rl = rl[:77] + "..."
                    print(f"       {DIM}│  {rl}{RESET}")
                if len(f.raw.strip().splitlines()) > 6:
                    extra = len(f.raw.strip().splitlines()) - 6
                    print(f"       {DIM}│  ... +{extra} more line(s){RESET}")
            print()

    if bundle.get("ai_summary"):
        print(f"{MAGENTA}{BOLD}  ── AI SYNTHESIS ──{RESET}")
        print()
        for line in _wrap(bundle["ai_summary"], 80):
            print(f"    {line}")
        print()

    if any(c == 0 for _, _, c, _ in check_status):
        print(f"{DIM}  ── Checks that reported nothing ──{RESET}")
        print()
        clean = [(cid, title) for cid, title, c, _ in check_status if c == 0]
        for cid, title in clean:
            print(f"    {GREEN}✓{RESET}  {DIM}{cid:12s}{RESET}  {title}")
        print()

    print(f"{RED}  {thin}{RESET}")
    print(f"{RED}  Read-only audit.  No changes were made to your system.{RESET}")
    print(f"{RED}  RAM-only — copy what you need before exiting.{RESET}")
    print(f"{RED}  {thin}{RESET}")
    print()
    print(f"  {DIM}(Generated by Ares v{VERSION} at "
          f"{datetime.datetime.now().isoformat(timespec='seconds')}){RESET}")
    print()


# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════

def main():
    banner()

    def _timeout(signum, frame):
        print()
        print(f"{YELLOW}   ⚠ hit {TOTAL_TIMEOUT_SEC}s timeout — wrapping up{RESET}")
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(TOTAL_TIMEOUT_SEC)

    try:
        bundle = run_audit()
    except KeyboardInterrupt:
        print()
        print(f"{YELLOW}   ⚠ interrupted — generating partial report{RESET}")
        bundle = {"findings": [], "check_status": [], "elapsed_sec": 0}
    finally:
        signal.alarm(0)

    bundle["ai_summary"] = write_ai_summary(bundle)
    render_report(bundle)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)
