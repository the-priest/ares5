# Ares — Read-only System Security Audit

```
 █████╗ ██████╗ ███████╗███████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝
███████║██████╔╝█████╗  ███████╗   🛡️
██╔══██║██╔══██╗██╔══╝  ╚════██║
██║  ██║██║  ██║███████╗███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
```

**Fast read-only system audit.** Run it on any Linux host — Ares
inspects the system, reports what's wrong, grades the overall
security posture, and tells you exactly how to fix each issue.

**Ares never modifies anything.** No installs. No service restarts.
No firewall changes. No file edits. No sudo. It only looks.

Single file. ~1100 lines. Runs in 30-60 seconds. Designed for
bare-metal Kali NetHunter (sdm845 / OnePlus 6 / Phosh) but works on
any Linux with Python 3.10+.

Built by **The Priest** as the second pillar of a Greek-pantheon stack:

| Tool | Role | Repo |
|------|------|------|
| Athena | offensive recon agent | [athena5](https://github.com/the-priest/athena5) |
| **Ares** | **defensive system audit** | **(this repo)** |
| Zeus | legal OSINT aggregator | [zeus5](https://github.com/the-priest/zeus5) |

---

## What it checks

```
boot → 18 parallel checks → score → graded report
```

| Check | What it looks at |
|-------|------------------|
| **FW** | ufw / iptables / nftables — is a firewall active? |
| **NET** | `ss -tlnpu` — public vs localhost listeners |
| **SSH** | `/etc/ssh/sshd_config` — root login, password auth, X11, etc. |
| **AUTH-A** | `journalctl _COMM=sudo` — failed sudo in last 24h |
| **AUTH-B** | `journalctl _COMM=sshd` — failed SSH logins in last 24h |
| **AUTH-C** | `last -n 10 -F` — recent successful logins |
| **PATCH-A** | `systemctl is-enabled unattended-upgrades` |
| **PATCH-B** | `apt list --upgradable` — pending security updates |
| **PRIV** | SUID files outside `/usr/bin /usr/sbin /bin /sbin` |
| **PERM** | World-writable files in `$HOME` |
| **MAC** | AppArmor (`aa-status`) or SELinux (`getenforce`) status |
| **CRYPTO** | `lsblk -f` — is `/` on a LUKS volume? |
| **CRON** | `crontab -l` + `/etc/cron.*` + `systemctl list-timers` |
| **PROC** | Network services running as root |
| **KERN** | Running kernel vs newest installed |
| **HIST** | Shell history files (empty = possibly wiped) |
| **RKHUNT** | `/var/log/rkhunter.log` warnings if rkhunter is installed |
| **DNS** | `/etc/resolv.conf` — non-standard DNS servers |

Every check runs **as your normal user**. No sudo, no privilege
escalation. If a check needs root and you're not root, it's skipped
silently.

---

## Severity model

Each finding is rated:

| Severity | Score | Examples |
|----------|-------|----------|
| `critical` | 20 | `PermitEmptyPasswords yes`, SSH protocol 1 |
| `high` | 8 | No firewall, `PermitRootLogin yes`, 100+ failed SSH attempts |
| `medium` | 3 | Password auth on SSH, no MAC, pending security updates |
| `low` | 1 | World-writable files in home, X11Forwarding on |
| `info` | 0 | Confirmation that something is set up correctly |

The overall **grade** comes from the sum of all severity scores:

| Total score | Grade |
|-------------|-------|
| 0 | A+ |
| 1-3 | A |
| 4-8 | B |
| 9-16 | C |
| 17-30 | D |
| 31+ | F |

---

## What it deliberately doesn't do

- **No system modification.** Ares only reads.
- **No sudo.** If it can't access something as your user, the
  check is skipped — never escalated.
- **No `shell=True`.** All commands run via Python arg-lists, so
  there's no command-injection surface even if a path or hostname
  contains weird characters.
- **No AI-driven commands.** The previous version (v1.0) had a
  50-turn agent loop that let an LLM propose shell commands. That's
  gone. The 18 checks are hardcoded.
- **No incident response.** Ares tells you what's wrong; it doesn't
  fight back. If you want to ban an IP, change a config, kill a
  process — you do it yourself with the fix hint provided.
- **No disk persistence.** Findings live in RAM. No report files,
  no logs, no `~/.ares` directory. Copy what you need before
  exiting.

---

## Installation

```bash
git clone https://github.com/the-priest/ares5.git
cd ares5
./install.sh
```

The installer is minimal — it only:
- Checks Python 3.10+ is available
- Installs `groq>=0.4.0` (optional, for the AI summary)
- Makes `ares.py` executable
- Symlinks `~/.local/bin/ares` → `ares.py`

It does NOT install any system packages, change any system
configuration, or require sudo.

### Manual install

```bash
pip install groq --break-system-packages
chmod +x ares.py
mkdir -p ~/.local/bin
ln -sf "$PWD/ares.py" ~/.local/bin/ares

# Optional: AI summary paragraph
export GROQ_API_KEY=gsk_...
echo 'export GROQ_API_KEY=gsk_...' >> ~/.bashrc
```

---

## Usage

```bash
ares
```

That's it. No flags, no subcommands, no config file. Ares boots,
runs 18 checks in parallel, and prints a graded report.

### Example output

```
╔══════════════════════════════════════════════════════════════════════╗
║  ARES v5.0  ·  SYSTEM SECURITY AUDIT REPORT                          ║
╚══════════════════════════════════════════════════════════════════════╝

    SECURITY GRADE: C  (score: 14)

  Host:       velvet-tunder
  Kernel:     6.6.58-sdm845-nh
  Time:       5s
  Checks:     18 run, 5 produced findings

   1 high    2 medium    2 info

  ── ⚠ HIGH (1) ──

    FW-006        No firewall detected
       what:   ufw / iptables / nft all report no active rules
       fix:    sudo apt install ufw && sudo ufw default deny incoming
       fix:    && sudo ufw allow ssh && sudo ufw enable

  ── ● MEDIUM (2) ──

    MAC-005       No MAC framework active
       what:   no apparmor / selinux mandatory access control detected
       fix:    Kali ships with apparmor — check it's enabled.

    PATCH-002     Automatic security updates not configured
       what:   unattended-upgrades not installed
       fix:    sudo apt install unattended-upgrades

  ── Checks that reported nothing ──

    ✓  SSH           SSH server config
    ✓  NET           Listening ports
    ✓  PERM          Home dir permissions
    ✓  AUTH-B        Failed SSH logins
    ...

  Read-only audit.  No changes were made to your system.
```

---

## Configuration

All controlled by constants at the top of `ares.py`:

| Constant | Default | What it does |
|----------|---------|--------------|
| `TOTAL_TIMEOUT_SEC` | `120` | hard wall-clock cap |
| `PER_CHECK_TIMEOUT` | `15` | one check's subprocess timeout |
| `PARALLEL_CHECKS` | `6` | concurrent check threads |

Edit them in-place if you need longer timeouts (slow disks, big
SUID scans) or want more parallelism.

---

## Why a rewrite?

The old Ares v1.0 was 6,725 lines. It had:
- A 50-turn AI agent loop that proposed shell commands
- `subprocess.run(..., shell=True)` execution of those commands
- `install_if_missing()` running `sudo apt install -y <toolname>`
  without confirmation
- A multi-specialist routing system with 11 agents
- DESTRUCTIVE_COMMANDS and DOUBLE_CONFIRM lists that depended on
  the AI's restraint to stay safe

It worked, but the safety model was "trust the AI". That's fragile.

v5.0 has zero AI-driven commands. The 18 checks are pure Python
calling specific read-only system commands via arg-lists. The AI
is only used **once at the end** to write a short summary paragraph
from the verified findings. If Groq is down, that paragraph is
skipped and the report still works.

**86% code reduction.** Same defensive value. Zero risk of the AI
deciding to "helpfully" run something it shouldn't.

---

## Tested on

- Kali Linux Rolling (aarch64) on OnePlus 6, NetHunter,
  kernel `6.6.58-sdm845-nh`, Phosh UI
- Linux Mint Cinnamon (x86_64), Dell Latitude E5540
- ThinkPad X395 dedicated Kali SSD
- Ubuntu 24.04 LTS container

---

## API keys

- **Groq** — `GROQ_API_KEY`, free tier. Used **only** for the
  optional AI summary paragraph at the end. Ares works fine
  without it.

That's the only optional integration. Everything else is local.

---

## License

MIT — see `LICENSE`.

---

## Acknowledgements

Inspired by Lynis, CIS benchmarks, and Phil Hagen's SOF-ELK
defaults. None of those projects endorse this tool. The
specific check selection, parallelism, scoring model, and
reporting layer are mine.
