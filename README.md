# Ares — AI Defensive Security Agent

**v1.0** · Bare-metal Kali NetHunter · Commander: The Priest

Ares is the symmetric defensive counterpart to **Athena**. Same skeleton,
opposite mission. You give it a host and an objective, it picks the
right specialist agent, picks the right tool, and runs commands one at
a time through a `y/n` confirmation gate. Read-only by default;
containment actions (kill, block, quarantine, account lock) hit a
double-confirm gate. Every finding is regex-extracted from real
subprocess output (no AI hallucinations), tagged with MITRE ATT&CK from
the detection side, and tracked in a Defense Task Tree (DTT) plus a
networkx-backed threat graph.

Where Athena attacks, Ares watches, detects, investigates, and
remediates. Run them side-by-side: Athena finds the path in, Ares
verifies you've closed the same path against yourself.

---

## What Ares does

Ares is a defender's copilot built for the same rig as Athena and
sharing the same Groq API key. The architecture is identical — single
file, deterministic dispatch, structured tool builders, MITRE auto-tag,
smart context manager, scope enforcement, attack/threat graph. The
contents are different: defensive KB, defensive tools, defensive
workflows, defender persona.

### Specialist agents (10 + strategist)

- **♛ Strategist** — routes the DTT, picks which agent runs next.
- **🚨 Triage** — first-30-minutes host health check; verdict: healthy / suspicious / compromised.
- **📜 Log Analyst** — journalctl, /var/log, auditd, web access logs.
- **🩻 Threat Hunter** — cron, systemd, ld.preload, web shells, kernel modules, PAM tampering, WMI subscriptions.
- **🌐 Network Defender** — Suricata, Zeek, tshark, tcpdump, firewall.
- **🛟 Incident Responder** — containment + eradication + recovery; evidence-first, double-confirm gates.
- **🛡 Hardening Auditor** — Lynis, OpenSCAP, sysctl, PAM, SSH, file perms vs CIS/STIG.
- **🧬 Malware Analyst** — static-only triage: file, strings, exiftool, capa, yara, clamav.
- **🔬 Forensics Analyst** — volatility3, sleuthkit, foremost; chain-of-custody preserved.
- **🪪 Identity Defender** — passwd/shadow, sudoers, SSH keys, Kerberos, SSSD, AD audit.
- **📋 Reporter** — consolidates findings, maps to ATT&CK, drops unverified noise.

### Workflows (23 pre-built engagement templates)

Triage / Health Check · Live IR — Suspected Compromise · Hardening
Audit · Linux Persistence Hunt · Process / Network Anomaly Hunt · Auth
Failure Analysis · Malware Static Triage · PCAP Analysis · Memory
Forensics · Disk Forensics · Log Review · TLS / SSL Audit · Account
Audit · SUID / Capability Audit · Service Exposure Audit · Linux
Post-Compromise IR · Container / Cloud Audit · File Integrity Check ·
Suricata / Zeek Alert Review · IDS Rule Tuning · Firewall Audit ·
Forensics Evidence Collection · Rootkit Hunt.

### Structured tool registry (51 builders)

`ps_tree` · `ss_listening` · `ss_established` · `lsof_net` ·
`journalctl` · `auth_log_grep` · `auditd_search` · `aureport_summary` ·
`find_recent_files` · `find_suid` · `find_caps` · `find_world_writable`
· `cron_sweep` · `systemd_enabled` · `systemd_recent_units` ·
`aide_check` · `debsums_check` · `file_hash` · `lynis_audit` ·
`rkhunter_scan` · `chkrootkit_scan` · `openscap_scan` ·
`tcpdump_capture` · `tshark_read` · `suricata_replay` · `zeek_offline`
· `fail2ban_status` · `firewall_show` · `yara_scan` · `clamscan` ·
`file_strings` · `file_inspect` · `capa_run` · `volatility_run` ·
`sleuthkit_fls` · `mactime_render` · `foremost_carve` · `curl_basic` ·
`virustotal_hash` · `abuseipdb_check` · `crt_sh_lookup` ·
`shadow_audit` · `sudoers_audit` · `authorized_keys_sweep` · `sslscan`
· `testssl` · `ssh_audit` · `chainsaw_hunt` · `hayabusa_timeline` ·
`dig_lookup` · `whois_lookup`.

### Carried over from Athena's architecture (unchanged where it matters)

- Defense Task Tree (DTT) — same `PTT` class internally, but the goal,
  finding types, phases, and natural-language serialisation are
  defender-flavoured.
- Threat graph (networkx) — host / service / IOC / vuln / account
  nodes, with pivot suggestions surfaced to the LLM on demand.
- 33 MITRE ATT&CK detection mappings — same TTP IDs as Athena's
  attack-side mappings, but tagged when defensive tooling fires.
- Smart context manager with `[NEED]ptt|history|graph|kb N[/NEED]`
  re-fetch protocol — saves tokens on quiet turns, expands
  automatically on yellow/red confidence or stuck loops.
- IOC fanout queue — when a hash / suspicious IP / YARA hit / persistence
  artifact lands, the threat hunter automatically gets a sweep node
  added so the indicator gets propagated across all relevant sources.
- Source-tagged finding extraction — every finding records the exact
  shell command that produced it.  No AI hallucinations enter the
  case file.
- Groq provider chain — biggest → smallest, same as Athena.
- Per-command timeouts — volatility/yara/clamscan get 1800s, journalctl
  60s, ps/ss/lsof 30s.  No hung sessions.
- Boot lock auto-expires after 6h.
- Scope / RoE enforcement via `~/.ares/scope.json`.
- y/n/q gate on every command. Double-confirm gate on containment-style
  actions: kill -9, killall, pkill, fail2ban-client unban/stop, nft
  flush, ufw disable/reset, iptables -F, usermod -L, passwd -l,
  userdel, chattr +i, auditctl -D, suricatasc.
- Loop breaker — same shell command twice → forced agent rotation +
  RED conf override.  Three repeats → handle_stuck.
- No on-disk persistence except `~/.ares/scope.json`, `~/.ares/logs/`,
  and reports.

---

## Install

Tested on Kali Linux NetHunter (sdm845, Phosh).  Should work on any
Debian / Ubuntu / Arch system with python ≥ 3.10.

```bash
git clone https://github.com/the-priest/ares.git
cd ares
chmod +x install.sh
./install.sh
```

The installer:

1. Detects your login shell, picks the right rc file.
2. Verifies Python 3.10+.
3. Installs `groq` and `networkx` (with `--break-system-packages` on
   PEP 668 systems).
4. Creates `~/.ares/logs/`.
5. Symlinks `/usr/local/bin/ares` → `ares.py` (or falls back to a
   shell alias if you don't have sudo).
6. Picks up `GROQ_API_KEY` from your environment if Athena already
   set it; otherwise prompts for it.

If the installer can't run for any reason, the manual route is:

```bash
pip install groq networkx --break-system-packages
export GROQ_API_KEY='your_key_here'
python3 ares.py
```

If you already run Athena, you don't need a new key — Ares uses the
same `GROQ_API_KEY`. The installer detects an existing `~/.athena`
directory and tells you the two are designed to run side-by-side.

---

## Usage

```
$ ares
```

You'll see the v1.0 banner, the boot sequence, then a prompt for the
host you're investigating.  After that, type any objective or one of
the built-in commands.

### Commands

| Command  | What it does |
|----------|--------------|
| `workflow` | Open the workflow menu (23 pre-built engagement templates) |
| `target`   | Set or update the host under investigation |
| `findings` | Show every extracted finding (verified + unverified) |
| `tree`     | Render the Defense Task Tree |
| `graph`    | Show the threat graph state + pivot suggestions |
| `scope`    | Show / toggle engagement scope (RoE) |
| `mitre`    | Show MITRE ATT&CK techniques surfaced this session |
| `tools`    | Tool availability + auto-install missing |
| `model`    | Show provider chain status |
| `agent`    | List all specialist agents |
| `dashboard` | Concise session status panel |
| `save`     | Save conversation to file |
| `report`   | Generate the engagement report now |
| `clear`    | Clear AI memory (DTT preserved) |
| `reset`    | Reset everything (DTT + findings + history + sudo cache) |
| `help`     | Show the help menu |
| `exit` / `q` | End session and generate report |

Or just type any objective in plain English — Ares routes to the
right specialist.

### Output format the AI uses

```
[THOUGHT]<reasoning>[/THOUGHT]
[TOOL]<tool_name>[/TOOL][ARGS]<json>[/ARGS]    # or [CMD]<shell>[/CMD]
[CONF]green|yellow|red[/CONF]
[VERIFY]<verify_command>[/VERIFY]              # optional
[HANDOFF]<other_agent>[/HANDOFF]               # optional
[NEED]ptt|history|findings|graph|kb N[/NEED]   # optional, re-fetch
```

---

## Files

```
ares.py                    # the whole agent, single file
~/.ares/scope.json         # engagement scope / RoE
~/.ares/logs/session_*.txt # per-session command + output log
~/.ares/logs/report_*.md   # markdown report at end of session
/tmp/ares_session.lock     # boot-check TTL marker (6h)
```

---

## Safety

Ares **refuses**:

- `apt upgrade` / `apt full-upgrade` / `apt dist-upgrade` and any
  variants (Phosh + UI packages stay stable on a NetHunter phone).
- Destructive commands (`rm -rf /`, `dd if=`, `mkfs`, fork bombs,
  `shutdown`, `chmod -R 777 /`, `chown -R … /`).
- Interactive shells that would hijack the terminal — vim, nano, less,
  top, htop, mysql REPL, ssh interactive, telnet, wireshark GUI, and
  loop wrappers like `tail -f`, `journalctl -f`, `watch`.  Each gets
  a non-interactive replacement hint.
- Out-of-scope hosts when scope enforcement is enabled.

Ares **double-confirms** containment-style actions:

- Process termination: `kill -9`, `killall`, `pkill`.
- Firewall mutation: `iptables -F`, `iptables -X`, `nft flush`,
  `nft delete`, `ufw disable`, `ufw reset`, `fail2ban-client unban`,
  `fail2ban-client stop`.
- Service control: `systemctl stop|disable|mask|kill`,
  `service NAME stop`.
- Account lockdown: `usermod -L`, `passwd -l`, `userdel`,
  `usermod -s /sbin/nologin`.
- File quarantine: `chmod +s`, `chattr +i`, write to `/etc/...`.
- Audit/IDS mutation: `auditctl -D`, `suricatasc`,
  `suricata-update --no-sources`.

Every other command goes through the `y/n/q` gate before execution.
Sudo is opt-in, prompted once per session via `getpass`, cached only in
RAM, and fed to commands via `sudo -S` from stdin.

**Ares never disables logging or audit during an active incident.**
This is enforced by the IR Responder agent's extra-rules and the
double-confirm gate.

---

## Pairing with Athena

Ares and Athena are designed to run side-by-side on the same host.

- **Same Groq key.** No new account needed.
- **Separate state directories.** `~/.ares/` and `~/.athena/` don't
  share anything — different scope files, different logs, different
  reports.
- **Separate boot locks.** `/tmp/ares_session.lock` vs
  `/tmp/athena_session.lock`.
- **Same MITRE ATT&CK technique IDs**, viewed from opposite directions.
  Athena fires them when running `nmap` or `hashcat`.  Ares fires them
  when its tooling surfaces evidence of the same technique.
- **Same UI conventions.** Same boxed turn output, same status bar,
  same `y/n/q` gate, same `[TOOL]/[ARGS]/[CMD]` format.

A typical paired engagement:

1. Athena runs against a target.  Records what worked.
2. Ares runs against the same target's defender posture.
3. The diff is your hardening backlog.

---

## License

MIT — see [LICENSE](LICENSE) for the full text plus a use-only-on-systems-you-own
disclaimer. Personal project by The Priest. Use at your own risk.
