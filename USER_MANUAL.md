# Ares — User Manual

**v1.0** · Bare-metal Kali NetHunter · Commander: The Priest

This is the operator's manual. It assumes you've already installed
Ares (`./install.sh`) and have `GROQ_API_KEY` set. If you haven't,
read README.md first.

---

## 1. The mental model

Ares behaves like a senior defender at a console. It picks one
specialist agent at a time, runs one command at a time, and asks you
`y/n/q` before every command. You stay in the loop on every action.

The state that drives Ares is the **Defense Task Tree (DTT)**. Each
node is a step in the investigation. Each node has a phase (triage,
hunt, ir, hardening, malware, forensics, identity, network_defense,
report) and the phase determines which specialist agent runs.

Findings are extracted from the **raw subprocess output**. The AI's
own text never enters the case file. Every finding records the exact
shell command that produced it, gets tagged with a MITRE ATT&CK
technique ID where relevant, and is added to the threat graph if it
fits a node type (host / service / IOC / vuln / account).

---

## 2. The voices

When Ares prints to the terminal, the prefix tells you who's
speaking:

| Voice | Symbol | Who |
|-------|--------|-----|
| `⚔ priest` | magenta | You — the operator |
| `◈ ARES` | blue | The framework itself (boot, errors, reports) |
| `🚨 TRIAGE` (and other agents) | per-agent colour | The current AI specialist |
| `▌` | grey | A shell command about to run |
| `✓ / ⚠ / ✕` | green / yellow / red | Success / warn / error |

The persistent status bar above each prompt shows: **target · agent ·
model · ✓verified/?unverified findings · ATT&CK techniques · scope**.

---

## 3. First run

```
$ ares
```

You'll see the banner, the boot sequence, then a prompt asking for the
host under investigation:

```
   IP / CIDR range : 192.168.1.10
   Hostname        : web-prod-01
   Mission notes   : suspicious outbound traffic flagged by NIDS
```

Press Enter on any field to skip it. If you skip everything, Ares
defaults to localhost.

After that, type any objective in plain English (`hunt for persistence
on this box`) or one of the built-in commands (`workflow`, `findings`,
`tree`, etc.).

---

## 4. Commands cheat sheet

| Command | What it does |
|---------|--------------|
| `workflow` | Open the menu of 23 pre-built engagement templates |
| `target` | Reset or update the host under investigation |
| `findings` | Show all extracted findings, verified + unverified |
| `tree` | Render the Defense Task Tree (DTT) |
| `graph` | Show the threat graph state + pivot suggestions |
| `scope` | Show / toggle engagement scope (RoE) |
| `mitre` | Show ATT&CK techniques surfaced this session |
| `tools` | Tool availability + offer to auto-install missing |
| `model` | Show the Groq provider chain status |
| `agent` | List all specialist agents |
| `dashboard` | Concise session status panel |
| `save` | Save the full conversation to a text file |
| `report` | Generate the engagement report now |
| `clear` | Clear AI memory (DTT and findings preserved) |
| `reset` | Wipe everything (DTT, findings, history, sudo cache) |
| `help` | Show the help menu |
| `exit` / `q` | End the session and generate the report |

---

## 5. The 23 workflows

Type `workflow` and pick a number, or just type the workflow's name in
plain English and Ares will route to it.

| # | Name | One-line summary |
|---|------|------------------|
| 1 | Triage / Health Check | Identity → sockets → processes → recent /etc → auth bursts |
| 2 | Live IR — Suspected Compromise | Containment-first IR: triage → hunt → contain → eradicate |
| 3 | Hardening Audit | Lynis quick → deep dives on warnings → CIS gaps |
| 4 | Linux Persistence Hunt | Cron → systemd → init → SSH keys → ld.preload → modules |
| 5 | Process / Network Anomaly Hunt | Listening ports → PID → exe → outbound conn → IOC |
| 6 | Authentication Failure Analysis | auth.log brute detection → fail2ban verify → spray vs distributed |
| 7 | Malware Static Triage | file → hash → strings → capa → yara → IOC pivot |
| 8 | PCAP Analysis | Top talkers → DNS → TLS SNI → HTTP → Suricata replay |
| 9 | Memory Forensics | Banner ID → pstree → malfind → netscan → IOC pivot |
| 10 | Disk Forensics | Image hash → mmls → fls → mactime timeline → carve |
| 11 | Log Review | Time-windowed sweep across journal/auth/audit |
| 12 | TLS / SSL Audit | sslscan + testssl + ssh-audit on own services |
| 13 | Account Audit | passwd/shadow → sudoers → SSH keys → stale accounts |
| 14 | SUID / Capability Audit | find SUID/SGID → getcap -r → diff vs baseline |
| 15 | Service Exposure Audit | ss listening → vs expected → firewall match |
| 16 | Linux Post-Compromise IR | Containment chain after confirmed breach |
| 17 | Container / Cloud Audit | docker ps → privileged containers → trivy → kube-bench |
| 18 | File Integrity Check | AIDE check → debsums → diff /etc |
| 19 | Suricata / Zeek Alert Review | fast.log triage → pivot to host → IOC enrichment |
| 20 | IDS Rule Tuning | Test pcap → rule diff → false-positive review |
| 21 | Firewall Audit | Ruleset review → orphan rules → log-and-drop coverage |
| 22 | Forensics Evidence Collection | Hash → image → preserve → chain of custody |
| 23 | Rootkit Hunt | rkhunter + chkrootkit + lynis + hidden-pid sweep |

---

## 6. The y/n/q gate

Every command is presented in a boxed panel that shows:

- The shell command itself
- The MITRE ATT&CK technique it fires (if any)
- The confidence pill (GREEN ▶ EXECUTE / YELLOW · CAUTION / RED ✕ HOLD)

Then you get the prompt:

```
   [y] run    [n] skip    [q] quit  ›
```

- `y` runs it.
- `n` skips it. Ares records the skip and moves on.
- `q` ends the session and generates the report.

For containment-style actions (kill, block, quarantine, account lock,
firewall flush, audit-rule mutation), Ares throws a second confirm
gate after the first `y`:

```
   ⚠  This modifies system state. Confirm again.
   Really execute? [y/n]:
```

---

## 7. Sudo

Ares is read-only by default. Most defensive tooling needs sudo
(volatility on `/proc/kcore`, tcpdump, lynis, oscap, etc.). When a
command fails with a permission marker, Ares offers a one-tap retry:

```
   ◈ ARES — that command failed with a permission error.
   Retry with sudo? [y/n]:
```

The first time you say `y`, Ares prompts for your sudo password via
`getpass` (no echo). The password is cached **in RAM only** for the
session — never written to disk — and fed to subsequent commands via
`sudo -S` from stdin. On `reset` or `exit`, the cache is wiped.

If you skip the sudo prompt (Enter on empty), Ares records the skip
for the rest of the session and stops asking. Restart Ares to be
prompted again.

---

## 8. Scope / RoE enforcement

Open `~/.ares/scope.json`:

```json
{
  "enabled": false,
  "allowed_cidrs":   ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "blocked_cidrs":   [],
  "allowed_domains": [],
  "blocked_domains": [],
  "time_window": { "start": "", "end": "" }
}
```

Set `"enabled": true` and Ares refuses any command whose target falls
outside the allow-lists or inside the block-lists. Time window is
local TZ. Wildcards (`*.example.com`) work in domains. Out-of-scope
attempts are logged with the reason and surfaced as a red `⛔ ERROR`
panel.

This is the same scope enforcement Athena uses, but for defenders the
typical mistake is the opposite — accidentally auditing a system you
don't own. Scope catches it.

---

## 9. The smart context manager

By default, every turn ships a **minimal** system prompt:

- Active DTT node only (not the whole tree)
- Verified findings only (no unverified flood)
- Last 4 turns of history (not all 32)
- Role-filtered KB sections
- Compact tool registry

When the AI needs more, it emits `[NEED]target[/NEED]` and Ares
re-fetches with that target attached. Targets:

- `[NEED]ptt[/NEED]` — full Defense Task Tree
- `[NEED]history[/NEED]` — all 32 turns of history
- `[NEED]findings[/NEED]` — verified + unverified findings
- `[NEED]graph[/NEED]` — threat-graph compact text + pivots
- `[NEED]kb 7[/NEED]` — specific KB section by number

Auto-expansion triggers (no `[NEED]` required):
- Confidence in {yellow, red} → expanded slice + DTT + graph
- Stuck counter > 0 → expanded slice
- New node entered → DTT summary attached

The estimate of tokens saved is shown in the final report. Typical
saving is 30–50% on a multi-turn session.

---

## 10. The MITRE ATT&CK detection layer

Every command Ares runs is checked against 33 detection-side regex
patterns. When one matches, the command is tagged with the technique
ID + name + tactic, surfaced in the boxed command card, and counted
against the session-wide technique tally. Type `mitre` to see the
list.

This isn't the same as Athena's offensive tagging — Athena fires
T1046 when she runs `nmap`. Ares fires T1046 when its `ss -tlnp`
audit reveals exposed services. Same TTP ID, opposite side of the
fence. The pairing is intentional: a paired Athena/Ares engagement
produces a session log where the same techniques appear from both
directions.

---

## 11. The IOC fanout queue

When a finding lands that's a viable IOC — a hash, a YARA hit, an
AV hit, a Suricata alert, a persistence artifact, a suspicious
process, an IP / domain / URL surfaced as suspicious — Ares
automatically queues an "IOC sweep" subnode under the current DTT
node. The threat hunter agent picks it up and propagates the
indicator across:

- Other log sources (journalctl, auth.log, audit.log)
- Other pcaps already loaded
- Other hosts in the threat graph

This is the defensive equivalent of Athena's credential fanout. Same
queue mechanism, opposite intent: instead of testing a credential
against every authenticable service, you're hunting for an indicator
across every monitored surface.

---

## 12. Stuck-handler

Same shell command twice in 5 turns → forced agent rotation + RED
confidence override.

Three repeats → Ares calls the **stuck-handler**: it asks the AI for
3 alternative angles (e.g. "log review vs persistence hunt vs network
capture"), prints them numbered, and lets you pick `1/2/3` or type
your own objective. The current node is marked dead-end so you don't
loop back into it.

This is the same loop-breaker as Athena, retuned for defensive
pivots.

---

## 13. Reports

`exit` or `q` (or just `report` mid-session) generates a markdown
report at `~/.ares/logs/report_YYYYMMDD_HHMMSS.md`. The report has:

- Header (host, mission, commander, duration, scope state)
- LLM-generated executive summary (verdict: healthy / suspicious /
  compromised)
- Confirmed findings, grouped by ATT&CK technique
- Timeline (chronological)
- Containment actions taken
- Remaining risks
- Recommended hardening
- ATT&CK techniques surfaced
- Defense Task Tree final state
- Threat graph summary
- Raw findings with provenance (every finding shows its source command
  and the ATT&CK tag)
- Appendix: tooling & methodology

The session log (`session_YYYYMMDD_HHMMSS.txt`) is separate and
contains every command and its output verbatim, with ANSI codes
stripped.

---

## 14. Pairing with Athena

The intended workflow:

1. **Athena** against a target you own. Records what worked.
2. **Ares** against the same target's defender posture, focused on the
   workflows that match Athena's findings.
3. The diff is your hardening backlog.

Practical examples:

- Athena finds an SUID `/usr/bin/find` exploitable via GTFOBins
  → Ares' SUID/Capability Audit (workflow 14) verifies it's still
  there, then proposes removal as a containment action.
- Athena gets in via an outbound web shell on `/var/www/html/up.php`
  → Ares' Linux Persistence Hunt (workflow 4) hunts for the shell,
  then Live IR (workflow 2) quarantines it.
- Athena cracks a kerberoasted hash
  → Ares' Account Audit (workflow 13) flags the service account
  with weak password policy, then Identity Defender proposes
  rotation + tighter SPN policy.

Both run on the same Groq key, the same Kali NetHunter rig, the
same UI conventions. They don't share state — Ares' findings live in
`~/.ares/`, Athena's in `~/.athena/`. You correlate them yourself.

---

## 15. Troubleshooting

**Ares can't find `volatility` / `yara` / `lynis` / `chainsaw`.**

Run `tools` in the REPL — Ares lists every dispatchable tool and its
availability. Where possible it offers an install hint or alternative.
For non-apt tools (volatility3 via pipx, chainsaw / hayabusa from
GitHub releases), the hint is shown when the tool is first requested.

**"GROQ_API_KEY not set" on launch.**

Add it to your shell rc:
```
export GROQ_API_KEY='your_key_here'
```
Then `source ~/.bashrc` (or `~/.zshrc`) and re-run `ares`. Or re-run
`./install.sh` and it'll re-prompt.

**A command hangs.**

Per-command timeouts kill anything that runs longer than its
ceiling. Ctrl+C aborts a single command without killing the session.
Defaults: volatility/yara/clamscan 1800s, journalctl/tcpdump 60–120s,
ps/ss/lsof 30s. The active timeout is shown when a command starts.

**The AI loops.**

Same command twice → loop breaker fires. Three times → stuck-handler
proposes 3 alternatives. If the AI is generally confused, type
`reset` to wipe history + DTT and start over. Type `clear` to wipe
just AI memory while keeping the DTT and findings.

**networkx warning at boot.**

Threat graph is disabled but Ares still works. Install it:
```
pip install networkx --break-system-packages
```

---

## 16. Defender's discipline (philosophy)

A few lines from KB section 1 worth pinning to the wall:

> Assume breach. Hunt for the attacker, don't wait for the alarm.
> Every investigation has three parallel tracks: WHAT happened
> (timeline), WHERE it happened (scope), and WHO did it (attribution
> — usually last, sometimes never). Cheap, broad checks first;
> expensive, narrow checks last. ps/ss/journalctl before volatility.
> grep/awk before chainsaw. Read the log, don't query the SIEM. When
> you find one IOC, fanout across every other host you defend. A
> finding is only verified once its source command and timestamp are
> recorded — no AI hallucinations enter the case file.
> Pre-compromise: harden, monitor, drill. Post-compromise: contain,
> eradicate, recover, learn.
