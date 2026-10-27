## adExec

```
 █████╗ ██████╗ ███████╗██╗  ██╗███████╗ ██████╗
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝██╔════╝██╔════╝
███████║██║  ██║█████╗   ╚███╔╝ █████╗  ██║     
██╔══██║██║  ██║██╔══╝   ██╔██╗ ██╔══╝  ██║     
██║  ██║██████╔╝███████╗██╔╝ ██╗███████╗╚██████╗
╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝
```

AD recon orchestrator for HTB / pentest labs. Wraps the enumeration workflow
you'd otherwise run by hand into a single two-phase run, then drops you into a
**searchable web viewer** so you can actually read the output instead of
`cat`-ing twenty text files.

---

## What's new in v3

- **Step registry** — every command is a declarative step (`steps/*.py`) with
  its own tool requirement, run conditions, and output parser. Adding a new
  enumeration command is a few lines, not a new method buried in a phase class.
- **Deeper AD enumeration** — rpcclient / enum4linux-ng null sessions, domain
  users / groups / sessions / logged-on, password policy, GPP, Kerberoast &
  AS-REP (NetExec + impacket fallback), LDAP finds (PASSWD_NOTREQD, adminCount,
  MachineAccountQuota, LAPS, gMSA, delegation), ADCS (`certipy find`), MSSQL.
  All **read-only enumeration** — no exploitation, no credential dumping.
- **Web viewer** — results are written to `recon/<ip>/report.json` and served by
  a dependency-free local viewer that opens automatically: a severity-ranked
  findings dashboard, per-step command + parsed tables + raw output, and a
  global search box that highlights matches across every command's output.

---

## Installation

```bash
git clone https://github.com/47Com1c/adExec.git
cd adExec/
pip install -r requirements.txt     # only dependency is `rich`
```

## Dependencies

The orchestrator itself needs only Python 3.8+ and `rich`. The enumeration
steps call standard pentest tools — install whatever you have; **any missing
tool just skips its step** (shown as `no_tool` in the viewer).

```bash
# core (required for most steps)
sudo apt install nmap ldap-utils samba-common-bin   # nmap, ldapsearch, rpcclient
pipx install netexec                                 # nxc

# optional (each enables more steps)
sudo apt install enum4linux-ng
pipx install impacket certipy-ad bloodhound
# kerbrute — grab the binary from ropnop/kerbrute
```

> `nxc` is NetExec (the successor to CrackMapExec / `cme`).

---

## Usage

```bash
# Phase 1 — no creds
python adexec.py -t 10.10.10.10

# Full run with creds
python adexec.py -t 10.10.10.10 -u support -p '#00^BlackKnight'

# Pass-the-hash (SMB/NetExec steps; ldapsearch/BloodHound need user:pass)
python adexec.py -t 10.10.10.10 -u administrator --hash <NT_HASH>

# Phase 2 only
python adexec.py -t 10.10.10.10 --phase2-only -u support -p 'Pass'

# Re-open the viewer over existing results (no scanning)
python adexec.py --serve-only

# Run without launching the viewer
python adexec.py -t 10.10.10.10 --no-serve
```

When the run finishes, the viewer opens at `http://127.0.0.1:8777/`
(change with `--port`).

---

## Enumeration steps

### Phase 1 — unauthenticated
| Category | Steps |
|----------|-------|
| Nmap | full TCP port scan, service/version scan |
| SMB  | fingerprint (host/domain), null + guest shares, null user enum, null password policy |
| RPC  | `rpcclient` null session (dom info + users), `enum4linux-ng -A` |
| LDAP | anonymous RootDSE |

### Phase 2 — authenticated
| Category | Steps |
|----------|-------|
| SMB      | shares, domain users, RID brute, groups, password policy, logged-on users, sessions, GPP password search |
| LDAP     | users-with-descriptions, high-value group memberships, unconstrained/constrained delegation, domain SID, PASSWD_NOTREQD, adminCount, MachineAccountQuota, LAPS, gMSA |
| Kerberos | AS-REP roast (NetExec + impacket), Kerberoast (NetExec + impacket), kerbrute user validation |
| WinRM    | access check (if 5985/5986 open) |
| ADCS     | `certipy find -vulnerable` |
| MSSQL    | access check (if 1433 open) |
| BloodHound | full collection (`-c All`) |

Steps only run when their preconditions are met (port open, creds present,
domain known, tool installed) — the viewer records *why* anything was skipped.

---

## Output

```
recon/
└── 10.10.10.10/
    ├── report.json          ← the viewer reads this
    ├── nmap/tcpAllPorts, tcpScans
    ├── smb_*.txt, rpcclient_null.txt, enum4linux_ng.txt
    ├── ldap_*.txt
    ├── asrep_*.txt, kerberoast_*.txt, kerbrute.txt
    ├── certipy_find.txt, mssql_access.txt
    ├── users.txt
    └── bloodhound/*.zip
```

Every raw tool output is still saved to disk; `report.json` is the structured
index the web viewer renders.

---

## Adding a step

Steps are self-registering. Drop this into the relevant `steps/*.py`:

```python
register(Step(
    id="ldap_asreproast", name="NetExec LDAP — AS-REP roast",
    category="Kerberos", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(),
                         "--asreproast", "out"],
    parse=my_parser,          # (output, ctx) -> (findings, rows, columns)
    save_name="asrep.txt",
))
```

---

## Notes

- `ldapsearch` can't auth with an NTLM hash — LDAP steps fall back to
  user/pass only; BloodHound likewise needs user + password.
- WinRM / MSSQL steps only run if the ports were seen open in the nmap scan.
- The viewer is pure stdlib + vanilla JS — no server framework, no build step.
  `report.json` is self-contained; you can commit it per target or diff runs.
```
