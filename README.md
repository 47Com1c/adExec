# adExec

```
 █████╗ ██████╗ ███████╗██╗  ██╗███████╗ ██████╗
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝██╔════╝██╔════╝
███████║██║  ██║█████╗   ╚███╔╝ █████╗  ██║     
██╔══██║██║  ██║██╔══╝   ██╔██╗ ██╔══╝  ██║     
██║  ██║██████╔╝███████╗██╔╝ ██╗███████╗╚██████╗
╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝
```

AD recon orchestrator for HTB / pentest labs. Wraps your typical entire workflow into a single two-phase run.

---

## Dependencies

Install the required tools (Kali/Parrot have most by default):

```bash
# Python dependency
pip install rich

# Tool Requirement
sudo apt install nmap nxc ldap-utils
pip install impacket   
```

---

## Usage

```bash
# Phase 1 //no creds
python adreaper.py -t 10.10.10.10

# Run with creds
python adreaper.py -t 10.10.10.10 -u support -p '#00^BlackKnight'

# Pass-the-hash
python adreaper.py -t 10.10.10.10 -u administrator --hash <NT_HASH>

```

---

## Running List

### Phase 1 — No creds needed
| Step | Command |
|------|---------|
| Full port scan | `nmap -p- --min-rate 5000 -oG nmap/tcpAllPorts <IP>` |
| Service scan | `nmap -sCV -p <open_ports> -oN nmap/tcpScans <IP>` |
| SMB fingerprint | `nxc smb <IP>` → extracts hostname + domain |
| /etc/hosts entry | Prints line, asks confirmation, runs `sudo tee -a /etc/hosts` |
| Null session shares | `nxc smb <IP> -u '' -p '' --shares` |
| Anonymous LDAP policy | `ldapsearch -x` → password policy, lockout threshold |

### Phase 2 — Authenticated
| Step | Command |
|------|---------|
| Auth SMB shares | `nxc smb <IP> -u <user> -p <pass> --shares` |
| RID brute| `nxc smb <IP> -u <user> -p <pass> --rid-brute` |
| WinRM check | `nxc winrm <IP> -u <user> -p <pass>` (if port 5985/5986 open) |
| AS-REP roast | `impacket-GetNPUsers <domain>/ -usersfile users.txt --dc-ip <IP>` |
| LDAP users+descriptions | `ldapsearch` — surfaces password hints in descriptions |
| LDAP group memberships | Domain Admins, Backup Operators, DnsAdmins, and more |
| LDAP delegation | Unconstrained + constrained delegation misconfigs |

---

## Output

All raw tool output is saved to `./recon/<target_ip>/`:

```
recon/
└── 10.10.10.10/
    ├── nmap/
    │   ├── tcpAllPorts       
    │   └── tcpScans          
    ├── smb_fingerprint.txt
    ├── smb_shares_null.txt
    ├── smb_shares_guest.txt
    ├── smb_shares_auth.txt
    ├── rid_brute_raw.txt
    ├── users.txt             
    ├── winrm_check.txt
    ├── asrep_hashes.txt      
    ├── ldap_policy_anon.txt
    ├── ldap_users_desc.txt
    ├── ldap_group_*.txt
    ├── ldap_unconstrained.txt
    └── ldap_constrained.txt
```

---

## Notes

- `nxc` is the new name for `crackmapexec`. If you have the old `cme`, swap `nxc` → `cme` in `core/env.py` and the phase files.
- ldapsearch doesn't support NTLM hash auth — phase 2 LDAP steps fall back to user/pass only.
- WinRM steps only run if ports 5985/5986 were detected open in nmap.
