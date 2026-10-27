## adExec

```
 █████╗ ██████╗ ███████╗██╗  ██╗███████╗ ██████╗
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝██╔════╝██╔════╝
███████║██║  ██║█████╗   ╚███╔╝ █████╗  ██║     
██╔══██║██║  ██║██╔══╝   ██╔██╗ ██╔══╝  ██║     
██║  ██║██████╔╝███████╗██╔╝ ██╗███████╗╚██████╗
╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝
```

An AD recon tool for HTB and pentest labs. It runs the usual enumeration
commands for you in two phases (before and after you have credentials), saves
everything to disk, and opens a small web page where you can read and search
the results. No more digging through twenty text files.

## Install

```bash
git clone https://github.com/47Com1c/adExec.git
cd adExec
pip install -r requirements.txt
```

That installs `rich`, which is the only Python dependency.

The actual scanning is done by the usual tools. Install the ones you want.
If a tool is missing, adExec just skips that command and tells you.

```bash
sudo apt install nmap ldap-utils samba-common-bin enum4linux-ng
pipx install netexec impacket certipy-ad bloodhound
```

`nxc` is NetExec, the tool that used to be called crackmapexec.

## Run

```bash
# no credentials yet
python adexec.py -t 10.10.10.10

# with credentials
python adexec.py -t 10.10.10.10 -u support -p 'Password123'

# with an NT hash instead of a password
python adexec.py -t 10.10.10.10 -u administrator --hash <NT_HASH>
```

When the run finishes, the web viewer opens at `http://127.0.0.1:8777`.
To reopen it later without scanning again, run `python adexec.py --serve-only`.

## What it checks

Phase 1 (no credentials): nmap port and service scan, SMB fingerprint, null and
guest shares, rpcclient and enum4linux null sessions, anonymous LDAP.

Phase 2 (with credentials): shares, users, groups, sessions, password policy,
GPP passwords, AS-REP roasting, Kerberoasting, LAPS and gMSA reads, delegation,
machine account quota, WinRM and MSSQL access, ADCS templates, BloodHound
collection.

Everything here is read only. adExec enumerates, it does not exploit or dump
credentials.

## Output

Raw tool output goes to `recon/<target_ip>/`. The web viewer reads
`recon/<target_ip>/report.json`, which is the structured summary of the run.
