"""
phases/phase1.py — Unauthenticated recon.

Steps:
  1. nmap full port scan (-p- fast)
  2. nmap targeted service scan (-sCV on open ports)
  3. NXC SMB fingerprint  → extract hostname + domain
  4. /etc/hosts entry     → print + confirm + sudo tee
  5. NXC SMB null/guest share enum
  6. Anonymous LDAP bind  → RootDSE info (best-effort)
"""

import subprocess
from core.runner  import Runner
from core.parsers import (parse_open_ports, parse_services,
                           parse_smb_info, parse_shares)
from core.env     import tool_available


class Phase1:
    def __init__(self, ctx):
        self.ctx    = ctx
        self.runner = Runner(ctx.term)

    def run(self):
        self._nmap_full_scan()
        self._nmap_service_scan()
        self._smb_fingerprint()
        self._hosts_entry()
        self._smb_null_shares()
        self._ldap_anon()

    # ------------------------------------------------------------------ #
    #  1. nmap full port scan                                              #
    # ------------------------------------------------------------------ #

    def _nmap_full_scan(self):
        ctx  = self.ctx
        term = ctx.term
        term.phase("Phase 1 — Unauthenticated Recon")
        term.section("Nmap — full port scan")

        if not tool_available("nmap"):
            term.skip("nmap not found"); return

        out_file = ctx.nmap_dir / "tcpAllPorts"
        rc, output = self.runner.run(
            ["nmap", "-p-", "--min-rate", "5000", "-oG", str(out_file), ctx.target],
            timeout=600
        )

        ports = []
        try:
            ports = parse_open_ports(out_file.read_text())
        except Exception:
            ports = parse_open_ports(output)

        if ports:
            ctx.open_ports = ports
            term.success(f"Open ports: {', '.join(str(p) for p in sorted(ports))}")
        else:
            term.warn("No open ports detected — check target IP / connectivity.")

    # ------------------------------------------------------------------ #
    #  2. nmap service scan                                                #
    # ------------------------------------------------------------------ #

    def _nmap_service_scan(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("Nmap — service/version scan")

        if not ctx.open_ports:
            term.skip("No open ports from previous step."); return

        out_file = ctx.nmap_dir / "tcpScans"
        rc, output = self.runner.run(
            ["nmap", "-sCV", "-p", ctx.ports_csv(),
             "-oN", str(out_file), ctx.target],
            timeout=300
        )

        ctx.services   = parse_services(output)
        ctx.smb_open   = ctx.port_open(445) or ctx.port_open(139)
        ctx.ldap_open  = ctx.port_open(389) or ctx.port_open(636) or ctx.port_open(3268)
        ctx.winrm_open = ctx.port_open(5985) or ctx.port_open(5986)

        if ctx.winrm_open:
            term.finding("WinRM open (5985/5986) — test with creds later")
        if ctx.ldap_open:
            term.finding("LDAP open (389/3268)")
        if ctx.smb_open:
            term.finding("SMB open (445)")

    # ------------------------------------------------------------------ #
    #  3. NXC SMB fingerprint                                              #
    # ------------------------------------------------------------------ #

    def _smb_fingerprint(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("NXC — SMB fingerprint")

        if not tool_available("nxc"):
            term.skip("nxc not found"); return
        if not ctx.smb_open:
            term.skip("SMB not open"); return

        rc, output = self.runner.run(
            ["nxc", "smb", ctx.target],
            save_to=ctx.target_dir / "smb_fingerprint.txt"
        )

        hostname, domain = parse_smb_info(output)
        if hostname:
            ctx.hostname = hostname
            term.success(f"Hostname : {hostname}")
        if domain:
            ctx.domain = domain
            term.success(f"Domain   : {domain}")

    # ------------------------------------------------------------------ #
    #  4. /etc/hosts — fixed: subprocess.run with capture_output          #
    #     No Popen streaming → no stdin hang waiting for EOF              #
    # ------------------------------------------------------------------ #

    def _hosts_entry(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("/etc/hosts")

        if not ctx.hostname or not ctx.domain:
            term.skip("Hostname/domain not detected — skipping."); return

        fqdn  = f"{ctx.hostname}.{ctx.domain}".lower()
        short = ctx.hostname.lower()
        dom   = ctx.domain.lower()
        entry = f"{ctx.target}\t{fqdn} {short} {dom}"

        term.spacer()
        term.info("Suggested /etc/hosts entry:")
        term.highlight(f"  {entry}")
        term.spacer()

        answer = term.prompt("Append to /etc/hosts with sudo? [y/N]")
        if answer.strip().lower() != "y":
            term.info(f"Skipped. Run manually:")
            term.info(f"  echo '{entry}' | sudo tee -a /etc/hosts")
            return

        # subprocess.run with input= and capture_output=True
        # This sends the string to stdin and returns immediately — no freeze.
        term.cmd(f"echo '{entry}' | sudo tee -a /etc/hosts")
        try:
            result = subprocess.run(
                ["sudo", "tee", "-a", "/etc/hosts"],
                input=f"\n{entry}\n",
                text=True,
                capture_output=True,
                timeout=30
            )
            if result.returncode == 0:
                term.success("Appended to /etc/hosts")
            else:
                term.error(f"sudo tee failed: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            term.error("Timed out. Run manually:")
            term.info(f"  echo '{entry}' | sudo tee -a /etc/hosts")
        except Exception as e:
            term.error(f"Failed: {e}")

    # ------------------------------------------------------------------ #
    #  5. SMB null + guest share enum                                      #
    # ------------------------------------------------------------------ #

    def _smb_null_shares(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("NXC — SMB null/guest session shares")

        if not tool_available("nxc"):
            term.skip("nxc not found"); return
        if not ctx.smb_open:
            term.skip("SMB not open"); return

        for user, pwd, label in [("", "", "null"), ("guest", "", "guest")]:
            rc, output = self.runner.run(
                ["nxc", "smb", ctx.target, "-u", user, "-p", pwd, "--shares"],
                save_to=ctx.target_dir / f"smb_shares_{label}.txt"
            )
            shares = parse_shares(output)
            if shares:
                term.finding(f"Readable shares ({label} session): {', '.join(shares)}")
                for s in shares:
                    if s not in ctx.shares:
                        ctx.shares.append(s)

    # ------------------------------------------------------------------ #
    #  7. Anonymous LDAP — RootDSE only (best-effort)                     #
    # ------------------------------------------------------------------ #

    def _ldap_anon(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("LDAP — anonymous RootDSE")

        if not tool_available("ldapsearch"):
            term.skip("ldapsearch not found"); return
        if not ctx.ldap_open:
            term.skip("LDAP port not open"); return

        rc, output = self.runner.run(
            [
                "ldapsearch", "-x",
                "-H", f"ldap://{ctx.target}",
                "-b", "",
                "-s", "base",
                "(objectClass=*)",
                "defaultNamingContext", "dnsHostName", "ldapServiceName"
            ],
            save_to=ctx.target_dir / "ldap_rootdse.txt"
        )

        if "defaultNamingContext" in output:
            term.finding("Anonymous LDAP bind succeeded — RootDSE readable")
            for line in output.splitlines():
                if any(k in line for k in ("defaultNamingContext",
                                            "dnsHostName", "ldapServiceName")):
                    term.info(f"  {line.strip()}")
        else:
            term.info("Anonymous LDAP bind returned nothing (hardened — expected)")
