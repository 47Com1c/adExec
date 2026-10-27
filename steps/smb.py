"""steps/smb.py — SMB fingerprinting and share / user / policy enumeration."""

from core.steps   import (Step, Finding, register,
                          SMB_OPEN, HAS_CREDS,
                          INFO, LOW, MEDIUM, HIGH)
from core.parsers import parse_smb_info, parse_shares, parse_rid_users, parse_nxc_users

DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL", "PRINT$"}


# ------------------------------------------------------------------ #
#  Phase 1 — unauthenticated                                           #
# ------------------------------------------------------------------ #

def _fingerprint(output, ctx):
    hostname, domain = parse_smb_info(output)
    findings = []
    if hostname:
        ctx.hostname = hostname
        findings.append(Finding(INFO, f"Hostname: {hostname}"))
    if domain:
        ctx.domain = domain
        findings.append(Finding(INFO, f"Domain: {domain}"))
    return findings, [], []


def _null_shares(output, ctx):
    shares = parse_shares(output)
    findings, rows = [], []
    for s in shares:
        if s not in ctx.shares:
            ctx.shares.append(s)
        rows.append({"share": s})
    if shares:
        findings.append(Finding(MEDIUM,
            f"Readable shares over null/guest session: {', '.join(shares)}"))
    return findings, rows, ["share"]


def _null_users(output, ctx):
    users = parse_nxc_users(output)
    findings, rows = [], []
    for u in users:
        if u not in ctx.users:
            ctx.users.append(u)
        rows.append({"username": u})
    if users:
        findings.append(Finding(HIGH,
            f"Users enumerated WITHOUT creds ({len(users)}) — null session leak"))
    return findings, rows, ["username"]


register(Step(
    id="smb_fingerprint", name="NetExec — SMB fingerprint (host / domain)",
    category="SMB", phase=1, tool="nxc", requires=[SMB_OPEN],
    build_cmd=lambda c: ["nxc", "smb", c.target],
    save_name="smb_fingerprint.txt", parse=_fingerprint,
))

register(Step(
    id="smb_null_shares", name="NetExec — null session shares",
    category="SMB", phase=1, tool="nxc", requires=[SMB_OPEN],
    build_cmd=lambda c: ["nxc", "smb", c.target, "-u", "", "-p", "", "--shares"],
    save_name="smb_shares_null.txt", parse=_null_shares,
))

register(Step(
    id="smb_guest_shares", name="NetExec — guest session shares",
    category="SMB", phase=1, tool="nxc", requires=[SMB_OPEN],
    build_cmd=lambda c: ["nxc", "smb", c.target, "-u", "guest", "-p", "", "--shares"],
    save_name="smb_shares_guest.txt", parse=_null_shares,
))

register(Step(
    id="smb_null_users", name="NetExec — null session user enumeration",
    category="SMB", phase=1, tool="nxc", requires=[SMB_OPEN],
    build_cmd=lambda c: ["nxc", "smb", c.target, "-u", "", "-p", "", "--users"],
    save_name="smb_users_null.txt", parse=_null_users,
))

register(Step(
    id="smb_pass_pol_null", name="NetExec — password policy (null session)",
    category="SMB", phase=1, tool="nxc", requires=[SMB_OPEN],
    build_cmd=lambda c: ["nxc", "smb", c.target, "-u", "", "-p", "", "--pass-pol"],
    save_name="smb_pass_pol_null.txt",
))


# ------------------------------------------------------------------ #
#  Phase 2 — authenticated                                             #
# ------------------------------------------------------------------ #

def _auth_shares(output, ctx):
    shares = parse_shares(output)
    findings, rows = [], []
    for s in shares:
        if s not in ctx.shares:
            ctx.shares.append(s)
        is_custom = s.upper() not in DEFAULT_SHARES
        rows.append({"share": s, "non_default": "yes" if is_custom else ""})
    custom = [s for s in shares if s.upper() not in DEFAULT_SHARES]
    if shares:
        findings.append(Finding(INFO, f"Accessible shares: {', '.join(shares)}"))
    if custom:
        findings.append(Finding(MEDIUM,
            f"Non-default shares worth spidering: {', '.join(custom)}",
            hint="nxc smb <ip> <auth> --spider <share> --regex ."))
    return findings, rows, ["share", "non_default"]


def _rid_brute(output, ctx):
    users = parse_rid_users(output)
    findings, rows = [], []
    if users:
        for u in users:
            if u not in ctx.users:
                ctx.users.append(u)
        (ctx.target_dir / "users.txt").write_text("\n".join(ctx.users) + "\n")
        findings.append(Finding(INFO, f"RID brute found {len(users)} users → users.txt"))
        rows = [{"username": u} for u in users]
    else:
        findings.append(Finding(LOW, "No users from RID brute — check credentials"))
    return findings, rows, ["username"]


def _auth_users(output, ctx):
    users = parse_nxc_users(output)
    findings, rows = [], []
    for u in users:
        if u not in ctx.users:
            ctx.users.append(u)
        rows.append({"username": u})
    if ctx.users:
        (ctx.target_dir / "users.txt").write_text("\n".join(ctx.users) + "\n")
    if users:
        findings.append(Finding(INFO, f"Domain users enumerated: {len(users)}"))
    return findings, rows, ["username"]


def _gpp(output, ctx):
    findings = []
    if "Found credentials" in output or "password" in output.lower():
        findings.append(Finding(HIGH,
            "Group Policy Preferences (GPP) credentials found — check raw output",
            hint="GPP cpassword is decryptable; reuse creds domain-wide"))
    return findings, [], []


register(Step(
    id="smb_auth_shares", name="NetExec — authenticated shares",
    category="SMB", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "smb", c.target, *c.nxc_auth_flags(), "--shares"],
    save_name="smb_shares_auth.txt", parse=_auth_shares,
))

register(Step(
    id="smb_users", name="NetExec — domain users",
    category="SMB", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "smb", c.target, *c.nxc_auth_flags(), "--users"],
    save_name="smb_users.txt", parse=_auth_users,
))

register(Step(
    id="smb_rid_brute", name="NetExec — RID brute (user enumeration)",
    category="SMB", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "smb", c.target, *c.nxc_auth_flags(), "--rid-brute", "10000"],
    save_name="rid_brute_raw.txt", parse=_rid_brute,
))

register(Step(
    id="smb_groups", name="NetExec — domain groups",
    category="SMB", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "smb", c.target, *c.nxc_auth_flags(), "--groups"],
    save_name="smb_groups.txt",
))

register(Step(
    id="smb_pass_pol", name="NetExec — password policy (authenticated)",
    category="SMB", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "smb", c.target, *c.nxc_auth_flags(), "--pass-pol"],
    save_name="smb_pass_pol.txt",
))

register(Step(
    id="smb_loggedon", name="NetExec — logged-on users",
    category="SMB", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "smb", c.target, *c.nxc_auth_flags(), "--loggedon-users"],
    save_name="smb_loggedon.txt",
))

register(Step(
    id="smb_gpp", name="NetExec — GPP password search",
    category="SMB", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "smb", c.target, *c.nxc_auth_flags(), "-M", "gpp_password"],
    save_name="smb_gpp.txt", parse=_gpp,
))
