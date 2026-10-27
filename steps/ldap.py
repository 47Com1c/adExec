"""steps/ldap.py — LDAP enumeration (anonymous + authenticated)."""

import re

from core.steps   import (Step, Finding, register,
                          LDAP_OPEN, HAS_CREDS, HAS_DOMAIN,
                          INFO, MEDIUM, HIGH, CRITICAL)
from core.parsers import parse_ldap_users_with_desc, parse_domain_sid

HIGH_VALUE_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators",
    "Remote Management Users", "DnsAdmins", "Account Operators",
    "Server Operators", "Group Policy Creator Owners",
]

GROUP_HINTS = {
    "Domain Admins":          "DCSync: impacket-secretsdump <dom>/<user>:<pass>@<DC>",
    "Backup Operators":       "Back up SAM/SYSTEM or NTDS.dit → offline hash dump",
    "DnsAdmins":              "Load malicious DLL via dnscmd serverlevelplugindll",
    "Remote Management Users":"evil-winrm -i <IP> -u <user> -p <pass>",
    "Server Operators":       "Reconfigure a service on the DC to run as SYSTEM",
}


# ------------------------------------------------------------------ #
#  Phase 1 — anonymous                                                 #
# ------------------------------------------------------------------ #

def _rootdse(output, ctx):
    findings = []
    if "defaultNamingContext" in output or "namingContexts" in output:
        findings.append(Finding(INFO, "Anonymous LDAP bind succeeded — RootDSE readable"))
        for line in output.splitlines():
            if line.lower().startswith("defaultnamingcontext"):
                findings.append(Finding(INFO, line.strip()))
    else:
        findings.append(Finding(INFO, "Anonymous LDAP returned nothing (hardened — expected)"))
    return findings, [], []


register(Step(
    id="ldap_rootdse", name="LDAP — anonymous RootDSE", category="LDAP", phase=1,
    tool="ldapsearch", requires=[LDAP_OPEN],
    build_cmd=lambda c: ["ldapsearch", "-x", "-H", f"ldap://{c.target}",
                         "-b", "", "-s", "base", "(objectClass=*)",
                         "defaultNamingContext", "dnsHostName", "ldapServiceName"],
    save_name="ldap_rootdse.txt", parse=_rootdse,
))


# ------------------------------------------------------------------ #
#  Phase 2 — authenticated                                             #
# ------------------------------------------------------------------ #

def _users_desc(output, ctx):
    results = parse_ldap_users_with_desc(output)
    findings, rows = [], []
    for user, desc in results:
        rows.append({"user": user, "description": desc})
    if results:
        findings.append(Finding(HIGH,
            f"{len(results)} users have descriptions — check for passwords/hints"))
    return findings, rows, ["user", "description"]


def _groups(output, ctx):
    findings, rows = [], []
    current_cn, members = None, []

    def flush():
        if current_cn and members:
            sev = CRITICAL if current_cn in ("Domain Admins", "Enterprise Admins") else HIGH
            findings.append(Finding(sev,
                f"{current_cn} ({len(members)}): {', '.join(members)}",
                hint=GROUP_HINTS.get(current_cn, "")))
            for m in members:
                rows.append({"group": current_cn, "member": m})

    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("cn:"):
            val = line.split(":", 1)[1].strip()
            if val in HIGH_VALUE_GROUPS:
                flush()
                current_cn, members = val, []
        elif line.lower().startswith("member:"):
            m = re.match(r"CN=([^,]+)", line.split(":", 1)[1].strip(), re.IGNORECASE)
            if m:
                members.append(m.group(1))
    flush()
    return findings, rows, ["group", "member"]


def _samaccountnames(output):
    return [l.split(":", 1)[1].strip() for l in output.splitlines()
            if l.strip().lower().startswith("samaccountname:")]


def _unconstrained(output, ctx):
    t = _samaccountnames(output)
    if t:
        return ([Finding(CRITICAL, f"UNCONSTRAINED delegation: {', '.join(t)}",
                 hint="Coerce DC auth (PetitPotam) → capture TGT → DCSync")],
                [{"account": x} for x in t], ["account"])
    return [Finding(INFO, "No unconstrained delegation targets (excl. DCs)")], [], []


def _constrained(output, ctx):
    t = _samaccountnames(output)
    if t:
        return ([Finding(HIGH, f"CONSTRAINED delegation: {', '.join(t)}",
                 hint="impacket-getST -spn <SPN> -impersonate Administrator ...")],
                [{"account": x} for x in t], ["account"])
    return [Finding(INFO, "No constrained delegation targets")], [], []


def _get_sid(output, ctx):
    sid = parse_domain_sid(output)
    if sid:
        ctx.domain_sid = sid
        return [Finding(INFO, f"Domain SID: {sid}")], [], []
    return [], [], []


def _maq(output, ctx):
    m = re.search(r"MachineAccountQuota.*?(\d+)", output, re.IGNORECASE)
    if m:
        q = int(m.group(1))
        sev = HIGH if q > 0 else INFO
        return [Finding(sev, f"MachineAccountQuota = {q}"
                + (" — low-priv users can add computer accounts" if q > 0 else ""))], [], []
    return [], [], []


def _flag_hits(sev, label, hint=""):
    def parser(output, ctx):
        hits = _samaccountnames(output)
        if hits:
            return ([Finding(sev, f"{label}: {', '.join(hits)}", hint=hint)],
                    [{"account": x} for x in hits], ["account"])
        return [], [], []
    return parser


register(Step(
    id="ldap_users_desc", name="LDAP — users with descriptions",
    category="LDAP", phase=2, tool="ldapsearch", requires=[LDAP_OPEN, HAS_DOMAIN],
    build_cmd=lambda c: ["ldapsearch", *c.ldap_auth_flags(), "-H", f"ldap://{c.target}",
                         "-b", c.base_dn(),
                         "(&(objectClass=user)(objectCategory=person)(description=*))",
                         "sAMAccountName", "description"],
    save_name="ldap_users_desc.txt", parse=_users_desc,
))

register(Step(
    id="ldap_groups", name="LDAP — high-value group memberships",
    category="LDAP", phase=2, tool="ldapsearch", requires=[LDAP_OPEN, HAS_DOMAIN],
    build_cmd=lambda c: ["ldapsearch", *c.ldap_auth_flags(), "-H", f"ldap://{c.target}",
                         "-b", c.base_dn(),
                         "(&(objectClass=group)(|" +
                         "".join(f"(cn={g})" for g in HIGH_VALUE_GROUPS) + "))",
                         "cn", "member"],
    save_name="ldap_groups.txt", parse=_groups,
))

register(Step(
    id="ldap_unconstrained", name="LDAP — unconstrained delegation",
    category="LDAP", phase=2, tool="ldapsearch", requires=[LDAP_OPEN, HAS_DOMAIN],
    build_cmd=lambda c: ["ldapsearch", *c.ldap_auth_flags(), "-H", f"ldap://{c.target}",
                         "-b", c.base_dn(),
                         "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                         "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                         "(!(primaryGroupID=516))(!(primaryGroupID=521)))",
                         "sAMAccountName"],
    save_name="ldap_unconstrained.txt", parse=_unconstrained,
))

register(Step(
    id="ldap_constrained", name="LDAP — constrained delegation",
    category="LDAP", phase=2, tool="ldapsearch", requires=[LDAP_OPEN, HAS_DOMAIN],
    build_cmd=lambda c: ["ldapsearch", *c.ldap_auth_flags(), "-H", f"ldap://{c.target}",
                         "-b", c.base_dn(),
                         "(&(msDS-AllowedToDelegateTo=*)"
                         "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                         "sAMAccountName", "msDS-AllowedToDelegateTo"],
    save_name="ldap_constrained.txt", parse=_constrained,
))

# --- NetExec LDAP one-liners (fast, high signal) ---------------------- #

register(Step(
    id="ldap_get_sid", name="NetExec LDAP — domain SID",
    category="LDAP", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(), "--get-sid"],
    save_name="ldap_get_sid.txt", parse=_get_sid,
))

register(Step(
    id="ldap_pwd_not_required", name="NetExec LDAP — PASSWD_NOTREQD accounts",
    category="LDAP", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(),
                         "--password-not-required"],
    save_name="ldap_pwd_not_required.txt",
    parse=_flag_hits(HIGH, "Accounts with PASSWD_NOTREQD",
                     "Try blank password: nxc smb <ip> -u <user> -p ''"),
))

register(Step(
    id="ldap_admin_count", name="NetExec LDAP — adminCount=1 objects",
    category="LDAP", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(), "--admin-count"],
    save_name="ldap_admin_count.txt",
    parse=_flag_hits(MEDIUM, "Protected (adminCount=1) objects"),
))

register(Step(
    id="ldap_maq", name="NetExec LDAP — machine account quota",
    category="LDAP", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(), "-M", "maq"],
    save_name="ldap_maq.txt", parse=_maq,
))

register(Step(
    id="ldap_laps", name="NetExec LDAP — readable LAPS passwords",
    category="LDAP", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(), "--laps"],
    save_name="ldap_laps.txt",
    parse=_flag_hits(CRITICAL, "LAPS passwords readable", "Local admin on those hosts"),
))

register(Step(
    id="ldap_gmsa", name="NetExec LDAP — gMSA passwords",
    category="LDAP", phase=2, tool="nxc", requires=[HAS_CREDS],
    build_cmd=lambda c: ["nxc", "ldap", c.target, *c.nxc_auth_flags(), "--gmsa"],
    save_name="ldap_gmsa.txt",
    parse=_flag_hits(CRITICAL, "gMSA passwords readable"),
))
