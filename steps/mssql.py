"""steps/mssql.py — MSSQL access check (only when 1433 is open)."""

from core.steps import Step, Finding, register, HAS_CREDS, PORT, INFO, HIGH


def _mssql(output, ctx):
    findings = []
    if "Pwn3d!" in output:
        findings.append(Finding(HIGH, "MSSQL — admin / xp_cmdshell likely available",
                                 hint="nxc mssql <ip> <auth> -x whoami"))
    elif "[+]" in output:
        findings.append(Finding(INFO, "MSSQL — credentials valid"))
    return findings, [], []


register(Step(
    id="mssql_access", name="NetExec — MSSQL access check",
    category="MSSQL", phase=2, tool="nxc", requires=[HAS_CREDS, PORT(1433)],
    build_cmd=lambda c: ["nxc", "mssql", c.target, *c.nxc_auth_flags()],
    save_name="mssql_access.txt", parse=_mssql,
))
