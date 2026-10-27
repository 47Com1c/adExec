"""steps/winrm.py — WinRM access check (only when 5985/5986 is open)."""

from core.steps import Step, Finding, register, HAS_CREDS, WINRM_OPEN, INFO, HIGH


def _winrm(output, ctx):
    findings = []
    if "Pwn3d!" in output:
        findings.append(Finding(HIGH, "WinRM — shell available (admin)",
            hint=f"evil-winrm -i {ctx.target} -u {ctx.username} "
                 + ("-H <hash>" if ctx.ntlm_hash else "-p <pass>")))
    elif "[+]" in output:
        findings.append(Finding(INFO, "WinRM — credentials valid (no admin shell)"))
    else:
        findings.append(Finding(INFO, "WinRM — access denied with current creds"))
    return findings, [], []


register(Step(
    id="winrm_check", name="NetExec — WinRM access check",
    category="WinRM", phase=2, tool="nxc", requires=[HAS_CREDS, WINRM_OPEN],
    build_cmd=lambda c: ["nxc", "winrm", c.target, *c.nxc_auth_flags()],
    save_name="winrm_check.txt", parse=_winrm,
))
