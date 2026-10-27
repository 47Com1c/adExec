"""steps/adcs.py — Active Directory Certificate Services enumeration (certipy)."""

import re

from core.steps import Step, Finding, register, HAS_USERPASS, HAS_DOMAIN, INFO, CRITICAL


def _certipy(output, ctx):
    escs = sorted(set(re.findall(r"\bESC\d+\b", output)))
    findings, rows = [], []
    if escs:
        findings.append(Finding(CRITICAL,
            f"Vulnerable certificate templates: {', '.join(escs)}",
            hint="certipy req → forge cert → authenticate as target"))
        rows = [{"vulnerability": e} for e in escs]
    elif "Certificate Authorities" in output or "Certificate Templates" in output:
        findings.append(Finding(INFO, "ADCS present — no vulnerable templates flagged"))
    return findings, rows, ["vulnerability"]


register(Step(
    id="certipy_find", name="certipy — find vulnerable AD CS templates",
    category="ADCS", phase=2, tool="certipy", requires=[HAS_USERPASS, HAS_DOMAIN],
    build_cmd=lambda c: ["certipy", "find", "-u", f"{c.username}@{c.domain}",
                         "-p", c.password, "-dc-ip", c.target, "-vulnerable", "-stdout"],
    save_name="certipy_find.txt", parse=_certipy, timeout=240,
))
