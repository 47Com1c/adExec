"""
core/hosts.py — Offer to append the discovered FQDN to /etc/hosts.

Kept interactive and side-effecting (sudo), so it lives outside the step
engine. Called between phase 1 and phase 2 once the SMB fingerprint has
populated ctx.hostname / ctx.domain.
"""

import subprocess


def offer_hosts_entry(ctx):
    term = ctx.term
    if not ctx.hostname or not ctx.domain:
        return

    fqdn  = f"{ctx.hostname}.{ctx.domain}".lower()
    short = ctx.hostname.lower()
    dom   = ctx.domain.lower()
    entry = f"{ctx.target}\t{fqdn} {short} {dom}"

    term.section("/etc/hosts")
    term.info("Suggested entry:")
    term.highlight(f"  {entry}")

    answer = term.prompt("Append to /etc/hosts with sudo? [y/N]")
    if answer.strip().lower() != "y":
        term.info("Skipped. Run manually:")
        term.info(f"  echo '{entry}' | sudo tee -a /etc/hosts")
        return

    term.cmd(f"echo '{entry}' | sudo tee -a /etc/hosts")
    try:
        result = subprocess.run(
            ["sudo", "tee", "-a", "/etc/hosts"],
            input=f"\n{entry}\n", text=True, capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            term.success("Appended to /etc/hosts")
        else:
            term.error(f"sudo tee failed: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        term.error("Timed out. Run manually:")
        term.info(f"  echo '{entry}' | sudo tee -a /etc/hosts")
    except Exception as e:                       # noqa: BLE001
        term.error(f"Failed: {e}")
