"""steps/nmap.py — port and service discovery (Phase 1)."""

from core.steps   import Step, Finding, register, HAS_PORTS, INFO, MEDIUM
from core.parsers import parse_open_ports, parse_services


def _full_scan(output, ctx):
    # Prefer the grepable file nmap wrote; fall back to captured stdout.
    try:
        ports = parse_open_ports((ctx.nmap_dir / "tcpAllPorts").read_text())
    except Exception:
        ports = parse_open_ports(output)

    findings, rows = [], []
    if ports:
        ctx.open_ports = ports
        plist = ", ".join(str(p) for p in sorted(ports))
        findings.append(Finding(INFO, f"Open ports: {plist}"))
        rows = [{"port": p} for p in sorted(ports)]
    else:
        findings.append(Finding(MEDIUM, "No open ports detected — check target / connectivity"))
    return findings, rows, ["port"]


def _service_scan(output, ctx):
    ctx.services   = parse_services(output)
    ctx.smb_open   = ctx.port_open(445) or ctx.port_open(139)
    ctx.ldap_open  = ctx.port_open(389) or ctx.port_open(636) or ctx.port_open(3268)
    ctx.winrm_open = ctx.port_open(5985) or ctx.port_open(5986)

    findings, rows = [], []
    for port, svc in sorted(ctx.services.items()):
        rows.append({"port": port, "service": svc})
    if ctx.smb_open:
        findings.append(Finding(INFO, "SMB open (139/445)"))
    if ctx.ldap_open:
        findings.append(Finding(INFO, "LDAP open (389/636/3268) — domain controller likely"))
    if ctx.winrm_open:
        findings.append(Finding(INFO, "WinRM open (5985/5986) — test creds later"))
    return findings, rows, ["port", "service"]


register(Step(
    id="nmap_full", name="Nmap — full TCP port scan", category="Nmap", phase=1,
    tool="nmap",
    build_cmd=lambda c: ["nmap", "-p-", "--min-rate", "5000",
                         "-oG", str(c.nmap_dir / "tcpAllPorts"), c.target],
    parse=_full_scan, timeout=600,
))

register(Step(
    id="nmap_service", name="Nmap — service / version scan", category="Nmap", phase=1,
    tool="nmap", requires=[HAS_PORTS],
    build_cmd=lambda c: ["nmap", "-sCV", "-p", c.ports_csv(),
                         "-oN", str(c.nmap_dir / "tcpScans"), c.target],
    save_name="nmap/tcpScans.txt", parse=_service_scan, timeout=400,
))
