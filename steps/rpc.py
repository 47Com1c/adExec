"""steps/rpc.py — SMB NULL session enumeration via rpcclient / enum4linux-ng."""

from core.steps   import Step, Finding, register, SMB_OPEN, INFO, HIGH
from core.parsers import parse_rpcclient_users


def _rpcclient(output, ctx):
    users = parse_rpcclient_users(output)
    findings, rows = [], []
    for u in users:
        if u not in ctx.users:
            ctx.users.append(u)
        rows.append({"username": u})
    if users:
        findings.append(Finding(HIGH,
            f"rpcclient NULL session enumerated {len(users)} users"))
    return findings, rows, ["username"]


register(Step(
    id="rpcclient_null", name="rpcclient — NULL session domain info + users",
    category="RPC", phase=1, tool="rpcclient", requires=[SMB_OPEN],
    build_cmd=lambda c: ["rpcclient", "-U", "", "-N", c.target,
                         "-c", "querydominfo;enumdomusers;getdompwinfo"],
    save_name="rpcclient_null.txt", parse=_rpcclient,
))

register(Step(
    id="enum4linux", name="enum4linux-ng — full NULL session sweep",
    category="RPC", phase=1, tool="enum4linux-ng", requires=[SMB_OPEN],
    build_cmd=lambda c: ["enum4linux-ng", "-A", c.target],
    save_name="enum4linux_ng.txt", timeout=240,
))
