"""steps/bloodhound.py — BloodHound graph collection (read-only, -c All)."""

from core.steps import Step, Finding, register, HAS_USERPASS, HAS_DOMAIN, INFO


def _bloodhound(output, ctx):
    bh_dir = ctx.target_dir / "bloodhound"
    zips = list(bh_dir.glob("*.zip")) if bh_dir.exists() else []
    if zips:
        return [Finding(INFO, f"BloodHound data ready: {zips[0].name}",
                hint="Upload the zip to BloodHound → run 'Shortest paths to Domain Admins'")], [], []
    return [Finding(INFO, "bloodhound-python ran — check output for the zip")], [], []


def _build(ctx):
    bh_dir = ctx.target_dir / "bloodhound"
    bh_dir.mkdir(exist_ok=True)
    return ["bloodhound-python", "-d", ctx.domain, "-u", ctx.username,
            "-p", ctx.password, "-ns", ctx.target, "-c", "All", "--zip",
            "--outputdir", str(bh_dir)]


register(Step(
    id="bloodhound", name="BloodHound — full collection (-c All)",
    category="BloodHound", phase=2, tool="bloodhound-python",
    requires=[HAS_USERPASS, HAS_DOMAIN],
    build_cmd=_build, save_name="bloodhound_raw.txt", parse=_bloodhound, timeout=400,
))
