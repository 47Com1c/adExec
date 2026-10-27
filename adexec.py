#!/usr/bin/env python3
"""
adExec - Active Directory Recon Orchestrator
Two-phase AD enumeration (unauth → authenticated) driven by a step registry,
with results written to recon/<target>/report.json and browsed in a searchable
local web viewer.

Usage:
    python adexec.py -t 10.10.10.10
    python adexec.py -t 10.10.10.10 -u support -p '#00^BlackKnight'
    python adexec.py -t 10.10.10.10 -u support --hash <NT>
    python adexec.py -t 10.10.10.10 --phase2-only -u support -p 'Pass'
    python adexec.py --serve-only            # just open the viewer
"""

import argparse
import datetime

import steps                         # noqa: F401  (registers all steps on import)
from core.env     import check_dependencies
from core.context import Context
from core.engine  import Engine
from core.hosts   import offer_hosts_entry
from core.report  import write_report
from core.server  import serve
from output.term  import Term


BANNER = r"""
  ____  ____  _____  _  _  ____  ___
 / _  ||    \|   __|| \/ ||    _||  _|
| |_| || || ||   __| >  < |  _|  | |
 \___ ||____/|_____||_/\_||____| |___|

     AD Recon Orchestrator  v3.0
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="adExec — AD recon orchestrator for HTB/pentest labs",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-t", "--target",   metavar="IP",     help="Target IP address")
    p.add_argument("-d", "--domain",   metavar="DOMAIN", help="Domain (auto-detected if omitted)")
    p.add_argument("-u", "--username", metavar="USER",   help="Username for authenticated phase")
    p.add_argument("-p", "--password", metavar="PASS",   help="Password for authenticated phase")
    p.add_argument("--hash",           metavar="HASH",   help="NTLM hash (NT only or LM:NT)")
    p.add_argument("--phase1-only",    action="store_true", help="Run phase 1 (unauthenticated) only")
    p.add_argument("--phase2-only",    action="store_true", help="Skip phase 1, run phase 2 (needs creds)")
    p.add_argument("--output-dir",     metavar="DIR", default="./recon",
                   help="Base output directory (default: ./recon)")
    p.add_argument("--no-color",       action="store_true", help="Disable colors")
    p.add_argument("--no-serve",       action="store_true", help="Do not launch the web viewer")
    p.add_argument("--serve-only",     action="store_true",
                   help="Launch the viewer over existing results and exit (no scanning)")
    p.add_argument("--port",           type=int, default=8777, help="Viewer port (default: 8777)")
    return p.parse_args()


def main():
    args = parse_args()
    term = Term(no_color=args.no_color)
    term.banner(BANNER)

    # View-only mode — serve whatever is already under output-dir.
    if args.serve_only:
        serve(args.output_dir, port=args.port, open_browser=not args.no_serve, term=term)
        return

    if not args.target:
        term.error("No target. Pass -t <IP>  (or --serve-only to just view results).")
        return

    missing = check_dependencies()
    if missing:
        term.warn(f"Missing tools (those steps will be skipped): {', '.join(missing)}")

    ctx = Context(
        target     = args.target,
        domain     = args.domain,
        username   = args.username,
        password   = args.password,
        ntlm_hash  = args.hash,
        output_dir = args.output_dir,
        term       = term,
    )
    ctx.setup_dirs()
    ctx.started_at = datetime.datetime.now().isoformat(timespec="seconds")

    engine = Engine(ctx)

    # Phase 1 — unauthenticated
    if not args.phase2_only:
        term.phase("Phase 1 — Unauthenticated Recon")
        engine.run_phase(1)
        offer_hosts_entry(ctx)

        if not args.phase1_only and not ctx.has_creds():
            term.spacer()
            if term.prompt("Phase 1 complete. Have credentials for Phase 2? [y/N]").strip().lower() == "y":
                ctx.prompt_creds()

    # Phase 2 — authenticated
    if not args.phase1_only:
        if ctx.has_creds():
            term.phase("Phase 2 — Authenticated Recon")
            term.info(f"Credentials : {ctx.cred_string()}")
            engine.run_phase(2)
        else:
            term.warn("No credentials — skipping Phase 2.")

    # Report + viewer
    ctx.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
    report_path = write_report(ctx)
    term.spacer()
    term.rule("adExec complete")
    term.info(f"Raw output : {ctx.target_dir}/")
    term.info(f"Report     : {report_path}")

    if not args.no_serve:
        term.spacer()
        serve(args.output_dir, port=args.port, open_browser=True, term=term)
    else:
        term.info(f"View later : python adexec.py --serve-only --output-dir {args.output_dir}")


if __name__ == "__main__":
    main()
