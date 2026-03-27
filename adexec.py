#!/usr/bin/env python3
"""
adExec - Active Directory Recon Orchestrator
Wraps nmap, netexec, ldapsearch, and impacket into a two-phase HTB recon workflow.

Usage:
    python adexec.py -t 10.10.10.10
    python adexec.py -t 10.10.10.10 -u support -p '#00^BlackKnight'
    python adexec.py -t 10.10.10.10 -u support --hash <NT>
    python adexec.py -t 10.10.10.10 --phase2-only -u support -p 'Pass'
"""

import argparse
import sys
from core.env      import check_dependencies
from core.context  import Context
from phases.phase1 import Phase1
from phases.phase2 import Phase2
from output.term   import Term


BANNER = r"""
  ____  ____  _____  _  _  ____  ___
 / _  ||    \|   __|| \/ ||    _||  _|
| |_| || || ||   __| >  < |  _|  | |
 \___ ||____/|_____||_/\_||____| |___|

  AD Recon Orchestrator  v2.0  |  HTB Edition
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="adExec — AD recon orchestrator for HTB/pentest labs",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("-t", "--target",      required=True, metavar="IP",
                   help="Target IP address")
    p.add_argument("-d", "--domain",      metavar="DOMAIN",
                   help="Domain name (auto-detected if omitted)")
    p.add_argument("-u", "--username",    metavar="USER",
                   help="Username for authenticated phase")
    p.add_argument("-p", "--password",    metavar="PASS",
                   help="Password for authenticated phase")
    p.add_argument("--hash",              metavar="HASH",
                   help="NTLM hash (NT only or LM:NT)")
    p.add_argument("--phase1-only",       action="store_true",
                   help="Run phase 1 (unauthenticated) only")
    p.add_argument("--phase2-only",       action="store_true",
                   help="Skip phase 1, run phase 2 (requires creds)")
    p.add_argument("--output-dir",        metavar="DIR", default="./recon",
                   help="Base output directory (default: ./recon)")
    p.add_argument("--no-color",          action="store_true",
                   help="Disable colors (for redirection to file)")
    return p.parse_args()


def main():
    args   = parse_args()
    term   = Term(no_color=args.no_color)
    term.banner(BANNER)

    # Dependency check — warn but don't abort
    missing = check_dependencies()
    if missing:
        term.warn(f"Missing tools (steps will be skipped): {', '.join(missing)}")

    # Build shared context object
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

    # Phase 1 — unauthenticated
    if not args.phase2_only:
        Phase1(ctx).run()

        if not args.phase1_only and not ctx.has_creds():
            term.spacer()
            answer = term.prompt("Phase 1 complete. Do you have credentials for Phase 2? [y/N]")
            if answer.strip().lower() == "y":
                ctx.prompt_creds()

    # Phase 2 — authenticated
    if not args.phase1_only:
        if ctx.has_creds():
            Phase2(ctx).run()
        else:
            term.warn("No credentials — skipping Phase 2.")
            term.info("Re-run with -u/-p or --hash when you have creds.")

    term.spacer()
    term.rule("adExec complete")
    term.info(f"All output saved to: {ctx.target_dir}/")


if __name__ == "__main__":
    main()
