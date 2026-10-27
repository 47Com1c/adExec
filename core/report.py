"""
core/report.py — Serialize a completed run into recon/<target>/report.json.

report.json is the single source of truth the web viewer reads. It flattens
every step's findings into a top-level list (for the dashboard) and keeps the
full per-step records (command, raw output, tables) for the detail panes.
"""

import json
from pathlib import Path

from core.steps import all_categories, SEVERITY_LABELS

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_report(ctx) -> dict:
    results = [r.as_dict() for r in ctx.results]

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    findings_flat = []
    for r in ctx.results:
        for f in r.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            findings_flat.append({
                "severity": f.severity,
                "text":     f.text,
                "hint":     f.hint,
                "step":     r.name,
                "step_id":  r.id,
                "category": r.category,
            })

    # Loudest findings first so the dashboard reads top-down by risk.
    findings_flat.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"])
                       if f["severity"] in SEVERITY_ORDER else 99)

    status_counts = {}
    for r in ctx.results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

    return {
        "target":          ctx.target,
        "domain":          ctx.domain,
        "hostname":        ctx.hostname,
        "domain_sid":      ctx.domain_sid,
        "creds":           ctx.cred_string() if ctx.has_creds() else None,
        "started_at":      ctx.started_at,
        "finished_at":     ctx.finished_at,
        "open_ports":      sorted(ctx.open_ports),
        "users":           ctx.users,
        "shares":          ctx.shares,
        "categories":      [c for c in all_categories()
                            if any(r.category == c for r in ctx.results)],
        "severity_counts": severity_counts,
        "severity_labels": SEVERITY_LABELS,
        "status_counts":   status_counts,
        "findings":        findings_flat,
        "results":         results,
    }


def write_report(ctx) -> Path:
    path = ctx.target_dir / "report.json"
    path.write_text(json.dumps(build_report(ctx), indent=2, default=str))
    return path
