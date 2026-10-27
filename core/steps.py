"""
core/steps.py — Declarative step registry.

A Step is a single enumeration command described as data:
  - what it is (id, name, category, phase)
  - when it may run (tool availability + requires conditions)
  - how to build the command (build_cmd)
  - how to turn raw output into findings/rows (parse)

Steps register themselves at import time via register(). The engine
(core/engine.py) walks the registry, honours the conditions, runs each
command through the Runner, and records a StepResult on the Context.
"""

from dataclasses import dataclass, field, asdict
from typing import Callable, Optional


# ------------------------------------------------------------------ #
#  Finding severities                                                  #
# ------------------------------------------------------------------ #

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

# Severities that deserve the [FIND] highlight in the terminal.
_LOUD = {CRITICAL, HIGH, MEDIUM}


@dataclass
class Finding:
    severity: str          # one of the constants above
    text: str
    hint: str = ""         # optional follow-up / attack note

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class StepResult:
    id: str
    name: str
    category: str
    phase: int
    command: str                       # the exact command that ran (display)
    status: str                        # ok | error | skipped | no_tool
    returncode: Optional[int] = None
    duration: float = 0.0
    raw_output: str = ""
    note: str = ""                     # skip reason / error context
    findings: list = field(default_factory=list)   # list[Finding]
    rows: list = field(default_factory=list)        # list[dict] (table data)
    columns: list = field(default_factory=list)     # column order for rows

    def as_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.as_dict() for f in self.findings]
        return d


# A parser takes (raw_output, ctx) and returns (findings, rows, columns).
ParseFn = Callable[[str, object], tuple]


@dataclass
class Step:
    id: str
    name: str
    category: str
    phase: int                         # 1 = unauthenticated, 2 = authenticated
    build_cmd: Callable                # ctx -> list[str] | None  (None = skip)
    tool: Optional[str] = None         # binary that must be on PATH
    requires: list = field(default_factory=list)   # list[Cond]
    parse: Optional[ParseFn] = None
    save_name: Optional[str] = None    # filename under target_dir for raw output
    timeout: int = 300
    cwd: Optional[Callable] = None     # ctx -> working directory for the command


# ------------------------------------------------------------------ #
#  Conditions — gate whether a step runs, with a human skip reason    #
# ------------------------------------------------------------------ #

class Cond:
    def __init__(self, fn: Callable, reason: str):
        self.fn = fn
        self.reason = reason

    def __call__(self, ctx) -> bool:
        return bool(self.fn(ctx))


HAS_CREDS    = Cond(lambda c: c.has_creds(),
                    "no credentials")
HAS_USERPASS = Cond(lambda c: bool(c.username and c.password is not None),
                    "needs username + password (NTLM hash not supported here)")
HAS_DOMAIN   = Cond(lambda c: bool(c.domain),
                    "domain unknown")
HAS_USERS    = Cond(lambda c: bool(c.users),
                    "no users enumerated yet")
HAS_PORTS    = Cond(lambda c: bool(c.open_ports),
                    "no open ports from scan")
SMB_OPEN     = Cond(lambda c: c.smb_open,
                    "SMB not open")
LDAP_OPEN    = Cond(lambda c: c.ldap_open,
                    "LDAP not open")
WINRM_OPEN   = Cond(lambda c: c.winrm_open,
                    "WinRM not open")


def PORT(*ports: int) -> Cond:
    label = "/".join(str(p) for p in ports)
    return Cond(lambda c: any(c.port_open(p) for p in ports),
                f"port {label} not open")


# ------------------------------------------------------------------ #
#  Registry                                                            #
# ------------------------------------------------------------------ #

REGISTRY: list = []


def register(step: Step) -> Step:
    REGISTRY.append(step)
    return step


def steps_for_phase(phase: int) -> list:
    return [s for s in REGISTRY if s.phase == phase]


def all_categories() -> list:
    seen = []
    for s in REGISTRY:
        if s.category not in seen:
            seen.append(s.category)
    return seen
