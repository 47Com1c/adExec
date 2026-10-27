"""
core/env.py — Check that external tools are available on PATH.
"""

import shutil

REQUIRED_TOOLS = {
    "nmap":        "nmap",
    "nxc":         "netexec (nxc)",
    "ldapsearch":  "ldap-utils",
}

OPTIONAL_TOOLS = {
    "enum4linux-ng":        "enum4linux-ng",
    "rpcclient":            "samba-common-bin (rpcclient)",
    "impacket-GetNPUsers":  "impacket",
    "impacket-GetUserSPNs": "impacket",
    "certipy":              "certipy-ad",
    "kerbrute":             "kerbrute",
    "bloodhound-python":    "bloodhound-python",
}

# Some tools ship under different binary names depending on how they were
# installed. Kali's package wraps impacket scripts as `impacket-GetNPUsers`,
# while a pip/GitHub install exposes them as `GetNPUsers.py`. We accept either.
TOOL_ALIASES = {
    "impacket-GetNPUsers":  ["impacket-GetNPUsers", "GetNPUsers.py", "getNPUsers.py"],
    "impacket-GetUserSPNs": ["impacket-GetUserSPNs", "GetUserSPNs.py", "getUserSPNs.py"],
    "impacket-secretsdump": ["impacket-secretsdump", "secretsdump.py"],
    "enum4linux-ng":        ["enum4linux-ng", "enum4linux-ng.py"],
    "certipy":              ["certipy", "certipy-ad"],
    "bloodhound-python":    ["bloodhound-python", "bloodhound-ce-python"],
}


def resolve_tool(name: str):
    """Return the first binary name that exists on PATH for `name`, or None."""
    for candidate in TOOL_ALIASES.get(name, [name]):
        if shutil.which(candidate):
            return candidate
    return None


def check_dependencies() -> list:
    """Return list of missing REQUIRED tool labels."""
    return [label for binary, label in REQUIRED_TOOLS.items()
            if resolve_tool(binary) is None]


def tool_available(binary: str) -> bool:
    return resolve_tool(binary) is not None
