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


def check_dependencies() -> list:
    """Return list of missing REQUIRED tool labels."""
    return [label for binary, label in REQUIRED_TOOLS.items()
            if not shutil.which(binary)]


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None
