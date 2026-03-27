"""
core/env.py — Check that required external tools are available on PATH.
"""

import shutil

REQUIRED_TOOLS = {
    "nmap":                 "nmap",
    "nxc":                  "netexec (nxc)",
    "impacket-GetNPUsers":  "impacket",
    "ldapsearch":           "ldap-utils",
}

OPTIONAL_TOOLS = {
    "kerbrute":           "kerbrute",
    "evil-winrm":         "evil-winrm",
    "bloodhound-python":  "bloodhound-python",
}


def check_dependencies() -> list:
    """Return list of missing required tool labels."""
    return [label for binary, label in REQUIRED_TOOLS.items()
            if not shutil.which(binary)]


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None
