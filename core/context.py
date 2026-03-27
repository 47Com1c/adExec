"""
core/context.py — Shared state passed between all phases and modules.
Holds target info, credentials, discovered data, and output paths.
"""

import os
import getpass
from pathlib import Path


class Context:
    def __init__(self, target, domain=None, username=None, password=None,
                 ntlm_hash=None, output_dir="./recon", term=None):
        self.target      = target
        self.domain      = domain         # filled in by phase1 SMB fingerprint
        self.hostname    = None           # filled in by phase1 SMB fingerprint
        self.username    = username
        self.password    = password
        self.ntlm_hash   = ntlm_hash
        self.output_dir  = output_dir
        self.term        = term

        # Discovered data (filled in as phases run)
        self.open_ports  : list  = []     # list of int
        self.services    : dict  = {}     # port -> service string
        self.users       : list  = []     # list of str usernames
        self.shares      : list  = []     # list of str share names
        self.winrm_open  : bool  = False
        self.ldap_open   : bool  = False
        self.smb_open    : bool  = False

        # Paths
        self.target_dir  = None
        self.nmap_dir    = None

    # ------------------------------------------------------------------ #
    #  Directory setup                                                     #
    # ------------------------------------------------------------------ #

    def setup_dirs(self):
        self.target_dir = Path(self.output_dir) / self.target
        self.nmap_dir   = self.target_dir / "nmap"
        self.nmap_dir.mkdir(parents=True, exist_ok=True)
        self.term.info(f"Output directory : {self.target_dir}/")

    # ------------------------------------------------------------------ #
    #  Credential helpers                                                  #
    # ------------------------------------------------------------------ #

    def has_creds(self) -> bool:
        return bool((self.username and self.password is not None) or self.ntlm_hash)

    def prompt_creds(self):
        self.term.spacer()
        self.username = input("  Username : ").strip()
        pwd = getpass.getpass("  Password : ")
        self.password = pwd if pwd else ""
        if not self.username:
            self.username = None

    def cred_string(self) -> str:
        """Return 'DOMAIN/user:pass' or 'DOMAIN/user' for display."""
        domain = self.domain or "."
        user   = self.username or "guest"
        if self.ntlm_hash:
            return f"{domain}/{user} (hash)"
        return f"{domain}/{user}:{self.password}"

    def nxc_auth_flags(self) -> list:
        """Return list of nxc auth flags appropriate for current creds."""
        if self.ntlm_hash:
            lm, nt = self._parse_hash()
            return ["-u", self.username, "-H", nt]
        if self.username and self.password is not None:
            return ["-u", self.username, "-p", self.password]
        return ["-u", "", "-p", ""]

    def impacket_target(self) -> str:
        """Return 'DOMAIN/user:pass@IP' for impacket tools."""
        domain = self.domain or "."
        if self.ntlm_hash:
            return f"{domain}/{self.username}@{self.target}"
        return f"{domain}/{self.username}:{self.password}@{self.target}"

    def _parse_hash(self):
        EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
        h = self.ntlm_hash.strip()
        if ":" in h:
            parts = h.split(":", 1)
            return parts[0], parts[1]
        return EMPTY_LM, h

    # ------------------------------------------------------------------ #
    #  Port helpers                                                        #
    # ------------------------------------------------------------------ #

    def port_open(self, port: int) -> bool:
        return port in self.open_ports

    def ports_csv(self) -> str:
        return ",".join(str(p) for p in sorted(self.open_ports))
