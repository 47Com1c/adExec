"""
core/parsers.py — Parse raw tool output into structured data.
"""

import re


# ------------------------------------------------------------------ #
#  Nmap parsers                                                        #
# ------------------------------------------------------------------ #

def parse_open_ports(nmap_grep_output: str) -> list:
    """
    Extract open port numbers from nmap -oG output.
    Matches patterns like: 22/open, 445/open
    """
    return [int(p) for p in re.findall(r"(\d+)/open", nmap_grep_output)]


def parse_services(nmap_scan_output: str) -> dict:
    """
    Extract port -> service mapping from nmap -sCV output.
    Returns dict like {445: 'microsoft-ds', 389: 'ldap', ...}
    """
    services = {}
    for line in nmap_scan_output.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            services[int(m.group(1))] = m.group(2)
    return services


# ------------------------------------------------------------------ #
#  NXC / SMB parsers                                                   #
# ------------------------------------------------------------------ #

def parse_smb_info(nxc_output: str) -> tuple:
    """
    Extract (hostname, domain) from nxc SMB output.
    Example line:
      SMB  10.10.10.10  445  DC01  [*] Windows Server ... (name:DC01) (domain:htb.local)
    Returns (hostname, domain) or (None, None).
    """
    m = re.search(r"\(name:([^)]+)\).*\(domain:([^)]+)\)", nxc_output)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return None, None


def parse_rid_users(nxc_output: str) -> list:
    """
    Extract usernames from nxc --rid-brute output filtered to SidTypeUser.
    Example line:
      500: DOMAIN\\Administrator (SidTypeUser)
    Returns list of bare usernames.
    """
    users = []
    for line in nxc_output.splitlines():
        if "SidTypeUser" in line:
            m = re.search(r"\\(\w[\w\s\-\.]+)\s+\(SidTypeUser\)", line)
            if m:
                user = m.group(1).strip()
                # Skip built-in noise
                if user not in ("Guest", "DefaultAccount", "WDAGUtilityAccount", "krbtgt"):
                    users.append(user)
    return list(dict.fromkeys(users))   # deduplicate, preserve order


def parse_shares(nxc_output: str) -> list:
    """
    Extract readable share names from nxc --shares output.
    Returns list of share name strings.
    """
    shares = []
    for line in nxc_output.splitlines():
        # Lines look like: [*] share_name  READ  comment
        m = re.search(r"\s+(\S+)\s+(READ|WRITE|READ,WRITE)", line, re.IGNORECASE)
        if m:
            shares.append(m.group(1))
    return shares


# ------------------------------------------------------------------ #
#  LDAP parsers                                                        #
# ------------------------------------------------------------------ #

def parse_ldap_users_with_desc(ldap_output: str) -> list:
    """
    Parse ldapsearch output for users that have a description set.
    Returns list of (sAMAccountName, description) tuples.
    """
    results = []
    current_user = None
    current_desc = None

    for line in ldap_output.splitlines():
        line = line.strip()
        if line.startswith("sAMAccountName:"):
            current_user = line.split(":", 1)[1].strip()
            current_desc = None
        elif line.startswith("description:"):
            current_desc = line.split(":", 1)[1].strip()
        elif line == "" and current_user and current_desc:
            results.append((current_user, current_desc))
            current_user = None
            current_desc = None

    return results


def parse_group_members(ldap_output: str, group_name: str) -> list:
    """
    Parse ldapsearch output for member DNs of a specific group.
    Returns list of CN values extracted from member DNs.
    """
    members = []
    in_group = False
    for line in ldap_output.splitlines():
        line = line.strip()
        if f"cn={group_name.lower()}" in line.lower() or in_group:
            in_group = True
        if in_group and line.startswith("member:"):
            dn = line.split(":", 1)[1].strip()
            m = re.match(r"CN=([^,]+)", dn, re.IGNORECASE)
            if m:
                members.append(m.group(1))
        if in_group and line == "" and members:
            break
    return members


# ------------------------------------------------------------------ #
#  AS-REP / Kerberos parsers                                           #
# ------------------------------------------------------------------ #

def parse_asrep_hashes(impacket_output: str) -> list:
    """
    Extract AS-REP hash lines from GetNPUsers output.
    Returns list of hash strings (lines starting with $krb5asrep$).
    """
    return [
        line.strip()
        for line in impacket_output.splitlines()
        if line.strip().startswith("$krb5asrep$")
    ]
