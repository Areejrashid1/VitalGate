"""Policy Enforcement Point commands (notebook 06 section 6): ipset entries with a timeout on the site gateway.
Every action expires by itself (fail-open). Here they are only rendered; the gateway service executes them."""
LEVEL_NAME = {0: "allow", 1: "watch", 2: "restrict", 3: "quarantine", 4: "isolate"}
LEVEL_TEXT = {0: "normal zero-trust checks only",
              1: "traffic counted and logged, SOC ticket",
              2: "new DICOM connections limited to 30 per minute, on-call engineer paged",
              3: "DICOM uploads go to the quarantine store for checking; everything else dropped, open connections reset",
              4: "all traffic to and from the host dropped, open connections reset"}


import ipaddress

SETS = {1: "watch", 2: "rate", 3: "quar", 4: "iso"}


def commands(ip, level, ttl, pacs_ip, dicom_port):
    """The nftables commands the PEP agent runs for this level (testbed/pep/rules.nft holds the rules they feed)."""
    if not level: return []
    ip = str(ipaddress.IPv4Address(ip))          # raises ValueError on anything that is not a plain IPv4 address
    if level not in SETS: raise ValueError(f"bad level {level!r}")
    ttl = int(ttl)
    cmds = [f"nft add element ip vg {SETS[level]} {{ {ip} timeout {ttl}s }}"]
    if level == 2: cmds[0] += "   # new DICOM connections limited to 30/min"
    if level == 3: cmds[0] += f"   # DICOM uploads redirected to the quarantine store, all else dropped"; cmds.append(f"conntrack -D -s {ip}")
    if level == 4: cmds += [f"conntrack -D -s {ip}", f"conntrack -D -d {ip}"]
    return cmds
