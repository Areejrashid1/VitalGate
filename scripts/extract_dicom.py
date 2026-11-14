"""
extract_dicom.py - DICOM command features + host roles from the raw pcaps (no extra packages).

The pcaps were captured with snaplen 512, so large DICOM data PDUs are cut off and TCP streams cannot be
fully reassembled. DICOM command messages are small (< 300 bytes), so each TCP segment is parsed on its own:
every PDU whose header (and, for commands, whole body) lies inside the captured bytes is read. Headers are
validated strictly (PDU type, reserved byte, PDV length, command group 0000) so pixel data is not misread.

Counts per (client_ip, 2-second window) - the same key as features.parquet (window_start = floor(ts/2)*2):
    cmd_store_out   C-STORE-RQ sent by the client to the PACS        (writes: normal modality upload / ransomware)
    cmd_store_in    C-STORE-RQ sent by the PACS to the client        (images pulled out via C-GET: exfiltration)
    cmd_find        C-FIND-RQ  sent by the client                    (queries)
    find_matches    C-FIND-RSP pending (FF00/FF01) to the client     (number of query results returned)
    cmd_get         C-GET-RQ   sent by the client
    cmd_move        C-MOVE-RQ  sent by the client
    cmd_echo        C-ECHO-RQ  sent by the client
    cmd_fail        responses to the client with a failure status

Also writes hosts.csv (one row per IP: site, packets, AE-title prefixes, commands sent, suggested role) for
the notebook-06 device-criticality table. AE titles are NOT model features (some are generator artefacts, e.g. RW_*).

Run from the repo root (takes a few minutes for all pcaps):
    python scripts/extract_dicom.py "C:\\Users\\rashi\\Desktop\\Netsol project dataset\\pcap" data/processed
"""
import struct, sys, re, collections
from pathlib import Path
import pandas as pd

PACS_SUFFIX = ".10"                    # the PACS server of each site (10.77.<site>.10)
WIN = 2                                # seconds, same windows as features.parquet
REQ = {0x0001: "store", 0x0020: "find", 0x0010: "get", 0x0021: "move", 0x0030: "echo"}
COLS = ["cmd_store_out", "cmd_store_in", "cmd_find", "find_matches", "cmd_get", "cmd_move", "cmd_echo", "cmd_fail"]
AE_OK = re.compile(r"^[A-Z]{2,4}_[0-9A-F]{3,6}$")
MODALITIES = {"CT", "MR", "DX", "CR", "US", "MG", "NM", "XA", "PT", "RF"}


def read_command(b):
    """(command_field, status) from a DIMSE command set, implicit VR LE. None if it is not a valid command set."""
    if len(b) < 12: return None, None
    g, e, ln = struct.unpack_from("<HHI", b, 0)
    if (g, e, ln) != (0, 0, 4): return None, None                      # must start with (0000,0000) UL, length 4
    cmd = status = None; i = 0
    while i + 8 <= len(b):
        g, e, ln = struct.unpack_from("<HHI", b, i)
        if g != 0 or i + 8 + ln > len(b): break
        if e == 0x0100 and ln == 2: cmd = struct.unpack_from("<H", b, i + 8)[0]
        if e == 0x0900 and ln == 2: status = struct.unpack_from("<H", b, i + 8)[0]
        i += 8 + ln
    return cmd, status


def pdus(seg, i=0):
    """Yield (type, body) for every complete-enough PDU in a captured TCP segment, starting at offset i."""
    while i + 6 <= len(seg):
        t, r, ln = seg[i], seg[i + 1], struct.unpack_from(">I", seg, i + 2)[0]
        if t not in (1, 2, 3, 4, 5, 6, 7) or r != 0 or ln > 1 << 24: return
        if t == 4:                                                       # P-DATA-TF: check the first PDV item
            if i + 12 > len(seg): return
            pdv = struct.unpack_from(">I", seg, i + 6)[0]
            if pdv < 2 or pdv > ln - 4 or seg[i + 11] > 3: return
        yield t, seg[i + 6: i + 6 + ln]                                  # may be cut short by snaplen
        i += 6 + ln


def packets(path):
    data = Path(path).read_bytes(); magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"): end, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"): end, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    else: raise ValueError(f"{path}: not a classic pcap file (convert pcapng with editcap -F pcap)")
    link = struct.unpack_from(end + "I", data, 20)[0]; off = 24
    while off + 16 <= len(data):
        ts, frac, incl, _ = struct.unpack_from(end + "IIII", data, off)
        p = data[off + 16: off + 16 + incl]; off += 16 + incl
        if link == 1:
            if len(p) < 14: continue
            eth = struct.unpack_from(">H", p, 12)[0]; p = p[14:]
            if eth == 0x8100 and len(p) >= 4: eth = struct.unpack_from(">H", p, 2)[0]; p = p[4:]
            if eth != 0x0800: continue
        elif link == 113: p = p[16:]
        elif link != 101: continue
        if len(p) < 20 or p[0] >> 4 != 4 or p[9] != 6: continue
        ihl = (p[0] & 15) * 4; tcp = p[ihl:]
        if len(tcp) < 20: continue
        sp, dp = struct.unpack_from(">HH", tcp, 0)
        yield (ts + frac / (1e9 if nano else 1e6), ".".join(map(str, p[12:16])), ".".join(map(str, p[16:20])),
               sp, dp, tcp[(tcp[12] >> 4) * 4:])


def main(pcap_dir, out_dir):
    pcap_dir, out_dir = Path(pcap_dir), Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(pcap_dir.glob("*.pcap"))
    if not files: sys.exit(f"no .pcap files in {pcap_dir}")
    win = collections.defaultdict(lambda: dict.fromkeys(COLS, 0))
    ae, sent, pk, site_of = (collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter),
                             collections.Counter(), {})
    for n, f in enumerate(files, 1):
        site = f.name.split("_")[0].replace("site", "")
        pending = {}                                                     # flow -> command bytes still to come
        for t, src, dst, sp, dp, pl in packets(f):
            pk[src] += 1; site_of.setdefault(src, site)
            if dst.endswith(PACS_SUFFIX) and not src.endswith(PACS_SUFFIX):   client, to_server = src, True
            elif src.endswith(PACS_SUFFIX) and not dst.endswith(PACS_SUFFIX): client, to_server = dst, False
            else: continue
            if not pl: continue
            w, flow, start = int(t // WIN) * WIN, (src, sp, dst, dp), 0

            def command(cmd_bytes):
                cmd, status = read_command(cmd_bytes)
                if cmd is None: return
                row = win[(client, w)]
                if cmd in REQ:
                    name = REQ[cmd]; sent[src][name] += 1
                    if name == "store": row["cmd_store_out" if to_server else "cmd_store_in"] += 1
                    elif to_server: row[f"cmd_{name}"] += 1
                elif not to_server and status is not None:
                    if cmd == 0x8020 and status in (0xFF00, 0xFF01): row["find_matches"] += 1
                    elif status not in (0x0000, 0xFF00, 0xFF01) and (status >> 12) != 0xB: row["cmd_fail"] += 1

            if flow in pending:                                          # command body sent in the next segment
                got, need = pending.pop(flow)
                take = pl[:need - len(got)]; got += take
                if len(got) == need: command(got); start = len(take)
            for ptype, body in pdus(pl, start):
                if ptype == 1 and to_server and len(body) >= 36:            # A-ASSOCIATE-RQ -> calling AE title
                    title = body[20:36].decode("ascii", "replace").strip()
                    ae[src][title.split("_")[0] if AE_OK.match(title) else "(non-standard)"] += 1
                elif ptype == 4 and len(body) >= 6 and (body[5] & 1):       # command PDV
                    need = struct.unpack_from(">I", body, 0)[0] - 2
                    got = body[6: 6 + need]
                    if len(got) == need: command(got)
                    elif need <= 1024: pending[flow] = (got, need)
        if n % 25 == 0 or n == len(files): print(f"[{n}/{len(files)}] {f.name}")

    D = pd.DataFrame([dict(client_ip=c, window_start=w, **v) for (c, w), v in win.items()])
    D = D.sort_values(["client_ip", "window_start"]).reset_index(drop=True)
    D.to_parquet(out_dir / "dicom_cmds.parquet", index=False)

    rows = []
    for ip in sorted(pk, key=lambda s: tuple(int(x) for x in s.split("."))):
        a, s = ae[ip], sent[ip]
        mods = sum(v for k, v in a.items() if k in MODALITIES)
        role = ("PACS server" if ip.endswith(PACS_SUFFIX) else "attacker (outside host)" if ip.endswith(".99")
                else "modality" if mods > a.get("WS", 0) else "workstation" if a.get("WS", 0) else "unknown")
        rows.append(dict(ip=ip, site=site_of.get(ip), packets=pk[ip], suggested_role=role,
                         ae_prefixes=dict(a.most_common()), commands_sent=dict(s.most_common())))
    H = pd.DataFrame(rows); H.to_csv(out_dir / "hosts.csv", index=False, encoding="utf-8-sig")
    print(f"\nwrote {len(D):,} windows with DICOM commands -> {out_dir / 'dicom_cmds.parquet'}")
    print(D[COLS].sum().to_string(), "\n")
    print(H[["ip", "site", "packets", "suggested_role", "ae_prefixes", "commands_sent"]].to_string(index=False))


if __name__ == "__main__":
    if len(sys.argv) != 3: sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
