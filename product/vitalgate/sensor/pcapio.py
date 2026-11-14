"""Classic-pcap reader for files AND live streams (`tcpdump -w -`). Yields (timestamp, ipv4_bytes).
Same link-layer handling as dicom-lab/features/extract_features.py (training extractor)."""
import struct


def _read_exact(f, n):
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def iter_pcap(f, name="<stream>"):
    gh = _read_exact(f, 24)
    if len(gh) < 24:
        return
    magic = gh[:4]
    if magic == b"\xd4\xc3\xb2\xa1": e, div = "<", 1e6
    elif magic == b"\xa1\xb2\xc3\xd4": e, div = ">", 1e6
    elif magic == b"\x4d\x3c\xb2\xa1": e, div = "<", 1e9
    elif magic == b"\xa1\xb2\x3c\x4d": e, div = ">", 1e9
    else:
        raise ValueError(f"{name}: not a classic pcap stream (pcapng is not supported)")
    lt = struct.unpack(e + "I", gh[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(e + "IIII")
    while True:
        h = _read_exact(f, 16)
        if len(h) < 16:
            return
        s, frac, incl, _ = rec.unpack(h)
        d = _read_exact(f, incl)
        if len(d) < incl:
            return
        if lt == 1:
            off, et = 14, d[12:14]
            while et in (b"\x81\x00", b"\x88\xa8"):
                et = d[off + 2:off + 4]; off += 4
            if et != b"\x08\x00":
                continue
        elif lt == 113:
            if d[14:16] != b"\x08\x00": continue
            off = 16
        elif lt == 276:
            if d[0:2] != b"\x08\x00": continue
            off = 20
        elif lt in (101, 12, 228):
            off = 0
        else:
            raise ValueError(f"{name}: unsupported link type {lt}")
        yield s + frac / div, d[off:]


def read_pcap(path):
    with open(path, "rb") as f:
        yield from iter_pcap(f, path)
