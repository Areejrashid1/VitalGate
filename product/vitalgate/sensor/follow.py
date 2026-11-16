"""Live input: follow the pcap files tcpdump is writing (-U -G rotation) and return new packets as they arrive.
Starts at the beginning of the newest file (a few minutes of backlog warm up the per-host history), then keeps
reading; when the file stops growing and a newer one exists, moves on. Same link-layer handling as pcapio."""
import struct
from pathlib import Path

_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
          b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}


class PcapFollower:
    def __init__(self, folder, pattern="*.pcap", start="newest"):
        self.dir, self.pattern = Path(folder), pattern
        self.cur, self.f, self.buf, self.hdr = None, None, b"", None
        self.files_done, self.packets = 0, 0
        files = self._files()
        if files:
            if start == "newest": self._open(files[-1])
            elif start == "oldest": self._open(files[0])
            else:                                     # a file name (or prefix): start at the first file >= it
                later = [f for f in files if f.name >= start]
                self._open(later[0] if later else files[-1])

    def _files(self):
        return sorted(self.dir.glob(self.pattern))

    def _open(self, path):
        if self.f: self.f.close()
        self.cur, self.f, self.buf, self.hdr = path, open(path, "rb"), b"", None

    def _parse_header(self):
        if len(self.buf) < 24: return False
        gh = self.buf[:24]; self.buf = self.buf[24:]
        if gh[:4] not in _MAGIC: raise ValueError(f"{self.cur}: not a classic pcap")
        e, div = _MAGIC[gh[:4]]
        self.hdr = (struct.Struct(e + "IIII"), div, struct.unpack(e + "I", gh[20:24])[0] & 0x0FFFFFFF)
        return True

    @staticmethod
    def _ip(d, lt):
        if lt == 1:
            off, et = 14, d[12:14]
            while et in (b"\x81\x00", b"\x88\xa8"):
                et = d[off + 2:off + 4]; off += 4
            return d[off:] if et == b"\x08\x00" else None
        if lt == 113: return d[16:] if d[14:16] == b"\x08\x00" else None
        if lt == 276: return d[20:] if d[0:2] == b"\x08\x00" else None
        if lt in (101, 12, 228): return d
        return None

    def poll(self, max_packets=200000):
        """Return the packets that arrived since the last call: list of (timestamp, ipv4 bytes)."""
        out = []
        if self.f is None:
            files = self._files()
            if not files: return out
            self._open(files[-1])
        while len(out) < max_packets:
            chunk = self.f.read(1 << 20)
            if chunk:
                self.buf += chunk
            if self.hdr is None and not self._parse_header():
                if not chunk: break
                continue
            rec, div, lt = self.hdr; pos = 0; n = len(self.buf)
            while pos + 16 <= n:
                s, frac, incl, _ = rec.unpack_from(self.buf, pos)
                if pos + 16 + incl > n: break
                ip = self._ip(self.buf[pos + 16:pos + 16 + incl], lt)
                if ip is not None: out.append((s + frac / div, ip))
                pos += 16 + incl
            self.buf = self.buf[pos:]
            if not chunk:
                newer = [f for f in self._files() if f.name > self.cur.name]
                if newer and not self.buf:            # current file finished (tcpdump rotated): move on
                    self._open(newer[0]); self.files_done += 1; continue
                break
        self.packets += len(out)
        return out
