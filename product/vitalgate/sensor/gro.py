"""Layer 1a: packet normalisation (software GRO). Makes any capture look like the training capture.

Why: the training lab captured inside a Docker veth, where the kernel hands tcpdump one "super-packet" per
application write (GSO/GRO, up to 64 KB) and the capture keeps the first 512 bytes. Packet counts, sizes and the
DICOM PDU counts in the features all depend on that view. A real switch port, or another sender (DCMTK instead of
pynetdicom), shows ordinary MTU-sized segments instead, so the same behaviour produces different numbers.

What: consecutive in-order data segments of one TCP direction are merged like Linux GRO does: same 4-tuple,
contiguous sequence numbers, only ACK/PSH flags, arriving within GAP_S of each other; the merged packet ends at
a PSH segment (end of an application write) or at 64 KB. The merged packet is then cut to the training snap
length (512 bytes of frame). Packets that are not mergeable pass through unchanged (also cut to the snap length).
Input and output: (timestamp, raw IPv4 bytes) in capture order; the merged packet keeps its first segment's time."""
import struct

U16 = struct.Struct("!H").unpack_from
U32 = struct.Struct("!I").unpack_from
MAX_LEN = 65535
GAP_S = 0.002          # segments of one write arrive back to back; anything slower is a new write
SNAP = 512             # training capture snap length (whole frame)
ETH = 14               # Ethernet header counted in the snap length


class Coalescer:
    def __init__(self, gap_s=GAP_S, snap=SNAP, max_len=MAX_LEN):
        self.gap, self.snap, self.max = gap_s, snap, max_len
        self.pend = {}                 # flow -> [t0, t_last, hdr(bytearray ip+tcp), cap(bytearray), plen, next_seq, ihl, doff]
        self.stats = dict(in_pkts=0, out_pkts=0, merged=0)

    def _cut(self, ihl, doff):
        return max(self.snap - ETH - ihl - doff, 0)

    def _emit(self, flow):
        t0, _, hdr, cap, plen, _, ihl, doff = self.pend.pop(flow)
        struct.pack_into("!H", hdr, 2, min(ihl + doff + plen, 0xFFFF))
        self.stats["out_pkts"] += 1
        return (t0, bytes(hdr) + bytes(cap[:self._cut(ihl, doff)]))

    def _expire(self, t):
        return [self._emit(k) for k in [k for k, p in self.pend.items() if t - p[1] > self.gap]]

    def feed(self, t, ip):
        self.stats["in_pkts"] += 1
        out = self._expire(t) if self.pend else []
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            self.stats["out_pkts"] += 1
            return out + [(t, ip)]
        ihl = (ip[0] & 15) * 4; tot = U16(ip, 2)[0]; tcp = ip[ihl:]
        if len(tcp) < 20:
            self.stats["out_pkts"] += 1
            return out + [(t, ip)]
        doff = (tcp[12] >> 4) * 4; fl = tcp[13]; seq = U32(tcp, 4)[0]
        plen = tot - ihl - doff
        flow = (ip[12:16], ip[16:20], tcp[0:2], tcp[2:4])
        data_only = plen > 0 and (fl & 0x10) and not (fl & 0x27)        # ACK set; no SYN, FIN, RST, URG
        psh = bool(fl & 0x08)
        p = self.pend.get(flow)
        if p is not None:
            if data_only and seq == p[5] and p[4] + plen <= self.max - ihl - doff and t - p[1] <= self.gap:
                if len(p[3]) == p[4]:                                     # everything so far captured: append
                    p[3] += tcp[doff:doff + plen][:max(self._cut(ihl, doff) - len(p[3]), 0)]
                p[4] += plen; p[5] = (seq + plen) & 0xFFFFFFFF; p[1] = t
                p[2][ihl + 13] |= fl                                     # keep PSH of the last segment
                self.stats["merged"] += 1
                if psh:
                    out.append(self._emit(flow))
                return out
            out.append(self._emit(flow))                                  # not mergeable: close the open one first
        if data_only and not psh:
            self.pend[flow] = [t, t, bytearray(ip[:ihl + doff]), bytearray(tcp[doff:doff + plen][:self._cut(ihl, doff)]),
                               plen, (seq + plen) & 0xFFFFFFFF, ihl, doff]
            return out
        self.stats["out_pkts"] += 1
        return out + [(t, ip[:ihl + doff + self._cut(ihl, doff)] if plen > 0 else ip)]

    def flush_all(self):
        return [self._emit(k) for k in list(self.pend)]
