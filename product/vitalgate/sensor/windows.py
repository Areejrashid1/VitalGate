"""Layer 1 (ingestion): packets -> 2 s windows per (client_ip), identical definitions to the training extractor
(dicom-lab/features/extract_features.py v2). The DICOM stream parser, new_row() and finish() are copied unchanged
from that file; WindowBuilder is parse_site() turned into an incremental, packet-at-a-time object so it can run
on a live capture. Only the window *emission* timing is configurable (flush_lag); row contents are identical."""
import socket, struct
import numpy as np

MAX_PDU = 1 << 24
U16 = struct.Struct(">H").unpack_from
U32 = struct.Struct(">I").unpack_from
OUT_TYPES = {1: "assoc_rq", 4: "pdata", 5: "release", 7: "abort"}
IN_TYPES = {2: "assoc_ac", 3: "assoc_rj", 7: "abort"}


def plausible_pdu_start(p):
    """Used only to resynchronise after a gap in the byte stream: does p look like the start of a DICOM PDU?"""
    if len(p) < 6 or p[1] != 0:
        return False
    t, L = p[0], U32(p, 2)[0]
    if t == 4:
        if not 6 <= L <= MAX_PDU: return False
        return len(p) < 12 or (2 <= U32(p, 6)[0] <= L and p[10] % 2 == 1 and p[11] <= 3)
    if t in (3, 5, 6, 7): return L == 4
    if t in (1, 2): return 68 <= L <= 65536
    return False


class Stream:
    """One direction of one TCP connection on the DICOM port."""
    __slots__ = ("nxt", "synced", "hdr", "want", "skip", "syn", "first", "last")

    def __init__(self, nxt, from_syn, t):
        self.nxt = nxt; self.synced = from_syn; self.hdr = bytearray(); self.want = 0; self.skip = 0
        self.syn = from_syn; self.first = from_syn; self.last = t

    def feed(self, seq, pl, plen):
        """Consume one segment. Returns a list of ('pdu', type, length) and ('ae', called, calling) events."""
        ev = []
        rel = ((seq - self.nxt + 0x80000000) & 0xFFFFFFFF) - 0x80000000
        if rel < 0:                                       # retransmission / overlap
            if rel + plen <= 0:
                return ev
            cut = -rel; pl = pl[cut:]; plen -= cut; seq = self.nxt
        elif rel > 0:                                     # bytes missing from the capture
            self.synced = False
        self.nxt = (seq + plen) & 0xFFFFFFFF
        if not self.synced:
            if not plausible_pdu_start(pl):
                return ev
            self.synced = True; self.hdr.clear(); self.want = 0; self.skip = 0; self.first = False
        i, n = 0, len(pl)
        while i < n:
            if self.skip:
                k = min(self.skip, n - i); self.skip -= k; i += k
                continue
            want = self.want or 6
            k = min(want - len(self.hdr), n - i)
            self.hdr += pl[i:i + k]; i += k
            if len(self.hdr) < want:
                break
            t, L = self.hdr[0], U32(self.hdr, 2)[0]
            if not self.want:                             # header just completed
                ev.append(("pdu", t, L))
                self.want = 42 if (t == 1 and L >= 36) else 6
                if self.want > 6:
                    continue
            else:                                         # first 42 bytes of an A-ASSOC-RQ
                ev.append(("ae", bytes(self.hdr[10:26]), bytes(self.hdr[26:42])))
            if L > MAX_PDU:                               # absurd length: drop sync, look for the next PDU start
                self.synced = False; self.hdr.clear(); self.want = 0
                return ev
            self.skip = 6 + L - len(self.hdr); self.hdr.clear(); self.want = 0
        if len(pl) < plen:                                # payload not fully captured (snaplen)
            self.synced = False
        return ev


# ----------------------------------------------------------------------------------------------- windows
def new_row():
    return dict(out_pkts=0, out_bytes=0, in_pkts=0, in_bytes=0, s_n=0, s_sum=0.0, s_sq=0.0, last_ts=None,
                i_n=0, i_sum=0.0, i_sq=0.0, syn=0, rst=0, fin=0, dst_ports=set(), src_ports=set(),
                assoc_rq=0, assoc_ac=0, assoc_rj=0, abort=0, release=0, pdata=0, called=set(), calling=set(),
                bad_first=0, big_len=0, http_post=0, preamble_exec=0)


def finish(site, client, w, r):
    if r["s_n"]:
        mp = r["s_sum"] / r["s_n"]; sp = np.sqrt(max(r["s_sq"] / r["s_n"] - mp * mp, 0.0))
    else:
        mp = sp = 0.0
    if r["i_n"]:
        mi = r["i_sum"] / r["i_n"]; si = np.sqrt(max(r["i_sq"] / r["i_n"] - mi * mi, 0.0))
    else:
        mi = si = 0.0
    return dict(site=site, client_ip=socket.inet_ntoa(client), window_start=w, out_pkts=r["out_pkts"],
                out_bytes=r["out_bytes"], in_pkts=r["in_pkts"], in_bytes=r["in_bytes"], mean_pkt=mp, std_pkt=sp,
                mean_iat=mi, std_iat=si, syn=r["syn"], rst=r["rst"], fin=r["fin"],
                n_dst_ports=len(r["dst_ports"]), n_src_ports=len(r["src_ports"]),
                assoc_rq=r["assoc_rq"], assoc_ac=r["assoc_ac"], assoc_rj=r["assoc_rj"], abort=r["abort"],
                release=r["release"], pdata_pkts=r["pdata"], n_called_ae=len(r["called"]),
                n_calling_ae=len(r["calling"]), bad_first_pdu=r["bad_first"], big_pdu_len=r["big_len"],
                http_post=r["http_post"], preamble_exec=r["preamble_exec"])


class WindowBuilder:
    """Feed packets in time order with feed(t, ip_bytes); finished window rows are returned as dicts.
    One builder per protected server (PACS). flush_lag = seconds behind the newest packet after which a window is
    final (training used 10 s; live use ~1 s so alerts are not delayed)."""

    def __init__(self, site, pacs_ip, dicom_port, http_port=8042, win=2, flush_lag=10.0, idle_drop=900.0,
                 flush_every=30.0):
        self.site, self.win, self.flush_lag, self.idle_drop, self.flush_every = site, win, flush_lag, idle_drop, flush_every
        self.pacs = socket.inet_aton(pacs_ip); self.dport = dicom_port; self.http = http_port
        self.rows, self.streams = {}, {}
        self.last_t = None; self.flushed_below = -1.0; self.next_flush = None; self.late = 0

    def _flush(self, cut):
        done = [k for k in self.rows if k[1] < cut]
        return [finish(self.site, k[0], k[1], self.rows.pop(k)) for k in sorted(done, key=lambda k: (k[1], k[0]))]

    def tick(self, now):
        """Call periodically on a live sensor (no packets = no flush otherwise)."""
        cut = int((now - self.flush_lag) // self.win) * self.win
        if cut <= self.flushed_below:
            return []
        self.flushed_below = cut
        return self._flush(cut)

    def flush_all(self):
        return self._flush(float("inf"))

    def feed(self, t, ip):
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            return []
        if self.last_t is None:
            self.last_t = t; self.next_flush = t + self.flush_every
        elif t > self.last_t:
            self.last_t = t
        ihl = (ip[0] & 15) * 4
        tot = U16(ip, 2)[0]
        tcp = ip[ihl:]
        if len(tcp) < 20:
            return []
        sp, dp = U16(tcp, 0)[0], U16(tcp, 2)[0]
        seq = U32(tcp, 4)[0]; doff = (tcp[12] >> 4) * 4; f = tcp[13]
        plen = tot - ihl - doff
        payload = tcp[doff:doff + plen] if plen > 0 else b""
        to_pacs = ip[16:20] == self.pacs
        if not to_pacs and ip[12:16] != self.pacs:
            return []                                   # not PACS traffic (training capture only saw PACS traffic)
        client = ip[12:16] if to_pacs else ip[16:20]
        if client == self.pacs:
            return []
        w = int(t // self.win) * self.win
        key = (client, w)
        r = self.rows.get(key)
        if r is None:
            if w < self.flushed_below:
                self.late += 1
            r = self.rows[key] = new_row()
        streams, dport = self.streams, self.dport
        if to_pacs:
            r["out_pkts"] += 1; r["out_bytes"] += tot
            r["s_n"] += 1; r["s_sum"] += tot; r["s_sq"] += tot * tot
            if r["last_ts"] is not None:
                d = t - r["last_ts"]; r["i_n"] += 1; r["i_sum"] += d; r["i_sq"] += d * d
            r["last_ts"] = t
            r["dst_ports"].add(dp); r["src_ports"].add(sp)
            is_syn = f & 0x02 and not f & 0x10
            if is_syn:
                r["syn"] += 1
            if dp == self.http and payload:
                head = payload[:512]
                if head.startswith(b"POST"): r["http_post"] += 1
                i = head.find(b"DICM")
                if i >= 128 and (head[i - 128:i - 126] == b"MZ" or head[i - 128:i - 124] == b"\x7fELF"):
                    r["preamble_exec"] += 1
            elif dp == dport:
                skey = (client, sp, 0)
                if is_syn:
                    streams[skey] = Stream((seq + 1) & 0xFFFFFFFF, True, t)
                elif payload:
                    st = streams.get(skey)
                    if st is None:
                        st = streams[skey] = Stream(seq, False, t)
                    st.last = t
                    for e in st.feed(seq, payload, plen):
                        if e[0] == "ae":
                            r["called"].add(e[1]); r["calling"].add(e[2]); continue
                        ty, L = e[1], e[2]
                        if st.first:
                            if ty != 1: r["bad_first"] += 1
                            st.first = False
                        name = OUT_TYPES.get(ty)
                        if name: r[name] += 1
                        if ty == 1 and L > 8192: r["big_len"] += 1
                if f & 0x04:
                    streams.pop(skey, None); streams.pop((client, sp, 1), None)
        else:
            r["in_pkts"] += 1; r["in_bytes"] += tot
            if f & 0x04: r["rst"] += 1
            if f & 0x01: r["fin"] += 1
            if sp == dport:
                skey = (client, dp, 1)
                if f & 0x12 == 0x12:
                    streams[skey] = Stream((seq + 1) & 0xFFFFFFFF, True, t)
                elif payload:
                    st = streams.get(skey)
                    if st is None:
                        st = streams[skey] = Stream(seq, False, t)
                    st.last = t
                    for e in st.feed(seq, payload, plen):
                        if e[0] == "pdu":
                            name = IN_TYPES.get(e[1])
                            if name: r[name] += 1
                if f & 0x04:
                    streams.pop(skey, None); streams.pop((client, dp, 0), None)
        if t >= self.next_flush:
            self.flushed_below = max(self.flushed_below, int((self.last_t - self.flush_lag) // self.win) * self.win)
            out = self._flush(self.flushed_below)
            for k in [k for k, s in streams.items() if self.last_t - s.last > self.idle_drop]:
                del streams[k]
            self.next_flush = t + self.flush_every
            return out
        return []
