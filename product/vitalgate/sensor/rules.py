"""Layer 2: deterministic signatures (no ML). Evaluated on every window row before the model.
preamble_exec is the only detector for preamble_polyglot (excluded from ML training, as in the dataset README)."""
RULES = {
    "preamble_exec": ("DICOM file with an executable (MZ/ELF) preamble uploaded", 3),
    "bad_first_pdu": ("connection opened with a PDU other than A-ASSOCIATE-RQ", 2),
    "big_pdu_len":   ("A-ASSOCIATE-RQ with an oversized length field (>8 KiB)", 2),
}


def check(row):
    """Return list of (rule, count, description, severity) that fired in this window."""
    return [(k, row[k], d, sev) for k, (d, sev) in RULES.items() if row.get(k, 0) > 0]
