# VitalGate test-bed traffic image. Independent of the training lab (dicom-lab): no pynetdicom/pydicom;
# DICOM traffic comes from the DCMTK command-line tools (C++), scans from nmap, raw PDUs from Python stdlib.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        dcmtk nmap iproute2 iputils-ping python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY make_library.py /app/
RUN python3 /app/make_library.py /library
COPY common.py benign.py attack.py entry.sh /app/
RUN chmod +x /app/entry.sh
ENTRYPOINT ["/app/entry.sh"]
CMD ["sleep", "infinity"]
