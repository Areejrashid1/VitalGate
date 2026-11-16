# VitalGate PEP agent: nftables + conntrack in the PACS network namespace, plus the quarantine-store manager.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables conntrack python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY rules.nft pep_agent.py /app/
CMD ["python3", "-u", "/app/pep_agent.py"]
