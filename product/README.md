# VitalGate product (Docker pipeline)

Layers per site: 1 ingestion (sensor) -> 2 rules -> 3 detector (federated XGBoost, v3, 83 features)
-> 4 explainer (SHAP) -> 5 risk/CUSUM -> 6 zero-trust gateway (L0-L4 ladder). Shared: federation server.

## Status
- [x] Layer 1 sensor: `vitalgate/sensor/` (pcap/live stream -> 2 s windows -> 83-feature vector)
- [x] Layer 2 rules: `vitalgate/sensor/rules.py`
- [ ] Detector, explainer, policy, gateway, federation server
- [ ] Independent traffic simulator (shares no code with dicom-lab)
- [ ] docker-compose test bed

## Feature parity test
The sensor must produce exactly the training features (dicom-lab extract_features.py v2 -> windows_v2.parquet).

    python tests/test_parity.py --data <folder with pcap/> --site B --files 12 --ref <v2 features.csv>

Result 2026-11-14: site A benign (4 pcaps, 152 windows) and site B with all 8 classes (12 pcaps, 1,851 windows):
0 window mismatches, 0 column mismatches, 0 mismatches in the 83 model features. Runs ~1,900x faster than real time.

Note: Netsol project dataset/features.csv is the old v1 (scapy) table, NOT the training table; do not use it as reference.
Note: training pcaps contain GSO/GRO super-packets (11.5% of packets > 1500 B, max 65 KB) because capture ran on the
PACS's Docker interface. The test bed must capture at the same kind of point, or the sensor needs segment coalescing.
