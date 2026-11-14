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

## Frozen model and offline evaluation (added 2026-11-15)
- `scripts/freeze_bundle.py` copies the trained model from `../models` into `bundle/` with SHA-256 hashes
  (`bundle/BUNDLE.json`). The product refuses a bundle whose files changed. Frozen: 48 federated updates
  (3,360 trees), 83 features, T = 0.75, CUSUM (k 0.6, h 0.5).
- `vitalgate/model/` evaluates the XGBoost JSON trees in numpy (no xgboost needed at run time).
- `vitalgate/response/engine.py` = CUSUM + L0-L4 ladder (and binary blocking baseline), same logic as notebook 06.
- `tests/test_model_parity.py` reproduces notebooks 05/06 on the lab test split exactly:
  macro-F1 0.9531 (05), ECE 0.0041, log-loss 0.0758, CUSUM 126/126 runs, 0.027 false episodes/h, median TTD 4 s,
  ladder vs binary clinical blocked 0.000 vs 0.101 min/h (06).
- `eval/offline_eval.py` runs the whole frozen pipeline on test-bed pcaps and scores it against `truth.csv`
  (known vs novel, class, variant, intensity, source). From product/:
  `python eval/offline_eval.py --pcap-dir testbed/out/pcap --truth testbed/out/truth.csv --run-id tb_0001 --out eval/results/tb_0001`
- `testbed/inventory.json` = device roles of the test bed (sets the criticality caps).
