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

## SOC dashboard (added 2026-11-16)
- `vitalgate/explain/` exact TreeSHAP for the federated forest (pure Python; additivity error 4e-15) + per-alert sentence
  and 8 feature groups as in notebook 05 (class signatures reproduce notebook 05).
- `vitalgate/response/incidents.py` turns per-window decisions into incidents (open when a host leaves L0, close at L0),
  with explanations, ladder actions and the PEP commands (`vitalgate/response/pep.py`).
- `soc/replay.py` streams captured test-bed traffic through the frozen pipeline into `soc/data/incidents.json`
  (the live detector will write the same file). `soc/server.py` serves the dashboard on http://localhost:8090 and
  stores analyst acknowledgements/verdicts/notes in `soc/data/feedback.json` (labels for the next federated round).
  Run (from product/), two terminals:  `python soc/server.py`   and   `python soc/replay.py --speed 30`
  (`--instant` = process everything at once; `--onboard-until auto` = onboarding-calibrated CUSUM;
  "evaluation mode" in the page shows the test-bed ground truth next to each incident).

## Real enforcement (added 2026-11-16)
- `testbed/pep/` = the Policy Enforcement Point: `pep-a` runs in the PACS network namespace (NET_ADMIN) and loads
  `rules.nft` (nftables table `ip vg`): sets `watch`/`rate`/`quar`/`iso` whose elements carry a timeout, so the kernel
  removes every action by itself unless renewed (fail-open). L2 = new DICOM connections <= 30/min; L3 = DICOM uploads
  DNAT-ed to the quarantine store `quar-a` (172.28.1.21, Orthanc VG_QUARANTINE), all else dropped, PACS cannot open
  connections to the device; L4 = drop both ways + conntrack flush.
- Controller: `soc/live.py --pep-dir testbed/out/pep` (default) writes `desired.json` (level + seconds left per device,
  analyst hold flags, AE-title map) about once a second; the agent applies changes and logs them with timestamps in
  `applied.jsonl`; `state.json` = kernel set contents + rule counters + quarantine summary (shown on the dashboard).
- Quarantine store: every held image is checked (executable DICOM preamble -> never released) and released to the PACS
  once its device is below L3, unless an analyst confirmed an attack on that device (hold). Note: a C-STORE over the
  network carries no file preamble, so for redirected scanner uploads the release decision rests on the verdict.
- `testbed/orchestrator/enforcement_test.py` measures live: time to first action / isolation, CT uploads during
  quarantine, REST cut, release + PACS lookup, and fail-open after killing the controller -> `testbed/out/enforcement/`.
