# VitalGate test bed (site A) - independent traffic

Purpose: test the trained pipeline on traffic it has never seen. Nothing here shares code with the training lab
(dicom-lab): different PACS image (orthancteam/orthanc vs jodogne/orthanc 1.12.4), DICOM clients are DCMTK
command-line tools (training: pynetdicom), scans use nmap, images are compressed/uncompressed phantoms
(training: random-noise 16-bit), different IPs (172.28.1.x), port (104), AE titles, and network noise (tc netem).

| Container | IP | Role |
|---|---|---|
| pacs-a | .20 | Orthanc PACS, DICOM port 104, AET VG_ARCHIVE, REST 8042 |
| cap-a | (PACS namespace) | tcpdump -s 512, 5-min pcaps -> out/pcap/tbA_*.pcap (same capture point as training) |
| ct/mr/cr/us/dx-a | .31-.35 | modalities: storescu exams, per-device PDU size, compression, offline backlogs, retries |
| ws1-a / ws2-a | .51 / .52 | reading workstations: findscu, getscu (ws1) or movescu C-MOVE (ws2), priors, web viewer GETs |
| mon-a | .60 | monitoring: TCP probes, echo checks, REST polls, pings (hard negatives) |
| atk-a | .77 | attacker (attacks also launch from compromised modalities/workstations) |

Attacks (sim/attack.py): 7 classes, 17 variants; `novel=1` in out/truth.csv marks techniques never seen in training
(e.g. nmap SYN scan, DICOM-aware nmap probe, C-MOVE exfiltration, low-and-slow drip, P-DATA fuzzing, echo storm,
ELF/STOW-RS polyglots, ransomware with REST deletes).

## Run (PowerShell, from this folder)
1. `docker compose build`          (first time ~5-10 min; builds the image library)
2. `docker compose up -d`
3. Smoke test:
   - `docker compose ps`                                   -> 11 running
   - `docker compose logs --tail 5 ct-a ws1-a ws2-a mon-a`  -> JSON lines with "ok": true
   - `docker compose exec atk-a python3 -c "import urllib.request as u;print(u.urlopen('http://pacs-a:8042/statistics').read())"` -> CountInstances grows
   - isolation: `docker compose exec atk-a ping -c 1 -W 2 8.8.8.8` must FAIL
   - `docker compose exec -T atk-a python3 /app/attack.py recon nmap_connect --duration 20 --run-id smoke` -> out/truth.csv gets a row
   - `dir out\pcap`                                        -> tbA_*.pcap files
4. Let benign traffic run at least 1 hour.
5. `python orchestrator/campaign.py --rounds 2 --run-id tb_0001`   (~3.5 h; `--dry` to preview)
6. `docker compose stop cap-a`, then send out/truth.csv and the pcap count/size for offline evaluation.
Stop everything: `docker compose down` (add `-v` to also delete the PACS database).
