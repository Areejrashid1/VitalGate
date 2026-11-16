"""Demo campaign for a screen recording: a fixed, story-like sequence of attacks with short gaps, so the SOC dashboard
fills up within minutes. Uses its own run id (demo_01 by default) so it never mixes with the evaluation campaigns
(eval/offline_eval.py --run-id tb_000x leaves other campaigns' windows out of the metrics).
Usage (from product/testbed, test bed running, dashboard open):  python orchestrator/demo.py [--gap 30] [--run-id demo_01]"""
import argparse, subprocess, time

STORY = [  # (what the viewer should notice, source container, class, variant, intensity, seconds)
    ("An unregistered device scans the network for the PACS",                "atk-a", "recon",             "nmap_connect", "high", 35),
    ("A compromised ultrasound guesses DICOM AE titles (cap: L3, never cut off)", "us-a", "ae_bruteforce",  "echo_guess",   "high", 40),
    ("A reading workstation bulk-downloads studies it should not (exfiltration)", "ws1-a", "exfiltration",  "find_get",     "high", 45),
    ("A DICOM file with a hidden executable is uploaded (DPI rule, < 1 s)",  "atk-a", "preamble_polyglot", "rest_mz",      "high", 30),
    ("A compromised CT scanner sends malformed DICOM handshakes",           "ct-a",  "malformed_pdu",     "assoc_fuzz",   "high", 40),
    ("Ransomware-like mass read and re-write of studies",                     "atk-a", "ransomware_like",   "get_restore",  "high", 45),
]

p = argparse.ArgumentParser(); p.add_argument("--gap", type=int, default=30); p.add_argument("--run-id", default="demo_01")
p.add_argument("--dry", action="store_true")
a = p.parse_args()
total = sum(s[-1] for s in STORY) + a.gap * len(STORY)
print(f"demo: {len(STORY)} attacks, about {total // 60} min {total % 60} s (run id {a.run_id})\n")
for i, (story, src, cls, var, it, dur) in enumerate(STORY, 1):
    print(f"[{i}/{len(STORY)}] in {a.gap} s: {story}\n        ({cls}/{var}, {it}, {dur} s, from {src})", flush=True)
    if a.dry: continue
    time.sleep(a.gap)
    t0 = time.strftime("%H:%M:%S")
    r = subprocess.run(["docker", "compose", "exec", "-T", src, "python3", "/app/attack.py", cls, var, "--intensity", it,
                        "--duration", str(dur), "--run-id", a.run_id])
    print(f"        started {t0}, finished {time.strftime('%H:%M:%S')}" + ("" if r.returncode == 0 else "  (attack exited with an error)"), flush=True)
if not a.dry:
    print("\nall attacks done - leave the dashboard running ~2 min to show the actions expiring (fail-open)")
