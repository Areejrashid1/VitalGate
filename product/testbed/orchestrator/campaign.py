"""Runs a randomised attack campaign on the test bed while benign traffic keeps running.
Every (class, variant) once per round, random intensity, duration and gap; sources are the attacker container,
a compromised modality or a compromised workstation. Ground truth goes to out/truth.csv (written by attack.py);
the plan is saved to out/plan_<run_id>.json. Usage (from product/testbed):
    python orchestrator/campaign.py --rounds 1 --run-id tb_0001 [--dry] [--site a]"""
import argparse, json, os, random, subprocess, sys, time

VARIANTS = {"recon": ["nmap_connect", "nmap_syn", "dicom_ping"], "ae_bruteforce": ["echo_guess", "find_guess"],
            "exfiltration": ["find_get", "move_to_self", "drip"], "malformed_pdu": ["assoc_fuzz", "pdata_fuzz"],
            "assoc_flood": ["hold_full_rq", "echo_storm"], "preamble_polyglot": ["rest_mz", "rest_elf", "stow_mz"],
            "ransomware_like": ["get_restore", "get_restore_delete"]}
MODS = ["ct", "mr", "cr", "us", "dx"]

p = argparse.ArgumentParser()
p.add_argument("--rounds", type=int, default=1); p.add_argument("--run-id", default="tb_0001")
p.add_argument("--site", default="a"); p.add_argument("--dry", action="store_true")
p.add_argument("--gap", default="90,300", help="min,max seconds of benign-only traffic between attacks")
p.add_argument("--duration", default="60,150", help="min,max attack seconds (slow runs x2)")
p.add_argument("--seed", type=int, default=None)
a = p.parse_args()
rng = random.Random(a.seed)
g0, g1 = map(int, a.gap.split(",")); d0, d1 = map(int, a.duration.split(","))
plan = []
for r in range(a.rounds):
    jobs = [(c, v) for c, vs in VARIANTS.items() for v in vs]; rng.shuffle(jobs)
    for c, v in jobs:
        it = rng.choice(["low", "high", "slow"])
        dur = rng.randint(d0, d1) * (2 if it == "slow" else 1)
        if v == "move_to_self": src = "ws2"
        else:
            x = rng.random()
            src = "atk" if x < 0.5 else (rng.choice(MODS) if x < 0.8 else "ws1")
        plan.append(dict(round=r + 1, label_class=c, variant=v, intensity=it, duration=dur, gap=rng.randint(g0, g1),
                         src=f"{src}-{a.site}"))
est = sum(j["duration"] + j["gap"] for j in plan) / 60
print(f"{len(plan)} attacks, about {est:.0f} min")
os.makedirs("out", exist_ok=True)
json.dump(plan, open(f"out/plan_{a.run_id}.json", "w"), indent=1)
for i, j in enumerate(plan, 1):
    print(f"[{i}/{len(plan)}] wait {j['gap']}s -> {j['label_class']}/{j['variant']} {j['intensity']} {j['duration']}s from {j['src']}", flush=True)
    if a.dry: continue
    time.sleep(j["gap"])
    cmd = ["docker", "compose", "exec", "-T", j["src"], "python3", "/app/attack.py", j["label_class"], j["variant"],
           "--intensity", j["intensity"], "--duration", str(j["duration"]), "--run-id", a.run_id]
    if subprocess.run(cmd).returncode != 0:
        print("  attack exited with an error, continuing", flush=True)
if not a.dry:
    time.sleep(60)
print("done")
