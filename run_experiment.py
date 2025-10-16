import os
import subprocess
import time
import json
import re
import signal

CONFIG = {
    "repetitions": 5,
    "learning_duration_seconds": 300,
    "profile_file": "behavior_profile.json",
    "aorm_agent_cmd": "sudo python3 -u main.py",
    "simulator_cmd": "sudo stdbuf -oL ./simulate_normal.sh",
    "attack_scenarios": {
        "1_recon": {"cmd": "./attack_recon.sh", "aorm_indicators": ["find /", "cat /etc/passwd"], "attack_log": "attack_recon_simulation.log"},
        "2_rootkit": {"cmd": "sudo ./attack_rootkit.sh", "aorm_indicators": ["/bin/ls", "mv /bin/ls"], "attack_log": "attack_rootkit_simulation.log"},
        "3_multistage": {"cmd": "./attack_multistage.sh", "aorm_indicators": ["payload", "wget", "/tmp/payload"], "attack_log": "attack_multistage_simulation.log"},
    },
    "fim_baseline_script": "sudo python3 fim_baseline.py"
}

def run_command(cmd, log_file=None, wait=False):
    args = cmd.split()
    if wait:
        return subprocess.run(args, capture_output=True, text=True)
    else:
        f = open(log_file, 'w') if log_file else subprocess.DEVNULL
        if "sudo" in cmd:
            return subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        return subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT)

def stop_process(p, name):
    if not p or p.poll() is not None:
        return
    print(f"  -> Stopping: {name} (PID: {p.pid})")
    try:
        os.killpg(p.pid, signal.SIGINT)
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=2)

def reset_environment():
    for f in [CONFIG["profile_file"], "simulation.log"]:
        if os.path.exists(f):
            os.remove(f)

def analyze_aorm_log(scenario_key, log_file, dedup_window_seconds=30):
    indicators = CONFIG["attack_scenarios"][scenario_key]["aorm_indicators"]
    if not os.path.exists(log_file):
        return {'tp': 0, 'fp': 0, 'fn': 1}

    with open(log_file, 'r') as f:
        lines = f.readlines()

    alerts = []
    for i, line in enumerate(lines):
        if "🚨" in line:
            ts = i
            m = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if m:
                try:
                    ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
                except Exception:
                    pass
            alerts.append((ts, line.strip(), lines[max(0, i-5):i+1]))

    seen, tp, fp = [], 0, 0
    for ts, text, ctx in alerts:
        if any(prev_text == text and abs(ts - prev_ts) <= dedup_window_seconds for prev_ts, prev_text in seen):
            continue
        seen.append((ts, text))
        matched = any(any(ind in c for c in ctx) for ind in indicators)
        if matched:
            tp += 1
        else:
            fp += 1

    if not seen:
        return {'tp': 0, 'fp': 0, 'fn': 1}
    return {'tp': tp, 'fp': fp, 'fn': 0 if tp > 0 else 1}

def calculate_final_metrics(results):
    tp = sum(r['tp'] for r in results)
    fp = sum(r['fp'] for r in results)
    fn = sum(r['fn'] for r in results)
    prec = tp / (tp + fp) if tp + fp > 0 else 0
    rec = tp / (tp + fn) if tp + fn > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
    return {"TP": tp, "FP": fp, "FN": fn, "precision": f"{prec:.2%}", "recall": f"{rec:.2%}", "f1_score": f"{f1:.2%}"}

def main():
    run_command(f"{CONFIG['fim_baseline_script']} create", wait=True)
    results = {"aorm": [], "fim": []}

    for i in range(CONFIG['repetitions']):
        print(f"\n--- AORM Repetition {i+1}/{CONFIG['repetitions']} ---")
        reset_environment()
        agent = run_command(CONFIG["aorm_agent_cmd"], "learning.log")
        sim = run_command(CONFIG["simulator_cmd"], "simulation.log")
        time.sleep(CONFIG["learning_duration_seconds"])
        stop_process(sim, "Simulator")
        stop_process(agent, "AORM Agent")

        for name, sc in CONFIG["attack_scenarios"].items():
            print(f"\n--- Running AORM Scenario: {name} ---")
            if os.path.exists(sc["attack_log"]):
                os.remove(sc["attack_log"])
            a_agent = run_command(CONFIG["aorm_agent_cmd"], sc["attack_log"])
            time.sleep(5)
            atk = run_command(sc["cmd"])
            timeout = 30
            end = time.time() + timeout
            while time.time() < end:
                if os.path.exists(sc["attack_log"]) and "🚨" in open(sc["attack_log"]).read():
                    break
                time.sleep(1)
            stop_process(atk, "Attack")
            stop_process(a_agent, "AORM Agent")
            r = analyze_aorm_log(name, sc["attack_log"])
            results["aorm"].append(r)

    a_metrics = calculate_final_metrics(results["aorm"])
    summary = {"AORM-TS-P": a_metrics}
    print(json.dumps(summary, indent=4))
    with open("experiment_summary.txt", "w") as f:
        json.dump(summary, f, indent=4)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root (sudo).")
        exit(1)
    main()
