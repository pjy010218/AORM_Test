#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import subprocess
import time
import json
import signal

# --- 1. 실험 환경 설정 ---
CONFIG = {
    "repetitions": 5,
    "learning_duration_seconds": 300,
    "profile_file": "behavior_profile.json",
    "aorm_agent_cmd": "sudo python3 -u main.py",
    "simulator_cmd": "sudo stdbuf -oL ./simulate_normal.sh",
    "attack_scenarios": {
        "1_recon": {
            "cmd": "./attack_recon.sh",
            "aorm_indicators": ["find", "cat /etc/passwd"],
            "attack_log": "attack_recon_simulation.log",
            "fim_expected_alerts": 1
        },
        "2_rootkit": {
            "cmd": "sudo ./attack_rootkit.sh",
            "aorm_indicators": ["/bin/ls", "mv", "cp", "/usr/bin/which"],
            "attack_log": "attack_rootkit_simulation.log",
            "fim_expected_alerts": 1
        },
        "3_multistage": {
            "cmd": "./attack_multistage.sh",
            "aorm_indicators": ["payload", "wget", "/tmp/payload", "/etc/passwd", "/etc/hosts"],
            "attack_log": "attack_multistage_simulation.log",
            "fim_expected_alerts": 2
        },
    },
    "fim_baseline_script": "sudo python3 fim_baseline.py"
}

# --- 2. 헬퍼 함수 정의 ---
def run_command(command, log_file=None, wait=False):
    """비동기 실행 + 로그 기록"""
    print(f"  -> Running: {command}")
    args = command.split()
    if wait:
        return subprocess.run(args, capture_output=True, text=True, check=False)
    else:
        f = open(log_file, 'w') if log_file else subprocess.DEVNULL
        if "sudo" in command:
            return subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        else:
            return subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT)

def stop_process(p_object, command_name):
    """프로세스 강제 종료 안전화 (이미 종료된 프로세스도 무시)"""
    if not p_object:
        return
    try:
        if p_object.poll() is not None:
            # 이미 종료됨
            print(f"  -> {command_name} already exited.")
            return
    except Exception:
        return

    print(f"  -> Stopping: {command_name} (PID: {p_object.pid})")
    try:
        os.killpg(p_object.pid, signal.SIGINT)
        p_object.wait(timeout=5)
        print(f"  -> {command_name} terminated gracefully.")
    except ProcessLookupError:
        # 이미 프로세스가 종료된 상태
        print(f"  -> {command_name} already terminated (no such PID).")
    except subprocess.TimeoutExpired:
        print(f"  [WARN] {command_name} not responding. Sending SIGKILL.")
        try:
            os.killpg(p_object.pid, signal.SIGKILL)
            p_object.wait(timeout=2)
            print(f"  -> {command_name} was forcefully terminated.")
        except ProcessLookupError:
            print(f"  -> {command_name} already gone during SIGKILL attempt.")
    except Exception as e:
        print(f"  [WARN] Unexpected error stopping {command_name}: {e}")

def reset_environment():
    """기존 로그 및 프로파일 삭제"""
    print("  -> Resetting environment...")
    for f in [CONFIG["profile_file"], "simulation.log"]:
        if os.path.exists(f):
            os.remove(f)
    os.remove("learning.log") if os.path.exists("learning.log") else None
    os.remove("simulation.log") if os.path.exists("simulation.log") else None

# --- AORM 로그 분석 ---
def analyze_aorm_log(scenario_key, log_file):
    """로그에서 ALERT/Indicator 분석"""
    total_alerts, true_alerts, false_alerts = 0, 0, 0
    indicators = CONFIG["attack_scenarios"][scenario_key]["aorm_indicators"]

    if not os.path.exists(log_file):
        return {'tp': 0, 'fp': 0, 'fn': 1}

    with open(log_file, 'r') as f:
        log_lines = f.readlines()

    seen_alerts = set()
    for i, line in enumerate(log_lines):
        if "🚨" not in line:
            continue
        alert_text = line.strip()
        if alert_text in seen_alerts:
            continue
        seen_alerts.add(alert_text)
        total_alerts += 1

        context_window = log_lines[max(0, i-5):i+1]
        matched = any(
            any(indicator in c_line for c_line in context_window)
            for indicator in indicators
        )

        if matched:
            true_alerts += 1
        else:
            false_alerts += 1

    if total_alerts == 0:
        return {'tp': 0, 'fp': 0, 'fn': 1}
    if true_alerts == 0:
        return {'tp': 0, 'fp': false_alerts, 'fn': 1}
    return {'tp': true_alerts, 'fp': false_alerts, 'fn': 0}

# --- FIM 로그 분석 ---
def analyze_fim_log(fim_output, scenario_key):
    alerts = fim_output.strip().split('\n')
    alert_count = len([line for line in alerts if "ALERT!" in line])
    expected_alerts = CONFIG["attack_scenarios"][scenario_key]["fim_expected_alerts"]
    if scenario_key == "1_recon":
        return {'tp': 0, 'fp': alert_count, 'fn': 1}
    return {'tp': 1, 'fp': alert_count - expected_alerts, 'fn': 0} if alert_count >= expected_alerts else {'tp': 0, 'fp': alert_count, 'fn': 1}

# --- 메트릭 계산 ---
def calculate_final_metrics(results):
    tp = sum(r['tp'] for r in results)
    fp = sum(r['fp'] for r in results)
    fn = sum(r['fn'] for r in results)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return {"TP": tp, "FP": fp, "FN": fn, "precision": f"{precision:.2%}", "recall": f"{recall:.2%}", "f1_score": f"{f1:.2%}"}

# --- 3. 메인 루프 ---
def main():
    print("="*10 + " Creating FIM Baseline " + "="*10)
    run_command(f"{CONFIG['fim_baseline_script']} create", wait=True)

    results_by_system = {"aorm": [], "fim": []}

    # --- AORM 실험 ---
    print("\n" + "="*20 + " Running AORM Experiment " + "="*20)
    for i in range(CONFIG["repetitions"]):
        print(f"\n--- AORM Repetition {i+1}/{CONFIG['repetitions']} ---")

        # 1. 학습 단계
        print("\n  --- Phase 1: Learning Normal Behavior ---")
        reset_environment()
        learning_agent_proc = run_command(CONFIG["aorm_agent_cmd"], "learning.log")
        time.sleep(5)
        sim_proc = run_command(CONFIG["simulator_cmd"], "simulation.log")
        print(f"  -> Learning phase for {CONFIG['learning_duration_seconds']} seconds...")
        time.sleep(CONFIG["learning_duration_seconds"])
        stop_process(sim_proc, "Simulator")
        stop_process(learning_agent_proc, "Learning Agent")
        print("  -> Learning complete. 'behavior_profile.json' saved.")

        # 2. 공격 시나리오별 탐지
        for name, scenario in CONFIG["attack_scenarios"].items():
            print(f"\n--- Running Scenario for AORM: {name} ---")
            attack_log_file = scenario["attack_log"]
            if os.path.exists(attack_log_file):
                os.remove(attack_log_file)

            attack_agent_proc = run_command(CONFIG["aorm_agent_cmd"], attack_log_file)
            time.sleep(5)
            attack_proc = run_command(scenario["cmd"])
            print(f"  -> Executing attack: {scenario['cmd']}")

            # 지능형 대기
            alert_found = False
            timeout = 30
            end_time = time.time() + timeout
            while time.time() < end_time:
                if os.path.exists(attack_log_file):
                    with open(attack_log_file, 'r') as f:
                        if "🚨" in f.read():
                            alert_found = True
                            print("  -> ✅ ALERT signal detected.")
                time.sleep(1)
            if not alert_found:
                print("  -> ❌ No ALERT detected (timeout).")

            stop_process(attack_proc, "Attack Script")
            stop_process(attack_agent_proc, "AORM Agent")

            result = analyze_aorm_log(name, attack_log_file)
            results_by_system["aorm"].append(result)
            print(f"  -> AORM Result: {result}")

    # --- FIM 실험 ---
    print("\n" + "="*20 + " Running FIM Experiment " + "="*20)
    for name, scenario in CONFIG["attack_scenarios"].items():
        print(f"\n--- Running Scenario for FIM: {name} ---")
        reset_environment()
        run_command(f"{scenario['cmd']} no-cleanup", wait=True)
        fim_proc = run_command(f"{CONFIG['fim_baseline_script']} check", wait=True)
        fim_result = analyze_fim_log(fim_proc.stdout, name)
        for _ in range(CONFIG["repetitions"]):
            results_by_system["fim"].append(fim_result)
        run_command(f"{scenario['cmd']} cleanup", wait=True)

    # --- 결과 출력 ---
    print(f"\n{'='*20} Final Experiment Summary {'='*20}")
    aorm_metrics = calculate_final_metrics(results_by_system["aorm"])
    fim_metrics = calculate_final_metrics(results_by_system["fim"])
    summary = {"AORM-TS-P": aorm_metrics, "Traditional_FIM": fim_metrics}
    print(json.dumps(summary, indent=4))

    # 파일로 저장
    with open("experiment_summary.txt", "w") as f:
        json.dump(summary, f, indent=4)
    print("\n✅ Results saved to 'experiment_summary.txt'")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Please run as root (sudo python3 run_experiment.py)")
        exit(1)
    main()
