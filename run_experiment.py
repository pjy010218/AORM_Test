# run_experiment.py

import os
import subprocess
import time
import json

# --- 1. 실험 환경 설정 ---
CONFIG = {
    "repetitions": 5,
    "learning_duration_seconds": 300,
    "aorm_agent_log": "aorm_agent.log",
    "profile_file": "behavior_profile.json",
    "aorm_agent_cmd": "sudo python3 -u main.py",
    "simulator_cmd": "sudo stdbuf -oL ./simulate_normal.sh",
    "attack_scenarios": {
        "1_recon": {"cmd": "./attack_recon.sh", "aorm_indicator": "Proc: 'find'", "fim_expected_alerts": 0},
        "2_rootkit": {"cmd": "sudo ./attack_rootkit.sh", "aorm_indicator": "File: '/bin/ls'", "fim_expected_alerts": 2},
        "3_multistage": {"cmd": "./attack_multistage.sh", "aorm_indicator": "Proc: 'payload'", "fim_expected_alerts": 1},
    },
    "fim_baseline_script": "sudo python3 fim_baseline.py"
}

# --- 2. 헬퍼 함수 정의 ---
def run_command(command, log_file=None, wait=False):
    print(f"  -> Running: {command}")
    args = command.split()
    if wait:
        return subprocess.run(args, capture_output=True, text=True, check=False)
    else:
        f = open(log_file, 'w') if log_file else subprocess.DEVNULL
        return subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT)

def stop_process(p_object, command_name):
    if p_object and p_object.poll() is None:
        print(f"  -> Stopping: {command_name} (PID: {p_object.pid})")
        # 'kill -9' (SIGKILL) 대신 'kill -INT' (SIGINT)를 사용하여 정상 종료 유도
        subprocess.run(f"sudo kill -INT {p_object.pid}".split(), capture_output=True)
        p_object.wait() # 프로세스가 스스로 종료될 때까지 기다림

def reset_environment():
    print("  -> Resetting environment...")
    for f in [CONFIG["aorm_agent_log"], CONFIG["profile_file"], "simulation.log"]:
        if os.path.exists(f):
            os.remove(f)

def analyze_aorm_log(scenario_key):
    """
    [수정됨] 로그 전체를 읽고, 경고(🚨)와 그 원인이 되는 indicator를 함께 분석합니다.
    """
    total_alerts = 0
    attack_detected = False
    indicator = CONFIG["attack_scenarios"][scenario_key]["aorm_indicator"]
    
    if not os.path.exists(CONFIG["aorm_agent_log"]):
        return {'tp': 0, 'fp': 0, 'fn': 1}

    # 파일을 한 번에 모두 읽어 메모리에 올립니다.
    with open(CONFIG["aorm_agent_log"], 'r') as f:
        log_lines = f.readlines()

    # 모든 라인을 순회하며 경고를 찾습니다.
    for i, line in enumerate(log_lines):
        if "🚨" in line:
            total_alerts += 1
            # 경고가 발견되면, 이전 5개 라인을 확인하여 indicator가 있는지 검사합니다.
            # 이것이 공격의 '맥락'을 확인하는 과정입니다.
            context_window = log_lines[max(0, i-5):i]
            for context_line in context_window:
                if indicator in context_line:
                    attack_detected = True
                    break # 하나의 경고에 대해 indicator를 찾으면 더 이상 찾을 필요 없음
    
    # recon 시나리오에 대한 특별 처리 (기존 로직 유지)
    if scenario_key == "1_recon" and total_alerts > 0:
        attack_detected = True
        
    if attack_detected:
        # 공격을 정확히 탐지했다면, 나머지 경고는 오탐(FP)으로 간주합니다.
        return {'tp': 1, 'fp': total_alerts - 1, 'fn': 0}
    else:
        # 공격을 탐지하지 못했다면, 발생한 모든 경고는 오탐(FP)입니다.
        return {'tp': 0, 'fp': total_alerts, 'fn': 1}

def analyze_fim_log(fim_output, scenario_key):
    alerts = fim_output.strip().split('\n')
    alert_count = len([line for line in alerts if "ALERT!" in line])
    expected_alerts = CONFIG["attack_scenarios"][scenario_key]["fim_expected_alerts"]
    if scenario_key == "1_recon":
        return {'tp': 0, 'fp': alert_count, 'fn': 1}
    return {'tp': 1, 'fp': alert_count - expected_alerts, 'fn': 0} if alert_count >= expected_alerts else {'tp': 0, 'fp': alert_count, 'fn': 1}

def calculate_final_metrics(results):
    total_tp = sum(r['tp'] for r in results); total_fp = sum(r['fp'] for r in results); total_fn = sum(r['fn'] for r in results)
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return {"TP": total_tp, "FP": total_fp, "FN": total_fn, "precision": f"{precision:.2%}", "recall": f"{recall:.2%}", "f1_score": f"{f1_score:.2%}"}

# --- 3. 메인 실험 루프 ---
def main():
    """실험 전체를 조율하고 결과를 출력합니다."""
    
    print("="*10 + " Creating FIM Baseline " + "="*10)
    run_command(f"{CONFIG['fim_baseline_script']} create", wait=True)
    results_by_system = {"aorm": [], "fim": []}

    # --- AORM 실험 ---
    print("\n" + "="*20 + " Running AORM Experiment " + "="*20)
    for i in range(CONFIG["repetitions"]):
        print(f"\n--- AORM Repetition {i+1}/{CONFIG['repetitions']} ---")
        for name, scenario in CONFIG["attack_scenarios"].items():
            print(f"\n--- Running Scenario for AORM: {name} ---")
            reset_environment()
            
            aorm_proc = run_command(CONFIG["aorm_agent_cmd"], CONFIG["aorm_agent_log"])
            time.sleep(5)
            
            sim_proc = run_command(CONFIG["simulator_cmd"], "simulation.log")
            print(f"  -> Learning phase for {CONFIG['learning_duration_seconds']} seconds...")
            time.sleep(CONFIG['learning_duration_seconds'])
            stop_process(sim_proc, "Simulator")

            print("  [DEBUG] Learning phase finished. Clearing log before attack phase.")
            # 공격 단계 시작 직전에 로그 파일을 초기화하여 오염을 방지
            if os.path.exists(CONFIG["aorm_agent_log"]):
                open(CONFIG["aorm_agent_log"], 'w').close()
            
            print("  -> Executing attack scenario...")
            run_command(scenario["cmd"], wait=True)
            time.sleep(5)
            
            stop_process(aorm_proc, "AORM Agent")
            
            aorm_result = analyze_aorm_log(name)
            results_by_system["aorm"].append(aorm_result)
            print(f"  -> AORM Analysis Result: {aorm_result}")

    # --- FIM 실험 ---
    print("\n" + "="*20 + " Running FIM Experiment " + "="*20)
    for i in range(CONFIG["repetitions"]):
        print(f"\n--- FIM Repetition {i+1}/{CONFIG['repetitions']} ---")
        for name, scenario in CONFIG["attack_scenarios"].items():
            print(f"\n--- Running Scenario for FIM: {name} ---")
            
            # FIM 실험에서는 학습이나 AORM 에이전트가 필요 없으므로 환경만 초기화
            reset_environment() 

            # 공격 스크립트를 'no-cleanup' 인자로 실행하여 탬퍼링된 상태 유지
            attack_cmd_for_fim = f"{scenario['cmd']} no-cleanup"
            print("  -> Executing attack scenario (no-cleanup mode)...")
            run_command(attack_cmd_for_fim, wait=True)
            
            # 탬퍼링된 상태에서 FIM 검사 실행
            fim_proc = run_command(f"{CONFIG['fim_baseline_script']} check", wait=True)
            fim_result = analyze_fim_log(fim_proc.stdout, name)
            results_by_system["fim"].append(fim_result)
            print(f"  -> FIM Analysis Result: {fim_result}")

            # 시스템 원상 복구를 위해 'cleanup' 모드만 안전하게 호출
            print("  -> Restoring system state...")
            cleanup_cmd = f"{scenario['cmd']} cleanup"
            run_command(cleanup_cmd, wait=True)

    # --- 최종 결과 집계 및 출력 ---
    print(f"\n{'='*20} Final Experiment Summary {'='*20}")
    
    aorm_metrics = calculate_final_metrics(results_by_system["aorm"])
    fim_metrics = calculate_final_metrics(results_by_system["fim"])

    summary = {
        "AORM-TS-P": aorm_metrics,
        "Traditional_FIM": fim_metrics
    }
    print(json.dumps(summary, indent=4))

if __name__ == "__main__":
    main()
