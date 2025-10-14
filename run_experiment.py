# run_experiment.py

import os
import subprocess
import time
import json

# --- 1. 실험 환경 설정 ---
CONFIG = {
    "repetitions": 5,
    "learning_duration_seconds": 300,
    # "aorm_agent_log": "aorm_agent.log", # 더 이상 사용하지 않음
    "profile_file": "behavior_profile.json",
    "aorm_agent_cmd": "sudo python3 -u main.py",
    "simulator_cmd": "sudo stdbuf -oL ./simulate_normal.sh",
    "attack_scenarios": {
        "1_recon": {
            "cmd": "./attack_recon.sh", 
            "aorm_indicators": ["find /", "cat /etc/passwd"],
            "attack_log": "attack_recon_simulation.log" # 시나리오별 로그 파일 지정
        },
        "2_rootkit": {
            "cmd": "sudo ./attack_rootkit.sh", 
            "aorm_indicators": ["/bin/ls", "mv /bin/ls", "cp /tmp/malicious_ls"],
            "attack_log": "attack_rootkit_simulation.log"
        },
        "3_multistage": {
            "cmd": "./attack_multistage.sh", 
            "aorm_indicators": ["payload", "wget", "/tmp/payload"],
            "attack_log": "attack_multistage_simulation.log"
        },
    },
    # FIM 관련 설정은 변경 없음
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
    for f in [CONFIG["profile_file"], "simulation.log"]:
        if os.path.exists(f):
            os.remove(f)

def analyze_aorm_log(scenario_key, log_file):
    """
    [수정됨] 지정된 로그 파일을 읽고, 경고와 그 원인이 되는 indicator를 함께 분석합니다.
    """
    total_alerts = 0
    attack_detected = False
    indicators = CONFIG["attack_scenarios"][scenario_key]["aorm_indicators"]
    
    print(f"  [DEBUG] Analyzing log file: '{log_file}' for indicators: {indicators}")
    if not os.path.exists(log_file):
        print(f"  [DEBUG] Log file not found. Marking as FN.")
        return {'tp': 0, 'fp': 0, 'fn': 1}

    with open(log_file, 'r') as f:
        log_lines = f.readlines()

    for i, line in enumerate(log_lines):
        if "🚨" in line:
            total_alerts += 1
            context_window = log_lines[max(0, i-5):i+1] # 경고 라인까지 포함
            for indicator in indicators:
                for context_line in context_window:
                    if indicator in context_line:
                        attack_detected = True
                        print(f"  [DEBUG] Attack DETECTED. Indicator '{indicator}' found near alert.")
                        break # 내부 루프 탈출
                if attack_detected:
                    break # 외부 루프 탈출
            
            if attack_detected:
                break # 공격이 탐지되었으면 더 이상 다른 경고를 분석할 필요 없음
    
    # recon 시나리오에 대한 특별 처리 (기존 로직 유지)
    if scenario_key == "1_recon" and total_alerts > 0:
        attack_detected = True
        
    if attack_detected:
        # 공격을 정확히 탐지했다면, 나머지 경고는 오탐(FP)으로 간주합니다.
        return {'tp': 1, 'fp': total_alerts - 1, 'fn': 0}
    else:
        # 공격을 탐지하지 못했다면, 발생한 모든 경고는 오탐(FP)입니다.
        print(f"  [DEBUG] Attack NOT detected. Total alerts found: {total_alerts}")
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
    """[수정됨] 실험 전체를 조율하고 결과를 출력합니다."""
    
    # ... (FIM Baseline 생성은 동일) ...
    results_by_system = {"aorm": [], "fim": []}

    # --- AORM 실험 ---
    print("\n" + "="*20 + " Running AORM Experiment " + "="*20)
    for i in range(CONFIG['repetitions']):
        print(f"\n--- AORM Repetition {i+1}/{CONFIG['repetitions']} ---")
        
        # --- 학습 단계 (모든 시나리오 시작 전 1회만 수행) ---
        print("\n  --- Phase 1: Learning Normal Behavior (once per repetition) ---")
        reset_environment() # behavior_profile.json 생성을 위해 초기화
        learning_agent_proc = run_command(CONFIG["aorm_agent_cmd"], "learning.log")
        time.sleep(5)
        sim_proc = run_command(CONFIG["simulator_cmd"], "simulation.log")
        print(f"  -> Learning phase for {CONFIG['learning_duration_seconds']} seconds...")
        time.sleep(CONFIG['learning_duration_seconds'])
        stop_process(sim_proc, "Simulator")
        stop_process(learning_agent_proc, "Learning Agent")
        print("  -> Learning complete. 'behavior_profile.json' is ready.")

        # --- 공격 탐지 단계 (시나리오별로 반복) ---
        for name, scenario in CONFIG["attack_scenarios"].items():
            print(f"\n--- Running Scenario for AORM: {name} ---")
            
            attack_log_file = scenario["attack_log"]
            # 이번 시나리오의 로그 파일만 삭제하여 깨끗한 상태에서 시작
            if os.path.exists(attack_log_file):
                os.remove(attack_log_file)
            
            # 공격 탐지 에이전트를 시나리오별 지정된 로그 파일에 기록하도록 실행
            attack_agent_proc = run_command(CONFIG["aorm_agent_cmd"], attack_log_file)
            print(f"  -> Attack detection agent is running. Logging to '{attack_log_file}'")
            time.sleep(5)
            
            print("  -> Executing attack scenario...")
            run_command(scenario["cmd"], wait=True)
            time.sleep(5)
            
            stop_process(attack_agent_proc, "AORM Agent")
            
            # 해당 시나리오의 로그 파일을 분석
            aorm_result = analyze_aorm_log(name, attack_log_file)
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

    # 1. 화면에 최종 요약 출력 (기존과 동일)
    print(json.dumps(summary, indent=4))

    # 2. 파일에 최종 요약 저장 (추가된 부분)
    summary_file_path = "experiment_summary.txt"
    try:
        with open(summary_file_path, 'w') as f:
            json.dump(summary, f, indent=4)
        print(f"\n✅ Successfully saved final results to '{summary_file_path}'")
    except Exception as e:
        print(f"\n❌ Failed to save results to file: {e}")

if __name__ == "__main__":
    # 스크립트가 root 권한으로 실행되었는지 확인
    if os.geteuid() != 0:
        print("❌ This script must be run as root. Please use 'sudo python3 run_experiment.py'")
        exit(1)
    main()