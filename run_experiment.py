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
    """[수정됨] 비동기 실행을 위해 preexec_fn을 Popen에만 적용"""
    print(f"  -> Running: {command}")
    args = command.split()
    if wait:
        return subprocess.run(args, capture_output=True, text=True, check=False)
    else:
        f = open(log_file, 'w') if log_file else subprocess.DEVNULL
        # sudo를 사용하는 에이전트와 시뮬레이터에만 preexec_fn 적용
        if "sudo" in command:
            return subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        else:
            return subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT)

def stop_process(p_object, command_name):
    """
    [수정됨] 지정된 시간 내에 종료되지 않으면 강제 종료하여 무한 실행을 방지합니다.
    """
    if not p_object or p_object.poll() is not None:
        # 이미 종료되었으면 아무것도 하지 않음
        return

    print(f"  -> Stopping: {command_name} (PID: {p_object.pid})")
    
    # 1. 프로세스 그룹 전체에 '정상 종료' 신호(SIGINT)를 보냄
    try:
        os.killpg(p_object.pid, signal.SIGINT)
        # 5초 동안 정상적으로 종료되기를 기다림
        p_object.wait(timeout=5)
        print(f"  -> {command_name} terminated gracefully.")
        return
    except subprocess.TimeoutExpired:
        # 5초가 지나도 종료되지 않은 경우
        print(f"  [WARN] {command_name} did not respond to graceful shutdown. Escalating to SIGKILL.")
    except Exception:
        # 프로세스가 그 사이에 이미 사라진 경우 등
        pass

    # 2. 그래도 종료되지 않았다면, '강제 종료' 신호(SIGKILL)를 보냄
    if p_object.poll() is None:
        try:
            os.killpg(p_object.pid, signal.SIGKILL)
            # 강제 종료가 처리될 시간을 잠시 기다림
            p_object.wait(timeout=2)
            print(f"  -> {command_name} was forcefully terminated.")
        except Exception:
            pass

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

def monitor_log_for_alerts(log_path, timeout=30, poll_interval=1, alert_token="🚨"):
    """
    Incrementally tail the given log file until `alert_token` appears or `timeout` expires.
    Returns (found_bool, matched_lines).
    """
    start = time.time()
    matched = []

    # 로그 파일이 생성될 때까지 대기
    end_time = start + timeout
    while not os.path.exists(log_path) and time.time() < end_time:
        time.sleep(0.1)
    if not os.path.exists(log_path):
        return False, matched

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            # 처음엔 파일 끝으로 이동
            f.seek(0, os.SEEK_END)
            while time.time() < end_time:
                line = f.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                if alert_token in line:
                    matched.append(line.strip())
                    return True, matched
    except Exception as e:
        print(f"[monitor_log_for_alerts] Warning: {e}")
        return False, matched

    return False, matched

def calculate_final_metrics(results):
    total_tp = sum(r['tp'] for r in results); total_fp = sum(r['fp'] for r in results); total_fn = sum(r['fn'] for r in results)
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return {"TP": total_tp, "FP": total_fp, "FN": total_fn, "precision": f"{precision:.2%}", "recall": f"{recall:.2%}", "f1_score": f"{f1_score:.2%}"}

# --- 3. 메인 실험 루프 ---
def main():
    """[최종 수정] '지능형 대기'를 통해 탐지 신뢰도를 확보한 실험을 조율합니다."""
    
    print("="*10 + " Creating FIM Baseline " + "="*10)
    run_command(f"{CONFIG['fim_baseline_script']} create", wait=True)
    results_by_system = {"aorm": [], "fim": []}

    # --- AORM 실험 ---
    print("\n" + "="*20 + " Running AORM Experiment " + "="*20)
    for i in range(CONFIG['repetitions']):
        print(f"\n--- AORM Repetition {i+1}/{CONFIG['repetitions']} ---")
        
        # --- 1. 학습 단계 (반복마다 1회) ---
        print("\n  --- Phase 1: Learning Normal Behavior ---")
        reset_environment()
        learning_agent_proc = run_command(CONFIG["aorm_agent_cmd"], "learning.log")
        time.sleep(5)
        sim_proc = run_command(CONFIG["simulator_cmd"], "simulation.log")
        print(f"  -> Learning phase for {CONFIG['learning_duration_seconds']} seconds...")
        time.sleep(CONFIG['learning_duration_seconds'])
        stop_process(sim_proc, "Simulator")
        stop_process(learning_agent_proc, "Learning Agent")
        print("  -> Learning complete. 'behavior_profile.json' is ready.")

        # --- 2. 공격 탐지 단계 (시나리오별) ---
        for name, scenario in CONFIG["attack_scenarios"].items():
            print(f"\n--- Running Scenario for AORM: {name} ---")
            
            attack_log_file = scenario["attack_log"]
            if os.path.exists(attack_log_file):
                os.remove(attack_log_file)
            
            # 공격 탐지 에이전트 실행
            attack_agent_proc = run_command(CONFIG["aorm_agent_cmd"], attack_log_file)
            print(f"  -> Attack detection agent (PID: {attack_agent_proc.pid}) is running.")
            time.sleep(5)
            
            # 공격 스크립트 '비동기' 실행
            print("  -> Executing attack scenario in background...")
            attack_proc = run_command(scenario["cmd"])

            print(f"  -> Waiting for ALERT in '{attack_log_file}'...")
            alert_found, matched_lines = monitor_log_for_alerts(attack_log_file, timeout=30, poll_interval=0.5)

            if alert_found:
                print(f"  -> ✅ ALERT signal detected! {matched_lines}")
            else:
                print("  -> ❌ Timeout: No ALERT signal detected within 30 seconds.")

            # 모든 관련 프로세스 정리
            stop_process(attack_proc, "Attack Scenario")
            stop_process(attack_agent_proc, "AORM Agent")
            
            # 분석
            aorm_result = analyze_aorm_log(name, attack_log_file)
            results_by_system["aorm"].append(aorm_result)
            print(f"  -> AORM Analysis Result: {aorm_result}")

    # --- FIM 실험 ---
    # FIM 실험은 1회만 수행 (결정론적이므로)
    print("\n" + "="*20 + " Running FIM Experiment (Single Run) " + "="*20)
    
    for name, scenario in CONFIG["attack_scenarios"].items():
        print(f"\n--- Running Scenario for FIM: {name} ---")
        reset_environment()
        
        # 공격 실행
        attack_cmd_for_fim = f"{scenario['cmd']} no-cleanup"
        run_command(attack_cmd_for_fim, wait=True)
        
        # FIM 검사
        fim_proc = run_command(f"{CONFIG['fim_baseline_script']} check", wait=True)
        fim_result = analyze_fim_log(fim_proc.stdout, name)
        
        # FIM은 반복 횟수만큼 결과를 복제하여 통계 비교를 공정하게
        for _ in range(CONFIG["repetitions"]):
            results_by_system["fim"].append(fim_result)
        
        print(f"  -> FIM Analysis Result: {fim_result}")
        
        # 복구
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
