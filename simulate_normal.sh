#!/bin/bash

# 이 스크립트는 AORM 에이전트가 '정상' 행위를 학습할 수 있도록,
# 일반적인 시스템 및 사용자 활동을 시뮬레이션합니다.
# sudo를 사용하여 루트 권한으로 실행해야 모든 기능이 정상 동작합니다.

LOG_PREFIX="[SIMULATOR]"

# 로그 출력 함수
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX $1"
}

# 일반적인 파일 시스템 탐색을 시뮬레이션하는 함수
simulate_browsing() {
    log_action "Simulating file system browsing..."
    local DIRS=("/var/log/" "/home/junyeong/" "/home/junyeong/Documents" "/home/junyeong/Downloads")
    local DIR_TO_LIST=${DIRS[$((RANDOM % ${#DIRS[@]}))]}
    
    if [ -d "$DIR_TO_LIST" ]; then
        ls -l $DIR_TO_LIST > /dev/null 2>&1
    fi
    
    # 공격 행위와 겹치지 않도록, 홈 디렉토리 내에서만 find 실행
    find /home/junyeong -name "*.txt" | head -n 1 > /dev/null 2>&1
}

# 로그 파일을 읽는 관리자 행위를 시뮬레이션하는 함수
simulate_log_reading() {
    log_action "Simulating log file reading..."
    local LOGS=("/var/log/syslog" "/var/log/auth.log" "/var/log/kern.log")
    local LOG_TO_READ=${LOGS[$((RANDOM % ${#LOGS[@]}))]}
    
    if [ -f "$LOG_TO_READ" ]; then
        head -n $((RANDOM % 20 + 5)) "$LOG_TO_READ" > /dev/null 2>&1
    fi
}

# 임시 파일을 생성하고 사용하는 애플리케이션 행위를 시뮬레이션하는 함수
simulate_temp_files() {
    log_action "Simulating temporary file activity..."
    local TEMP_FILE="/tmp/sim_temp_$(date +%s)_$RANDOM.tmp"
    
    echo "This is a temporary simulation file created at $(date)" > "$TEMP_FILE"
    sleep 1
    echo "Appending more data..." >> "$TEMP_FILE"
    sleep 1
    rm "$TEMP_FILE"
}

# 주기적인 패키지 업데이트 같은 시스템 관리 작업을 시뮬레이션하는 함수
simulate_system_management() {
    log_action "Simulating system package management (apt update)..."
    apt-get update > /dev/null 2>&1
}

# --- 메인 루프 ---
log_action "Starting Normal Behavior Simulation..."
log_action "This script should be run with 'sudo' for full functionality."
log_action "Press Ctrl+C in the foreground or use 'kill' to stop the background process."

while true; do
    ACTION_CHOICE=$((RANDOM % 100))

    if [ $ACTION_CHOICE -lt 40 ]; then
        simulate_browsing
    elif [ $ACTION_CHOICE -lt 70 ]; then
        simulate_log_reading
    elif [ $ACTION_CHOICE -lt 95 ]; then
        simulate_temp_files
    else
        if [ "$EUID" -eq 0 ]; then
            simulate_system_management
        else
            log_action "Skipping system management (requires root privileges)."
        fi
    fi

    SLEEP_INTERVAL=$((RANDOM % 30 + 10))
    log_action "Sleeping for $SLEEP_INTERVAL seconds..."
    sleep $SLEEP_INTERVAL
done