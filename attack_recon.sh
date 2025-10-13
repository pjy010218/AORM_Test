#!/bin/bash

# 시나리오 1-1: Exploitation 후 권한 상승 및 내부 정찰

LOG_PREFIX="[ATTACKER]"

log_attack() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX $1"
}

# --- 시나리오 시작 ---
log_attack "Scenario 1-1: Post-Exploitation & Reconnaissance Simulation START"
echo "------------------------------------------------------------------"

if [ "$EUID" -eq 0 ]; then
  log_attack "ERROR: This script must be run as a NON-ROOT user."
  exit 1
fi

# --- 1단계: 내부 정찰 (Reconnaissance) ---
log_attack "Phase 1: Reconnaissance..."
whoami; id; uname -a
sleep 2
log_attack "Reading /etc/passwd for user enumeration..."
cat /etc/passwd > /dev/null 2>&1
sleep 2
log_attack "Listing running processes..."
ps aux > /dev/null 2>&1
sleep 2

# --- 2단계: 취약점 탐색 (Searching for Weaknesses) ---
log_attack "Phase 2: Searching for Privilege Escalation vectors (SUID binaries)..."
find / -type f -perm -u=s -ls 2>/dev/null > /dev/null
sleep 3

# --- 3단계: 권한 상승 시도 (Exploitation Attempt) ---
log_attack "Phase 3: Attempting to create a backdoor file in /etc/cron.d/..."
echo "* * * * * root /bin/bash -c 'id'" > /etc/cron.d/backdoor
if [ $? -ne 0 ]; then
    log_attack "Attempt FAILED as expected."
else
    log_attack "Attempt SUCCEEDED. System is misconfigured."
fi
sleep 2

echo "------------------------------------------------------------------"
log_attack "Scenario 1-1: Simulation FINISHED."