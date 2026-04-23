#!/bin/bash
# AuditChain Health Check - Verifies chain is producing blocks

BLOCK_FILE="/tmp/last_block_number"
ALERT_LOG="/var/log/auditchain-alerts.log"

log_alert() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ALERT: $1" >> "$ALERT_LOG"
}

# Check if Besu is running
if ! systemctl is-active --quiet auditchain; then
    log_alert "Besu service not running! Attempting restart..."
    systemctl start auditchain
    exit 1
fi

# Check if RPC is responding
BLOCK_HEX=$(curl -s -m 5 -X POST http://localhost:8545     -H 'Content-Type: application/json'     -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'     | grep -o '"result":"[^"]*"' | cut -d'"' -f4)

if [ -z "$BLOCK_HEX" ]; then
    log_alert "RPC not responding! Restarting Besu..."
    systemctl restart auditchain
    exit 1
fi

# Convert hex to decimal
CURRENT_BLOCK=$((16#${BLOCK_HEX:2}))

# Check if blocks are progressing
if [ -f "$BLOCK_FILE" ]; then
    LAST_BLOCK=$(cat "$BLOCK_FILE")
    if [ "$CURRENT_BLOCK" -le "$LAST_BLOCK" ]; then
        log_alert "Chain not progressing! Block stuck at $CURRENT_BLOCK"
        # Don't restart yet - just log (could be temporary)
    fi
fi

echo "$CURRENT_BLOCK" > "$BLOCK_FILE"
echo "Block: $CURRENT_BLOCK - OK"
