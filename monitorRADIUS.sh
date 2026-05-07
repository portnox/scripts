#!/bin/bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /opt/portnox

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# the path to the localradfwtest.sh file
SCRIPT="/opt/portnox/localradfwtest.sh"

# Path to the monitoring log file
LOGFILE="/opt/portnox/monitorRADIUS.log"

# ---- Log rotation / pruning logic ----
MAX_LINES=50000
TRIM_LINES=10000

touch "$LOGFILE"

LINE_COUNT=$(wc -l < "$LOGFILE")

if [ "$LINE_COUNT" -gt "$MAX_LINES" ]; then
    echo "Log exceeded $LINE_COUNT lines, trimming oldest $TRIM_LINES lines..." >> "$LOGFILE"

    TMP_FILE=$(mktemp)

    # Keep everything after the first 10,000 lines
    tail -n +"$((TRIM_LINES + 1))" "$LOGFILE" > "$TMP_FILE" && mv "$TMP_FILE" "$LOGFILE"
fi

# Add a timestamp header to the log
echo "==================================================" >> "$LOGFILE"
echo "Run started: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOGFILE"
echo "==================================================" >> "$LOGFILE"

# Run the script and capture both stdout and stderr
"$SCRIPT" >> "$LOGFILE" 2>&1

# Add completion timestamp to the log
echo "Run completed: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOGFILE"
echo "" >> "$LOGFILE"
