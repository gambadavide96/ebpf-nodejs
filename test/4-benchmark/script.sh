#!/bin/bash
# Usage: sudo bash benchmark.sh <NODE_PID> [--enforce]
if [ -z "$1" ]; then
    echo "Usage: sudo bash script.sh <NODE_PID> [--enforce]"
    exit 1
fi

NODE_PID=$1
NODELEASH_PID=""
OUTPUT="benchmark.txt"

if [ "$2" = "--enforce" ]; then
    NODELEASH_PID=$(pgrep -x nodeleash)
    if [ -z "$NODELEASH_PID" ]; then
        echo "Error: --enforce specified but nodeleash process not found."
        exit 1
    fi
    echo "NodeLeash PID auto-detected: $NODELEASH_PID"
fi

echo "NodeLeash Benchmark — PID $NODE_PID — $(date)" | tee "$OUTPUT"
echo "" | tee -a "$OUTPUT"

echo "--- wrk ---" | tee -a "$OUTPUT"
wrk -t2 -c50 -d30s --timeout 10s --latency http://127.0.0.1:8080/ 2>&1 | tee -a "$OUTPUT" &

perf stat -p "$NODE_PID" sleep 30 2>/tmp/perf_node.txt &

if [ -n "$NODELEASH_PID" ]; then
    perf stat -p "$NODELEASH_PID" sleep 30 2>/tmp/perf_nodeleash.txt &
fi

wait

echo "" | tee -a "$OUTPUT"
echo "--- perf stat Node.js (PID $NODE_PID) ---" | tee -a "$OUTPUT"
cat /tmp/perf_node.txt | tee -a "$OUTPUT"
rm -f /tmp/perf_node.txt

if [ -n "$NODELEASH_PID" ]; then
    echo "" | tee -a "$OUTPUT"
    echo "--- perf stat NodeLeash (PID $NODELEASH_PID) ---" | tee -a "$OUTPUT"
    cat /tmp/perf_nodeleash.txt | tee -a "$OUTPUT"
    rm -f /tmp/perf_nodeleash.txt
fi

echo "" | tee -a "$OUTPUT"
echo "Results saved in: $OUTPUT"