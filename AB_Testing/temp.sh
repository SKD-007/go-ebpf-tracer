
#!/usr/bin/env bash

cleanup(){
    echo -e "\n[!] Shutting Down all servers and tracers..."
    
    # Regular kill for your binaries and user-space python scripts
    kill $SERVER1_PID $SERVER2A_PID $SERVER2B_PID $MAIN_PID $LOG1_PID $LOG2A_PID $LOG2B_PID $LOGC_PID 2> /dev/null
    
    # SUDO kill for the eBPF tracing scripts (since they were started with sudo)
    sudo kill $T1_PID $T2A_PID $T2B_PID $TC_PID 2> /dev/null
    
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

echo "[*] Starting Target Servers..."
./server1 &
SERVER1_PID=$!
./server2A &
SERVER2A_PID=$!
./server2B &
SERVER2B_PID=$!

echo "[*] Starting Central Trace Server (Main)..."
./main &
MAIN_PID=$!

sleep 3

echo "[*] Attaching eBPF Tracers (Requires Sudo)..."
sudo python3 tracing.py ./server1 &
T1_PID=$!
sleep 2  # Added extra time for initialization

sudo python3 tracing.py ./server2A &
T2A_PID=$!
sleep 2  # Give server2A time to fully bind and initialize

sudo python3 tracing.py ./server2B &
T2B_PID=$!
sleep 2

sudo python3 tracing.py ./client &
TC_PID=$!
sleep 3

echo "[*] Starting Log Processors..."
python3 logtracing.py ebpf_syscall_analysis_server1.log &
LOG1_PID=$!
python3 logtracing.py ebpf_syscall_analysis_server2A.log &
LOG2A_PID=$!
python3 logtracing.py ebpf_syscall_analysis_server2B.log &
LOG2B_PID=$!
python3 logtracing.py ebpf_syscall_analysis_client.log &
LOGC_PID=$!

sleep 3

echo "[*] Triggering Client Request..."
./client 

# Wait for traces to flow through and stitch together
sleep 5

echo "[*] Fetching final analysis report..."
curl -s http://127.0.0.1:9090/api/analyze > analysis.txt
cat analysis.txt