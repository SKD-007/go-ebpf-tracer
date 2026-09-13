#!/usr/bin/env bash

cleanup(){
    echo -e "\nShutting Down all servers..."
    kill $SERVER1_PID $SERVER2A_PID $SERVER2B_PID $MAIN_PID $T1_PID $T2A_PID $T2B_PID $TC_PID $LOG1_PID $LOG2A_PID $LOG2B_PID $LOGC_PID 2> /dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

./server1 &
SERVER1_PID=$!


./server2A &
SERVER2A_PID=$!


./server2B &
SERVER2B_PID=$!

sleep 5

sudo python3 tracing.py ./server1 &
T1_PID=$!

sleep 2

sudo python3 tracing.py ./server2A &
T2A_PID=$!

sleep 2

sudo python3 tracing.py ./server2B &
T2B_PID=$!

sleep 2

sudo python3 tracing.py ./client &
TC_PID=$!

sleep 2

./main > analysis.txt &
MAIN_PID=$!

echo "done running tracing.py"
sleep 5

python3 logtracing.py ebpf_syscall_analysis_server1.log  &
LOG1_PID=$!

sleep 2

python3 logtracing.py ebpf_syscall_analysis_server2A.log &
LOG2A_PID=$!

sleep 2

python3 logtracing.py ebpf_syscall_analysis_server2B.log &
LOG2B_PID=$!

sleep 2

python3 logtracing.py ebpf_syscall_analysis_client.log &
LOGC_PID=$!

sleep 5

./client 

sleep 5

wait $MAIN_PID
# sleep 5

# curl http://127.0.0.1:9090/api/.. > analysis.txt


# !/usr/bin/env bash

# cleanup(){
#     echo -e "\n[!] Shutting Down all servers and tracers..."
    
#     # Regular kill for your binaries and user-space python scripts
#     kill $SERVER1_PID $SERVER2A_PID $SERVER2B_PID $MAIN_PID $LOG1_PID $LOG2A_PID $LOG2B_PID $LOGC_PID 2> /dev/null
    
#     # SUDO kill for the eBPF tracing scripts (since they were started with sudo)
#     sudo kill $T1_PID $T2A_PID $T2B_PID $TC_PID 2> /dev/null
    
#     exit 0
# }

# trap cleanup SIGINT SIGTERM EXIT

# echo "[*] Starting Target Servers..."
# ./server1 &
# SERVER1_PID=$!
# ./server2A &
# SERVER2A_PID=$!
# ./server2B &
# SERVER2B_PID=$!

# echo "[*] Starting Central Trace Server (Main)..."
# ./main > analysis.txt &
# MAIN_PID=$!

# sleep 2

# echo "[*] Attaching eBPF Tracers (Requires Sudo)..."
# sudo python3 tracing.py ./server1 &
# T1_PID=$!
# sleep 1

# sudo python3 tracing.py ./server2A &
# T2A_PID=$!
# sleep 1

# sudo python3 tracing.py ./server2B &
# T2B_PID=$!
# sleep 1

# sudo python3 tracing.py ./client &
# TC_PID=$!
# sleep 3

# echo "[*] Starting Log Processors..."
# python3 logtracing.py ebpf_syscall_analysis_server1.log  &
# LOG1_PID=$!
# python3 logtracing.py ebpf_syscall_analysis_server2A.log &
# LOG2A_PID=$!
# python3 logtracing.py ebpf_syscall_analysis_server2B.log &
# LOG2B_PID=$!
# python3 logtracing.py ebpf_syscall_analysis_client.log &
# LOGC_PID=$!

# sleep 3

# echo "[*] Triggering Client Request..."
# ./client 

# echo "------------------------------------------------------"
# echo "[*] Tailing live analysis output! (Press Ctrl+C to stop)"
# echo "------------------------------------------------------"

# # This keeps the bash script alive indefinitely and streams the Go server's output to your terminal.
# # When you press Ctrl+C, the trap is triggered and gracefully kills everything.
# tail -f analysis.txt


