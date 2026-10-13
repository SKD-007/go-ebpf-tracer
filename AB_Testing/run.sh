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
