from bcc import BPF
import socket
import struct
import argparse
import sys
import os
import shutil
import re

parser = argparse.ArgumentParser(description="eBPF Network Trace with Go Coroutines")
parser.add_argument("binary", help="Path to your compiled Go binary (e.g., ./main)")
args = parser.parse_args()
print(args.binary, type(args.binary))

binary_path = os.path.abspath(args.binary)
if not os.path.isfile(binary_path):
    # If it's not in the current folder, check the system $PATH
    binary_path = shutil.which(args.binary)
    if not binary_path:
        print(f"[!] Error: Cannot find binary file for '{args.binary}'")
        sys.exit(1)

# 2. Extract exactly how the Linux kernel will report the app name
# The kernel's TASK_COMM_LEN is 16 bytes (15 characters + null terminator)
app_base_name = os.path.basename(binary_path)[:15]

print(f"[*] Resolved binary path: {binary_path}")
print(f"[*] Listening for kernel app name: {app_base_name}")

f = open("tracing.bpf.c","r")

bpf_text = f.read()

b = BPF(text=bpf_text)

# attaching the user function to ebpf function
print(f"[*] Attaching Go specific uprobes to {args.binary}...")

# Helper function to attach probes resiliently 
def attach_probe(sym_name, fn_name, is_ret=False):
    try:
        if is_ret:
            b.attach_uretprobe(name=binary_path, sym=sym_name, fn_name=fn_name)
        else:
            b.attach_uprobe(name=binary_path, sym=sym_name, fn_name=fn_name)
        print(f" [+] Attached to {sym_name}")
    except Exception as e:
        # Gracefully handle missing symbols without crashing the script
        print(f" [-] Skipping {sym_name} (Not found in this binary)")

# 1. Client-Side Hooks (Will succeed on server1, gracefully skip on server2)
attach_probe("net/http.(*persistConn).roundTrip", "trace_checkout")
attach_probe("net/http.(*persistConn).writeLoop", "trace_worker_loop")
attach_probe("net/http.(*persistConn).readLoop", "trace_worker_loop")

# 2. Server-Side Hooks (Will succeed on BOTH server1 and server2)
attach_probe("net/http.serverHandler.ServeHTTP", "trace_servehttp_enter")

# 3. Goroutine Tree Hooks (Will succeed on BOTH)
attach_probe("runtime.newproc1", "trace_newproc1_enter")
attach_probe("runtime.newproc1", "trace_newproc1_return", is_ret=True)

# 4. Cleanup Hooks (Client-Side)
try:
    b.attach_uprobe(name=binary_path, sym="net/http.(*Transport).putOrCloseIdleConn", fn_name="trace_put_conn")
    print(" [+] Attached to putOrCloseIdleConn")
except:
    attach_probe("net/http.(*Transport).tryPutIdleConn", "trace_put_conn")

# Map the integer OP codes back to string names
op_map = {
    1: "connect", 2: "bind", 3: "accept4", 
    4: "setsockopt", 5: "getsockopt", 6: "getpeer",
    7: "read", 8: "write", 9: "EPOLL_WAIT", 10: "inet_csk_accept"
}

# Open a log file to write the results
log_file = open(f"ebpf_syscall_analysis_{app_base_name}.log", "w")

def log_and_print(message):
    # print(message)
    log_file.write(message + "\n")
    log_file.flush()

header = f"{'UID':<6} {'PID':<8} {'TID':<8} {'APP':<15} {'SYSCALL':<12} {'P_GOID':<8} {'W_GOID':<8} {'TIME(s)':<14} {'ARGUMENTS & DETAILS'}"
log_and_print("Starting raw eBPF Network Trace... Hit Ctrl+C to end.")
log_and_print(header)
log_and_print("-" * 90)

def print_event(ctx, data, size):
    event = b["events"].event(data)
    
    app_name = event.comm.decode('utf-8', 'replace')
    # Restricting ourself with only looking at these specific apps
    valid_apps = [app_base_name]
    
    if app_name not in valid_apps:
        return # Silently ignore background OS noise like 'node' or 'udevd'

    syscall_name = op_map.get(event.op, "unknown")
    
    # Base details string
    details = f"FD: {event.fd} | "
    if event.pconn_addr != 0:
        details += f"PCONN: {hex(event.pconn_addr)} | "

    # Format the rest of the string based on exactly which syscall triggered
    if event.op == 1: # connect 
        remote_ip_str = socket.inet_ntoa(struct.pack("<I", event.daddr))
        local_ip_str = socket.inet_ntoa(struct.pack("<I", event.saddr))
        details += f"local: {local_ip_str}:{event.sport} remote: {remote_ip_str}:{event.dport} tcp_seq: {event.tcp_seq}"

    elif event.op == 3: # accept4
        remote_ip_str = socket.inet_ntoa(struct.pack("<I", event.daddr))
        local_ip_str = socket.inet_ntoa(struct.pack("<I", event.saddr))
        details += f"local: {local_ip_str}:{event.sport} remote: {remote_ip_str}:{event.dport} tcp_seq: {event.tcp_seq}"
        # details += f"Flags: {event.flags}"

    elif event.op in (4, 5): # setsockopt or getsockopt
        details += f"Level: {event.level:<2} | OptName: {event.optname}"
    elif event.op in [7, 8]:  # OP_READ=7, OP_WRITE=8
        payload = ""
        try:
            # Decode bytes to text, ignore garbage binary, replace newlines with a visual separator
            payload = event.payload.decode('utf-8', 'ignore').replace('\n', ' | ').replace('\r', '')
        except:
            pass        
        details += f"Bytes: {event.count} | tcp_seq: {event.tcp_seq} | Data: {payload[:400]}"
    elif event.op == 9:
        details += f"Maxevent: {event.maxevents}"
    elif event.op == 10: # inet_csk_accept
        remote_ip_str = socket.inet_ntoa(struct.pack("<I", event.daddr))
        local_ip_str = socket.inet_ntoa(struct.pack("<I", event.saddr))

        details += f"local: {local_ip_str:<15}{event.sport} | remote: {remote_ip_str}{event.dport}"

    time_s = event.timestamp_ns / 1000000000.0
    time_str = f"{time_s:.8f}"

    row = f"{event.uid:<6} {event.pid:<8} {event.tid:<8} {app_name:<15} {syscall_name:<12} {event.parent_goid:<8} {event.goid:<8} {time_str:<14} {details}"
    log_and_print(row)

# Hook up the callback and start listening
b["events"].open_ring_buffer(print_event)
try:
    while True:
        b.ring_buffer_poll(timeout=500)
except KeyboardInterrupt:
    log_and_print("\nTrace stopped by user. Log saved to ebpf_syscall_analysis.log")
    log_file.close()
    exit()
