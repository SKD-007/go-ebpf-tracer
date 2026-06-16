from bcc import BPF
import socket
import struct

f = open("tracing.bpf.c","r")

bpf_text = f.read()

b = BPF(text=bpf_text)

# Map the integer OP codes back to string names
op_map = {
    1: "connect", 2: "bind", 3: "accept4", 
    4: "setsockopt", 5: "getsockopt", 6: "getpeer",
    7: "read", 8: "write", 9: "EPOLL_WAIT", 10: "inet_csk_accept"
}

# Open a log file to write the results
log_file = open("ebpf_syscall_analysis.log", "w")

def log_and_print(message):
    print(message)
    log_file.write(message + "\n")
    log_file.flush()

header = f"{'UID':<6} {'PID':<8} {'TID':<8} {'APP':<15} {'SYSCALL':<12} {'TIME(s)':<14} {'ARGUMENTS & DETAILS'}"
log_and_print("Starting raw eBPF Network Trace... Hit Ctrl+C to end.")
log_and_print(header)
log_and_print("-" * 90)

def print_event(ctx, data, size):
    event = b["events"].event(data)
    
    app_name = event.comm.decode('utf-8', 'replace')
    # Restricting ourself with only looking at these specific apps
    valid_apps = ["server1", "main"]
    
    if app_name not in valid_apps:
        return # Silently ignore background OS noise like 'node' or 'udevd'

    syscall_name = op_map.get(event.op, "unknown")
    
    # Base details string
    details = f"FD: {event.fd} | "
    
    # Format the rest of the string based on exactly which syscall triggered
    if event.op in (1, 2): # connect or bind
        remote_ip_str = socket.inet_ntoa(struct.pack("<I", event.daddr))
        details += f"remote: {remote_ip_str}:{event.dport}"
    elif event.op == 3: # accept4
        local_ip_str = socket.inet_ntoa(struct.pack("<I", event.saddr))

        details += f"local: {local_ip_str}:{event.sport}"
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
        details += f"Bytes: {event.count} | Data: {payload[:80]}"
    elif event.op == 9:
        details += f"Maxevent: {event.maxevents}"
    elif event.op == 10: # inet_csk_accept
        remote_ip_str = socket.inet_ntoa(struct.pack("<I", event.daddr))
        local_ip_str = socket.inet_ntoa(struct.pack("<I", event.saddr))

        details += f"local: {local_ip_str:<15}{event.sport} | remote: {remote_ip_str}{event.dport}"

    time_s = event.timestamp_ns / 1000000000.0
    time_str = f"{time_s:.8f}"

    row = f"{event.uid:<6} {event.pid:<8} {event.tid:<8} {app_name:<15} {syscall_name:<12} {time_str:<14} {details}"
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