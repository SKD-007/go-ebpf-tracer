#!/usr/bin/env python3
from bcc import BPF
import ctypes 
import time
import socket
import struct
import json
import http.client
import threading
from queue import Queue, Empty
import sys
from datetime import datetime

# --- Configuration ---
COLLECTOR_HOST = "10.128.7.227"
COLLECTOR_PORT = 5000
BATCH_SIZE = 100
log_queue = Queue(maxsize=10000)

def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("<I", addr))

# --- BPF Program (C) ---
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

struct conn_info_t {
    u32 local_ip;
    u32 remote_ip;
    u16 local_port;
    u16 remote_port;
};

struct data_t {
    u64 pid;
    u64 ts;      
    int bytes;      
    char comm[TASK_COMM_LEN];
    char event_type[12];
    char tracepoint[32];        // <-- NEW: kernel probe that fired
    struct conn_info_t conn;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(stashed_sock, u64, struct sock *);
BPF_HASH(conn_table, struct sock *, struct conn_info_t); 

static inline bool is_target_process() {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e') return true;
    if (comm[0] == 'P' && comm[1] == 'M' && comm[2] == '2') return true;
    return false;
}

static inline void fill_conn_info(struct sock *sk, struct conn_info_t *conn) {
    if (!sk) return;
    bpf_probe_read_kernel(&conn->local_ip, sizeof(conn->local_ip), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&conn->remote_ip, sizeof(conn->remote_ip), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&conn->local_port, sizeof(conn->local_port), &sk->__sk_common.skc_num);
    u16 dp;
    bpf_probe_read_kernel(&dp, sizeof(dp), &sk->__sk_common.skc_dport);
    conn->remote_port = ntohs(dp);
}

int kprobe_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    if (!is_target_process()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    stashed_sock.update(&id, &sk);
    return 0;
}

int kretprobe_tcp_v4_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct sock **skpp = stashed_sock.lookup(&id);
    if (!skpp) return 0;
    struct sock *sk = *skpp;

    int ret = PT_REGS_RC(ctx);
    if (ret == 0) {
        struct conn_info_t conn = {0};
        fill_conn_info(sk, &conn);
        conn_table.update(&sk, &conn);

        struct data_t data = {0};
        data.pid = id >> 32;
        data.ts = bpf_ktime_get_ns();
        data.conn = conn;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        __builtin_memcpy(&data.event_type, "CONNECT", 8);
        __builtin_memcpy(&data.tracepoint, "tcp_v4_connect", 15);   // <-- NEW
        events.perf_submit(ctx, &data, sizeof(data));
    }
    stashed_sock.delete(&id);
    return 0;
}

int kprobe_sock_io_entry(struct pt_regs *ctx, struct socket *sock) {
    if (!is_target_process()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct sock *sk = sock->sk;
    stashed_sock.update(&id, &sk);
    return 0;
}

int kprobe_tcp_send_entry(struct pt_regs *ctx, struct sock *sk) {
    if (!is_target_process()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    stashed_sock.update(&id, &sk);
    return 0;
}

// Updated to accept a tracepoint label too
static inline void report_io(struct pt_regs *ctx, char *label, char *tp_name, int tp_len) {
    u64 id = bpf_get_current_pid_tgid();
    struct sock **skpp = stashed_sock.lookup(&id);
    if (!skpp) return;

    struct conn_info_t *info = conn_table.lookup(skpp);
    if (info) {
        struct data_t data = {0};
        data.pid = id >> 32;
        data.ts = bpf_ktime_get_ns();
        data.bytes = PT_REGS_RC(ctx);
        data.conn = *info;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        __builtin_memcpy(&data.event_type, label, 12);
        __builtin_memcpy(&data.tracepoint, tp_name, tp_len);         // <-- NEW
        events.perf_submit(ctx, &data, sizeof(data));
    }
    stashed_sock.delete(&id);
}

// Each kretprobe now passes its own tracepoint name
int kretprobe_sock_write(struct pt_regs *ctx) {
    report_io(ctx, "WRITE_SO", "sock_sendmsg", 13);
    return 0;
}

int kretprobe_sock_read(struct pt_regs *ctx) {
    report_io(ctx, "READ_SO", "sock_recvmsg", 13);
    return 0;
}

int kretprobe_inet_csk_accept(struct pt_regs *ctx) {
    if (!is_target_process()) return 0;
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk) return 0;

    struct conn_info_t conn = {0};
    fill_conn_info(newsk, &conn);
    conn_table.update(&newsk, &conn);

    struct data_t data = {0};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    data.conn = conn;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event_type, "ACCEPT", 7);
    __builtin_memcpy(&data.tracepoint, "inet_csk_accept", 16);       // <-- NEW
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

void kprobe_tcp_close(struct pt_regs *ctx, struct sock *sk) {
    struct conn_info_t *info = conn_table.lookup(&sk);
    if (info) {
        struct data_t data = {0};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.ts = bpf_ktime_get_ns();
        data.conn = *info;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        __builtin_memcpy(&data.event_type, "CLOSE_SO", 9);
        __builtin_memcpy(&data.tracepoint, "tcp_close", 10);         // <-- NEW
        events.perf_submit(ctx, &data, sizeof(data));
        conn_table.delete(&sk);
    }
}
"""

# --- Python Logic ---
class ConnInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("local_ip", ctypes.c_uint), ("remote_ip", ctypes.c_uint),
                ("local_port", ctypes.c_ushort), ("remote_port", ctypes.c_ushort)]

class Data(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("pid",        ctypes.c_ulonglong),
        ("ts",         ctypes.c_ulonglong),
        ("bytes",      ctypes.c_int),
        ("comm",       ctypes.c_char * 16),
        ("event_type", ctypes.c_char * 12),
        ("tracepoint", ctypes.c_char * 32),   # <-- NEW: must match BPF struct order
        ("conn",       ConnInfo),
    ]

boot_time = time.time() - (BPF.monotonic_time() / 1e9)

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    label      = event.event_type.decode().strip()
    tracepoint = event.tracepoint.decode().strip()        # <-- NEW
    precise_ts = datetime.fromtimestamp(boot_time + (event.ts / 1e9)).strftime('%H:%M:%S.%f')
    
    l_ip, r_ip = int_to_ip(event.conn.local_ip), int_to_ip(event.conn.remote_ip)
    bytes_val  = event.bytes if event.bytes > 0 else 0
    
    log_queue.put({
        "timestamp":  precise_ts,
        "label":      label,
        "tracepoint": tracepoint,                         # <-- NEW
        "pid":        event.pid,
        "comm":       event.comm.decode(),
        "bytes":      bytes_val,
        "local":      f"{l_ip}:{event.conn.local_port}",
        "remote":     f"{r_ip}:{event.conn.remote_port}",
    })

# --- ASYNC SENDER WITH BATCHING ---
def async_log_sender():
    conn = None
    batch = []
    
    while True:
        try:
            item = log_queue.get(timeout=1.0)
            if item is None:
                if batch:
                    send_batch(conn, batch)
                break
            batch.append(item)
        except Empty:
            pass

        if batch and (len(batch) >= BATCH_SIZE or log_queue.empty()):
            conn = send_batch(conn, batch)
            batch.clear()

def send_batch(conn, batch):
    try:
        if conn is None:
            conn = http.client.HTTPConnection(COLLECTOR_HOST, COLLECTOR_PORT, timeout=5)
        
        headers = {"Content-Type": "application/json"}
        body    = json.dumps(batch)
        conn.request("POST", "/log/event", body, headers)
        
        response = conn.getresponse()
        response.read()
        
        if response.status != 200:
            print(f"Logs rejected by collector: {response.status}")
        return conn
    except Exception as e:
        print(f"Network Error: {e}")
        if conn:
            conn.close()
        return None

# --- Main ---
b = BPF(text=bpf_program)

b.attach_kprobe(event="tcp_v4_connect",   fn_name="kprobe_tcp_v4_connect")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="kretprobe_tcp_v4_connect")
b.attach_kretprobe(event="inet_csk_accept", fn_name="kretprobe_inet_csk_accept")
b.attach_kprobe(event="sock_sendmsg",     fn_name="kprobe_sock_io_entry")
b.attach_kretprobe(event="sock_sendmsg",  fn_name="kretprobe_sock_write")
b.attach_kprobe(event="tcp_sendmsg",      fn_name="kprobe_tcp_send_entry")
b.attach_kretprobe(event="tcp_sendmsg",   fn_name="kretprobe_sock_write")
b.attach_kprobe(event="sock_recvmsg",     fn_name="kprobe_sock_io_entry")
b.attach_kretprobe(event="sock_recvmsg",  fn_name="kretprobe_sock_read")
b.attach_kprobe(event="tcp_close",        fn_name="kprobe_tcp_close")

threading.Thread(target=async_log_sender, daemon=True).start()
print("Tracing Node Topology... READY")

b["events"].open_perf_buffer(handle_event)
while True:
    try: 
        b.perf_buffer_poll()
    except KeyboardInterrupt: 
        log_queue.put(None)
        sys.exit()
