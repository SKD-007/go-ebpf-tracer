#!/usr/bin/env python3
from bcc import BPF
import ctypes
import time
import socket
import struct
from datetime import datetime

TARGET_PID = 5365

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <bcc/proto.h>

struct sock_common {
    u32 skc_rcv_saddr;
    u32 skc_daddr;
    union {
        struct { u16 skc_dport; u16 skc_num; };
    };
};

struct sock {
    struct sock_common __sk_common;
};

struct conn_info_t {
    u32 local_ip;
    u32 remote_ip;
    u16 local_port;
    u16 remote_port;
};

struct data_t {
    u32 pid;
    u32 tid;
    u64 ts;
    char event_type[16];
    struct conn_info_t conn;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(stashed_sock, u64, struct sock *);
BPF_HASH(conn_table,   struct sock *, struct conn_info_t);

static inline void fill_conn_info(struct sock *sk, struct conn_info_t *conn) {
    if (!sk) return;
    bpf_probe_read_kernel(&conn->local_ip,   sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&conn->remote_ip,  sizeof(u32), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&conn->local_port, sizeof(u16), &sk->__sk_common.skc_num);
    u16 dp = 0;
    bpf_probe_read_kernel(&dp, sizeof(u16), &sk->__sk_common.skc_dport);
    conn->remote_port = (dp >> 8) | (dp << 8);
}

static inline void emit(struct pt_regs *ctx, u64 id,
                        const char *label, int label_len,
                        struct conn_info_t *conn) {
    struct data_t data = {0};
    data.pid  = id >> 32;
    data.tid  = (u32)id;
    data.ts   = bpf_ktime_get_ns();
    data.conn = *conn;
    __builtin_memcpy(&data.event_type, label, label_len);
    events.perf_submit(ctx, &data, sizeof(data));
}

// ── tcp_v4_connect: outgoing connection ──────────────────────────────────
int kprobe_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != TARGET_PID) return 0;
    stashed_sock.update(&id, &sk);
    return 0;
}

int kretprobe_tcp_v4_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != TARGET_PID) return 0;
    struct sock **skpp = stashed_sock.lookup(&id);
    if (!skpp) return 0;
    if ((int)PT_REGS_RC(ctx) == 0) {
        struct conn_info_t conn = {0};
        fill_conn_info(*skpp, &conn);
        conn_table.update(skpp, &conn);
        emit(ctx, id, "CONNECT", 8, &conn);
    }
    stashed_sock.delete(&id);
    return 0;
}

// ── inet_csk_accept: incoming connection ─────────────────────────────────
int kretprobe_inet_csk_accept(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != TARGET_PID) return 0;
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk) return 0;
    struct conn_info_t conn = {0};
    fill_conn_info(newsk, &conn);
    conn_table.update(&newsk, &conn);
    emit(ctx, id, "ACCEPT", 7, &conn);
    return 0;
}

// ── tcp_sendmsg / sock_sendmsg: write ────────────────────────────────────
int kprobe_sock_io_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != TARGET_PID) return 0;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    stashed_sock.update(&id, &sk);
    return 0;
}

int kretprobe_sock_write(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != TARGET_PID) return 0;
    struct sock **skpp = stashed_sock.lookup(&id);
    if (!skpp) return 0;
    struct conn_info_t *info = conn_table.lookup(skpp);
    if (info) emit(ctx, id, "WRITE", 6, info);
    stashed_sock.delete(&id);
    return 0;
}

// ── tcp_recvmsg: read ─────────────────────────────────────────────────────
int kretprobe_sock_read(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != TARGET_PID) return 0;
    struct sock **skpp = stashed_sock.lookup(&id);
    if (!skpp) return 0;
    struct conn_info_t *info = conn_table.lookup(skpp);
    if (info) emit(ctx, id, "READ", 5, info);
    stashed_sock.delete(&id);
    return 0;
}

// ── tcp_close: cleanup ────────────────────────────────────────────────────
int kprobe_tcp_close(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != TARGET_PID) return 0;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct conn_info_t *info = conn_table.lookup(&sk);
    if (info) {
        emit(ctx, id, "CLOSE", 6, info);
        conn_table.delete(&sk);
    }
    return 0;
}
"""

# ── ctypes structs ────────────────────────────────────────────────────────
class ConnInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("local_ip",    ctypes.c_uint),
        ("remote_ip",   ctypes.c_uint),
        ("local_port",  ctypes.c_ushort),
        ("remote_port", ctypes.c_ushort),
    ]

class Data(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("pid",        ctypes.c_uint),
        ("tid",        ctypes.c_uint),
        ("ts",         ctypes.c_ulonglong),
        ("event_type", ctypes.c_char * 16),
        ("conn",       ConnInfo),
    ]

def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("<I", addr))

boot_time = time.time() - (BPF.monotonic_time() / 1e9)

def handle_event(cpu, data, size):
    event  = ctypes.cast(data, ctypes.POINTER(Data)).contents
    label  = event.event_type.decode().strip('\x00')
    ts     = datetime.fromtimestamp(boot_time + event.ts / 1e9).strftime('%H:%M:%S.%f')
    l_ip   = int_to_ip(event.conn.local_ip)
    r_ip   = int_to_ip(event.conn.remote_ip)
    l_port = event.conn.local_port
    r_port = event.conn.remote_port
    print(f"[{ts}] {label:<10} pid={event.pid} tid={event.tid} "
          f"local={l_ip}:{l_port} remote={r_ip}:{r_port}")

# ── attach probes ─────────────────────────────────────────────────────────
b = BPF(text=bpf_program, cflags=["-DTARGET_PID=%d" % TARGET_PID])

b.attach_kprobe   (event="tcp_v4_connect",   fn_name="kprobe_tcp_v4_connect")
b.attach_kretprobe(event="tcp_v4_connect",   fn_name="kretprobe_tcp_v4_connect")
b.attach_kretprobe(event="inet_csk_accept",  fn_name="kretprobe_inet_csk_accept")
b.attach_kprobe   (event="tcp_sendmsg",      fn_name="kprobe_sock_io_entry")
b.attach_kretprobe(event="tcp_sendmsg",      fn_name="kretprobe_sock_write")
b.attach_kprobe   (event="tcp_recvmsg",      fn_name="kprobe_sock_io_entry")
b.attach_kretprobe(event="tcp_recvmsg",      fn_name="kretprobe_sock_read")
b.attach_kprobe   (event="tcp_close",        fn_name="kprobe_tcp_close")

print(f"Tracing Go server (PID={TARGET_PID})... Ctrl+C to stop")

b["events"].open_perf_buffer(handle_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nStopping tracer...")
        break
