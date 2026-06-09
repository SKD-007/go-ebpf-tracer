#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/sched.h>

// Define operation codes so Python knows what to print
enum {
    OP_CONNECT = 1, 
    OP_BIND, 
    OP_ACCEPT4, 
    OP_SETSOCKOPT, 
    OP_GETSOCKOPT, 
    OP_GETPEERNAME,
    OP_READ,
    OP_WRITE
};

#define MAX_PAYLOAD_SIZE 256



//Data Structure sent through the ring buffer
struct data_t {
    u32 pid;          // Process ID (User Space PID)
    u32 tid;          // Thread ID (User Space TID)
    u32 uid;          // User ID
    u32 op;           // Operation code (from enum above)
    u32 fd;           // File Descriptor
    u32 ip;           // IPv4 Address
    u16 port;         // Port
    u32 flags;        // For accept4
    u32 level;        // For setsockopt/getsockopt
    u32 optname;      // For setsockopt/getsockopt
    u64 count;        // For read/write byte count
    char payload[MAX_PAYLOAD_SIZE];
    char comm[TASK_COMM_LEN]; // App Name
};

BPF_PERF_OUTPUT(events);

struct rw_args_t {
    u32 fd;
    const char *buf;
};

BPF_HASH(active_reads, u64, struct rw_args_t);
BPF_HASH(active_writes, u64, struct rw_args_t);

// Helper function to save the common data
static inline void populate_base(struct data_t *data, u32 op_code, u32 fd) {
    // id = ( (pid)32bit + (tid)32bit )64bit
    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;
    data->tid = id;

    // ( (uid)32bit + (gid)32bit )64bit
    data->uid = bpf_get_current_uid_gid() >> 32;

    // op-code is used for figuring out what system call is this
    data->op = op_code;
    data->fd = fd;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

// TRACEPOINTS 

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    populate_base(&data, OP_CONNECT, args->fd);

    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);
    if (addr.sin_family == AF_INET) {
        data.ip = addr.sin_addr.s_addr;
        data.port = bpf_ntohs(addr.sin_port);
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    struct data_t data = {};
    populate_base(&data, OP_BIND, args->fd);

    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), args->umyaddr);
    if (addr.sin_family == AF_INET) {
        data.ip = addr.sin_addr.s_addr;
        data.port = bpf_ntohs(addr.sin_port);
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    struct data_t data = {};
    populate_base(&data, OP_ACCEPT4, args->fd);
    data.flags = args->flags;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setsockopt) {
    struct data_t data = {};
    populate_base(&data, OP_SETSOCKOPT, args->fd);
    data.level = args->level;
    data.optname = args->optname;
    events.perf_submit(args, &data, sizeof(data));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getsockopt) {
    struct data_t data = {};
    populate_base(&data, OP_GETSOCKOPT, args->fd);
    data.level = args->level;
    data.optname = args->optname;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getpeername) {
    struct data_t data = {};
    populate_base(&data, OP_GETPEERNAME, args->fd);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 id = bpf_get_current_pid_tgid();
    struct rw_args_t saved_args = {};
    saved_args.fd = args->fd;
    saved_args.buf = args->buf;
    
    active_reads.update(&id, &saved_args);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 id = bpf_get_current_pid_tgid();
    struct rw_args_t *saved = active_reads.lookup(&id);
    if (!saved) return 0; 

    long ret = args->ret;
    if (ret > 0) {
        struct data_t data = {};
        populate_base(&data, OP_READ, saved->fd);
        data.count = ret;
        
        u32 read_size = (ret < MAX_PAYLOAD_SIZE) ? ret : (MAX_PAYLOAD_SIZE - 1);
        bpf_probe_read_user(&data.payload, read_size, saved->buf);
        
        events.perf_submit(args, &data, sizeof(data));
    }
    active_reads.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {

    if (args->fd < 3) return 0;
    
    u64 id = bpf_get_current_pid_tgid();
    struct rw_args_t saved_args = {};
    saved_args.fd = args->fd;
    saved_args.buf = args->buf;
    
    active_writes.update(&id, &saved_args);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u64 id = bpf_get_current_pid_tgid();
    struct rw_args_t *saved = active_writes.lookup(&id);
    if (!saved) return 0;

    long ret = args->ret;
    if (ret > 0) {
        struct data_t data = {};
        populate_base(&data, OP_WRITE, saved->fd);
        data.count = ret;
        
        u32 read_size = (ret < MAX_PAYLOAD_SIZE) ? ret : (MAX_PAYLOAD_SIZE - 1);
        bpf_probe_read_user(&data.payload, read_size, saved->buf);
        
        events.perf_submit(args, &data, sizeof(data));
    }
    active_writes.delete(&id);
    return 0;
}