#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <net/sock.h>
// Define operation codes so Python knows what to print
enum {
    OP_CONNECT = 1, 
    OP_BIND, 
    OP_ACCEPT4, 
    OP_SETSOCKOPT, 
    OP_GETSOCKOPT, 
    OP_GETPEERNAME,
    OP_READ,
    OP_WRITE,
    OP_EPOLL_WAIT,
    OP_INET_CSK_ACCEPT4
};

#define MAX_PAYLOAD_SIZE 256



//Data Structure sent through the ring buffer
struct data_t {
    u64 timestamp_ns;  // Time
    u32 pid;          // Process ID (User Space PID)
    u32 tid;          // Thread ID (User Space TID)
    u32 uid;          // User ID

    u32 op;           // Operation code (from enum above)
    u32 fd;           // File Descriptor
    
    u32 saddr;         // Source IP address
    u32 daddr;         // Destination IP address
    u32 sport;         //  Source Port
    u32 dport;         //  Destination Port
    
    u32 flags;        // For accept4
    // u32 level;        // For setsockopt/getsockopt
    // u32 optname;      // For setsockopt/getsockopt
    u64 count;        // For read/write byte count
    u32 maxevents;
    char payload[MAX_PAYLOAD_SIZE];
    char comm[TASK_COMM_LEN]; // App Name
};

BPF_RINGBUF_OUTPUT(events, 1024);

struct rw_args_t {
    u32 fd;
    const char *buf;
};

// Map wxit read content to the entry read
BPF_HASH(active_reads, u64, struct rw_args_t);
// Map entry write content to the exit write
BPF_HASH(active_writes, u64, struct rw_args_t);

// Map to pass the sockaddr pointer from enter_accept4 to exit_accept4
BPF_HASH(active_accepts, u64, struct sockaddr *);

// Helper function to save the common data
static inline void populate_base(struct data_t *data, u32 op_code, u32 fd) {
    
    data->timestamp_ns = bpf_ktime_get_ns();
    
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
        data.daddr = addr.sin_addr.s_addr;
        data.dport = bpf_ntohs(addr.sin_port);
        data.sport = 0;
        data.saddr = 0;
        events.ringbuf_output(&data, sizeof(data), 0);
        // events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

// TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
//     struct data_t data = {};
//     populate_base(&data, OP_BIND, args->fd);

//     struct sockaddr_in addr = {};
//     bpf_probe_read_user(&addr, sizeof(addr), args->umyaddr);
//     if (addr.sin_family == AF_INET) {
//         data.ip = addr.sin_addr.s_addr;
//         data.port = bpf_ntohs(addr.sin_port);
//         events.ringbuf_output(&data, sizeof(data), 0);
//         // events.perf_submit(args, &data, sizeof(data));
//     }
//     return 0;
// }

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    
    // args->upeer_sockaddr is the pointer where the kernel will write the IP
    struct sockaddr *addr = (struct sockaddr *)args->upeer_sockaddr;
    active_accepts.update(&id, &addr);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    
    // 1. Look up the pointer we saved
    struct sockaddr **addr_ptr = active_accepts.lookup(&id);
    if (!addr_ptr) return 0;

    // 2. The return value of accept4 IS the new File Descriptor!
    long new_fd = args->ret;
    
    // If accept was successful (fd > 0)
    if (new_fd > 0) {
        struct sockaddr_in addr = {};
        
        // 3. Copy the now-populated IP data from User Space
        bpf_probe_read_user(&addr, sizeof(addr), *addr_ptr);

        // 4. Check if it's IPv4 OR IPv6-mapped-IPv4 (Go's default)
        // AF_INET = 2, AF_INET6 = 10
        if (addr.sin_family == AF_INET || addr.sin_family == 10) {
            struct data_t data = {};
            
            // Pass the new FD into our base populator!
            populate_base(&data, OP_ACCEPT4, new_fd);
            
            // Note: Since this is an incoming connection, the remote client 
            // is stored in the user-space sockaddr.
            data.saddr = addr.sin_addr.s_addr;
            data.sport = bpf_ntohs(addr.sin_port);
            
            events.ringbuf_output(&data, sizeof(data), 0);
        }
    }
    
    active_accepts.delete(&id);
    return 0;
}

// TRACEPOINT_PROBE(syscalls, sys_enter_setsockopt) {
//     struct data_t data = {};
//     populate_base(&data, OP_SETSOCKOPT, args->fd);
//     data.level = args->level;
//     data.optname = args->optname;
//     events.ringbuf_output(&data, sizeof(data), 0);
//     // events.perf_submit(args, &data, sizeof(data));
    
//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_enter_getsockopt) {
//     struct data_t data = {};
//     populate_base(&data, OP_GETSOCKOPT, args->fd);
//     data.level = args->level;
//     data.optname = args->optname;
//     events.ringbuf_output(&data, sizeof(data), 0);
//     // events.perf_submit(args, &data, sizeof(data));
//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_enter_getpeername) {
//     struct data_t data = {};
//     populate_base(&data, OP_GETPEERNAME, args->fd);
//     events.ringbuf_output(&data, sizeof(data), 0);
//     // events.perf_submit(args, &data, sizeof(data));
//     return 0;
// }

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

        events.ringbuf_output(&data, sizeof(data), 0);
        // events.perf_submit(args, &data, sizeof(data));
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

        events.ringbuf_output(&data, sizeof(data), 0);
        // events.perf_submit(args, &data, sizeof(data));
    }
    active_writes.delete(&id);
    return 0;
}

// TRACEPOINT_PROBE(syscalls, sys_enter_epoll_pwait) {
//     struct data_t data = {};
    
//     // args->epfd is the epoll instance being waited on
//     populate_base(&data, OP_EPOLL_WAIT, args->epfd); 
    
//     data.maxevents = args->maxevents;
//     events.ringbuf_output(&data, sizeof(data), 0);
//     // events.perf_submit(args, &data, sizeof(data));
    
//     return 0;
// }



















// int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    
//     // PT_REGS_RC grabs the return value of the function.
//     // For inet_csk_accept, this is a pointer to the NEW socket.
//     struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

//     // If accept failed (e.g., the queue was empty), newsk will be NULL
//     if (newsk == NULL) {
//         return 0;
//     }

//     // Optional: Filter for IPv4 to avoid IPv6 garbage data
//     u16 family = newsk->__sk_common.skc_family;
//     if (family != AF_INET) {
//         return 0;
//     }

//     struct data_t data = {};
    
//     // Note: We pass 0 for fd. Getting the new user-space fd from deep 
//     // inside this kernel function is highly complex and usually unnecessary 
//     // for network monitoring.
//     populate_base(&data, OP_INET_CSK_ACCEPT4, 0); 

//     // The kernel has fully populated the new socket, so we can grab the 4-tuple!
//     data.saddr = newsk->__sk_common.skc_rcv_saddr;
//     data.daddr = newsk->__sk_common.skc_daddr;
    
//     // Grab the ports (remembering to flip the destination port endianness)
//     data.sport = newsk->__sk_common.skc_num; 
//     data.dport = bpf_ntohs(newsk->__sk_common.skc_dport);

//     events.ringbuf_output(&data, sizeof(data), 0);
//     return 0;
// }