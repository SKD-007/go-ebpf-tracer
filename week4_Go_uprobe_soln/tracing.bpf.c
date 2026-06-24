// --- BCC / New Kernel Header Compatibility Patch ---
struct bpf_wq { void *ptr; };
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ 1
#endif
#ifndef BPF_STORE_REL
#define BPF_STORE_REL 2
#endif
// ---------------------------------------------------

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

// map persisConn pointer -> parent Goid
BPF_HASH(checkout_map,u64,u64);
// map worker goid - persisConn pointer
BPF_HASH(worker_map,u64,u64) ;

// extracting the goid from thread TLS
static __always_inline u64 get_goid(){
    struct task_struct *task = (struct task_struct*) bpf_get_current_task();

    char *fs_base;
    bpf_probe_read(&fs_base,sizeof(fs_base),&task->thread.fsbase);

    char *goid_ptr;
    bpf_probe_read(&goid_ptr,sizeof(goid_ptr),fs_base - 8);

    u64 goid = 0;
    bpf_probe_read(&goid,sizeof(goid),goid_ptr + 152);

    return goid;
}

// Delete the persist from hash in case the connection is closed
int trace_put_conn(struct pt_regs * ctx){
    u64 persisConn = ctx->ax;
    checkout_map.delete(&persisConn);
    return 0;
}

//Data Structure sent through the ring buffer
struct data_t {
    u64 timestamp_ns;  // Time
    u32 pid;          // Process ID (User Space PID)
    u32 tid;          // Thread ID (User Space TID)
    u32 uid;          // User ID

    u64 goid;
    u64 parent_goid;
    u64 pconn_addr;

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

    // data->goid = get_goid();
    // u64 *parent = worker_map.lookup(&data->goid);

    // if(parent){
    //     // parent does exist for this
    //     data->parent_goid = *parent;
    // }
    // else{
    //     // put the parent as same as that of worker
    //     data->parent_goid = data->goid;
    // }

    data->goid = get_goid();
    data->parent_goid = data->goid;
    data->pconn_addr = 0;

    u64 *pc_ptr = worker_map.lookup(&data->goid);
    if(pc_ptr){
        data->pconn_addr = *pc_ptr;
	u64 *parent_ptr = checkout_map.lookup(pc_ptr);
        if(parent_ptr){
            data->parent_goid = *parent_ptr;
        }
    }
}

// TRACEPOINTS 

// Tracing USERSPACE

// Uretprobe on net/http.(*Transport).getConn - This is where the persisConn is created
int trace_checkout(struct pt_regs *ctx) {
    u64 parent_goid = get_goid();
    u64 persistConn = ctx->ax;

    if (persistConn == 0) {
        // Fallback 2: Try Closure Context in RDX
        bpf_probe_read(&persistConn, sizeof(persistConn), (void *)(ctx->dx + 8));
    }
    if (persistConn == 0) {
        // Fallback 3: Try Stack
        bpf_probe_read(&persistConn, sizeof(persistConn), (void *)(ctx->sp + 8));
    }

    if (persistConn != 0) {
        checkout_map.update(&persistConn, &parent_goid);
    }
    return 0;
}

// Uprobe on net/http.(*persistConn).writeLoop & readLoop
int trace_worker_loop(struct pt_regs *ctx){
    u64 worker_goid = get_goid();

    u64 persisConn = ctx->ax; // Fallback 1: Try RAX

    if (persisConn == 0) {
        // Fallback 2: Try Closure Context in RDX
        bpf_probe_read(&persisConn, sizeof(persisConn), (void *)(ctx->dx + 8));
    }
    if (persisConn == 0) {
        // Fallback 3: Try Stack
        bpf_probe_read(&persisConn, sizeof(persisConn), (void *)(ctx->sp + 8));
    }

    bpf_trace_printk("Worker | Worker GOID: %d | PCONN: %llx\\n", worker_goid, persisConn);

    if(persisConn != 0){
        worker_map.update(&worker_goid, &persisConn);
    }
    return 0;
}


/*
// Uprobe on net/http.(*persistConn).writeLoop & readLoop
int trace_worker_loop(struct pt_regs *ctx){
    u64 worker_goid = get_goid();
    u64 persisConn = ctx->ax;

    // u64 * parent_goid = checkout_map.lookup(&persisConn);
    // if(parent_goid){
    //     worker_map.update(&worker_goid,parent_goid);
    // }

    if(persisConn != 0){
        worker_map.update(&worker_goid,&persisConn);
    }
    return 0;
}
*/
// 3. Uprobe on putOrCloseIdleConn (Cleanup)
int trace_put_Conn(struct pt_regs * ctx){
    u64 persisConn = ctx->ax;
    checkout_map.delete(&persisConn);
    return 0;
}


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
    else if (addr.sin_family == AF_INET6) { // AF_INET6 is family 10
        // Handle IPv6 / Go's Dual-Stack connections
        struct sockaddr_in6 addr6 = {};
        bpf_probe_read_user(&addr6, sizeof(addr6), args->uservaddr);
        
        // Trick: Grab the last 4 bytes of the 16-byte IPv6 address.
        // For IPv4-mapped addresses (::ffff:127.0.0.1), this extracts the exact IPv4 IP!
        __builtin_memcpy(&data.daddr, (char *)&addr6.sin6_addr + 12, 4);
        
        data.dport = bpf_ntohs(addr6.sin6_port);
        data.sport = 0;
        data.saddr = 0;
        events.ringbuf_output(&data, sizeof(data), 0);
    }
    return 0;
}

// TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
//  
//    struct data_t data = {};
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
        struct data_t data = {};
        populate_base(&data, OP_ACCEPT4, new_fd);
        
        // 1. Peek at the family first
        short family = 0;
        bpf_probe_read_user(&family, sizeof(family), *addr_ptr);

        // 2. Handle based on the specific struct size and offsets
        if (family == AF_INET) {
            struct sockaddr_in addr4 = {};
            bpf_probe_read_user(&addr4, sizeof(addr4), *addr_ptr);
            
            data.daddr = addr4.sin_addr.s_addr;
            data.dport = bpf_ntohs(addr4.sin_port);
            
            events.ringbuf_output(&data, sizeof(data), 0);
            
        } else if (family == 10) { // AF_INET6
            struct sockaddr_in6 addr6 = {};
            bpf_probe_read_user(&addr6, sizeof(addr6), *addr_ptr);
            
            // Extract the last 4 bytes of the IPv4-mapped IPv6 address
            __builtin_memcpy(&data.daddr, (char *)&addr6.sin6_addr + 12, 4);
            data.dport = bpf_ntohs(addr6.sin6_port);
            
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




