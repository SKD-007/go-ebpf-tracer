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
#include <net/tcp.h>
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

BPF_RINGBUF_OUTPUT(events, 1024*8 );

struct rw_args_t {
    u32 fd;
    const char *buf;
};


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

    u32 tcp_seq;       // TCP Sequence Number (Initial/Next)
    
    u32 flags;        // For accept4
    // u32 level;        // For setsockopt/getsockopt
    // u32 optname;      // For setsockopt/getsockopt
    u64 count;        // For read/write byte count
    u32 maxevents;
    char payload[MAX_PAYLOAD_SIZE];
    char comm[TASK_COMM_LEN]; // App Name

    // Used purely inside the kernel to pass state between probes.
    // Your Go/Python user-space code can just ignore this field.
    u64 sk_ptr;
};

// map persisConn pointer -> parent Goid
BPF_HASH(checkout_map,u64,u64);
// map worker goid - persisConn pointer
BPF_HASH(worker_map,u64,u64) ;


// Map exit read content to the entry read
BPF_HASH(active_reads, u64, struct rw_args_t);
// Map entry write content to the exit write
BPF_HASH(active_writes, u64, struct rw_args_t);

// Map to pass the sockaddr pointer from enter_accept4 to exit_accept4
BPF_HASH(active_accepts, u64, struct data_t);
// Map the connect related system call
BPF_HASH(active_connects, u64, struct data_t);

// Key: Child GoID | Value: Parent GoID
BPF_HASH(goid_parent_map, u64, u64);
// Key: OS Thread ID (TID) | Value: Parent GoID
BPF_HASH(newproc1_active, u32, u64);

// Anchoring goid for traversing up the tree
BPF_HASH(request_anchors, u64, u8);

// Process ID -> fd for read and write syscall tcp_sequence
BPF_HASH(fd_to_sock_map, u64, u64);




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

    data->goid = get_goid();
    data->parent_goid = data->goid; 
    data->pconn_addr = 0;

    u64 *pc_ptr = worker_map.lookup(&data->goid);

    if(pc_ptr){
        data->pconn_addr = *pc_ptr;
        u64 *renter_goid_ptr = checkout_map.lookup(pc_ptr);

        if (renter_goid_ptr) {
            data->parent_goid = *renter_goid_ptr;
            u64 current_search_goid = data->parent_goid;
            #pragma unroll
            for (int i = 0; i < 10; i++) {
                u64 *static_parent_ptr = goid_parent_map.lookup(&current_search_goid);
                
                if (static_parent_ptr) {
                    current_search_goid = *static_parent_ptr; 
                    
                    u8 *is_anchor = request_anchors.lookup(&current_search_goid);
                    if (is_anchor) {
                        // WE FOUND THE ROOT HANDLER STOP HERE.
                        data->parent_goid = current_search_goid;
                        break; 
                    }
                    
                    data->parent_goid = current_search_goid;

                } else {
                    break;
                }
            }
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

// 3. Uprobe on putOrCloseIdleConn (Cleanup)
int trace_put_Conn(struct pt_regs * ctx){
    u64 persisConn = ctx->ax;
    checkout_map.delete(&persisConn);
    return 0;
}


// TRACEPOINT_PROBE(syscalls, sys_enter_connect) {

//     u64 id = bpf_get_current_pid_tgid();

//     struct data_t data = {};
//     populate_base(&data, OP_CONNECT, args->fd);

//     struct sockaddr_in addr = {};
//     bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);

//     if (addr.sin_family == AF_INET) {
//         data.daddr = addr.sin_addr.s_addr;
//         data.dport = bpf_ntohs(addr.sin_port);
//         data.sport = 0;
//         data.saddr = 0;
//         // events.ringbuf_output(&data, sizeof(data), 0);
//         active_connects.update(&id,&data);
        
//     }
//     else if (addr.sin_family == AF_INET6) { // AF_INET6 is family 10
//         // Handle IPv6 / Go's Dual-Stack connections
//         struct sockaddr_in6 addr6 = {};
//         bpf_probe_read_user(&addr6, sizeof(addr6), args->uservaddr);
        
//         // Trick: Grab the last 4 bytes of the 16-byte IPv6 address.
//         // For IPv4-mapped addresses (::ffff:127.0.0.1), this extracts the exact IPv4 IP!
//         __builtin_memcpy(&data.daddr, (char *)&addr6.sin6_addr + 12, 4);
        
//         data.dport = bpf_ntohs(addr6.sin6_port);
//         data.sport = 0;
//         data.saddr = 0;
//         // events.ringbuf_output(&data, sizeof(data), 0);
//         active_connects.update(&id,&data);

//     }
//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
//     u64 id = bpf_get_current_pid_tgid();
    
//     //Look up the data we saved in sys_enter_connect
//     struct data_t *datap = active_connects.lookup(&id);
//     if (!datap) {
//         return 0; // Missed the entry event, or not an IPv4/IPv6 connection
//     }

//     // Check if the connect() call succeeded (ret == 0 or -EINPROGRESS)
//     if (args->ret == 0 || args->ret == -115) { 
//         events.ringbuf_output(datap, sizeof(struct data_t), 0);
//     }

//     // delete the map entry to prevent memory leaks
//     active_connects.delete(&id);
//     return 0;
// }

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u64 id = bpf_get_current_pid_tgid();
    
    struct data_t data = {};
    populate_base(&data, OP_CONNECT, args->fd);
    
    active_connects.update(&id, &data);
    
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();
    
    struct data_t *datap = active_connects.lookup(&id);
    if (datap) {
        // Attach the socket pointer to it.
        datap->sk_ptr = (u64) sk;
    }
    
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    
    struct data_t *datap = active_connects.lookup(&id);
    if (!datap || !datap->sk_ptr) {
        return 0; // Missed previous steps, or not an IPv4 connect
    }
    
    // Check if the connection attempt was successful
    int ret = PT_REGS_RC(ctx);
    if (ret != 0 && ret != -115 && ret != -2) {
        return 0; 
    }

    struct sock *sk = (struct sock *) datap->sk_ptr;

    // This works because in Go server both accept and read are handled via the same process
    u32 tgid = id >> 32;
    u64 map_key = ((u64)tgid << 32) | (u32)datap->fd; 
    u64 sk_address = datap->sk_ptr;
    
    fd_to_sock_map.update(&map_key, &sk_address);

    struct tcp_sock *ts = tcp_sk(sk);

    // Fill the final missing pieces: The Network 4-Tuple!
    bpf_probe_read_kernel(&datap->saddr, sizeof(datap->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&datap->daddr, sizeof(datap->daddr), &sk->__sk_common.skc_daddr);
    
    u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    datap->sport = sport;
    datap->dport = bpf_ntohs(dport);

    bpf_probe_read_kernel(&datap->tcp_seq, sizeof(datap->tcp_seq), &ts->snd_nxt);

    // Send the beautifully fully-populated struct to user space
    events.ringbuf_output(datap, sizeof(*datap), 0);
    
    return 0;
}

int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    struct data_t *datap = active_connects.lookup(&id);
    if (datap) {
        // Attach the socket pointer (disguised as u64)
        datap->sk_ptr = (u64) sk;
    }
    return 0;
}

int kretprobe__tcp_v6_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct data_t *datap = active_connects.lookup(&id);
    if (!datap || !datap->sk_ptr) {
        return 0; // Missed previous steps
    }

    int ret = PT_REGS_RC(ctx);
    if (ret != 0 && ret != -115 && ret != -2) {
        return 0;
    }

    struct sock *sk = (struct sock *) datap->sk_ptr;

    // This works because in Go server both accept and read are handled via the same process
    u32 tgid = id >> 32;
    u64 map_key = ((u64)tgid << 32) | (u32)datap->fd; 
    u64 sk_address = datap->sk_ptr;
    
    fd_to_sock_map.update(&map_key, &sk_address);

    struct tcp_sock *ts = tcp_sk(sk);

    // 1. Read the 16-byte IPv6 addresses
    char saddr6[16] = {};
    char daddr6[16] = {};
    bpf_probe_read_kernel(&saddr6, sizeof(saddr6), &sk->__sk_common.skc_v6_rcv_saddr);
    bpf_probe_read_kernel(&daddr6, sizeof(daddr6), &sk->__sk_common.skc_v6_daddr);

    // 2. Extract the last 4 bytes for the mapped IPv4
    __builtin_memcpy(&datap->saddr, saddr6 + 12, 4);
    __builtin_memcpy(&datap->daddr, daddr6 + 12, 4);

    // 3. Extract the ports (stored in the exact same place as IPv4)
    u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    datap->sport = sport;
    datap->dport = bpf_ntohs(dport);

    bpf_probe_read_kernel(&datap->tcp_seq, sizeof(datap->tcp_seq), &ts->snd_nxt);

    // Send the beautifully fully-populated struct to user space
    events.ringbuf_output(datap, sizeof(*datap), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    u64 id = bpf_get_current_pid_tgid();
    
    // Always clean up to prevent memory leaks!
    active_connects.delete(&id);
    
    return 0;
}

// TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
//     u64 id = bpf_get_current_pid_tgid();
    
//     // args->upeer_sockaddr is the pointer where the kernel will write the IP
//     struct sockaddr *addr = (struct sockaddr *)args->upeer_sockaddr;
//     active_accepts.update(&id, &addr);
//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
//     u64 id = bpf_get_current_pid_tgid();
    
//     // 1. Look up the pointer we saved
//     struct sockaddr **addr_ptr = active_accepts.lookup(&id);
//     if (!addr_ptr) return 0;

//     // 2. The return value of accept4 IS the new File Descriptor!
//     long new_fd = args->ret;
    
//     // If accept was successful (fd > 0)
//     if (new_fd > 0) {
//         struct data_t data = {};
//         populate_base(&data, OP_ACCEPT4, new_fd);
        
//         // 1. Peek at the family first
//         short family = 0;
//         bpf_probe_read_user(&family, sizeof(family), *addr_ptr);

//         // 2. Handle based on the specific struct size and offsets
//         if (family == AF_INET) {
//             struct sockaddr_in addr4 = {};
//             bpf_probe_read_user(&addr4, sizeof(addr4), *addr_ptr);
            
//             data.daddr = addr4.sin_addr.s_addr;
//             data.dport = bpf_ntohs(addr4.sin_port);
            
//             events.ringbuf_output(&data, sizeof(data), 0);
            
//         } else if (family == 10) { // AF_INET6
//             struct sockaddr_in6 addr6 = {};
//             bpf_probe_read_user(&addr6, sizeof(addr6), *addr_ptr);
            
//             // Extract the last 4 bytes of the IPv4-mapped IPv6 address
//             __builtin_memcpy(&data.daddr, (char *)&addr6.sin6_addr + 12, 4);
//             data.dport = bpf_ntohs(addr6.sin6_port);
            
//             events.ringbuf_output(&data, sizeof(data), 0);
//         }
        
//     }
    
//     active_accepts.delete(&id);
//     return 0;
// }


TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    
    struct data_t data = {};
    
    populate_base(&data, OP_ACCEPT4, 0);
    
    active_accepts.update(&id, &data);
    
    return 0;
}


int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk) return 0; 

    struct data_t *datap = active_accepts.lookup(&id);
    if (datap) {
        datap->sk_ptr = (u64) newsk;
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    
    struct data_t *datap = active_accepts.lookup(&id);
    if (!datap) return 0; // Missed entry

    long new_fd = args->ret;
    
    // If the FD is strictly greater than 0, the accept succeeded
    if (new_fd > 0 && datap->sk_ptr != 0) {

        // This works because in Go server both accept and read are handled via the same process
        u32 tgid = id >> 32; 
        u64 map_key = ((u64)tgid << 32) | (u32)new_fd;
        u64 sk_address = datap->sk_ptr;
        
        fd_to_sock_map.update(&map_key, &sk_address);
        
        struct sock *sk = (struct sock *) datap->sk_ptr;
        datap->fd = (u32)new_fd;

        // Extracting the TCP sequence number 
        struct tcp_sock *ts = tcp_sk(sk);
        bpf_probe_read_kernel(&datap->tcp_seq, sizeof(datap->tcp_seq), &ts->rcv_nxt);
        
        u16 family = 0;
        bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
        
        if (family == AF_INET) { // Standard IPv4
            
            // Extract the IPs
            bpf_probe_read_kernel(&datap->saddr, sizeof(datap->saddr), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read_kernel(&datap->daddr, sizeof(datap->daddr), &sk->__sk_common.skc_daddr);
            
            // Extract the Ports
            u16 sport = 0, dport = 0;
            bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
            bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
            
            datap->sport = sport;
            datap->dport = bpf_ntohs(dport);

            events.ringbuf_output(datap, sizeof(*datap), 0);
            
        } else if (family == 10) { // AF_INET6 (Dual-Stack)
            
            // Extract the IPs. 
            char saddr6[16] = {};
            char daddr6[16] = {};
            
            bpf_probe_read_kernel(&saddr6, sizeof(saddr6), &sk->__sk_common.skc_v6_rcv_saddr);
            bpf_probe_read_kernel(&daddr6, sizeof(daddr6), &sk->__sk_common.skc_v6_daddr);
            
            // Trick: Extract the last 4 bytes for the mapped IPv4
            __builtin_memcpy(&datap->saddr, saddr6 + 12, 4);
            __builtin_memcpy(&datap->daddr, daddr6 + 12, 4);
            
            u16 sport = 0, dport = 0;
            bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
            bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
            
            datap->sport = sport;
            datap->dport = bpf_ntohs(dport);

            events.ringbuf_output(datap, sizeof(*datap), 0);
        }
    }
    
    active_accepts.delete(&id);
    
    return 0;
}


// For finding parent -> child relation in goid's
int trace_newproc1_enter(struct pt_regs *ctx) {
    // u64 parent_goid = get_goid(); 
    // u32 tid = bpf_get_current_pid_tgid();
    
    // newproc1_active.update(&tid, &parent_goid);
    
    // return 0;

    char *callergp = (char *)ctx->bx; 
    
    u64 parent_goid = 0;
    
    // Read the true parent's GOID directly from its runtime.g struct at offset 152
    if (callergp != NULL) {
        bpf_probe_read(&parent_goid, sizeof(parent_goid), callergp + 152);
    }
    
    u32 tid = bpf_get_current_pid_tgid();
    
    // Save it so the return probe can link it to the newly created child
    newproc1_active.update(&tid, &parent_goid);
    
    return 0;
}

int trace_newproc1_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    
    u64 *parent_goid_ptr = newproc1_active.lookup(&tid);
    if (!parent_goid_ptr) {
        return 0; 
    }
    
    u64 parent_goid = *parent_goid_ptr;

    char *new_g_ptr = (char *)PT_REGS_RC(ctx);

    if (new_g_ptr != NULL) {
        u64 child_goid = 0;
        bpf_probe_read(&child_goid, sizeof(child_goid), new_g_ptr + 152);
        goid_parent_map.update(&child_goid, &parent_goid);   
    }

    newproc1_active.delete(&tid);
    
    return 0;
}

int trace_servehttp_enter(struct pt_regs *ctx) {
    u64 current_goid = get_goid();
    u8 val = 1;
    request_anchors.update(&current_goid, &val);
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
    u64 tgid = id >> 32;
    struct rw_args_t *saved = active_reads.lookup(&id);
    if (!saved) return 0; 

    long ret = args->ret;
    if (ret > 0) {
        
        // Initializing before as BCC requires variable to be declared before any executing statement
        struct data_t data = {};
        u64 map_key;
        u64 *sk_address;
        struct tcp_sock *ts;
        u32 read_size;


        populate_base(&data, OP_READ, saved->fd);
        data.count = ret;

        // Extract copied_seq for the READ syscall to get tcp_sequence
        map_key = ((u64)tgid << 32) | (u32)saved->fd;
        sk_address = fd_to_sock_map.lookup(&map_key);
        
        if (sk_address && *sk_address != 0) {
            ts = (struct tcp_sock *)*sk_address;
            bpf_probe_read_kernel(&data.tcp_seq, sizeof(data.tcp_seq), &ts->copied_seq);
        } else {
            data.tcp_seq = 0; // Fallback if this is a normal file read, not a network socket
        }
        
        read_size = (ret < MAX_PAYLOAD_SIZE) ? ret : (MAX_PAYLOAD_SIZE - 1);
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
    u64 tgid = id >> 32;
    
    struct rw_args_t *saved = active_writes.lookup(&id);
    if (!saved) return 0;

    long ret = args->ret;
    if (ret > 0) {
struct data_t data = {};
        u64 map_key;
        u64 *sk_address;
        struct tcp_sock *ts;
        u32 read_size;
        
        populate_base(&data, OP_WRITE, saved->fd);
        data.count = ret;

        // Extract copied_seq for the READ syscall to get tcp_sequence
        map_key = ((u64)tgid << 32) | (u32)saved->fd;
        sk_address = fd_to_sock_map.lookup(&map_key);
        
        if (sk_address && *sk_address != 0) {
            ts = (struct tcp_sock *)*sk_address;
            bpf_probe_read_kernel(&data.tcp_seq, sizeof(data.tcp_seq), &ts->write_seq);
        } else {
            data.tcp_seq = 0; // Fallback if this is a normal file read, not a network socket
        }
        
        
        read_size = (ret < MAX_PAYLOAD_SIZE) ? ret : (MAX_PAYLOAD_SIZE - 1);
        bpf_probe_read_user(&data.payload, read_size, saved->buf);

        events.ringbuf_output(&data, sizeof(data), 0);
        // events.perf_submit(args, &data, sizeof(data));
    }
    active_writes.delete(&id);
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

// TRACEPOINT_PROBE(syscalls, sys_enter_epoll_pwait) {
//     struct data_t data = {};
    
//     // args->epfd is the epoll instance being waited on
//     populate_base(&data, OP_EPOLL_WAIT, args->epfd); 
    
//     data.maxevents = args->maxevents;
//     events.ringbuf_output(&data, sizeof(data), 0);
//     // events.perf_submit(args, &data, sizeof(data));
    
//     return 0;
// }




