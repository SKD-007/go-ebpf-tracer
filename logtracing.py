from collections import deque
import datetime

file_r = open("ebpf_syscall_analysis.log","r")
file_w= open("traced_output.txt", "w")

next(file_r)
next(file_r)
next(file_r)

fd_table = {}
goid_table = {}

HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
HTTP_VERSIONS = ("HTTP/1.1 ", "HTTP/1.0 ")

connection_count = 0
accept_count = 0
connect_count = 0


import datetime

def print_details(goid_data):
    global connection_count
    connection_count += 1

    goid = goid_data.get('goid', 'UNKNOWN')

    print(f"{connection_count:<4}=== GoID: {goid} ===")

    # convert raw seconds to HH:MM:SS.ms
    def format_uptime(t_str):
        if not t_str:
            return "N/A"
        try:
            formatted_time = str(datetime.timedelta(seconds=float(t_str)))
            return formatted_time[:-3] 
        except ValueError:
            return "N/A"

    # Helper function to print the inner event details (handles both accept and connect)
    def print_event_block(syscall_type, event):
        if not event:
            return

        if syscall_type == 'accept':
            syscall_str = "ACCEPT (Incoming)"
        elif syscall_type == 'connect':
            syscall_str = "CONNECT (Outbound)"
        else:
            syscall_str = "UNKNOWN"

        print(f"    ├─ Syscall Type:  {syscall_str}")
        print(f"    ├─ File Desc:     FD {event.get('fd', 'N/A')}")
        
        # Updated IP and Port formatting
        lip = event.get('local_ip', 'N/A')
        lport = event.get('local_port', 'N/A')
        rip = event.get('remote_ip', 'N/A')
        rport = event.get('remote_port', 'N/A')
        
        print(f"    ├─ Local Addr:    {lip}:{lport}")
        print(f"    ├─ Remote Addr:   {rip}:{rport}")
        
        read_time_str = event.get('read_time')
        write_time_str = event.get('write_time')
        
        read_tid = event.get('read_thread_pid', 'N/A')
        write_tid = event.get('write_thread_pid', 'N/A')

        # Print both the raw kernel time and the readable time
        print(f"    ├─ Read Time:     {read_time_str} ({format_uptime(read_time_str)}) [TID: {read_tid}]")
        print(f"    ├─ Write Time:    {write_time_str} ({format_uptime(write_time_str)}) [TID: {write_tid}]")

        raw_read = event.get('read_data', '') or ''
        read_payload = raw_read.split('Data: ')[-1] if 'Data: ' in raw_read else 'N/A'
        
        raw_write = event.get('write_data', '') or ''
        write_payload = raw_write.split('Data: ')[-1] if 'Data: ' in raw_write else 'N/A'
        
        print(f"    ├─ Request:       {read_payload}")
        print(f"    ├─ Response:      {write_payload}")

        # Calculate Duration
        if read_time_str and write_time_str:
            try:
                r_time = float(read_time_str)
                w_time = float(write_time_str)
                
                duration_sec = abs(w_time - r_time)
                duration_ms = duration_sec * 1000 
                
                print(f"    └─ Duration:      {duration_sec:.6f} sec ({duration_ms:.2f} ms)")
            except ValueError:
                 print("    └─ Duration:      N/A (Parse Error)")
        else:
            print("    └─ Duration:      N/A (Incomplete Request/Response)")
        print("    │") 

    if goid_data.get('accept'):
        print_event_block('accept', goid_data['accept'])

    if goid_data.get('connect'):
        print_event_block('connect', goid_data['connect'])

    print("▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼\n")

def handle_read(row):

    parts = row.split("Data:")
    metadata = parts[0].split()
    payload = parts[1].strip() # it is still string

    try:
        fd_indx = metadata.index("FD:")
        fd = metadata[fd_indx + 1]

        if payload.startswith(HTTP_METHODS):
            
            if(fd_table[fd]["accept/connect"] == "a"):
                new_event = {
                        "read_time": metadata[7],
                        "read_data": row,
                        "read_thread_pid":metadata[2],
                        "write_time": "",
                        "write_data": "",
                        "write_thread_pid":""
                    }
            
                # Append this new event to the connection's queue
                fd_table[fd]["requests"].append(new_event)

                goid_table[metadata[5]] = {"goid" : metadata[5]}


        elif payload.startswith(HTTP_VERSIONS):
            if(fd_table[fd]["accept/connect"] == "c"):

                data = fd_table[fd]["requests"].popleft()
                data["read_time"] = metadata[7]   
                data["read_data"] = row    
                data["read_thread_pid"] = metadata[2]
                
                data["local_ip"] = fd_table[fd]["local_ip"]
                data["local_port"] = fd_table[fd]["local_port"]
                data["remote_ip"] = fd_table[fd]["remote_ip"]
                data["remote_port"] = fd_table[fd]["remote_port"]

                data["fd"] = fd_table[fd]["fd"]
                data["accept/connect"] = fd_table[fd]["accept/connect"]
                goid_table[metadata[5]]["connect"] = data

                global connect_count
                connect_count += 1

    except:
        pass

def handle_write(row):

    parts = row.split("Data:")
    metadata = parts[0].split()
    payload = parts[1].strip() # it is still string

    try:
        fd_indx = metadata.index("FD:")
        fd = metadata[fd_indx + 1]

        if payload.startswith(HTTP_METHODS):
            
            if(fd_table[fd]["accept/connect"] == "c"):
                new_event = {
                        "write_time": metadata[7],
                        "write_data": row,
                        "write_thread_pid":metadata[2],
                        "read_thread_pid":"",
                        "read_time": "",
                        "read_data": ""
                    }
                
                # Append this new event to the connection's queue
                fd_table[fd]["requests"].append(new_event)

        elif payload.startswith(HTTP_VERSIONS):
            if(fd_table[fd]["accept/connect"] == "a"):

                data = fd_table[fd]["requests"].popleft()
                data["write_time"] = metadata[7]
                data["write_data"] = row
                data["write_thread_pid"] = metadata[2]
                
                # Inject the connection metadata into this event 
                data["local_ip"] = fd_table[fd]["local_ip"]
                data["local_port"] = fd_table[fd]["local_port"]
                data["remote_ip"] = fd_table[fd]["remote_ip"]
                data["remote_port"] = fd_table[fd]["remote_port"]

                data["fd"] = fd_table[fd]["fd"]
                data["accept/connect"] = fd_table[fd]["accept/connect"]
                
                goid_table[metadata[5]]["accept"] = data
                print_details(goid_table[metadata[5]])
                global accept_count
                accept_count += 1

    except:
        pass
    

# accept has fd, local
def handle_accept(row):
    # print("accept")

    fd_indx = row.index("FD:")
    fd = row[fd_indx + 1]

    local_indx = row.index("local:")
    local = row[local_indx + 1]

    remote_indx = row.index("remote:")
    remote = row[remote_indx + 1]
    
    local_ip_port = local.split(":")
    remote_ip_port = remote.split(":")

    fd_table[fd] = {
        "accept/connect": "a",
        "fd": fd,
        "local_ip": local_ip_port[0],
        "local_port": local_ip_port[1],
        "remote_ip": remote_ip_port[0],
        "remote_port": remote_ip_port[1],
        "requests": deque() 
    }

    

def handle_connect(row):

    fd_indx = row.index("FD:")
    fd = row[fd_indx + 1]

    local_indx = row.index("local:")
    local = row[local_indx + 1]

    remote_indx = row.index("remote:")
    remote = row[remote_indx + 1]

    local_ip_port = local.split(":")
    remote_ip_port = remote.split(":")

    fd_table[fd] = {
        "accept/connect": "c",
        "fd": fd,
        "local_ip": local_ip_port[0],
        "local_port": local_ip_port[1],
        "remote_ip": remote_ip_port[0],
        "remote_port": remote_ip_port[1],
        "requests": deque() 
    }



for line in file_r:
    line = line.strip()
    lis = line.split()
    try:
        if lis[4] == "read":
            handle_read(line)
        elif lis[4] == "write":
            handle_write(line)
        elif lis[4] == "accept4":
            handle_accept(lis)
        elif lis[4] == "connect":
            handle_connect(lis)
            
    except IndexError:
        continue  

print(f"Totol incoming request = {accept_count}")
print(f"Totol outgoing request = {connect_count}")
file_r.close()
file_w.close()
