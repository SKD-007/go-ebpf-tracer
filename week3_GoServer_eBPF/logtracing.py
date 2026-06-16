from collections import deque

file_r = open("ebpf_syscall_analysis.log","r")
file_w= open("traced_output.txt", "w")
next(file_r)
next(file_r)
next(file_r)

fd_table = {}
HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
HTTP_VERSIONS = ("HTTP/1.1 ", "HTTP/1.0 ")

def print_details(event):
    print(f"   ├─ IP&PortNo:      {event.get('ip')}:{event.get('port')}")
    print(f"   ├─ Read Time:   {event.get('read_time')}")
    print(f"   ├─ Write Time:  {event.get('write_time')}")
    
    # Extract just the HTTP payload from the raw string to make it readable
    raw_read = event.get('read_data', '') or ''
    read_payload = raw_read.split('Data: ')[-1] if 'Data: ' in raw_read else 'N/A'
    
    raw_write = event.get('write_data', '') or ''
    write_payload = raw_write.split('Data: ')[-1] if 'Data: ' in raw_write else 'N/A'
    
    print(f"   ├─ Request:     {read_payload}")
    print(f"   └─ Response:    {write_payload}")

    read_time_str = event.get('read_time')
    write_time_str = event.get('write_time')
    if read_time_str and write_time_str:
        try:
            r_time = float(read_time_str)
            w_time = float(write_time_str)
            
            # abs() ensures it is always positive, even if the order gets flipped
            duration_sec = abs(w_time - r_time)
            duration_ms = duration_sec * 1000  # Convert to milliseconds for easier reading
            
            print(f"   ├─ Duration:    {duration_sec:.6f} sec ({duration_ms:.2f} ms)")
        except ValueError:
             print("   ├─ Duration:    N/A (Parse Error)")
    else:
        print("   ├─ Duration:    N/A (Incomplete Request/Response)")
        
    # The visual marker indicating the end of this FD's block
    print("▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼")

def handle_read(row):
    parts = row.split("Data:")
    metadata = parts[0].split()
    payload = parts[1].strip() # it is still string

    try:
        fd_indx = metadata.index("FD:")
        fd = metadata[fd_indx + 1]

        if payload.startswith(HTTP_METHODS):
            # print(row, fd)
            data = fd_table[fd].popleft()
            if(data["accept/connect"] == "a"):
                data["read_time"] = metadata[5] # filling the time only for the first time
                data["read_data"] = row
            # print("mm")
            fd_table[fd].append(data)

        elif payload.startswith(HTTP_VERSIONS):
            data = fd_table[fd].popleft()
            if(data["accept/connect"] == "c"):
                # print("here5")
                data["read_time"] = metadata[5] # filling the time each time to find the end
                data["read_data"] = row
            # print("here1")
            fd_table[fd].append(data)

    except:
        pass

def handle_write(row):
    parts = row.split("Data:")
    metadata = parts[0].split()
    payload = parts[1].strip() # it is still string

    try:
        fd_indx = metadata.index("FD:")
        fd = metadata[fd_indx + 1]

        if payload.startswith(HTTP_VERSIONS):
            # print(row, fd)
            data = fd_table[fd].popleft()
            if(data["accept/connect"] == "a"):
                data["write_time"] = metadata[5] # filling the time only for the first time
                data["write_data"] = row
            # print("mm")
            fd_table[fd].append(data)


        elif payload.startswith(HTTP_METHODS):
            data = fd_table[fd].popleft()
            if(data["accept/connect"] == "c"):
                data["write_time"] = metadata[5] # filling the time each time to find the end
                data["write_data"] = row
                
            
            fd_table[fd].append(data)

    except:
        pass
    

# accept has fd, local
def handle_accept(row):
    fd_indx = row.index("FD:")
    fd = row[fd_indx + 1]

    local_indx = row.index("local:")
    local = row[local_indx + 1]

    # hash[fd] = 
    if fd_table.get(fd) :
        event = fd_table[fd].popleft()
        print_details(event)
    else:
        q = deque()
        fd_table[fd] = q

    data = {}
    data["accept/connect"] = "a"
    data["fd"] = fd
    ip_port = local.split(":")
    data["port"] = ip_port[1]
    data["ip"] = ip_port[0]
    data["read_time"] = None
    data["write_time"] = None
    data["read_data"] = None
    data["write_data"] = None

    fd_table[fd].append(data)
    # print(fd_table)

def handle_connect(row):
    fd_indx = row.index("FD:")
    fd = row[fd_indx + 1]

    local_indx = row.index("remote:")
    local = row[local_indx + 1]

    # hash[fd] = 
    if fd_table.get(fd) :
        event = fd_table[fd].popleft()
        print_details(event)
        
    else:
        q = deque()
        fd_table[fd] = q

    data = {}
    data["accept/connect"] = "c"
    data["fd"] = fd
    ip_port = local.split(":")
    data["port"] = ip_port[1]
    data["ip"] = ip_port[0]
    data["read_time"] = None
    data["write_time"] = None
    data["read_data"] = None
    data["write_data"] = None

    fd_table[fd].append(data)
    # print(fd_table)



for line in file_r:
    line = line.strip()
    lis = line.split()
    # print(lis)
    if lis[4] == "read":
        handle_read(line)
    elif lis[4] == "write":
        handle_write(line)
    elif lis[4] == "accept4":
        handle_accept(lis)
    elif lis[4] == "connect":
        handle_connect(lis)

    # if lis[]
    # break

for fd, queue in fd_table.items():
    for event in queue:
        print_details(event)
# print(fd_table)

file_r.close()
file_w.close()