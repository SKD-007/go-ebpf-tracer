""" 
eBPF Network Telemetry parser

This script parses through the eBPF syscall log file (accept, connect, write, read) and correlates
them into complete HTTP request/response traces. It then sends the detail as a HTTP request to 
server (http://127.0.0.1:9090/api/traces) present in main.go. It 
"""

import argparse
import sys
import os
from collections import deque
import datetime
import json
import urllib.request
import time
from concurrent.futures import ThreadPoolExecutor

# To allocate 5 threads to manage the sending handle the delay (wait time) caused by sending HTTP
# request to main server.
telemetry_shipper = ThreadPoolExecutor(max_workers = 5)

parser = argparse.ArgumentParser(description="Parse eBPF syscall analysis logs.")
parser.add_argument("input_file", help="Path to the log file (e.g., ebpf_syscall_analysis.log)")
args = parser.parse_args()

if not os.path.isfile(args.input_file):
    print(f"[!] Error: The file '{args.input_file}' does not exist.")
    sys.exit(1)

file_r = open(args.input_file, "r")

base_name = os.path.basename(args.input_file)

name_without_ext, _ = os.path.splitext(base_name)

output_filename = f"traced_{name_without_ext}.txt"

file_w = open(output_filename, "w")

class Tee:
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()
    def flush(self):
        for f in self.files:
            f.flush()

sys.stdout = Tee(sys.stdout, file_w)

CENTRAL_SERVER_URL = "http://127.0.0.1:9090/api/traces"
# TODO: In the future, extract SERVICE_NAME from environment variables or input flags
SERVICE_NAME = name_without_ext 

# Skip the first 3 lines (assuming they are file headers or table column definitions)
next(file_r)
next(file_r)
next(file_r)

"""
fd_table:
    "accept/connect" (str) : whether it is accept or connect syscall
    "fd" (str) : file descriptor
    "local_ip" (str) : local ip address
    "local_port" (str) : local port number
    "remote_ip" (str) : remote ip address
    "remote_port" (str) : remort port address
    "tcp_seq" (str): tcp sequence number

    NOTE: It is essential for this to be a queue as first read will be associated to the first write
    "requests" (deque): queue to store all the subsequent read/write associated with the connect syscall
"""
fd_table = {}
        

"""
goid_table:{
    "goid" (str) : goid of the parent ( accept syscall if exist )
    "has_accept" (bool) : whether this goid_table was created by a accept syscall (to identify stand alone connect syscall) 
    
    "connect" (dict) : data associated with connect syscall
        connect: {
        # This represents an OUTBOUND request made by your microservice (Client side)
        "write_time" (str) : time at which write system call for connect is completed (Sending HTTP Request)
        "write_data" (str) : data that is written around 80 bytes (e.g., "GET /api HTTP/1.1")
        "write_thread_pid" (str) : thread id that executed write syscall associated with connect
        "write_tcp_seq" (str) : tcp sequence of write syscall associated with connect  
        "read_thread_pid" (str) : thread id that executed read syscall associated with connect
        "read_time" (str) : time at which read system call for connect is completed (Receiving HTTP Response)
        "read_data" (str) : data that is read around 80 bytes (e.g., "HTTP/1.1 200 OK")
        "read_tcp_seq" (str) : tcp sequence of read syscall associated with connect
        "local_ip" (str) : local ip of the outbound connection mapped from fd_table
        "local_port" (str) : local port of the outbound connection mapped from fd_table
        "remote_ip" (str) : remote ip of the outbound connection mapped from fd_table
        "remote_port" (str) : remote port of the outbound connection mapped from fd_table
        "tcp_seq" (str) : initial tcp sequence from the connect syscall mapped from fd_table
        "fd" (str) : file descriptor number
        "accept/connect" (str) : literal string "c" mapped from fd_table
        }


    "accept" (dict) : data associated with accept syscall
        "accept": {
            # This represents an INBOUND request received by your microservice (Server side)
            "read_time" (str) : time at which read system call for accept is completed (Receiving HTTP Request)
            "read_data" (str) : data that is read around 80 bytes (e.g., "GET /api HTTP/1.1")
            "read_thread_pid" (str) : thread id that executed read syscall associated with accept
            "read_tcp_seq" (str) : tcp sequence of read syscall associated with accept
            "write_time" (str) : time at which write system call for accept is completed (Sending HTTP Response)
            "write_data" (str) : data that is written around 80 bytes (e.g., "HTTP/1.1 200 OK")
            "write_thread_pid" (str) : thread id that executed write syscall associated with accept
            "write_tcp_seq" (str) : tcp sequence of write syscall associated with accept  
            "local_ip" (str) : local ip of the inbound connection mapped from fd_table
            "local_port" (str) : local port of the inbound connection mapped from fd_table
            "remote_ip" (str) : remote ip of the inbound connection mapped from fd_table
            "remote_port" (str) : remote port of the inbound connection mapped from fd_table
            "tcp_seq" (str) : initial tcp sequence from the accept syscall mapped from fd_table
            "fd" (str) : file descriptor number
            "accept/connect" (str) : literal string "a" mapped from fd_table
        }
}
"""
goid_table = {}

HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
HTTP_VERSIONS = ("HTTP/1.1 ", "HTTP/1.0 ")

connection_count = 0
accept_count = 0
connect_count = 0

def push_to_central_server(payload):
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            CENTRAL_SERVER_URL, data = data, headers = {'Content-Type' : 'application/json'}
        )
        urllib.request.urlopen(req, timeout = 2.0)
    except Exception as e:
        print(f"[!] Telemetry drop: Failed to send trace: {e}")


def print_details(goid_data):
    global connection_count
    connection_count += 1

    # Extract the GoID from the parent dictionary
    goid = goid_data.get('goid', 'UNKNOWN')

    # Print the parent block header
    print(f"{connection_count:<4}=== GoID: {goid} ===")

    # 1. Helper logic to convert raw seconds to HH:MM:SS.ms
    def format_uptime(t_str):
        if not t_str:
            return "N/A"
        try:
            formatted_time = str(datetime.timedelta(seconds=float(t_str)))
            return formatted_time[:-3] 
        except ValueError:
            return "N/A"

    # 2. Helper function to print the inner event details (handles both accept and connect)
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
        tcp_seq = event.get('tcp_seq', 'N/A')
        
        print(f"    ├─ Local Addr:    {lip}:{lport}")
        print(f"    ├─ Remote Addr:   {rip}:{rport}")
        print(f"    ├─ TCP Seq Num:   {tcp_seq}")
        
        read_time_str = event.get('read_time')
        write_time_str = event.get('write_time')
        
        read_tid = event.get('read_thread_pid', 'N/A')
        write_tid = event.get('write_thread_pid', 'N/A')

        read_tcp = event.get('read_tcp_seq', 'N/A')
        write_tcp = event.get('write_tcp_seq', 'N/A')

        # Print both the raw kernel time, readable time, TID, and the payload TCP Sequence
        print(f"    ├─ Read Time:     {read_time_str} ({format_uptime(read_time_str)}) [TID: {read_tid}] [Seq: {read_tcp}]")
        print(f"    ├─ Write Time:    {write_time_str} ({format_uptime(write_time_str)}) [TID: {write_tid}] [Seq: {write_tcp}]")

        # Extract HTTP payloads
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
                
                # abs() ensures it is always positive
                duration_sec = abs(w_time - r_time)
                duration_ms = duration_sec * 1000 
                
                print(f"    └─ Duration:      {duration_sec:.6f} sec ({duration_ms:.2f} ms)")
            except ValueError:
                 print("    └─ Duration:      N/A (Parse Error)")
        else:
            print("    └─ Duration:      N/A (Incomplete Request/Response)")
        print("    │") # Spacer for readability if there are multiple events

    # 3. Process the 'accept' event if it exists in this GoID
    if goid_data.get('accept'):
        print_event_block('accept', goid_data['accept'])

    # 4. Process the 'connect' event if it exists in this GoID
    if goid_data.get('connect'):
        print_event_block('connect', goid_data['connect'])

    # The visual marker indicating the end of this GoID's block
    print("▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼\n")

    
    # TODO: maybe change this events to connect and accept
    # creating the payload for sending to central server
    trace_payload =  {
        "service_name" : SERVICE_NAME,
        "goid" : goid,
        "events" : []
    }

    def package_event(event_type, event_data):
        if not event_data:
            return None
            
        r_time = event_data.get('read_time')
        w_time = event_data.get('write_time')
        
        duration_ms = None
        if r_time and w_time:
            try:
                duration_ms = abs(float(w_time) - float(r_time)) * 1000
            except ValueError:
                pass

        return {
            "type": event_type,
            "fd": event_data.get('fd'),
            "local_addr": f"{event_data.get('local_ip', '')}:{event_data.get('local_port', '')}",
            "remote_addr": f"{event_data.get('remote_ip', '')}:{event_data.get('remote_port', '')}",
            "tcp_seq": event_data.get('tcp_seq'),
            "read_tcp_seq": event_data.get('read_tcp_seq'),
            "write_tcp_seq": event_data.get('write_tcp_seq'),
            "read_time": r_time,
            "write_time": w_time,
            "duration_ms": duration_ms,

            # Truncate payloads to 500 chars to avoid crashing the central DB with massive files
            "request_payload": (event_data.get('read_data') or '')[:500],
            "response_payload": (event_data.get('write_data') or '')[:500]
        }

    # Package Accept and Connect if they exist
    if goid_data.get('accept'):
        trace_payload['events'].append(package_event('accept', goid_data['accept']))
    
    if goid_data.get('connect'):
        trace_payload['events'].append(package_event('connect', goid_data['connect']))

    # Ship it asynchronously! (This returns instantly and won't block   eBPF)
    if trace_payload['events']:
        telemetry_shipper.submit(push_to_central_server, trace_payload)


def handle_read(row):

    # print("read")

    parts = row.split("Data:")
    metadata = parts[0].split()
    payload = parts[1].strip() # it is still string


    try:
        fd_indx = metadata.index("FD:")
        fd = metadata[fd_indx + 1]

        tcp_ind = metadata.index("tcp_seq:")
        tcp_seq = metadata[tcp_ind + 1]

        if payload.startswith(HTTP_METHODS):
            
            if(fd_table[fd]["accept/connect"] == "a"):
                # TODO make these data structure to proper class objects
                new_event = {
                        "read_time": metadata[7],
                        "read_data": row,
                        "read_thread_pid":metadata[2],
                        "read_tcp_seq": tcp_seq,
                        "write_time": "",
                        "write_data": "",
                        "write_thread_pid":"",
                        "write_tcp_seq": "",

                    }
            
                # Append this new event to the connection's queue
                fd_table[fd]["requests"].append(new_event)

                ### BUG does it needs to be 6 instead of 5 verify later because 5 is parent_goid###
                # goid_table[metadata[5]] = {"goid" : metadata[5], "has_accept" : True}
                goid_table[metadata[6]] = {"goid" : metadata[6], "has_accept" : True}

                # print(goid_table)


        elif payload.startswith(HTTP_VERSIONS):
            if(fd_table[fd]["accept/connect"] == "c"):

                data = fd_table[fd]["requests"].popleft()
                data["read_time"] = metadata[7]   
                data["read_data"] = row    
                data["read_thread_pid"] = metadata[2]
                data["read_tcp_seq"] = tcp_seq

                # Inject the connection metadata into this event
                data["local_ip"] = fd_table[fd]["local_ip"]
                data["local_port"] = fd_table[fd]["local_port"]
                data["remote_ip"] = fd_table[fd]["remote_ip"]
                data["remote_port"] = fd_table[fd]["remote_port"]
                data["tcp_seq"] = fd_table[fd]["tcp_seq"]

                data["fd"] = fd_table[fd]["fd"]
                data["accept/connect"] = fd_table[fd]["accept/connect"]

                goid = metadata[5]

                if goid not in goid_table:
                    goid_table[goid] = { "goid" : goid}
                
                goid_table[goid]["connect"] = data

                global connect_count
                connect_count += 1

                if not goid_table[goid].get("has_accept"):
                    print_details(goid_table[goid])
                    del goid_table[goid]
    except:
        pass

def handle_write(row):
    
    # splitting from the first occurace of 'Data:' field
    parts = row.split("Data:",1)
    
    metadata = parts[0].split()
    payload = parts[1].strip() # it is still string

    try:
        fd_indx = metadata.index("FD:")
        fd = metadata[fd_indx + 1]

        tcp_ind = metadata.index("tcp_seq:")
        tcp_seq = metadata[tcp_ind + 1]

        
        if payload.startswith(HTTP_METHODS):
            if(fd_table[fd]["accept/connect"] == "c"):
                # This corresponds the service writing to the request it gave to another server            
                
                new_event = {
                        "write_time": metadata[7],
                        "write_data": row,
                        "write_thread_pid":metadata[2],
                        "write_tcp_seq": tcp_seq,
                        "read_thread_pid":"",
                        "read_time": "",
                        "read_data": "",
                        "read_tcp_seq": "",

                    }
                
                # Append this new event to the connection's queue
                fd_table[fd]["requests"].append(new_event)

        elif payload.startswith(HTTP_VERSIONS):

            if(fd_table[fd]["accept/connect"] == "a"):
            
                # This corresponds to the service writing to the request it received this is the end of the cycle
            
                data = fd_table[fd]["requests"].popleft()
                
                data["write_time"] = metadata[7]
                data["write_data"] = row
                data["write_thread_pid"] = metadata[2]
                data["write_tcp_seq"] = tcp_seq
                
                # Inject the connection metadata into this event 
                data["local_ip"] = fd_table[fd]["local_ip"]
                data["local_port"] = fd_table[fd]["local_port"]
                data["remote_ip"] = fd_table[fd]["remote_ip"]
                data["remote_port"] = fd_table[fd]["remote_port"]
                data["tcp_seq"] = fd_table[fd]["tcp_seq"]

                data["fd"] = fd_table[fd]["fd"]
                data["accept/connect"] = fd_table[fd]["accept/connect"]
                
                goid = metadata[5]
                goid_table[goid]["accept"] = data
                
                print_details(goid_table[goid])

                global accept_count
                accept_count += 1

                del goid_table[goid]
    except:
        pass
    

def handle_accept(row):
    ''' 
    input : 
        row : list consisting metadate (string)

    stores the meta data of accept system call in the 'fd_table' which has key as file descriptor
    and value as the meta data    
    
    metadata includes
        "accept/connect",
        "fd",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "tcp_seq",
        "requests",
    '''

    fd_indx = row.index("FD:")
    fd = row[fd_indx + 1]

    local_indx = row.index("local:")
    local = row[local_indx + 1]

    remote_indx = row.index("remote:")
    remote = row[remote_indx + 1]

    tcp_ind = row.index("tcp_seq:")
    tcp_seq = row[tcp_ind + 1]
    
    local_ip_port = local.split(":")
    remote_ip_port = remote.split(":")

    fd_table[fd] = {
        "accept/connect": "a",
        "fd": fd,
        "local_ip": local_ip_port[0],
        "local_port": local_ip_port[1],
        "remote_ip": remote_ip_port[0],
        "remote_port": remote_ip_port[1],
        "tcp_seq": tcp_seq,
        "requests": deque() # The queue lives inside the connection now!
    }

    

def handle_connect(row):
    ''' 
    input : 
        row : list consisting metadate (string)

    stores the meta data of connect system call in the 'fd_table' which has key as file descriptor
    and value as the meta data    
    
    metadata includes
        "accept/connect",
        "fd",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "tcp_seq",
        "requests",
    '''

    fd_indx = row.index("FD:")
    fd = row[fd_indx + 1]

    local_indx = row.index("local:")
    local = row[local_indx + 1]

    remote_indx = row.index("remote:")
    remote = row[remote_indx + 1]

    tcp_ind = row.index("tcp_seq:")
    tcp_seq = row[tcp_ind + 1]

    local_ip_port = local.split(":")
    remote_ip_port = remote.split(":")

    fd_table[fd] = {
        "accept/connect": "c",
        "fd": fd,
        "local_ip": local_ip_port[0],
        "local_port": local_ip_port[1],
        "remote_ip": remote_ip_port[0],
        "remote_port": remote_ip_port[1],
        "tcp_seq": tcp_seq,
        "requests": deque() # The queue lives inside the connection now!
    }

line_buffer = ""


# Main loop that iterates through the log file and associates each syscall to their
# appropriate function to handle then
while True:
    chunk = file_r.readline()
    if chunk is None:
        time.sleep(0.1)
        continue

    line_buffer += chunk

    if not line_buffer.endswith('\n'):
        continue

    full_line = line_buffer.strip()
    line_buffer = ""

    if not full_line:
        continue

    lis = full_line.split()
    
    try:
        if lis[4] == "read":
            handle_read(full_line)
        elif lis[4] == "write":
            handle_write(full_line)
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
