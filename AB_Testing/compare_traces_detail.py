import re
import requests
import sys

JAEGER_API_URL = "http://localhost:16686/api/traces/"
FILE_PATH = "traced_ebpf_syscall_analysis_server1.txt"  # Set to your eBPF output log path


def parse_server1_ebpf_logs(file_path):
    """
    Parses the eBPF log and yields a dictionary for every GoID block 
    that contains BOTH an ACCEPT and a CONNECT syscall.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: Could not find {file_path}")
        sys.exit(1)

    # Split the file by the GoID header block
    goid_blocks = re.split(r'=== GoID: (\d+) ===', content)
    
    events = [] 
    
    # goid_blocks[0] is preamble. The rest alternate between GoID and the block text
    for i in range(1, len(goid_blocks), 2):
        goid = goid_blocks[i]
        block_text = goid_blocks[i+1]
        
        # Check for proxy services (like search) that handle both ACCEPT and CONNECT
        if 'ACCEPT' in block_text and 'CONNECT' in block_text:
            
            # Case-insensitive match for traceparent header in eBPF socket dump
            accept_match = re.search(
                r'ACCEPT.*?traceparent:\s*00-([a-f0-9]{32})-([a-f0-9]{16})', 
                block_text, 
                re.DOTALL | re.IGNORECASE
            )
            connect_match = re.search(
                r'CONNECT.*?traceparent:\s*00-([a-f0-9]{32})-([a-f0-9]{16})', 
                block_text, 
                re.DOTALL | re.IGNORECASE
            )
            
            if accept_match and connect_match:
                trace_id_accept = accept_match.group(1)
                span_id_accept = accept_match.group(2)
                
                trace_id_connect = connect_match.group(1)
                span_id_connect = connect_match.group(2)
                
                # Sanity check: Ensure eBPF captured the same TraceID for both
                if trace_id_accept == trace_id_connect:
                    events.append({
                        'goid': goid,
                        'trace_id': trace_id_accept,
                        'accept_span_id': span_id_accept,
                        'connect_span_id': span_id_connect
                    })

    return events


def check_causality_in_jaeger(trace_id, accept_span_id, connect_span_id):
    """
    Queries Jaeger and verifies that connect_span is a child/descendant of accept_span.
    """
    url = f"{JAEGER_API_URL}{trace_id}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "[FAIL]", f"Trace {trace_id} not found in Jaeger"
            
        trace_data = response.json()
        if not trace_data.get('data'):
            return "[FAIL]", "Trace found but contains no span data"
            
        spans = trace_data['data'][0]['spans']
        span_map = {span['spanID']: span for span in spans}
        
    except requests.exceptions.RequestException as e:
        return "[ERROR]", f"Failed to connect to Jaeger API: {e}"

    # 1. Verify both spans exist in the Jaeger Trace
    if accept_span_id not in span_map:
        return "[FAIL]", f"Incoming ACCEPT Span ({accept_span_id}) missing in Jaeger"
    if connect_span_id not in span_map:
        return "[FAIL]", f"Outgoing CONNECT Span ({connect_span_id}) missing in Jaeger"

    # 2. Verify Causality by traversing up the tree from CONNECT to ACCEPT
    current_span_id = connect_span_id
    visited = set()
    
    while current_span_id:
        if current_span_id == accept_span_id:
            return "[PASS]", "CONNECT is a direct descendant of ACCEPT (Same Request Flow)"
            
        if current_span_id in visited:
            break
        visited.add(current_span_id)
        
        current_span = span_map.get(current_span_id)
        if not current_span:
            break
            
        parent_id = None
        for ref in current_span.get('references', []):
            if ref.get('refType') == 'CHILD_OF':
                parent_id = ref.get('spanID')
                break
                
        current_span_id = parent_id 

    return "[FAIL]", "Spans exist, but CONNECT is NOT a descendant of ACCEPT (Broken Causality)"


def main():
    print(f"[*] Parsing {FILE_PATH} for proxy requests (ACCEPT + CONNECT)...")
    proxy_events = parse_server1_ebpf_logs(FILE_PATH)
    
    if not proxy_events:
        print("[!] No matching GoID blocks found containing both ACCEPT and CONNECT.")
        sys.exit(0)
        
    print(f"[*] Found {len(proxy_events)} proxy request(s). Verifying against Jaeger...\n")
    
    passed_count = 0
    for count, event in enumerate(proxy_events):
        print(f"{count} === GoID: {event['goid']} ===")
        print(f" ├─ Trace ID    : {event['trace_id']}")
        print(f" ├─ ACCEPT Span : {event['accept_span_id']}")
        print(f" ├─ CONNECT Span: {event['connect_span_id']}")
        
        status, reason = check_causality_in_jaeger(
            event['trace_id'], 
            event['accept_span_id'], 
            event['connect_span_id']
        )
        
        print(f" └─ Verification: {status} {reason}\n")
        if status == "[PASS]":
            passed_count += 1

    print("=" * 60)
    print(f"SUMMARY: {passed_count}/{len(proxy_events)} requests successfully verified in Jaeger.")
    print("=" * 60)


if __name__ == "__main__":
    main()