# Observability-using-eBPF

Investigating the feasibility of a kernel-level observability tool utilizing eBPF and BCC to monitor HTTP traffic in Go servers without modifying application source code.

> **Note:** This is a supporting/experimental setup rather than the main repository. The steps below focus on getting it running and understanding what the analysis scripts produce.

## Running the eBPF Tool

1. Start Jaeger:

   ```bash
   docker-compose start jaeger
   ```

2. Move into the `go-micro-service` directory and start the local environment:

   ```bash
   cd go-micro-service
   sudo ./scripts/run-local.sh
   ```

Once traffic has been captured, the eBPF tool writes per-service syscall logs to `ebpf/logs/traced_ebpf_syscall_analysis_<service>.txt`.

## Analysis Scripts

### 1. Compare Proxy Spans Against Jaeger

```bash
python3 ebpf/compare_traces_detail.py
```

* **What it does:** Reads the eBPF logs for `frontend` and `search`, finds goroutine (`GoID`) blocks that have both an incoming `ACCEPT` and an outgoing `CONNECT` with matching `traceparent` Trace IDs, and queries the local Jaeger API (`http://localhost:16686`) to check if the `CONNECT` span is actually a child/descendant of the `ACCEPT` span.
* **What it produces:** `ebpf/jaeger_comaparison.txt` — a report listing each matched `GoID`, its Trace ID, `ACCEPT` and `CONNECT` Span IDs, and a `[PASS]` / `[FAIL]` / `[ERROR]` status, followed by per-service and overall verification counts.

### 2. Stitch Full End-to-End Request Traces

```bash
python3 ebpf/entire_mapping.py
```

* **What it does:** Reads the eBPF logs across all five services (`frontend`, `search`, `geo`, `rate`, and `profile`) and stitches network hops together by matching each outgoing `CONNECT` `(remote, local, tcp_seq)` to the corresponding incoming `ACCEPT` `(local, remote, tcp_seq)`. It also checks whether the `traceparent` Trace ID matches across each hop.
* **What it produces:** `ebpf/stitched_traces.txt` (plus a console summary) — a visual call tree for every request starting at `frontend`, showing each service hop, IP/port pairs, TCP sequence numbers, and Jaeger Trace ID match status, ending with a summary of verified end-to-end requests and hop-level match/mismatch/missing counts.
