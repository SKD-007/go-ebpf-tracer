package main

import(
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"log"
)


type TraceEvent struct {
	Type            string  `json:"type"`
	FD              string  `json:"fd"` 
	LocalAddr       string  `json:"local_addr"`
	RemoteAddr      string  `json:"remote_addr"`
	TCPSeq          string  `json:"tcp_seq"`
	ReadTime        string  `json:"read_time"`
	WriteTime       string  `json:"write_time"`
	DurationMs      float64 `json:"duration_ms"`
	RequestPayload  string  `json:"request_payload"`
	ResponsePayload string  `json:"response_payload"`
}

type TracePayload struct {
	ServiceName string       `json:"service_name"`
	GoID        any  `json:"goid"` // Using interface{} to handle both ints and strings safely
	Events      []TraceEvent `json:"events"`
}

var (
	traceDB []TracePayload 
	mu sync.Mutex
)

func main() {
	http.HandleFunc("/api/traces", ingestTraceHandler)
	http.HandleFunc("/api/analyze", analyzeTailLatencyHandler)

	fmt.Println("[*] Central Trace Server listening on http://127.0.0.1:9090")
	fmt.Println("[*] API Endpoints:")
	fmt.Println("    - POST /api/traces   (Used by Python eBPF agent)")
	fmt.Println("    - GET  /api/analyze  (Used by you to trigger the math)")

	log.Fatal(http.ListenAndServe(":9090",nil))
}

func ingestTraceHandler(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost{
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload TracePayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	mu.Lock()
	traceDB = append(traceDB, payload)
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func analyzeTailLatencyHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	if len(traceDB) == 0 {
		fmt.Fprintf(w, "No traces collected yet.\n")
		return
	}

	// Helper struct to hold math for a single trace
	type TraceMetrics struct {
		AcceptMs      float64
		ConnectMs     float64
		ExclusiveTime float64
	}

	type AnalysisGroup struct {
		metrics []TraceMetrics
	}
	groups := make(map[string]*AnalysisGroup)

	// Step 1: Parse the database and group metrics by service
	for _, payload := range traceDB {
		var hasAccept bool
		var acceptMs, connectMs float64

		for _, event := range payload.Events {
			if event.Type == "accept" {
				hasAccept = true
				acceptMs = event.DurationMs
			} else if event.Type == "connect" {
				connectMs = event.DurationMs
			}
		}

		if hasAccept {
			if groups[payload.ServiceName] == nil {
				groups[payload.ServiceName] = &AnalysisGroup{}
			}
			
			exclusive := acceptMs - connectMs
			if exclusive < 0 {
				exclusive = 0
			}
			
			groups[payload.ServiceName].metrics = append(groups[payload.ServiceName].metrics, TraceMetrics{
				AcceptMs:      acceptMs,
				ConnectMs:     connectMs,
				ExclusiveTime: exclusive,
			})
		}
	}

	response := "=== ADVANCED TAIL LATENCY ANALYSIS (Baseline vs Top 2%) ===\n\n"
	var rootCauseNodes []string

	// Step 2: Analyze every service against its own Baseline
	for serviceName, group := range groups {
		if len(group.metrics) < 10 {
			response += fmt.Sprintf("[%s] Not enough traces (Found %d)\n\n", serviceName, len(group.metrics))
			continue
		}

		// Sort metrics by total AcceptMs to find the Top 2% threshold
		sort.Slice(group.metrics, func(i, j int) bool {
			return group.metrics[i].AcceptMs < group.metrics[j].AcceptMs
		})

		p98Index := int(float64(len(group.metrics)) * 0.98)
		p98Threshold := group.metrics[p98Index].AcceptMs

		var baselineExclusive, baselineWait float64
		var tailExclusive, tailWait float64
		var baselineCount, tailCount int

		// Split the traffic into Baseline vs Tail
		for _, m := range group.metrics {
			if m.AcceptMs < p98Threshold {
				baselineExclusive += m.ExclusiveTime
				baselineWait += m.ConnectMs
				baselineCount++
			} else {
				tailExclusive += m.ExclusiveTime
				tailWait += m.ConnectMs
				tailCount++
			}
		}

		// Calculate Averages
		avgBaseExclusive := baselineExclusive / float64(baselineCount)
		avgBaseWait := baselineWait / float64(baselineCount)

		var avgTailExclusive, avgTailWait float64
		if tailCount > 0 {
			avgTailExclusive = tailExclusive / float64(tailCount)
			avgTailWait = tailWait / float64(tailCount)
		} else {
			continue // Safety fallback
		}

		// Calculate the "Inflation" (How much worse was the tail compared to normal?)
		exclusiveInflation := avgTailExclusive - avgBaseExclusive
		waitInflation := avgTailWait - avgBaseWait

		// Print the transparent metrics for this specific node
		response += fmt.Sprintf("--- NODE: %s ---\n", serviceName)
		response += fmt.Sprintf("Traces Analyzed           : %d (Baseline: %d, Tail: %d)\n", len(group.metrics), baselineCount, tailCount)
		response += fmt.Sprintf("98th Percentile Threshold : %.2f ms\n", p98Threshold)
		response += fmt.Sprintf("Baseline (Bottom 98%%)    : Exclusive = %.2f ms | Wait = %.2f ms\n", avgBaseExclusive, avgBaseWait)
		response += fmt.Sprintf("Tail (Top 2%%)            : Exclusive = %.2f ms | Wait = %.2f ms\n", avgTailExclusive, avgTailWait)
		response += fmt.Sprintf("INFLATION (Tail - Base)   : Internal Delay = +%.2f ms | Downstream Delay = +%.2f ms\n\n", exclusiveInflation, waitInflation)

		// Step 3: Identify Root Cause
		// Did this node's internal processing inflate more than its downstream dependencies did?
		// (We include a small 5ms buffer to ignore random OS jitter)

		anomalyThreshold := avgBaseExclusive * 0.20 
		
		// To prevent micro-jitters on ultra-fast nodes (e.g., 0.1ms going to 0.2ms), 
		// we ensure the inflation is at least 20% OR at least 2ms, whichever is larger.
		if anomalyThreshold < 2.0 {
			anomalyThreshold = 2.0
		}

		// The Final Master Logic
		if exclusiveInflation > anomalyThreshold {
			rootCauseNodes = append(rootCauseNodes, serviceName)
		}
	}

	// Step 4: The Master System Verdict
	response += "=== GLOBAL VERDICT ===\n"
	if len(rootCauseNodes) == 0 {
		response += "No definitive internal anomaly found across the analyzed nodes.\n"
	} else {
		response += "The root cause of the tail latency anomaly is INTERNAL to the following node(s):\n"
		for _, node := range rootCauseNodes {
			response += fmt.Sprintf(" -> [ %s ]\n", node)
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(response))
}