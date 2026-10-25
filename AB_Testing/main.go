package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	// "sort"
	"strings"
	"sync"
	"time"
)

var TargetAddress = "127.0.0.1:9090"

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
	Timestamp time.Time 
}

type TraceBuffer struct{
	mu sync.RWMutex
	Payload  []TracePayload
}

var globalBuffer = &TraceBuffer{
	Payload: make([]TracePayload, 0),
}

// --- GLOBAL STATE ---
var parentMapMu sync.RWMutex
var globalParentMap = make(map[string]TracePayload)

// 1. Make scores global so they accumulate over time
var totalScoreA int = 0
var totalScoreB int = 0

// 2. A queue to hold traces that are waiting for their parents to arrive
var unresolvedTraces []TracePayload

func main() {
	http.HandleFunc("/api/traces", handleIncomingRequest)
	http.HandleFunc("/api/void", DoNothing)
	go StartStitcherDaemon()

	fmt.Println("[*] Central Trace Server listening on http://127.0.0.1:9090")
	fmt.Println("[*] API Endpoints:")
	fmt.Println("    - POST /api/traces   (Used by Python eBPF agent)")
	fmt.Println("    - GET  /api/analyze  (Used by you to trigger the math)")

	log.Fatal(http.ListenAndServe(":9090",nil))
}

func DoNothing(w http.ResponseWriter, r *http.Request){
	w.WriteHeader(http.StatusOK)
}

func handleIncomingRequest(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)	
		return
	} 

	var payload TracePayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w,err.Error(), http.StatusBadRequest)
		return
	}

	payload.Timestamp = time.Now()

	globalBuffer.mu.Lock()
	globalBuffer.Payload = append(globalBuffer.Payload, payload)
	globalBuffer.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func StartStitcherDaemon(){
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		globalBuffer.mu.Lock()
		currentPayload := globalBuffer.Payload
		globalBuffer.Payload = make([]TracePayload, 0)
		globalBuffer.mu.Unlock()

		if(len(currentPayload) == 0 && len(unresolvedTraces) == 0){
			fmt.Println("[DEBUG DAEMON] Ticker fired, but buffer and unresolved queue are EMPTY.")
			continue
		}

		fmt.Printf("[DEBUG DAEMON] Processing Batch: %d new payloads, %d unresolved from past batches\n", 
            len(currentPayload), len(unresolvedTraces))

		processBatch(currentPayload)
	}
}

func processBatch( payloads []TracePayload){


	parentMapMu.Lock()	
	for _, p := range payloads {
		for _, e := range p.Events {
			if e.Type == "connect" {
				key := e.TCPSeq + "|" + e.LocalAddr + "->" + e.RemoteAddr
				globalParentMap[key] = p
			}
		}
	}
	parentMapMu.Unlock()

	// 2. Gather targets: Traces from PREVIOUS batches + Traces from THIS batch
	var targetsToEvaluate []TracePayload
	targetsToEvaluate = append(targetsToEvaluate, unresolvedTraces...) // Add pending ones

	for _, p := range payloads {
		for _, e := range p.Events {
			if e.Type == "connect" &&  strings.Contains(e.RemoteAddr, ":9090") {
				targetsToEvaluate = append(targetsToEvaluate, p)
			}
		}
	}

	// Inside processBatch():
	fmt.Printf("[DEBUG BATCH START] Evaluates %d targets against criteria...\n", len(targetsToEvaluate))
	if len(targetsToEvaluate) == 0 {
		fmt.Println("[DEBUG BATCH WARN] No payloads matched the target criteria in this batch!")
	}

	var stillUnresolved []TracePayload
	var batchScoreA int = 0
	var batchScoreB int = 0

	for _, p := range targetsToEvaluate {

		currentPayload := p
		isResolved := false

		for{
			reachedTarget := false

			for _, e  := range currentPayload.Events{

				if strings.Contains(e.LocalAddr, ":8082") || strings.Contains(e.RemoteAddr, ":8082"){
					batchScoreA += 15
					reachedTarget = true
					break

				} else if strings.Contains(e.LocalAddr, ":8083") || strings.Contains(e.RemoteAddr, ":8083"){
					batchScoreB += 20
					reachedTarget = true
					break

				}

			}
			
			if reachedTarget == true {
				isResolved = true
				break
			}

			var acceptEvent *TraceEvent
			for i, e  := range currentPayload.Events{
				if e.Type == "accept" {
					acceptEvent = &currentPayload.Events[i]
					break
				}
			}

			if acceptEvent == nil {
				isResolved = true
				break
			}

			key := acceptEvent.TCPSeq + "|" + acceptEvent.RemoteAddr + "->" + acceptEvent.LocalAddr

			parentMapMu.RLock()
			parentPayload, exist := globalParentMap[key]
			parentMapMu.RUnlock()

			if !exist {
				fmt.Printf("[DEBUG LOOKUP FAILED] Could not find parent key: '%s' in parentMap!\n", key)
				break
			} else {
				fmt.Printf("[DEBUG LOOKUP MATCH] Found parent for key: '%s'\n", key)
			}

			currentPayload = parentPayload

		}
		
		if !isResolved {
			stillUnresolved = append(stillUnresolved, p)
		}
	}

	unresolvedTraces = stillUnresolved
	totalScoreA += batchScoreA
	totalScoreB += batchScoreB

fmt.Printf("[*] Processed %d payloads (Pending: %d). THIS BATCH -> A: %d | B: %d || TOTAL SCORE -> A: %d | B: %d\n",
		len(payloads), len(unresolvedTraces), batchScoreA, batchScoreB, totalScoreA, totalScoreB)
	}



// func ingestTraceHandler(w http.ResponseWriter, r *http.Request){
// 	if r.Method != http.MethodPost{
// 		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var payload TracePayload

// 	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
// 		http.Error(w, "Invalid JSON", http.StatusBadRequest)
// 		return
// 	}

// 	mu.Lock()
// 	traceDB = append(traceDB, payload)
// 	mu.Unlock()

// 	w.WriteHeader(http.StatusOK)
// }

// func analyzeTailLatencyHandler(w http.ResponseWriter, r *http.Request) {
// 	mu.Lock()
// 	defer mu.Unlock()

// 	if len(traceDB) == 0 {
// 		fmt.Fprintf(w, "No traces collected yet.\n")
// 		return
// 	}

// 	// Helper struct to hold math for a single trace
// 	type TraceMetrics struct {
// 		AcceptMs      float64
// 		ConnectMs     float64
// 		ExclusiveTime float64
// 	}

// 	type AnalysisGroup struct {
// 		metrics []TraceMetrics
// 	}
// 	groups := make(map[string]*AnalysisGroup)

// 	// Step 1: Parse the database and group metrics by service
// 	for _, payload := range traceDB {
// 		var hasAccept bool
// 		var acceptMs, connectMs float64

// 		for _, event := range payload.Events {
// 			if event.Type == "accept" {
// 				hasAccept = true
// 				acceptMs = event.DurationMs
// 			} else if event.Type == "connect" {
// 				connectMs = event.DurationMs
// 			}
// 		}

// 		if hasAccept {
// 			if groups[payload.ServiceName] == nil {
// 				groups[payload.ServiceName] = &AnalysisGroup{}
// 			}
			
// 			exclusive := acceptMs - connectMs
// 			if exclusive < 0 {
// 				exclusive = 0
// 			}
			
// 			groups[payload.ServiceName].metrics = append(groups[payload.ServiceName].metrics, TraceMetrics{
// 				AcceptMs:      acceptMs,
// 				ConnectMs:     connectMs,
// 				ExclusiveTime: exclusive,
// 			})
// 		}
// 	}

// 	response := "=== ADVANCED TAIL LATENCY ANALYSIS (Baseline vs Top 2%) ===\n\n"
// 	var rootCauseNodes []string

// 	// Step 2: Analyze every service against its own Baseline
// 	for serviceName, group := range groups {
// 		if len(group.metrics) < 10 {
// 			response += fmt.Sprintf("[%s] Not enough traces (Found %d)\n\n", serviceName, len(group.metrics))
// 			continue
// 		}

// 		// Sort metrics by total AcceptMs to find the Top 2% threshold
// 		sort.Slice(group.metrics, func(i, j int) bool {
// 			return group.metrics[i].AcceptMs < group.metrics[j].AcceptMs
// 		})

// 		p98Index := int(float64(len(group.metrics)) * 0.98)
// 		p98Threshold := group.metrics[p98Index].AcceptMs

// 		var baselineExclusive, baselineWait float64
// 		var tailExclusive, tailWait float64
// 		var baselineCount, tailCount int

// 		// Split the traffic into Baseline vs Tail
// 		for _, m := range group.metrics {
// 			if m.AcceptMs < p98Threshold {
// 				baselineExclusive += m.ExclusiveTime
// 				baselineWait += m.ConnectMs
// 				baselineCount++
// 			} else {
// 				tailExclusive += m.ExclusiveTime
// 				tailWait += m.ConnectMs
// 				tailCount++
// 			}
// 		}

// 		// Calculate Averages
// 		avgBaseExclusive := baselineExclusive / float64(baselineCount)
// 		avgBaseWait := baselineWait / float64(baselineCount)

// 		var avgTailExclusive, avgTailWait float64
// 		if tailCount > 0 {
// 			avgTailExclusive = tailExclusive / float64(tailCount)
// 			avgTailWait = tailWait / float64(tailCount)
// 		} else {
// 			continue // Safety fallback
// 		}

// 		// Calculate the "Inflation" (How much worse was the tail compared to normal?)
// 		exclusiveInflation := avgTailExclusive - avgBaseExclusive
// 		waitInflation := avgTailWait - avgBaseWait

// 		// Print the transparent metrics for this specific node
// 		response += fmt.Sprintf("--- NODE: %s ---\n", serviceName)
// 		response += fmt.Sprintf("Traces Analyzed           : %d (Baseline: %d, Tail: %d)\n", len(group.metrics), baselineCount, tailCount)
// 		response += fmt.Sprintf("98th Percentile Threshold : %.2f ms\n", p98Threshold)
// 		response += fmt.Sprintf("Baseline (Bottom 98%%)    : Exclusive = %.2f ms | Wait = %.2f ms\n", avgBaseExclusive, avgBaseWait)
// 		response += fmt.Sprintf("Tail (Top 2%%)            : Exclusive = %.2f ms | Wait = %.2f ms\n", avgTailExclusive, avgTailWait)
// 		response += fmt.Sprintf("INFLATION (Tail - Base)   : Internal Delay = +%.2f ms | Downstream Delay = +%.2f ms\n\n", exclusiveInflation, waitInflation)

// 		// Step 3: Identify Root Cause
// 		// Did this node's internal processing inflate more than its downstream dependencies did?
// 		// (We include a small 5ms buffer to ignore random OS jitter)

// 		anomalyThreshold := avgBaseExclusive * 0.20 
		
// 		// To prevent micro-jitters on ultra-fast nodes (e.g., 0.1ms going to 0.2ms), 
// 		// we ensure the inflation is at least 20% OR at least 2ms, whichever is larger.
// 		if anomalyThreshold < 2.0 {
// 			anomalyThreshold = 2.0
// 		}

// 		// The Final Master Logic
// 		if exclusiveInflation > anomalyThreshold {
// 			rootCauseNodes = append(rootCauseNodes, serviceName)
// 		}
// 	}

// 	// Step 4: The Master System Verdict
// 	response += "=== GLOBAL VERDICT ===\n"
// 	if len(rootCauseNodes) == 0 {
// 		response += "No definitive internal anomaly found across the analyzed nodes.\n"
// 	} else {
// 		response += "The root cause of the tail latency anomaly is INTERNAL to the following node(s):\n"
// 		for _, node := range rootCauseNodes {
// 			response += fmt.Sprintf(" -> [ %s ]\n", node)
// 		}
// 	}

// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }