package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"ebpftracer/tracer"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// customTransport intercepts outbound HTTP requests to set attributes directly
// on the client span created by otelhttp.
type customTransport struct {
	rt http.RoundTripper
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Retrieve the active client span created by otelhttp from request context
	span := trace.SpanFromContext(req.Context())
	if reqIDStr := req.Header.Get("X-Payload"); reqIDStr != "" {
		if reqID, err := strconv.Atoi(reqIDStr); err == nil {
			span.SetAttributes(attribute.Int("server.request_id", reqID))
		}
	}
	return t.rt.RoundTrip(req)
}

func getGoroutineID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]

	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]

	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func generate_score(cohort string) int {
	if cohort == "Server2B" {
		return 15
	} else if cohort == "Server2A" {
		return 10
	}
	return 0
}

func sendScoreToCentralServer(client *http.Client, cohort string, score int) {
	payload := struct {
		Cohort string `json:"cohort"`
		Score  int    `json:"score"`
	}{
		Cohort: cohort,
		Score:  score,
	}

	jsonData, _ := json.Marshal(payload)

	// Send to Central Server (Port 9090)
	resp, err := client.Post("http://127.0.0.1:9090/api/void", "application/json", bytes.NewBuffer(jsonData))
	if err == nil {
		resp.Body.Close()
	}
}

type reqCounter struct {
	count int
	mu    sync.Mutex
}

func main() {
	// Reusing the same client is critical for connection pooling
	ctx := context.Background()

	shutdown, err := tracer.InitTracer(ctx, "client", "localhost:4317")
	if err != nil {
		log.Fatalf("Error while initiating the OTPL : %v", err)
	}
	defer shutdown(ctx)

	tr := otel.Tracer("client")

	// Wrap http.DefaultTransport with customTransport inside otelhttp.NewTransport
	Client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: otelhttp.NewTransport(&customTransport{
			rt: http.DefaultTransport,
		}),
	}

	const numRequests = 500
	var wg sync.WaitGroup
	var requestid reqCounter

	fmt.Printf("[*] Starting %d concurrent requests...\n", numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1) // Tell the WaitGroup we are starting a task

		// Launch a Goroutine (Concurrent execution)
		go func(id int) {
			defer wg.Done()

			reqCtx, span := tr.Start(ctx, fmt.Sprintf("ClientWorker-%d", id))
			defer span.End()

			goid := getGoroutineID()
			var reqid int

			requestid.mu.Lock()
			requestid.count += 1
			reqid = requestid.count
			requestid.mu.Unlock()

			span.SetAttributes(
				attribute.Int64("go.goroutine_id", int64(goid)),
				attribute.Int("client.worker_id", id),
				attribute.Int("server.request_id", reqid),
			)

			Data := []byte(strconv.Itoa(reqid))
			req1, err := http.NewRequestWithContext(reqCtx, "POST", "http://localhost:8081", bytes.NewBuffer(Data))
			if err != nil {
				log.Printf("Request %d failed: %v", id, err)
				return
			}

			req1.Header.Set("Content-Type", "text/plain")
			req1.Header.Set("X-Payload", strconv.Itoa(reqid))

			resp1, err1 := Client.Do(req1)
			if err1 == nil {
				resp1.Body.Close()
			}

		}(i)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	if err := shutdown(ctx); err != nil {
		log.Printf("Error shutting down tracer: %v", err)
	}

	fmt.Println("[*] Experiment done")
}
