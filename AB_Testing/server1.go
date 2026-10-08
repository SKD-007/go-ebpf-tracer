package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"ebpftracer/tracer"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// customTransport intercepts outbound requests to attach attributes to the client span
type customTransport struct {
	rt http.RoundTripper
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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

type Data struct {
	val int
}

type Gateway struct {
	Client *http.Client
}

type reqCounter struct {
	count int
	mu    sync.Mutex
}

var requestID reqCounter

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)

	requestID.mu.Lock()
	requestID.count += 1
	var reqid = requestID.count
	requestID.mu.Unlock()

	goid := getGoroutineID()
	span.SetAttributes(
		attribute.Int64("go.goroutine_id", int64(goid)),
		attribute.Int64("server.request_id", int64(reqid)),
	)

	bodyBytes, _ := io.ReadAll(r.Body)
	num, _ := strconv.Atoi(string(bodyBytes))

	var tempnum int = num + 1
	log.Printf("Server 1 received %d, Server1 sent : %d\n", num, tempnum)

	dataToSend := []byte(strconv.Itoa(reqid))

	type asyncResult struct {
		data   []byte
		cohort string
		err    error
	}
	resultChan := make(chan asyncResult, 1)

	go func() {
		go func() {
			workerGoID := getGoroutineID()
			span.SetAttributes(
				attribute.Int64("go.worker_goroutine_id", int64(workerGoID)),
			)

			var resp *http.Response
			var err error
			var cohort string
			var targetURL string
			if rand.Float32() < 0.1 {
				cohort = "Server2B"
				targetURL = "http://localhost:8083"
			} else {
				cohort = "Server2A"
				targetURL = "http://localhost:8082"
			}

			req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewBuffer(dataToSend))
			if err != nil {
				resultChan <- asyncResult{err: err}
				return
			}
			
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("X-Payload", strconv.Itoa(reqid))

			resp, err = g.Client.Do(req)
			if err != nil {
				resultChan <- asyncResult{err: err}
				return
			}
			defer resp.Body.Close()

			finalAnswer, err := io.ReadAll(resp.Body)
			resultChan <- asyncResult{finalAnswer, cohort, err}
		}()
	}()

	res := <-resultChan

	if res.err != nil {
		http.Error(w, "Failed to reach Server2", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("AB-Cohort", res.cohort)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Payload", strconv.Itoa(reqid))
	w.Write(res.data)
}

func main() {
	fmt.Printf("[Main] Application started on Goroutine ID: %d\n", getGoroutineID())

	bctx := context.Background()

	shutdown, err := tracer.InitTracer(bctx, "server1", "localhost:4317")
	if err != nil {
		log.Fatalf("Error while initiating tracer : %v", err)
	}
	defer shutdown(bctx)

	baseTransport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100,
	}

	Gate := &Gateway{
		Client: &http.Client{
			Timeout: 3 * time.Second,
			Transport: otelhttp.NewTransport(&customTransport{
				rt: baseTransport,
			}),
		},
	}

	otelHandler := otelhttp.NewHandler(Gate, "Server1-Gateway")

	http.Handle("/", otelHandler)
	fmt.Println("Server1 Listening to Client in port 8081...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}