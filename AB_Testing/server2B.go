package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"bytes"
	"runtime"
	"sync"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"ebpftracer/tracer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func getGoroutineID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]

	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]

	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

type reqCounter struct {
	count int
	mu sync.Mutex
}

var requestID reqCounter

func Server3(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract active span from request context
	span := trace.SpanFromContext(ctx)

	requestID.mu.Lock()
	requestID.count += 1
	var reqid = requestID.count
	requestID.mu.Unlock() 

	// Attach Goroutine ID to Jaeger attributes
	goid := getGoroutineID()
	span.SetAttributes(
		attribute.Int64("go.goroutine_id", int64(goid)),
		attribute.Int64("server.request_id", int64(reqid)),
	)

	// To find the IPV version of the server3
	host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        fmt.Println("Error parsing remote address:", err)
    }

    clientIP := net.ParseIP(host)

    if clientIP.To4() != nil {
        fmt.Println("The Server3 connected using IPv4")
    } else {
        fmt.Println("The Server3 connected using IPv6")
    }

	bodyBytes, _ := io.ReadAll(r.Body)
	num , _ := strconv.Atoi(string(bodyBytes))

	// Server3 modifies the data by adding 3
	var tempnum int = num + 3
	log.Printf("Server3 received %d, Server3 sent : %d\n",num,tempnum)

	dataToSend := []byte(strconv.Itoa(reqid))

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Payload", strconv.Itoa(reqid))


	// if rand.Float32() < 0.20 {
    //     time.Sleep(300 * time.Millisecond) // Inflate latency by 40ms
    // }

	w.Write(dataToSend)
	}
	
func main(){

	bctx := context.Background()

	shutdown, err := tracer.InitTracer(bctx, "server2B", "localhost:4317")

	if err != nil {
		log.Fatalf("Error while initiating server2B tracer : %v", err)
	}

	defer shutdown(bctx)

	handler := http.HandlerFunc(Server3)
	otelHandler := otelhttp.NewHandler(handler, "Server2B-Receive")

	http.Handle("/", otelHandler)

	// http.HandleFunc("/",Server3)
	fmt.Println("Server2B Listening to Server1 in port 8083...")
	log.Fatal(http.ListenAndServe(":8083",nil))
}

