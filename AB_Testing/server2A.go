package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"runtime"
	"bytes"
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

func Server2(w http.ResponseWriter, r *http.Request) {

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

	// To find the IPV version of the server2
	host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        fmt.Println("Error parsing remote address:", err)
    }

    clientIP := net.ParseIP(host)

    if clientIP.To4() != nil {
        fmt.Println("The Server2 connected using IPv4")
    } else {
        fmt.Println("The Server2 connected using IPv6")
    }

	bodyBytes, _ := io.ReadAll(r.Body)
	num , _ := strconv.Atoi(string(bodyBytes))

	// Server2 modifies the data by adding 2
	var tempnum int = num + 2
	log.Printf("Server 2 received %d, Server2 sent : %d\n",num,tempnum)

	dataToSend := []byte(strconv.Itoa(reqid))

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Payload", strconv.Itoa(reqid))

	w.Write(dataToSend)
	}
	
func main(){
	bctx := context.Background()

	shutdown, err := tracer.InitTracer(bctx, "server2A", "localhost:4317")

	if err != nil {
		log.Fatalf("Error while initiating server2A tracer : %v", err)
	}

	defer shutdown(bctx)

	handler := http.HandlerFunc(Server2)
	otelHandler := otelhttp.NewHandler(handler, "Server2A-Receive")

	http.Handle("/", otelHandler)
	// http.HandleFunc("/",Server2)
	fmt.Println("Server2A Listening to Server1 in port 8082...")
	log.Fatal(http.ListenAndServe(":8082",nil))
}

