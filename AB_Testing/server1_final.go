package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"net/http/httptrace"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
)

func initTracer() *sdktrace.TracerProvider{
	exporter, err := otlptracehttp.New(context.Background(),
					otlptracehttp.WithEndpoint("localhost:4318"),
					otlptracehttp.WithInsecure(),)

	if err != nil {
		log.Fatal(err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("server1-gateway"),
		)),
	)
	otel.SetTracerProvider(tp)
	return tp

}

func getGoroutineID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

type Data struct{
	val int;
}

type Gateway struct {
	Client *http.Client
}

func (g * Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {


	inboundSpan := trace.SpanFromContext(r.Context())

	// ---- LEG 1: Inbound 4-Tuple (Client -> Server 1) ----
	// Remote (Client) details
	clientHost, clientPort, _ := net.SplitHostPort(r.RemoteAddr)
	
	// Local (Server 1 Listening) details via Go's internal context key
	localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	var server1Host, server1Port string
	if ok {
		server1Host, server1Port, _ = net.SplitHostPort(localAddr.String())
	}

	// Inject Leg 1 into the Inbound Span
	inboundSpan.SetAttributes(
		attribute.String("net.inbound.client.ip", clientHost),
		attribute.String("net.inbound.client.port", clientPort),
		attribute.String("net.inbound.server1.ip", server1Host),
		attribute.String("net.inbound.server1.port", server1Port),
		attribute.Int64("net.goroutine.id", int64(getGoroutineID())),
	)


	fmt.Printf("[ServeHTTP] Handling request on Goroutine ID (start): %d\n", getGoroutineID())
	// To find the IPV version 
	host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        fmt.Println("Error parsing remote address:", err)
    }

    // Parse the string into a net.IP object
    clientIP := net.ParseIP(host)

    if clientIP.To4() != nil {
        fmt.Println("The client connected using IPv4")
    } else {
        fmt.Println("The client connected using IPv6")
    }
		
	bodyBytes, _ := io.ReadAll(r.Body)
	num , _ := strconv.Atoi(string(bodyBytes))

	// Server1 updates the value by adding 1
	var tempnum int = num + 1
	log.Printf("Server 1 received %d, Server1 sent : %d\n",num,tempnum)

	dataToSend := []byte(strconv.Itoa(tempnum))

	req, err := http.NewRequestWithContext(r.Context(), "POST", "http://localhost:8082", bytes.NewBuffer(dataToSend))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "text/plain")

	clientTrace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				outboundSpan := trace.SpanFromContext(req.Context())
				
				s1OutHost, s1OutPort, _ := net.SplitHostPort(info.Conn.LocalAddr().String())
				s2InHost, s2InPort, _ := net.SplitHostPort(info.Conn.RemoteAddr().String())

				outboundSpan.SetAttributes(
					attribute.String("net.outbound.server1.ip", s1OutHost),
					attribute.String("net.outbound.server1.port", s1OutPort), // Ephemeral Port!
					attribute.String("net.outbound.server2.ip", s2InHost),
					attribute.String("net.outbound.server2.port", s2InPort), // 8082
				)
			}
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), clientTrace))

	resp, err := g.Client.Do(req)
	if err != nil {
		http.Error(w, "Failed to reach Server2", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	finalAnswer, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(finalAnswer)
	}
	
func main(){

	fmt.Printf("[Main] Application started on Goroutine ID: %d\n", getGoroutineID())

	tp := initTracer()
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}()

	// Inject the OTel transport into the Gateway's outgoing Client
	Gate := &Gateway{
		Client: &http.Client{
			Timeout:   3 * time.Second,
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
	}

	handler := otelhttp.NewHandler(Gate, "Incoming-Gateway-Request")

	http.Handle("/",handler)
	fmt.Println("Server1 Listening to Client in port 8081...")
	log.Fatal(http.ListenAndServe(":8081",nil))

}

