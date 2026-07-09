package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"time"
)

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

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	parentGoID := getGoroutineID()
	fmt.Printf("[ServeHTTP] Handling request on Goroutine ID (start): %d\n", parentGoID)

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
	num, _ := strconv.Atoi(string(bodyBytes))

	// Server1 updates the value by adding 1
	var tempnum int = num + 1
	log.Printf("Server 1 received %d, Server1 sent : %d\n", num, tempnum)

	dataToSend := []byte(strconv.Itoa(tempnum))


	// Create a channel to receive the result from our child goroutine
	type asyncResult struct {
		data []byte
		err  error
	}
	resultChan := make(chan asyncResult)

	// Using a separate go func to send request to server2
	go func() {
		childGoID := getGoroutineID()
		fmt.Printf("[Child Goroutine] Making request to Server2 on Goroutine ID: %d (Parent was %d)\n", childGoID, parentGoID)

		resp, err := g.Client.Post("http://localhost:8082", "text/plain", bytes.NewBuffer(dataToSend))
		if err != nil {
			resultChan <- asyncResult{nil, err}
			return
		}
		defer resp.Body.Close()

		finalAnswer, err := io.ReadAll(resp.Body)
		resultChan <- asyncResult{finalAnswer, err}
	}()

	// Wait until the child goroutine sends data back through the channel
	res := <-resultChan

	if res.err != nil {
		http.Error(w, "Failed to reach Server2", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(res.data)

}

func main() {
	fmt.Printf("[Main] Application started on Goroutine ID: %d\n", getGoroutineID())

	// Inject the custom transport into the Gateway's Client
	Gate := &Gateway{
		Client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}

	http.Handle("/", Gate)
	fmt.Println("Server1 Listening to Client in port 8081...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}